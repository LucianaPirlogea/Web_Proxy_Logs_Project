# Versiunile folosite la rularea modelului
# !pip install keras==2.4.3
# !pip install tensorflow==2.4.1

"""
Librarii
numpy: algebra liniara
pandas: procesarea datelor
sklearn.model_selection: impartirea datelor in train si test
keras: construirea retelei neuronale
gc: garbage collection
tensorflow: pentru instantiere TPU(Tensor Processing Unit)
"""

import numpy as np
import pandas as pd
import gc
import subprocess
from sklearn.model_selection import train_test_split
import tensorflow as tf
from keras.preprocessing.sequence import pad_sequences
from keras.models import Sequential, load_model
from keras.layers.core import Dense, Dropout, Activation
from keras.layers.embeddings import Embedding
from keras.layers.recurrent import LSTM
from keras.callbacks import EarlyStopping
from sklearn.metrics import confusion_matrix

# Procesarea datelor, label encoding,
# renuntand la jumate din date din cauza limitelor RAM

df = pd.read_csv("../input/dga-or-benign-domain-names/final_15million.csv")

df = df.drop("Unnamed: 0", 1)
df['label'] = df['label'].str.replace('benign', '0')
df['label'] = df['label'].str.replace('dga', '1')

df.drop(df.label.eq('0').sample(frac=.5).index, inplace=True)
df = df.reset_index(drop=True)
df.drop(df.label.eq('1').sample(frac=.5).index, inplace=True)
df = df.reset_index(drop=True)

X = df[["domain"]].astype(str)
y = df[["label"]].astype(str).astype(int)

"""Atribuim fiecarui caracter(unic) gasit in domenii cate un numar,
pentru a putea fi transmis in reteaua neuronala
Fiecare domeniu va deveni un array de dimensiunea celui mai lung
domeniu gasit(adus la dimensiunea maxima printr-un padding de 0-uri)
"""

domain_set = set()
for domain in X['domain']:
    dom = str(domain)
    for letter in dom:
        domain_set.add(str(letter))
valid_characters = {}
i = 0
for letter in domain_set:
    i = i+1
    valid_characters[letter] = i
max_features = len(valid_characters) + 1  # Numarul de caractere unice gasite
print(valid_characters)
max_length = np.max([len(x) for x in X['domain']]) # Numarul maxim de caractere ale unui domeniu
X = [[valid_characters[y] for y in x] for x in X['domain']]
print(max_length)

X = pad_sequences(X, maxlen=max_length)  #Aduc toti vectorii la lungimea maxima

# Impartim datele in training si testing data,
# 20% din date pentru testing si eliberam memoria

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

del X
del y
gc.collect()

# Detectare TPU si instantiere pentru

tpu = tf.distribute.cluster_resolver.TPUClusterResolver.connect()
tpu_strategy = tf.distribute.experimental.TPUStrategy(tpu)

"""Sequential model: appropriate for a plain stack of layers where
each layer has exactly one input tensor and one output tensor.
Embedding layer: Turns positive integers (indexes) into dense vectors of fixed size.
Transforma vectorii de lungime max_features(numarul de caractere unice) in vectori de lungime 128(pt LSTM)
Long Short-Term Memory layer:Recurrent neural network capable of learning
order dependence in sequence prediction problems.
Dropout layer: randomly sets input units to 0 with a frequency of 0.5
at each step during training time, which helps prevent overfitting.
Dense implements the operation: output = activation(dot(input, kernel) + bias)
Sigmoid converts a vector of values to a probability distribution(for 2 elements).
Cross-entropy is a measure of the difference between two probability distributions
for a given random variable or set of events.
Binary_crossentropy => 2 possible outputs
"""

with tpu_strategy.scope():
    model = Sequential()
    model.add(Embedding(max_features, 128, input_length=max_length)) 
    model.add(LSTM(128))
    model.add(Dropout(0.5))
    model.add(Dense(1))
    model.add(Activation('sigmoid'))
    model.compile(loss='binary_crossentropy', optimizer='rmsprop')

# Retinem cel mai bun model si il salvez

early_stopping_monitor = EarlyStopping(
    monitor='binary_crossentropy',
    min_delta=0,
    patience=0,
    verbose=0,
    mode='auto',
    baseline=None,
    restore_best_weights=True
)

model.save("DGA_7million.h5")

# Testam modelul pe datele de test

prediction = model.predict(X_test)
prediction = (prediction > 0.5).astype(int)

# Calculez acuratetea

tn, fp, fn, tp = confusion_matrix(y_test, prediction).ravel()
print((tp+tn)/(tp+tn+fp+fn))

# Testam modelul pentru un domeniu dat de noi

domain = [[valid_characters[y] for y in "laoksdjasdjajfs"]]
prediction = model.predict(pad_sequences(domain, maxlen=max_length)) > 0.5
if prediction[0][0] == 1:
    print("DGA")
else:
    print("Not DGA")
