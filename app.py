#!/usr/bin/env python

import threading
import base64
import time
import whois
import datetime
import is_disposable_email
import requests
from keras.preprocessing.sequence import pad_sequences
import json
from keras.models import load_model
import tensorflow as tf
import tldextract
import logging

logging.disable(logging.WARNING)  # Elimina warning-uri primite de la tensorflow

"""Proiect: Attack Detection with Web Proxy Logs
    Echipa:
        Avian Silviu-Gabriel
        Ioan Tudor Alexandru
        Pirlogea Luciana-Elena
        Radu Mihai-Danut
        Vlad Melisa-Andra
"""

"""Campuri pe care le va avea un log:
    0 - date -
    1 - time -
    2 - duration -
    3 - client-ip -
    4 - request status -
    5 - server action -
    6 - bytes out -
    7 - bytes in -
    8 - method -
    9 - protocol -
    10 - adresa serverului -
    11 - path-ul in server -
    12 - query -
    13 - content type -
    14 - server ip -
    15 - user-agent -
"""


def verify_blacklist(log):
    """Functie care verifica site-urile accesate din loguri in blacklist.

    Va adauga intr-un dictionar(d_blacklist) ip-urile clientilor pe post de
    chei si logurile suspicioase ca valori.
    """

    global ls_blacklist, ls_logs, d_blacklist, whitelist, d_dga

    client_ip = log[3]
    address = log[10]

    # Daca minim un cuvant cheie din blacklist se afla in site-ul din log, site-ul nu este
    # in whitelist si website-ul a fost detectat ca fiind un DGA

    if (any(word in address for word in ls_blacklist) and address not in whitelist) or \
            (address in d_dga.keys() and d_dga[address] == 1):

        # Daca ip-ul respectiv se afla deja in dictionarul cu loguri
        # suspicioase, adaugam logul nou gasit
        if log[3] in d_blacklist.keys():
            aux = d_blacklist[client_ip]

            # Verificam daca logul este sau nu un duplicat
            if log not in aux:
                aux.append(log)
                d_blacklist[client_ip] = aux
        # Altfel, adaugam acel ip cu logul gasit
        else:
            d_blacklist[client_ip] = [log]


def verify_time():
    """Functie care verifica requesturile facute de acelasi client la aceeasi
    ora, catre acelasi site, in zile diferite.

    Variabile:
        ls_logs_sorted(list): lista de loguri sortata dupa ora, ip si numele site-ului
        count(int): variabila pentru numarul de zile diferite in care avem
        request la aceeasi ora, de la acelasi client, catre acelasi site
        time(string): variabila pentru ora la care se face requestul
        l_date(dictionar): dictionar cu zile diferite pentru requestul facut la aceeasi ora
        ip(string): variabila pentru ip-ul clientului care face requestul
        l_logs(list): lista cu loguri suspicioase facute la aceeasi ora, de
        acelasi client, catre acelasi site
        site(string): variabila pentru numele site-ului pe care clientul vrea sa-l acceseze

    Adauga intr-un dictionar(d_ora) ip-urile clientilor pe post de chei si
    logurile suspicioase ca valori.
    """

    global ls_logs, d_ora

    ls_logs_sorted = ls_logs
    ls_logs_sorted.sort(key=lambda x: (x[1], x[3], x[10]))

    count = 1
    time = ls_logs_sorted[0][1]
    l_date = {ls_logs_sorted[0][0]: 1}
    ip = ls_logs_sorted[0][3]
    l_logs = [ls_logs_sorted[0]]
    site = ls_logs_sorted[0][10]

    # Iteram prin lista sortata de loguri
    for i in range(1, len(ls_logs_sorted)):
        # Daca gasim un request la aceeasi ora catre acelasi website, in zi
        # diferita, de la un client cu acelasi ip, in lista de loguri sortata
        if time == ls_logs_sorted[i][1] and ip == ls_logs_sorted[i][3] and \
                site == ls_logs_sorted[i][10] and (ls_logs_sorted[i][0] not in l_date.keys()):
            count += 1
            l_date[ls_logs_sorted[i][0]] = 1
            l_logs.append(ls_logs_sorted[i])
        else:
            # Daca exista minim 2 zile diferite in care s-a facut un request la aceeasi ora de la acelasi
            # client catre acelasi site
            if count > 1:
                # Daca ip-ul se afla deja in dictionar, adaugam lista de loguri
                if ip in d_ora.keys():
                    aux = d_ora[ip]
                    aux.append(l_logs)
                    d_ora[ip] = aux
                # Altfel, adaugam ip-ul nou, cu lista gasita
                else:
                    d_ora[ip] = [l_logs]

            # Reinitializam variabilele folosite
            count = 1
            time = ls_logs_sorted[i][1]
            l_date = {ls_logs_sorted[i][0]: 1}
            ip = ls_logs_sorted[i][3]
            l_logs = [ls_logs_sorted[i]]
            site = ls_logs_sorted[i][10]


def verify_useragent(log):
    """Functie care verifica user agent-ul.

    Variabile:
        user_agent(string): variabila pentru user agent
        client_ip(string): variabila pentru client ip

    Adauga intr-un dictionar(d_user_agent) loguri suspicioase in functie de client ip
    si intr-un alt dictionar(user_agent) de cate ori apare acel user agent.
    """

    global ua_keywords, ua_frequency, d_user_agent

    user_agent = log[15]
    client_ip = log[3]

    # Verificare pentru encoding in base64 sau user agent gol
    if user_agent == "" or 'Vm0wd' == user_agent[:5]:
        # Daca ip-ul respectiv se afla deja in dictionarul cu loguri suspicioase
        if client_ip in d_user_agent.keys():
            aux = d_user_agent[client_ip]

            # Daca logul nu a fost deja adaugat in lista, adaugam logul nou gasit
            if log not in aux:
                aux.append(log)
                d_user_agent[client_ip] = aux
        # Altfel, adaugam acel ip cu logul gasit
        else:
            d_user_agent[client_ip] = [log]

    if any(word in user_agent.lower() for word in ua_keywords):
        # Daca ip-ul respectiv se afla deja in dictionarul cu loguri suspicioase
        if client_ip in d_user_agent.keys():
            aux = d_user_agent[client_ip]

            # Daca logul nu a fost deja adaugat in lista, adaugam logul nou gasit
            if log not in aux:
                aux.append(log)
                d_user_agent[client_ip] = aux
        # Altfel, adaugam acel ip cu logul gasit
        else:
            d_user_agent[client_ip] = [log]

    # Verificam daca un user agent se afla deja in dictionar
    if user_agent in ua_frequency.keys():
        ua_frequency[user_agent] += 1
    # Altfel, initializam numarul de aparitii cu 1
    else:
        ua_frequency[user_agent] = 1


def verify_HTTPmethod(log):
    """Functie care verifica metodele HTTP din loguri.

    Variabile:
        client_ip(string): variabila pentru client ip
        method(string): variabila pentru metoda HTTP din log

    Adauga intr-un dictionar(d_method) numarul de metode unsafe si numarul
    total de metode trimise de catre un client ip.
    """

    global d_method

    client_ip = log[3]
    method = log[8]

    # Daca metoda este una din categoria SAFE
    if method in ['GET', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']:
        # Daca ip-ul a fost deja adaugat in dictionar
        if client_ip in d_method.keys():
            value = d_method[client_ip]
            value[1] += 1
            d_method[client_ip] = value
        # Altfel, initializam lista ce va contine pe prima pozitie numarul de metode UNSAFE si pe a doua pozitie
        # numarul total de metode
        else:
            d_method[client_ip] = [0, 1]
    else:
        # Daca ip-ul a fost deja adaugat in dictionar
        if client_ip in d_method.keys():
            value = d_method[client_ip]
            value[0] += 1
            value[1] += 1
            d_method[client_ip] = value
        # Altfel, initializam lista ce va contine pe prima pozitie numarul de metode UNSAFE si pe a doua pozitie
        # numarul total de metode
        else:
            d_method[client_ip] = [1, 1]


def verify_whois(domain):
    """Functie care verifica un domeniu accesat de catre client.

    Variabile:
        detalii(json): contine detalii despre un domeniu accesat
        exp_date(string): data la care expira domeniul
        creation_date(string): data la care a fost creat domeniul
        lifespan(datetime): lifespan-ul domeniului
        age(datetime): durata care a trecut de la crearea domeniului
        email_address(string): adresa de email cu care a fost inregistrat domeniul
        count(int): numarul de conditii indeplinite care fac acel domeniu sa fie suspicios

    Returneaza True daca domeniul este incadrat ca fiind suspicios sau False, altfel.
    """

    # Daca putem gasi informatii despre acel site
    try:
        flags = whois.NICClient().WHOIS_QUICK
        detalii = whois.whois(domain, flags=flags)
    # Altfel, ignoram acel site
    except Exception:
        return False

    # Daca comeniul cautat are o data de creare si o data de expirare(acesta exista)
    if detalii.creation_date and detalii.expiration_date:
        count = 0
        if isinstance(detalii.expiration_date, list):
            exp_date = detalii.expiration_date[0]
        else:
            exp_date = detalii.expiration_date
        if isinstance(detalii.creation_date, list):
            creation_date = detalii.creation_date[0]
        else:
            creation_date = detalii.creation_date

        # Daca API-ul nu stie exact data la care a fost creat site-ul, il ignoram
        if isinstance(exp_date, str) or isinstance(creation_date, str):
            return False

        lifespan = (exp_date - creation_date).days

        # Verificam ca lifespan-ul sa nu fie mai mic de 14 de zile
        if lifespan < 14:
            count += 1
        age = (datetime.datetime.now() - creation_date).days

        # Verificam ca perioada care a trecut de la crearea domeniului
        # sa nu fie mai mica de 14 de zile.
        if age < 14:
            count += 1

        # Verificam ca mail-ul sau unul din mail-urile asociate domeniului
        # inregistrat sa nu fie descoperit ca o adresa de e-mail disposable.
        if isinstance(detalii.emails, list):
            if any(is_disposable_email.check(email) for email in detalii.emails):
                count += 1
        else:
            email_address = detalii.emails
            if email_address:
                result = is_disposable_email.check(email_address)
                if result:
                    count += 1

        # Daca sunt indeplinite minim 2 din cele 3 conditii cautate,
        # atunci domeniul e considerat suspicios
        if count >= 2:
            return True
        else:
            return False
    # Daca domeniul a fost descoperit ca fiind unul legitim, dar nu putem afla
    # foarte multe despre el, il ignoram.
    else:
        return False


def verify_dga(url):
    """Functie care verifica daca un domeniu este generat de catre un DGA.

    Incarcam modelul antrenat si importam dictionarul cu literele encodate.
    Prezicem daca domeniul este generat de DGA sau nu.

    Variabile:
        max_length(int): lungimea maxima a domeniului din datele de train
        valid_characters(dict): doate caracterele din datele de train

    Returneza 1 daca e DGA, 0 altfel.
    """

    global valid_characters, max_length, model

    # Extragem root domain-ul din url, folosind libraria tldextract
    domain = tldextract.extract(url).domain

    if any(character not in valid_characters.keys() for character in domain):
        return 0

    domain_encoded = [[valid_characters[y] for y in domain]]
    prediction = model.predict(pad_sequences(domain_encoded, maxlen=max_length)) > 0.9  # Certitudine > 90%

    if prediction[0][0] == 1:
        return 1  # DGA
    else:
        return 0  # NON DGA


def verify_top_domains():
    """Functie care verifica daca site-urile accesate se afla in lista top domeniilor.

    Variabile:
        ls_logs_sorted(list): lista sortata de loguri
        count(int): variabila care retine numarul de aparitii al domeniilor cheie
        ip_current(string): variabila care retine ip-ul curent
        address(string): variabila pentru adresa serverului accesat de client
        d_dga_occurency(dict): dictionar pentru frecventa cu care un client ip a intrat pe un site detectat ca fiind dga
        d_whois_occurency(dict): dictionar pentru frecventa cu care un client ip a intrat pe un site detectat ca fiind
        suspicios, folosind API-ul de la whois
        threshold(double): numarul la care ip-ul devine suspicios

    Creeaza o lista cu ip-uri suspicioase dupa acest criteriu.
    """

    global ls_top_domains, ls_logs, d_blacklist, whitelist, suspicious_ip, d_dga, d_whois, bounds

    ls_logs_sorted = ls_logs
    ls_logs_sorted.sort(key=lambda x: (x[3]))  # Sortam dupa ip
    count = 0
    ip_current = ls_logs_sorted[0][3]
    threshold = int(bounds["top_domains_threshold"])

    d_dga_occurency = {}
    d_whois_occurency = {}

    for log in ls_logs_sorted:
        client_ip = log[3]  # Variabila care retine ip-ul
        address = log[10]  # Variabila pentru adresa serverului accesat de client

        # Daca adresa a fost detectata ca fiind suspicioasa, folosind functia verify_whois
        if address in d_whois.keys() and d_whois[address]:
            if client_ip not in d_whois_occurency.keys():
                d_whois_occurency[client_ip] = 1
            else:
                d_whois_occurency[client_ip] += 1

        # Daca adresa a fost detectata ca fiind dga
        if address in d_dga.keys() and d_dga[address] == 1:
            if client_ip not in d_dga_occurency.keys():
                d_dga_occurency[client_ip] = 1
            else:
                d_dga_occurency[client_ip] += 1

        # Verificam daca logul apartine aceluiasi ip
        if client_ip == ip_current:
            # Iteram prin domenii si verific daca adresa
            # serverului se regaseste in lista si nu e in whitelist
            for word in ls_top_domains:
                if ("www." + word) == address and address not in whitelist:
                    count = count + 1

        # Daca se schimba ip-ul, reinitializam variabila count
        # si verificam daca ip-ul este suspicios daca numarul este mai mic decat tresholdul
        else:
            # Daca numarul este mai mic decat thresholdul, adaugam ip-ul in lista cu ip-uri suspicioase
            if count < threshold:
                suspicious_ip.add(ip_current)
            for word in ls_top_domains:
                if ("www." + word) in address and address not in whitelist:
                    count = 1
                else:
                    count = 0
            ip_current = client_ip  # Ip-ul curent devine ip-ul nou

    if (count < threshold):  # Verificam pentru ultimul ip din lista
        suspicious_ip.add(ip_current)

    for c_ip in d_dga_occurency.keys():
        if d_dga_occurency[c_ip] > bounds['dga_bound']:
            suspicious_ip.add(c_ip)

    for c_ip in d_whois_occurency.keys():
        if d_whois_occurency[c_ip] > bounds['whois_bound']:
            suspicious_ip.add(c_ip)


def verify_content_type():
    """Functie care verifica daca content type-ul are o aparitie rara.

    Variabile:
        d_content_type_count(dict): dicitonar care retine numarul de aparitii
        al fiecarui content type
        number_of_methods(int): varibila care retine numarul de total de content type-uri
        threshold(float): procentul la care un ip devine suspicios
        l_suspect_content_types(dict): dictionar cu content type-uri suspecte

    Creeaza o lista cu ip-uri suspicioase dupa acest criteriu.
    """

    global ls_logs, suspicious_ip, bounds

    d_content_type_count = {}
    number_of_methods = 0
    threshold = float(bounds["content_type_threshold"])
    l_suspect_content_types = {}

    for log in ls_logs:
        content = log[13]
        method = log[8]

        # Daca metoda este POST si daca content type-ul exista in dictionar
        # incrementam content type-ul si numarul total de metode
        if method == 'POST':
            if content in d_content_type_count.keys():
                d_content_type_count[content] += 1
            else:  # Altfel initializez si incrementez numarul total de metode
                d_content_type_count[content] = 1
            number_of_methods += 1

    # Modificam in dictionar numarul de aparitii intr-un procent
    # care va fi folosit pentru determinerea ip-urilor suspecte
    for key in d_content_type_count.keys():
        d_content_type_count[key] /= number_of_methods

        if d_content_type_count[key] <= threshold:
            l_suspect_content_types[key] = 1

    # Adaugam ip-urile care au acel content-type la lista suspicioasa
    for log in ls_logs:
        content = log[13]
        method = log[8]

        if method == 'POST' and content in l_suspect_content_types:
            client_ip = log[3]
            suspicious_ip.add(client_ip)


def verify_bi():
    """Functie care verifica daca numarul de bytes-in rezultat dintr-un request este suspicios.

    Variabile:
        ls_logs_sorted(list): lista sortata de loguri
        count(int): variabila care retine numarul de loguri cu acelasi numar
        de bytes in in aceeasi zi
        date(string): variabila care retine ziua la care se face requestul
        time(string): variabila care retine ora la care se face requestul
        ip(string): variabila care retine ip-ul clientului care face requestul
        site(string): variabila care retine numele site-ului pe care clientul vrea sa-l acceseze
        bytes_in(string): variabila care retine bytes-in dintr-un request
        l_logs(list): lista cu loguri suspicioase facute de acelasi client catre acelasi site
        sum_bytes_in(int): variabila care retine suma de bytes-in per source-destination
        higher_value_ratio(int): variabila care retine higher value for ratio

    Creeaza un dictionar cu logurile specifice source-destination care sunt
    suspicioase din punctul de vedere al numarului de bytes-in.
    """

    global ls_logs, d_bytes_in, bounds

    ls_logs_sorted = ls_logs
    # Sortam dupa data, ora, ip, numele site-ului, nr de bytes in
    ls_logs_sorted.sort(key=lambda x: (x[0], x[1], x[3], x[7], x[10]))

    count = 1
    date = ls_logs_sorted[0][0]
    time = ls_logs_sorted[0][1]
    ip = ls_logs_sorted[0][3]
    site = ls_logs_sorted[0][10]
    bytes_in = ls_logs_sorted[0][7]

    l_logs = [ls_logs_sorted[0]]  # loguri facute in aceeasi zi

    # Abordam prima situatie: in aceeasi zi primim acelasi numar de bytes-in
    # de la aceeasi pereche source-destination
    # Iteram prin lista sortata de loguri
    for i in range(1, len(ls_logs_sorted)):
        # Verificam daca gasim loguri de la aceeasi sursa catre aceeasi
        # destinatie cu acelasi numar de bytes-in in aceeasi zi => C2 server
        if date == ls_logs_sorted[i][0] and ip == ls_logs_sorted[i][3] \
          and site == ls_logs_sorted[i][10] and time != ls_logs_sorted[i][1] \
          and bytes_in == ls_logs_sorted[i][7]:
            count += 1
            l_logs.append(ls_logs_sorted[i])
        else:
            # Verificam daca perechea source-destination are mai multe
            # requesturi cu acelasi numar de bytes-in in aceeasi zi
            if count > bounds['count_bi']:
                # Verificam daca ip-ul se afla deja in dictionar => adaugam lista de loguri
                if (ip, site) in d_bytes_in.keys():
                    aux = d_bytes_in[(ip, site)]
                    aux.extend(l_logs)
                    d_bytes_in[(ip, site)] = aux
                # Altfel, adaugam ip-ul nou, cu lista gasita
                else:
                    d_bytes_in[(ip, site)] = l_logs

            # Reinitializam valorile variabilelor
            count = 1
            date = ls_logs_sorted[i][0]
            time = ls_logs_sorted[i][1]
            ip = ls_logs_sorted[i][3]
            l_logs = [ls_logs_sorted[i]]
            site = ls_logs_sorted[i][10]
            bytes_in = ls_logs_sorted[i][7]

    ls_logs_sorted = ls_logs
    # Sortam dupa ip si numele serverului
    ls_logs_sorted.sort(key=lambda x: (x[3], x[10]))

    count = 1
    time = ls_logs_sorted[0][1]
    ip = ls_logs_sorted[0][3]
    site = ls_logs_sorted[0][10]
    bytes_in = ls_logs_sorted[0][7]

    l_logs = [ls_logs_sorted[0]]  # Loguri facute pe parcursul a mai multor zile (nu doar intr-o zi)
    sum_bytes_in = int(bytes_in)

    higher_value_ratio = bounds["bi_higher_value_ratio"]

    # Abordam a doua situatie: identificam logurile cu high values pentru ratio
    # de bytes-in pentru fiecare pereche source-destination indiferent de zi
    # Iteram prin lista sortata de loguri
    for i in range(1, len(ls_logs_sorted)):
        # Verificam daca s-au produs mai multe requesturi de la aceeasi sursa
        # catre aceeasi destinatie
        if ip == ls_logs_sorted[i][3] and site == ls_logs_sorted[i][10] \
                and time != ls_logs_sorted[i][1]:
            # Le numaram si pe cele cu acelasi nr de bytes-in in aceeasi zi,
            # insa nu vor avea efect asupra rezultatului
            sum_bytes_in += int(bytes_in)
            count += 1
            l_logs.append(ls_logs_sorted[i])
        else:
            # Calculam media numarului de bytes-out per source-destination
            ratio = sum_bytes_in / count
            # Verificam daca media obtinuta este peste higher value
            if int(ratio) > higher_value_ratio:
                # Verificam daca ip-ul se afla deja in dictionar => adaugam lista de loguri
                if (ip, site) in d_bytes_out.keys():
                    aux = d_bytes_in[(ip, site)]
                    aux.extend(l_logs)
                    d_bytes_in[(ip, site)] = aux
                # Altfel, adaugam ip-ul nou, cu lista gasita
                else:
                    d_bytes_in[(ip, site)] = l_logs

            # Reinitializam valorile
            count = 1
            sum_bytes_in = int(ls_logs_sorted[i][7])
            time = ls_logs_sorted[i][1]
            ip = ls_logs_sorted[i][3]
            l_logs = [ls_logs_sorted[i]]
            site = ls_logs_sorted[i][10]
            bytes_in = ls_logs_sorted[i][7]


def verify_bo():
    """Functie care verifica daca numarul de bytes-out rezultat dintr-un request este suspicios.

    Variabile:
        ls_logs_sorted(list): lista sortata de loguri
        count_logs(int): variabila care retine numarul de loguri suspicioase din cadrul unei source-destination
        date(string): variabila care retine ziua la care se face requestul
        time(string): variabila care retine ora la care se face requestul
        ip(string): variabila care retine ip-ul clientului care face requestul
        site(string): variabila care retine numele site-ului pe care clientul vrea sa-l acceseze
        bytes_out(string): variabila care retine bytes-out dintr-un request
        l_logs(list): lista cu loguri suspicioase facute de acelasi client catre acelasi site in aceeasi zi
        sum_bytes_out(int): variabila care retine suma de bytes-out per source-destination
        higher_value_ratio(int): variabila care retine higher value for ratio
        higher_value_sum(int): variabila care retine higher value for sum of bytes-out

    Creeaza un dictionar cu logurile specifice source-destination care sunt suspicioase
    din punctul de vedere al numarului de bytes-out.
    """

    global ls_logs, d_bytes_out, bounds

    ls_logs_sorted = ls_logs
    # Sortam dupa data, ora, ip, numele site-ului
    ls_logs_sorted.sort(key=lambda x: (x[0], x[1], x[3], x[10]))

    count_logs = 1
    date = ls_logs_sorted[0][0]
    time = ls_logs_sorted[0][1]
    ip = ls_logs_sorted[0][3]
    site = ls_logs_sorted[0][10]
    bytes_out = ls_logs_sorted[0][6]

    l_logs = []
    l_logs.append([ls_logs_sorted[0]])
    sum_bytes_out = int(bytes_out)

    higher_value_ratio = bounds["bo_higher_value_ratio"]
    higher_value_sum = bounds["bo_higher_value_sum"]

    # Iteram prin lista sortata de loguri
    for i in range(1, len(ls_logs_sorted)):
        # Verificam daca in aceeasi zi s-au produs mai multe requesturi de la
        # aceeasi sursa catre aceeasi destinatie
        if date == ls_logs_sorted[i][0] and ip == ls_logs_sorted[i][3] \
          and site == ls_logs_sorted[i][10] and time != ls_logs_sorted[i][1]:
            # Adunam bytes-out per source-destination
            sum_bytes_out += int(ls_logs_sorted[i][6])
            count_logs += 1
            l_logs.append(ls_logs_sorted[i])
        else:
            # Calculam media numarului de bytes-out per source-destination intr-o zi
            ratio = sum_bytes_out / count_logs

            # Verificam daca valorile obtinute sunt peste higher values
            if sum_bytes_out > higher_value_sum or ratio > higher_value_ratio:
                # Verificam daca ip-ul se afla deja in dictionar => adaugam lista de loguri
                if (ip, site) in d_bytes_out.keys():
                    aux = d_bytes_out[(ip, site)]
                    aux.extend(l_logs)
                    d_bytes_out[(ip, site)] = aux
                # Altfel, adaugam ip-ul nou, cu lista gasita
                else:
                    d_bytes_out[(ip, site)] = l_logs

            # Reinitializam valorile
            count_logs = 1
            date = ls_logs_sorted[i][0]
            time = ls_logs_sorted[i][1]
            ip = ls_logs_sorted[i][3]
            l_logs = [ls_logs_sorted[i]]
            site = ls_logs_sorted[i][10]
            bytes_out = ls_logs_sorted[i][7]
            sum_bytes_out = int(bytes_out)


def verify_duration(ls_logs):
    """Functie care verifica daca suma duratelor tranzactiilor efectuate de la
    un client-ip la un server-ip intr-un interval de 24h indica valoare mare.

    Variabile:
        l_duration(list): lista cu logurile suspicioase identificate
        higher_value(float): variabila care indica numarul la care ne raportam
        cu privire la valoarea mare a sumei
        ls_logs_sorted(list): lista sortata dupa ip client, ip server si data
        sum(int): variabila care calculeaza suma duratelor tranzactiilor efectuate
        de la un client-ip la un server-ip intr-un interaval de 24h
        date(string): variabila pentru data la care se face requestul
        ip_c(string): variabila pentru ip-ul clientului care face requestul
        ip_s(string): variabila pentru ip-ul serverului la care se face requestul

    Creeaza o lista cu logurile suspicioase dupa criteriul enuntat anterior.
    """

    global l_duration

    l_duration = []

    higher_value = int(bounds["higher_value"])

    ls_logs_sorted = ls_logs
    # Sortam dupa ip client, ip server si data
    ls_logs_sorted.sort(key=lambda x: (x[3], x[14], x[0]))

    sum = int(ls_logs_sorted[0][2])  # Initial contine valoarea din duration pt. primul log
    date = ls_logs_sorted[0][0]
    ip_c = ls_logs_sorted[0][3]
    ip_s = ls_logs_sorted[0][14]

    for i in range(1, len(ls_logs_sorted)):  # Iteram prin lista sortata de loguri

        ls = ls_logs_sorted[i]
        # Daca gasim un request de la acelasi client-ip la acelasi server-ip
        # in aceeasi data calendaristica, in lista de loguri sortata
        if date == ls_logs_sorted[i][0] and ip_c == ls_logs_sorted[i][3] and ip_s == ls_logs_sorted[i][14]:
            # Adaugam la suma valoarea din duration pt logul curent
            sum += int(ls_logs_sorted[i][2])
        else:
            # Reinitializam variabilele folosite
            date = ls_logs_sorted[i][0]
            ip_c = ls_logs_sorted[i][3]
            ip_s = ls_logs_sorted[i][14]
            sum = int(ls_logs_sorted[i][2])

        # Daca suma indica valoare mare
        if sum >= higher_value:
            l_duration.append(ls)


def verify_http_status(ls_logs):
    """Functie care verifica daca nr de http-status-uri care nu fac parte din
    Successful Transactions pt. o pereche ip_client-ip_server este minim un procent
    dat % din totalul de loguri pentru o astfel de pereche.

    Variabile:
        l_http_status(list): lista cu logurile suspicioase identificate
        procent(double): variabila care indica procentul la care ne raportam atunci
        cand verificam numarul de http-status-uri suspicioase din numarul total de loguri
        ls_logs_sorted(list): lista sortata dupa ip client, ip server
        nr(int): variabila care calculeaza nr de http-status-uri care nu fac parte
        din Successful Transactions pt o pereche ip_client-ip_server
        ip_c(string): variabila pentru ip-ul clientului care face requestul
        ip_s(string): variabila pentru ip-ul serverului la care se face requestul
        index(int): variabila pentru a retine pozitia de la care trebuie sa retinem
        logurile identificate ca fiind suspicioase in lista sortata de loguri

    Creeaza o lista cu logurile suspicioase dupa criteriul enuntat anterior.
    """

    global l_http_status, bounds

    l_http_status = []

    procent = bounds["httpstatus_procent"]

    ls_logs_sorted = ls_logs
    # Sortam dupa ip client, ip server
    ls_logs_sorted.sort(key=lambda x: (x[3], x[14]))

    # Daca http_status nu face parte din Successful Transactions
    if (int(ls_logs_sorted[0][4][0])) != 2:
        nr = 1  # Numaram cate http_status-uri suspicioase sunt pentru o pereche ip_client - ip_server
    else:
        nr = 0

    ip_c = ls_logs_sorted[0][3]  # Variabila pentru ip-ul clientului care face requestul
    ip_s = ls_logs_sorted[0][14]  # Variabila pentru ip-ul serverului la care se face requestul
    index = 0

    # Iteram prin lista sortata de loguri
    for i in range(1, len(ls_logs_sorted)):

        # Daca gasim un request de la acelasi client-ip la acelasi server-ip, in
        # lista de loguri sortata si http_status nu face parte din Successful Transactions
        if (ip_c == ls_logs_sorted[i][3] and ip_s == ls_logs_sorted[i][14]):
            if((int(ls_logs_sorted[i][4][0])) != 2):
                # Numaram cate http_status-uri suspicioase sunt pentru o pereche ip_client - ip_server
                nr += 1
        else:
            # Daca nr de http_status-uri suspicioase pentru o pereche ip_client - ip_server
            # este minim procent % din totalul de loguri pentru aceasta pereche
            if nr >= (procent / 100) * (i - index):
                ls = ls_logs_sorted[index:(i - 1)]  # salvam logurile acestea suspicioase
                if ls != []:
                    l_http_status.append(ls)

            # Reinitializam variabilele folosite
            index = i
            ip_c = ls_logs_sorted[i][3]
            ip_s = ls_logs_sorted[i][14]
            if (int(ls_logs_sorted[i][4][0])) != 2:
                nr = 1
            else:
                nr = 0


def verify_url_query_length(logs):
    """Functie care verifica daca lungimea url_query-ului este mai mare decat 2*media lungimilor,
    pentru website-urile care nu se afla in whitelist.

    Variabile:
        logs(list): variabila ce contine log-urile
        medium_query_length(int): variabila ce contine lungimea medie a url_query-urilor
        url_query_length_logs(list): variabila in care se stocheaza query-urile suspicioase

    Functia va adauga logurile suspicioase in lista.
    """

    global medium_query_length, url_query_length_logs, whitelist

    for log in logs:
        if len(log[12]) >= bounds["url_query_multiplier"] * medium_query_length and log[10] not in whitelist:
            url_query_length_logs.append(log)


def verify_url_path(logs):
    """Functie care verifica daca un path este accesat de prea multe ori.

    Variabile:
        high_number: numar de request-uri Source-Destination-URLPath considerat periculos
        logs(list): variabila care contine log-urile
        access(dict): dictionar ce are ca si cheie un tuplu format din
        Source-Destination-URLPath si valoare numarul de accesari
        sortdict(dict): dictionarul access sortat dupa nr de accesari
        first_x_items(list): primele x% date din sortdict in functie de accesari
        url_path_logs(list): variabila ce va contine informatii despre posibile atacuri

    Functia va adauga logurile suspicioase in lista.
    """

    high_number = bounds["high_number"]

    # Sorteaza log-urile dupa Source-Destination-URLPath
    logs = sorted(logs, key=lambda x: (x[3], x[10], x[11]))
    access = dict()

    # Dictionar ce contine perechile Source-Destination-URLPath
    for log in logs:
        if len(log[11]) <= 1:
            continue
        if tuple([log[3], log[10], log[11]]) in access.keys():
            access[tuple([log[3], log[10], log[11]])] += 1
        else:
            access[tuple([log[3], log[10], log[11]])] = 1

    # Sorteaza dictionarul dupa nr de request-uri pentru cheie
    marklist = sorted(((value, key) for (key, value) in access.items()), reverse=True)
    sortdict = dict([(k, v) for v, k in marklist])

    # Afiseaza primele beaconing_bound% date dupa nr de accesari
    first_x_items = list(sortdict.items())[:int(bounds['beaconing_bound'] * len(sortdict))]

    for log in first_x_items:
        if log[1] > high_number or log[0][1] in whitelist:
            return
        string = "User: " + log[0][0] + " Website: " + log[0][1] + " Path:" + log[0][2] + " Accessed " + str(
            log[1]) + " times"
        url_path_logs.append(string)


def verify_url_query(log):
    """Functie care verifica daca url_query contine un atac folosind cuvintele
    din attack_wordlist (reflected xss / sqli / path traversal / lfi).

    Variabile:
        log: variabila care contine log-ul pe care il verificam
        medium_query_length: variabila care va stoca suma lungimilor query-urilor
        query_count: variabila care va stoca numarul query-urilor valide verificate
        method: contine metoda request-ului, functia avand nevoie de cele cu GET
        url_query: contine query-ul
        parameters: un dictionar ce stocheaza parametrii si valorile
        att_words: stocheaza cuvintele folosite in atacuri

    Adauga intr-un dictionar(url_query_logs) logurile suspicioase.
    """

    global medium_query_length, query_count, url_query_logs

    method = log[8]

    # Daca metoda nu este get, nu avem query, deci trecem peste
    if method != 'GET':
        return

    # Salvam query-ul in url_query
    url_query = log[12]

    # Eliminam encoding-ul din url
    url_query = requests.utils.unquote(url_query)

    # Daca nu avem query sau parametrii
    if len(url_query) <= 1 or '=' not in url_query or '?' not in url_query:
        return

    medium_query_length += len(url_query)
    query_count += 1

    parameters = dict()
    att_words = open('attack_wordlist.txt', 'r')

    url_query = url_query[1:].split('&')  # Salvam parametrii si valorile intr-o lista

    url_query = [x for x in url_query if x.strip() and '=' in x and len(x) >= 3]

    for p in url_query:
        p = p.split('=', 1)
        parameters[p[0]] = p[1]

    for p in parameters:
        b_64p = ''
        b_64v = ''

        # Verificam pentru xss / sqli / path traversal / lfi si in parametrul decriptat din base64
        if len(p) % 4 == 0:
            try:
                b_64p = (
                    base64.b64decode(p)).decode().lower()  # Transformam in lowercase pentru cautare case insensitive
            except Exception:
                pass
        if len(parameters[p]) % 4 == 0:
            try:
                b_64v = (base64.b64decode(parameters[p])).decode().lower()
            except Exception:
                pass

        for word in att_words:
            word = word.strip()

            if word in b_64p or word in b_64v or word in p or word in parameters[p]:
                url_query_logs.append(log)
                return


def verify():
    """Functie care va itera prin fiecare log si va verifica fiecare camp al unui log.

    Itereaza prin loguri si face verificari pe campurile din fiecare log, in functie de comanda data de user.
    """

    global ls_logs, ua_frequency, d_method, medium_query_length, query_count, bounds, command

    for i in range(len(ls_logs)):
        if command == "b":
            verify_blacklist(ls_logs[i])
        if command == "ua":
            verify_useragent(ls_logs[i])
        if command == "m":
            verify_HTTPmethod(ls_logs[i])
        if command == "q" or command == "l":
            verify_url_query(ls_logs[i])

    if command == "q" or command == "l":
        # Aflam lungimea medie a unui query
        medium_query_length /= query_count

    # Verificare dictionar pentru frecventa unui user agent
    if command == "ua":
        frequency = float(bounds["frequency"])
        for key in ua_frequency.keys():
            value = ua_frequency[key]
            # Daca acel user agent apare in mai putin de 5% din loguri
            if value < frequency*len(ls_logs):

                # Pentru fiecare log din lista de loguri
                for log in ls_logs:
                    user_agent = log[15]  # Variabila pentru user agent
                    client_ip = log[3]  # Variabila pentru client ip

                    # Daca logul are acelasi user agent
                    if user_agent == key:
                        # Daca client ip-ul se afla deja in dictionar
                        if client_ip in d_user_agent.keys():
                            aux = d_user_agent[client_ip]
                            # Verificam ca noul log gasit sa nu fie dublura (sa nu-l fi gasit deja)
                            if log not in aux:
                                aux.append(log)  # Adaugam noul log la lista de loguri suspicioase
                                d_user_agent[client_ip] = aux
                        # Altfel, adaugam noua cheie(client ip) si initializam lista de loguri suspicioase
                        # cu primul log gasit
                        else:
                            d_user_agent[client_ip] = [log]

    # Verificare ip-uri suspicioase dupa raportul de metode HTTP unsafe raportat la toate metodele
    if command == "m":
        ratio = float(bounds["unsafe_methods"])

        # Lista care va retine ip-urile suspicioase(cele care au trimis > 50% requesturi cu metode unsafe)
        ip_suspicioase = []

        # Pentru fiecare client ip gasit din dictionar
        for ip in d_method.keys():
            value = d_method[ip]  # Preluam numarul de metode unsafe si numarul total de metode
            # Verificam daca raportul este mai mare decat limita setata de noi
            if (value[0] / value[1]) > ratio:
                ip_suspicioase.append(ip)  # Adaugam ip-ul suspicios gasit la lista

        # Daca am gasit minim un ip suspicios, afisam mesaj si afisam ip-urile gasite, impreuna cu raportul
        if len(ip_suspicioase):
            g.write("S-au gasit ip-uri suspicioase dupa verificarea metodelor HTTP trimise!\n\nIP-uri suspicioase :\n")
            for ip in ip_suspicioase:
                ratio = d_method[ip][0] / d_method[ip][1]
                g.write(f"\t{ip} ({round(ratio * 100, 2)}% din metode sunt unsafe)\n")
        else:  # Altfel, afisam un mesaj corespunzator
            g.write("Nu s-au gasit ip-uri suspicioase dupa verificarea metodelor HTTP trimise!\n")

    # Verificare URL Query
    if command == "q":
        if len(url_query_logs):
            for log in url_query_logs:
                g.write(f"{str(log)}\n")
        else:
            g.write("Nu exista astfel de loguri suspicioase.\n")

    # Verificare URL Path
    if command == "p":
        verify_url_path(ls_logs)

        if len(url_path_logs):
            for log in url_path_logs:
                g.write(f"{str(log)}\n")
        else:
            g.write("Nu exista astfel de loguri suspicioase.\n")

    # Verficare URL Query length
    if command == "l":
        verify_url_query_length(ls_logs)

        if len(url_query_length_logs):
            for log in url_query_length_logs:
                g.write(f"{str(log)}\n")
        else:
            g.write("Nu exista astfel de loguri suspicioase.\n")


def dga_dictionary():
    """Functie care creeaza dictionarul care are ca si chei website-urile si
    ca value daca acestea sunt detectate ca fiind dga sau nu.

    Variabile:
        d_dga(dict): dictionarul in care memoram datele
        d_whois(dict): dictionar pentru aceleasi site-uri, dar folosind whois
        unique_websites(set) : set care va contine site-urile unice din loguri

    Va creea un dictionar cu valorile de adevar gasite pentru logurile noastre.
    """

    global d_dga, d_whois, ls_logs

    unique_websites = set([])
    for log in ls_logs:
        unique_websites.add(log[10])

    for website in unique_websites:
        if website not in whitelist:
            d_dga[website] = verify_dga(website)
            d_whois[website] = verify_whois(website)


# Functie care are scopul de a afisa meniul cu optiuni
def show_options():
    print('''
        Optiuni:
            opt - afisare optiuni
            b - verificare blacklist
            t - verificare ore fixe
            ua - verificare user agent
            m - verificare HTTP methods
            h - verificare hitlist
            c - verificare content type
            bi - verificare bytes in
            bo - verficare bytes out
            d - verificare duration
            s - verificare http status
            l - verificare query length
            p - verificare query path
            q - verificare query
            all - verficare completa
            quit - iesire program
    ''')


def ui():
    """Functie pentru interfata cu user-ul

    Variabile:
        d_ora(dict): dictionar pentru logurile suspicioase detectate cautand requesturi facute la ore fixe in zile
        diferite de la acelasi client catre acelasi server
        d_blacklist(dict): dictionar pentru logurile suspicioase detectate folosind un blacklist
        d_user_agent(dict): dictionar pentru logurile suspicioase detectate folosind user agent
        ua_frequency(dict): dictionar pentru frecventa unui user agent
        d_method(dict): dictionar pentru logurile cu HTTP method vulnerabile
        suspicious_ip(set): set cu ip-uri suspicioase
        d_bytes_in(dict): dictionar pentru logurile suspicioase detectate folosind bytes in
        d_bytes_out(dict): dictionar pentru logurile suspicioase detectate folosind bytes out
        l_duration(list): lista pentru logurile suspicioase folosind duration
        l_http_status(list): lista pentru logurile suspicioase folosind http_status
        medium_query_length(int): lungimea medie a unui query
        query_count(int): numarul de query-uri
        url_query_logs(list): lista pentru verificare query-uri
        url_path_logs(list): lista pentru verificare query path
        url_query_length_logs(list): lista pentru verificare query length
        command(string): variabila care retine ce comanda este data de catre user
        list_of_commands(list): lista cu toate comenzile posibile
    """

    while True:
        global d_ora, d_blacklist, d_user_agent, ua_frequency, d_method, suspicious_ip, d_bytes_in, d_bytes_out, \
          l_duration, l_http_status, medium_query_length, query_count, url_query_logs, url_path_logs, \
          url_query_length_logs, command

        d_ora = {}
        d_blacklist = {}
        d_user_agent = {}
        ua_frequency = {}
        d_method = {}
        suspicious_ip = set([])
        d_bytes_in = {}
        d_bytes_out = {}
        l_duration = []
        l_http_status = []
        medium_query_length = 0
        query_count = 1
        url_query_logs = []
        url_path_logs = []
        url_query_length_logs = []

        command = input("\nIntroduceti comanda : ")

        list_of_commands = ["b", "t", "ua", "m", "h", "c", "bi", "bo", "d", "s", "l", "p", "q", "all"]

        # Meniu interactiv cu user-ul
        if command == "quit":  # Comanda de iesire din program
            print("\nInchidere program...")
            break
        elif command == "opt":  # Comanda pentru afisare optiuni
            show_options()
        elif command in list_of_commands:  # Comenzi pentru analiza logurilor
            all_commands = False
            if command == "all":
                print("\nVerificare completa...\n\n")
                all_commands = True
            if all_commands:
                command = "b"
            if command == "b":
                g.write("Verificare requesturi catre website-uri blacklisted...\n")
                verify()
                if len(d_blacklist):
                    for ip in d_blacklist.keys():
                        g.write(f"\nPentru IP-ul {ip}:\n")
                        for log in d_blacklist[ip]:
                            g.write(f"{str(log)}\n")
                else:
                    g.write("Nu s-au detectat requesturi catre website-uri blacklisted\n")
            if all_commands:
                command = "t"
            if command == "t":
                g.write("\nVerificare requesturi facute la ore fixe in zile diferite...\n")
                verify_time()
                if len(d_ora):
                    for ip in d_ora.keys():
                        g.write(f"\nPentru IP-ul {ip}:\n")
                        for log in d_ora[ip]:
                            g.write(f"{str(log)}\n")
                else:
                    g.write("Nu s-au detectat requesturi suspicioase facute la ore fixe.\n")
            if all_commands:
                command = "ua"
            if command == "ua":
                g.write("\nVerificare user agents suspiciosi...\n")
                verify()
                if len(d_user_agent):
                    for ip in d_user_agent.keys():
                        g.write(f"\nPentru IP-ul {ip}:\n")
                        for log in d_user_agent[ip]:
                            g.write(f"{str(log)}\n")
                else:
                    g.write("Niciun user agent suspicios detectat.\n")
            if all_commands:
                command = "m"
            if command == "m":
                g.write("\nVerificare raport metode HTTP unsafe...\n")
                verify()
            if all_commands:
                command = "c"
            if command == "c":
                verify_content_type()
                g.write(f"\nVerificare content-type rar utilizat :\n")
                if len(suspicious_ip):
                    for ip in suspicious_ip:
                        g.write(f"\t{ip}\n")
                else:
                    g.write("Niciun ip suspicios detectat.\n")
            if all_commands:
                command = "bi"
            if command == "bi":
                g.write("\nVerificare numere de bytes in suspiciosi...\n")
                verify_bi()
                if len(d_bytes_in):
                    for (ip, site) in d_bytes_in.keys():
                        g.write(f"\nPentru IP-ul {ip} si sursa {site}:\n")
                        for log in d_bytes_in[(ip, site)]:
                            g.write(f"{str(log)}\n")
                else:
                    g.write("Niciun numar de bytes in detectat ca fiind suspicios.\n")
            if all_commands:
                command = "bo"
            if command == "bo":
                g.write("\nVerificare numere de bytes out suspiciosi...\n")
                verify_bo()
                if len(d_bytes_out):
                    for (ip, site) in d_bytes_out.keys():
                        g.write(f"\nPentru IP-ul {ip} si sursa {site}:\n")
                        for log in d_bytes_out[(ip, site)]:
                            g.write(f"{str(log)}\n")
                else:
                    g.write("Niciun numar de bytes out detectat ca fiind suspicios.\n")
            if all_commands:
                command = "d"
            if command == "d":
                g.write("\nVerificare loguri suspicioase folosind duration... \n")
                verify_duration(ls_logs)
                if len(l_duration):
                    for ls in l_duration:
                        g.write(f"{ls}\n")
                else:
                    g.write("Nu exista astfel de loguri suspicioase.\n")
            if all_commands:
                command = "s"
            if command == "s":
                g.write("\nVerificare loguri suspicioase folosind http_status...\n")
                verify_http_status(ls_logs)
                if len(l_http_status):
                    for log in l_http_status:
                        g.write(f"{str(log)}\n")
                else:
                    g.write("Nu exista astfel de loguri suspicioase.\n")
            if all_commands:
                command = "l"
            if command == "l":
                g.write("\nVerificare loguri suspicioase folosind URL query length...\n")
                verify()
            if all_commands:
                command = "p"
            if command == "p":
                g.write("\nVerificare loguri suspicioase folosind URL path...\n")
                verify()
            if all_commands:
                command = "q"
            if command == "q":
                g.write("\nVerificare loguri suspicioase folosind URL query...\n")
                verify()
            if all_commands:
                command = "h"
            if command == "h":
                g.write("\nVerificare loguri suspicioase folosind hitlist...\n")
                command = input("""
Alege tipul de lista(short/medium/large):
    1 - Top 10 mii domenii
    2 - Top 100 de mii domenii
    3 - Top 1 milion domenii
Optiune: """)
                ls_top_domains = []
                if command == "1":
                    f = open("top-10000-domains", 'r')  # Citire top 10000 domenii
                    for line in f:
                        elem = line.rstrip('\n')
                        ls_top_domains.append(elem)
                    f.close()
                    g.write("\nVerificare hitlist pentru top 10 mii domenii...\n")
                elif command == "2":
                    f = open("top-100000-domains", 'r')  # Citire top 100000 domenii
                    for line in f:
                        elem = line.rstrip('\n')
                        ls_top_domains.append(elem)
                    f.close()
                    g.write("\nVerificare hitlist pentru top 100 de mii domenii...\n")
                elif command == "3":
                    f = open("top-100000-domains", 'r')  # Citire top 1000000 domenii
                    for line in f:
                        elem = line.rstrip('\n')
                        ls_top_domains.append(elem)
                    f.close()
                    g.write("\nVerificare hitlist pentru top 1 milion domenii...\n")
                else:
                    g.write("Optiune nevalida. Nu se poate verifica hitlist-ul.\n")
                    continue

                verify_top_domains()

                if len(suspicious_ip):
                    g.write("\nIp-uri suspicioase gasite:\n")
                    for ip in suspicious_ip:
                        g.write(f"\t{ip}\n")
                else:
                    g.write("Niciun ip suspicios detectat.\n")
        else:
            print("\nComanda invalida!")
            continue


if __name__ == '__main__':
    start_time = time.time()

    # Citiri din fisier
    f = open("blacklist.txt", 'r')  # Citire blacklist
    ls_blacklist = []
    for line in f:
        elem = line.rstrip('\n')
        ls_blacklist.append(elem)
    f.close()

    f = open("whitelist.txt", 'r')  # Citire whitelist
    whitelist = {}
    for line in f:
        elem = line.rstrip('\n')
        whitelist[elem] = 1
    f.close()

    # Citire loguri gasite
    '''
    f = open("web_proxy_log.log", 'r')
    ls_logs = []
    for line in f:
        aux = line.split()
        user_agent = line.rsplit("\"")[1]   # Split dupa ghilimele pentru user agent
        log_list = []  # Variabila ce va contine campurile de care avem nevoie pentru analizarea unui log
        for i in range(len(aux)):
            # Daca elementul din log nu e user agent sau este un camp de care nu avem nevoie, il adaugam
            if i < 13 or i == 16 or i == len(aux)-5:
                log_list.append(aux[i])
        log_list.append(user_agent)    # Adaugam si user agent-ul
        ls_logs.append(log_list)
    f.close()
    '''

    # Citire loguri create de noi
    f = open("proxy_logs.log", "r")
    ls_logs = []
    for line in f:
        log = []

        # Preluam data si convertim din luna scrisa ca string in luna ca int
        date = line.split(":")[0][1:]
        aux = date.split("/")
        month = datetime.datetime.strptime(aux[1], "%b").month
        date = aux[0] + "/" + str(month) + "/" + aux[2]
        log.append(date)

        time_ = line.split(":", 1)[1].split()[0]
        log.append(time_)

        aux = line.split()[2:14]
        path = aux[8] + aux[9]
        for elem in aux[:9]:
            log.append(elem)

        # Concatenam adresa si query-ul pentru a obtine path-ul
        log.append(path)

        for elem in aux[9:]:
            log.append(elem)

        user_agent = line.split("\"")[1]
        log.append(user_agent)

        # am inversat bytes in si bytes out
        aux = log[6]
        log[6] = log[7]
        log[7] = aux

        log[11] = log[12]
        if log[11].count("?") >= 1:
            log[11] = log[11].split("?", 1)
            log[12] = '?' + log[11][1]
            log[11] = log[11][0]
        if log[14] != '-':
            ls_logs.append(log)
    f.close()

    f = open("user_agents_keywords.txt", 'r')  # Citire keyword-uri pentru user agents suspiciosi
    ua_keywords = []
    line = f.readline().split('|')  # Prima linie din config file contine cuvinte/simboluri despartite de |
    for elem in line:
        ua_keywords.append(elem.lower())
    # Restul liniilor contin cuvintele pe fiecare rand
    for line in f:
        aux = line.rstrip('\n')
        ua_keywords.append(aux.lower())
    f.close()

    f = open("top-10000-domains", 'r')  # Citire top 10000 domenii
    ls_top_domains = []
    for line in f:
        elem = line.rstrip('\n')
        ls_top_domains.append(elem)
    f.close()

    f = open("top-100000-domains", 'r')  # Citire top 100000 domenii
    ls_top_domains = []
    for line in f:
        elem = line.rstrip('\n')
        ls_top_domains.append(elem)
    f.close()

    f = open("top-100000-domains", 'r')  # Citire top 1000000 domenii
    ls_top_domains = []
    for line in f:
        elem = line.rstrip('\n')
        ls_top_domains.append(elem)
    f.close()

    # Citire bound-uri (pana la care logurile sunt considerate trafic normal) din config file
    bounds = ""
    with open('config_file.json', 'r') as f:
        bounds = json.load(f)

    # Dictionar pentru website-uri care are ca si cheie website-ul si ca value daca acesta este
    # detectat ca fiind suspicios de catre verify_whois
    d_whois = {}

    # Dictionar pentru website-uri care are ca si cheie website-ul si ca value daca acesta este
    # detectat ca fiind dga sau nu
    d_dga = {}

    # Incarcam modelul de ML si citim dictionarul cu caractere valide
    model = load_model('DGA_7million.h5')
    with open('valid_characters.txt') as f:
        data = f.read()

    valid_characters = json.loads(data)
    max_length = 63

    dga_dictionary()

    print('''
        ##############################################
        ##############################################
        #####Attack Detection with Web Proxy Logs#####
        ##############################################
        ##############################################
    ''')
    show_options()

    g = open("output.txt", "w")

    ui()

    g.close()
