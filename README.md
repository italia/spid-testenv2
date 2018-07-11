<img src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png" alt="SPID" data-canonical-src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png" width="500" height="98" />

[![Join the #spid-testenv channel](https://img.shields.io/badge/Slack%20channel-%23spid--testenv-blue.svg?logo=slack)](https://developersitalia.slack.com/messages/C7ESTMQDQ)
[![Get invited](https://slack.developers.italia.it/badge.svg)](https://slack.developers.italia.it/)
[![SPID on forum.italia.it](https://img.shields.io/badge/Forum-SPID-blue.svg)](https://forum.italia.it/c/spid)

> ⚠️ **WORK IN PROGRESS** ⚠️

# spid-testenv2

## Identity Provider di test per SPID

Questo repository ospita lo sviluppo di un nuovo Identity Provider di test per consentire agli sviluppatori di verificare le proprie integrazioni con [SPID](https://www.spid.gov.it) in modo semplice, ottenendo messaggi diagnostici chiari ed essere certi dell'interoperabilità.

Ad oggi questo pacchetto è funzionante ma è in corso un lavoro di evoluzione e documentazione. Se ne raccomanda l'uso, ed eventuali problemi possono essere segnalati aprendo issue.

In alternativa è possibile usare il [precedente IdP di test](https://github.com/italia/spid-testenv). 

## Requisiti

Installare le seguenti librerie:

* [xmlsec1](http://www.aleksey.com/xmlsec/)

* [libffi-dev](http://sourceware.org/libffi/)

Su MacOS X si può usare `brew install libxmlsec1 libffi`.

Su Debian/Ubuntu si può usare `apt-get install libxmlsec1 libffi6`.

## Installazione

### Manuale

Creare ed attivare un virtualenv (opzionale ma raccomandato)

```
virtualenv -p `which python` env
. env/bin/activate
```

Installare i pacchetti necessari tramite pip

```
pip install -r requirements.txt
```

### Ansible

Alternativamente alla procedura di installazione manuale riportata sopra, è possible installare l'Identity Provider di test tramite lo strumento di configuration management [ansible](https://www.ansible.com/). Tutte le informazioni sono nella directory [ansible/](ansible/).

### Docker

Alternativamente alla procedura di installazione manuale è possible installare ed eseguire l'Identity Provider di test tramite [Docker](https://www.docker.com/).

Installazione:

1) Creare immagine Docker tramite il Dockerfile incluso nel progetto

```
docker build -t spid-testenv:latest .
```

2) Eseguire un container basato sull'immagine Docker ottenuta al passo precedente

```
docker run -d -p 8088:8088  spid-testenv
```

## Configurazione

Generare una chiave privata ed un certificato.

```
openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -keyout conf/idp.key -out conf/idp.crt
```

Creare e configurare il file config.yaml.

```
cp conf/config.yaml.example conf/config.yaml
```

L'unico valore che è necessario modificare rispetto ai default è `metadata`, che contiene i metadata dei Service Provider che si intendono collegare all'IdP di test. Per generare tali metadati vi sono tre possibilità:

1. compilarli a mano a partire dal file [sp_metadata.xml.example](conf/sp_metadata.xml.example);
2. compilarli usando l'interfaccia disponibile in https://idp.spid.gov.it:8080/
3. generarli (ed esporli) automaticamente dalla propria implementazione Service Provider (ad esempio https://www.mioserviceprovider.it/spid/metadata).

## Avvio

```
python spid-testenv.py
```

## Home page

Nella home page è presente una lista di Service Providers registrati sull'IdP di test.

## Metadata IdP

Il metadata dell'Identity Provider di test è generato automaticamente ed esposto all'URL `/metadata`. Questo metadata deve essere inserito nella configurazione del proprio Service Provider.

## Utenti

Gli utenti di test sono configurati nel file _users.json_ e possono essere aggiunti chiamando la pagina `/add-user`.

## Logging

Il log del flusso di login / logout viene registrato nel file idp.log (tramite configurazione pysaml2) e inviato in STDOUT insieme al log del web server.

## Maintainer

Questo repository è mantenuto da AgID - Agenzia per l'Italia Digitale con l'ausilio del Team per la Trasformazione Digitale.

## Link utili

* [Sito ufficiale SPID](https://www.spid.gov.it/)
* [Sezione SPID su Developers Italia](https://developers.italia.it/it/spid/)
* [Sezione SPID su AgID](https://www.agid.gov.it/it/piattaforme/spid)
