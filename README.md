<img src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png" alt="SPID" data-canonical-src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png" width="500" height="98" />

[![Join the #spid-testenv channel](https://img.shields.io/badge/Slack%20channel-%23spid--testenv-blue.svg?logo=slack)](https://developersitalia.slack.com/messages/C7FPEULVC)
[![Get invited](https://slack.developers.italia.it/badge.svg)](https://slack.developers.italia.it/)
[![SPID on forum.italia.it](https://img.shields.io/badge/Forum-SPID-blue.svg)](https://forum.italia.it/c/spid) [![Build Status](https://travis-ci.org/italia/spid-testenv2.svg?branch=master)](https://travis-ci.org/italia/spid-testenv2)

# spid-testenv2

## Identity Provider di test per SPID

Questo Identity Provider consente agli sviluppatori di verificare le proprie integrazioni con [SPID](https://www.spid.gov.it) in modo semplice, ottenendo messaggi diagnostici chiari ed assicurandosi dell'interoperabilità.

Può essere facilmente eseguito in locale o su un proprio server seguendo le istruzioni di seguito riportate.

> ⚠️ **AVVISO DI SICUREZZA: spid-testenv2 non deve essere utilizzato in ambienti di produzione.** Nessun Service Provider deve accettare **in produzione** autenticazioni prodotte da spid-testenv2, che è solo uno strumento da utilizzarsi in fase di sviluppo e test.

## Requisiti

Installare le seguenti librerie (non necessario se si usa il container
Docker):

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

Alternativamente alla procedura di installazione manuale è possible installare ed eseguire l'Identity Provider di test usando l'immagine presente su [Docker Hub](https://hub.docker.com/).

Per ottenere la persistenza della configurazione è necessario creare nell'host una directory, da collocarsi in un percorso a piacere (di seguito un suggerimento). Tale directory sarà mappata in `conf/` all'interno del container.

```
mkdir /etc/spid-testenv2
```

### Manuale

Creare nella directory il file config.yaml e la coppia chiave/certificato per l'IdP, nonché eventuali metadata SP, come indicato nel paragrafo successivo.

Creare il container con il seguente comando:

```
docker create --name spid-testenv2 -p 8088:8088 --restart=always \
   --mount src="/etc/spid-testenv2",target="/app/conf",type=bind \
   italia/spid-testenv2
```

Avviare il container:

```
docker start spid-testenv2
```

Il log si può visualizzare con il comando:

```
docker logs -f spid-testenv2
```

### Docker Desktop

Creare nella directory il file config.yaml e il file sp_metadata.xml (sono presenti due esempi nella cartella "conf" di questo repository).

Abilitare i Linux Container

Da Settings > General eliminare il check da "Use the WSL 2 based engine"

In Resources > Disk Image Location aggiungere la cartella relativa alla persistenza della configurazione

In Images verificare la presenza del container "italia/spid-testenv2"

Creare il container con RUN. In "Optional Settings" impostare:

- Container Name: spid-testenv2 (o un nome a piacere)
- Ports: la porta utilizzata (in genere 8080)
- Volumes: in Host Path indicare la cartella relativa alla persistenza della configurazione e in Container Path indicare /app/conf  

Avviare il container che sarà raggiungibile all'url di configurazione di Docker (es. http://localhost:8080)

## Configurazione

Generare una chiave privata ed un certificato (non necessario se si usa il container Docker).

```
openssl req -x509 -nodes -sha256 -subj '/C=IT' -newkey rsa:2048 -keyout conf/idp.key -out conf/idp.crt
```

Creare e configurare il file config.yaml.

```
cp conf/config.yaml.example conf/config.yaml
```

E' possibile che sia necessario modificare il base_url (es. in Docker Desktop con http://localhost:8080)

### Caricamento metadata Service Provider 

L'unico valore che è necessario modificare rispetto ai default è `metadata`, che indica i metadata dei Service Provider che si intendono collegare all'IdP di test.

I metadati possono essere:

1. Compilati manualmente a partire dal file [sp_metadata.xml.example](conf/sp_metadata.xml.example);
2. Generati ed esposti automaticamente dalla propria implementazione
   del Service Provider (ad esempio https://mioserviceprovider.example.com/metadata).
3. Inseriti manualmente dall'interfaccia in `/admin/databasesprecord`.

Il testenv2 supporta il caricamento in tre modalità, che possono essere combinate tra loro:

* `local`: i metadati vengono letti da file locali (all'avviamento del testenv2);
* `remote`: i metadati vengono letti da URL HTTP remote (all'avviamento del testenv2);
* `db`: i metadati vengono letti da un database PostgreSQL (alla ricezione di ciascuna richiesta).

Nel caso in cui si usi la modalità `db` è sufficiente creare il database e poi spid-testenv2 creerà automaticamente la tabella. Abilitando l'opzione `database_admin_interface` spid-testenv2 esporrà una semplice interfaccia di gestione all'indirizzo /admin; è possibile ovviamente usare un qualsiasi tool di gestione esterno.

## Avvio

```
python spid-testenv.py
```

## Home page

Nella home page è presente la lista dei Service Providers registrati sull'IdP di test.

## Metadata IdP

Il metadata dell'Identity Provider di test è generato automaticamente ed esposto all'URL `/metadata`. Questo metadata deve essere inserito nella configurazione del proprio Service Provider.

Il file sp_metadata.xml deve essere ripulito da tutti i commenti presenti per passare la validazione.

Nel file va modificato:

- entityID: è una URI che individua univocamente il Service Provider
- X509Certificate: presente due volte, va inserito il contenuto del certificato senza i delimitatori ‐‐‐ BEGIN CERTIFICATE ‐‐‐ e ‐‐‐ END CERTIFICATE ‐‐‐ -->
- SingleLogoutService e AssertionConsumerService: va modificato con gli url della propria applicazione e index="1"
- AttributeConsumingService: va modificato con nome del servizio e descrizione del servizio e gli attributi richiesti
- Organization: va modificato con l'anagrafica del Service Provider

## Utenti

Gli utenti di test sono configurati nel file _users.json_ e possono essere aggiunti chiamando la pagina `/add-user`.

In alternativa è possibile usare un database Postgres configurando l'opzione `users_db`.

## Logging

Il log del flusso di login / logout viene registrato nel file idp.log (tramite configurazione pysaml2) e inviato in STDOUT insieme al log del web server.

## Autori

Questo software è stato sviluppato dal [Team per la Trasformazione Digitale](https://teamdigitale.governo.it/), ed è mantenuto con l'ausilio della community di [Developers Italia](https://developers.italia.it/).

## Link utili

* [Regole tecniche consolidate](https://docs.italia.it/italia/spid/spid-regole-tecniche/)
* [Sito ufficiale SPID](https://www.spid.gov.it/)
* [Sezione SPID su Developers Italia](https://developers.italia.it/it/spid/)
* [Sezione SPID su AgID](https://www.agid.gov.it/it/piattaforme/spid)
