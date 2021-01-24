<!-- markdownlint-disable first-line-h1 -->
<img
    src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png"
    alt="SPID"
    data-canonical-src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png"
    width="500" height="98"
/>

[![Join the #spid-testenv channel](https://img.shields.io/badge/Slack%20channel-%23spid--testenv-blue.svg?logo=slack)](https://developersitalia.slack.com/messages/C7FPEULVC)
[![Get invited](https://slack.developers.italia.it/badge.svg)](https://slack.developers.italia.it/)
[![SPID on forum.italia.it](https://img.shields.io/badge/Forum-SPID-blue.svg)](https://forum.italia.it/c/spid)
![.github/workflows/ci.yml](https://github.com/italia/spid-testenv2/workflows/.github/workflows/ci.yml/badge.svg)

# spid-testenv2

## Identity Provider di test per SPID

Questo Identity Provider consente agli sviluppatori di verificare le proprie
integrazioni con [SPID](https://www.spid.gov.it) in modo semplice, ottenendo
messaggi diagnostici chiari ed assicurandosi dell'interoperabilità.

Può essere facilmente eseguito in locale o su un proprio server seguendo le
istruzioni di seguito riportate.

> ⚠️ **AVVISO DI SICUREZZA: spid-testenv2 non deve essere utilizzato in
> ambienti di produzione.** Nessun Service Provider deve accettare **in
> produzione** autenticazioni prodotte da spid-testenv2, che è solo uno
> strumento da utilizzarsi in fase di sviluppo e test.

## Requisiti

* Python 3.7

* [xmlsec1](http://www.aleksey.com/xmlsec/)

* [libffi-dev](http://sourceware.org/libffi/)

## Installazione

### Docker (consigliata)

1. Clonare il repository in locale

   ```shell
   git clone https://github.com/italia/spid-testenv2.git
   ```

1. Entrare nella directory

   ```shell
   cd spid-testenv2
   ```

1. Fare build dell'immagine

   ```shell
   docker build -t italia/spid-testenv2 .
   ```

1. Lanciare il container:

   ```shell
   docker run -p 8088:8088 -v $(pwd)/conf:/app/conf italia/spid-testenv2
   ```

L'immagine `italia/spid-testenv2` a anche disponibile su [Docker Hub](https://hub.docker.com/).

### Manuale

1. Installare le dipendenze.

   Su macOS si può usare `brew install libxmlsec1 libffi`.

   Su Debian/Ubuntu si può usare `apt-get install libxmlsec1 libffi6`.

1. Creare ed attivare un virtualenv

   ```shell
   virtualenv -p `which python` env
   . env/bin/activate
   ```

1. Installare i pacchetti necessari tramite pip

   ```shell
   pip install -r requirements.txt
   ```

1. Generare una chiave privata ed un certificato

   ```shell
   openssl req -x509 \
               -nodes \
               -sha256 \
               -subj '/C=IT' \
               -newkey rsa:2048 \
               -keyout conf/idp.key \
               -out conf/idp.crt
   ```

1. Creare e modificare il file config.yaml secondo le esigenze.

   ```shell
   cp conf/config.yaml.example conf/config.yaml
   ```

1. Avvio

   ```shell
   python spid-testenv.py
   ```

### Ansible

Alternativamente alle procedure riportate sopra, è
possible installare spid-testenv2 tramite [ansible](https://www.ansible.com/).

Tutte le informazioni sono nella directory [ansible/](ansible/).

### Caricamento metadata Service Provider

L'unico valore che è necessario modificare rispetto ai default è `metadata`,
che indica i metadata dei Service Provider che si intendono collegare a
spid-testenv2.

I metadati possono essere:

1. Compilati manualmente a partire dal file [sp_metadata.xml.example](conf/sp_metadata.xml.example);
2. Generati ed esposti automaticamente dalla propria implementazione
   del Service Provider (ad esempio https://mioserviceprovider.example.com/metadata).
3. Inseriti manualmente dall'interfaccia in `/admin/databasesprecord`.

spid-testenv2 supporta il caricamento in tre modalità, che possono essere combinate
tra loro:

* `local`: i metadati vengono letti da file locali (all'avvio di testenv2);
* `remote`: i metadati vengono letti da URL HTTP remote (all'avvio di testenv2);
* `db`: i metadati vengono letti da un database PostgreSQL (alla ricezione di
  ciascuna richiesta).

Nel caso in cui si usi la modalità `db` è sufficiente creare il database e poi
spid-testenv2 creerà automaticamente la tabella. Abilitando l'opzione
`database_admin_interface` spid-testenv2 esporrà una semplice interfaccia di
gestione all'indirizzo /admin; è possibile ovviamente usare un qualsiasi tool
di gestione esterno.

I Service Provider registrati correttamente saranno visualizzati
nella pagina principale in <https://localhost:8088/>.

## Metadata

Il metadata dell'Identity Provider di test è generato automaticamente ed
esposto all'URL `/metadata`. Questo metadata deve essere inserito nella
configurazione del proprio Service Provider.

## Utenti

Gli utenti di test sono configurati nel file `users.json` e possono essere
aggiunti nella pagina `/add-user`.

In alternativa è possibile usare un database Postgres configurando l'opzione `users_db`.

## Autori

Questo software è stato sviluppato dal [Team per la Trasformazione
Digitale](https://teamdigitale.governo.it/), ed è mantenuto con l'ausilio
della community di [Developers Italia](https://developers.italia.it/).

## Link utili

* [Regole tecniche consolidate](https://docs.italia.it/italia/spid/spid-regole-tecniche/)
* [Sito ufficiale SPID](https://www.spid.gov.it/)
* [Sezione SPID su Developers Italia](https://developers.italia.it/it/spid/)
* [Sezione SPID su AgID](https://www.agid.gov.it/it/piattaforme/spid)
