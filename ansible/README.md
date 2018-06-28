# Installazione via ansible

È possible installare l'Identity Provider di test tramite lo strumento di configuration management [ansible](https://www.ansible.com/).

Prima di iniziare:

- effettuare il provisioning dell'[host](https://docs.ansible.com/ansible/devel/reference_appendices/glossary.html#term-host) su cui si vuole installare il testenv (che può essere una macchina fisica, una macchina virtuale o un container), con il sistema operativo **Debian 9.4 (stretch)**

- assicurarsi che sull'host:
  - python sia installato (è richiesto da ansible)
  - esista un utente non privilegiato (username di difetto: `simevo`)

- assicurarsi che il controller (il computer da cui si intende controllare l'host):
  - abbia ansible 2.2 o posteriori installato
  - possa raggiungere l'host con un FQDN (valore di difetto `idp.simevo.com`)
  - possa effettuare l'accesso ssh con chiave crittografica come utente root e come utente non privilegiato

Configurare le variabili nel file `ansible/spid-testenv2_vars.yml` e il nome dell'host in `ansible/hosts` avviare l'installazione con il comando:
```
ansible-playbook -i ansible/hosts ansible/site.yml
```

Verifica dell'installazione: [https://idp.simevo.com/metadata](https://idp.simevo.com/metadata) ritorna i metadati dell'IDP.
