## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.102
```
ttl: 63 -> maquina Linux. 
Recordar que en cuanto a ttl se trata 64 = linux y 128 = windows. 
Pero como estamos en hackthebox el ttl disminuye en una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.102 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,5000 10.10.10.102 -oN targeted
```

| Puerto | Servicio     | Que se nos occure?    | Que falta?   |
| ------ | ------------ | --------------------- | ------------ |
| 21     | ftp          | Accesso por anonymous |              |
| 22     | ssh          | Accesso directorio    | Credenciales |
| 80     | http         | Web, fuzzing          |              |
| 5435   | tcpwrapped   |                       |              |
| 8082   | http         | Web, fuzzing          |              |
| 9092   | XmlIpcRegSvc |                       |              |


### Conneccion como anonymous al servicio FTP {-}

```bash
ftp 10.1.10.102
Name: anonymous
```

Mirando los ficheros con `ls -la` encontramos un fichero oculto llamado `.drupal.txt.enc`. Lo descargamos en nuestra
maquina de atacante.

```bash
ls -la
cd messages
ls -la
get .drupal.txt.enc
```

### Analizando el fichero .drupal.txt.enc {-}

```bash
mv .drupal.txt.enc drupal.txt.enc
cat drupal.txt.enc
```

Aqui vemos que el contenido del fichero esta encodeado en base64.

```bash
cat drupal.txt.enc | xargs | tr -d ' ' | base64 -d; echo
```

Aqui el contenido parece ser un binario. La mejor cosa que hacer en estas situaciones seria guardarlo en un nuevo fichero

```bash
cat drupal.txt.enc | xargs | tr -d ' ' | base64 -d; echo > drupal
rm drupal.txt.enc
mv drupal dupal.txt.crypted
```

Ahora podemos mirar que typo de fichero es.

```bash
cat drupal.txt.crypted
strings drupal.txt.crypted
file drupal.txt.crypted
```

El comando file nos muestra que el fichero a sido encriptado por openssl con una contraseña.

### Desencripcion del fichero drupal.txt.crypted {-}

El problema en este caso es que para leer el fichero necesitamos:

- una contraseña
- el modo de cifrado utlizado para encriptar

Aqui tendriamos que intentar multiples modo de cifrado pero buscando por internet, vemos que el mas comun seria el `aes-256-cbc`

En modo de ejemplo, estas serian la lineas para encriptar y desencriptar un fichero con openssl:

1. Encripcion
    ```bash
    openssl aes-256-cbc -in fichero -out fichero.crypted -k password123
    ```
1. Desencripcion

    ```bash
    openssl aes-256-cbc -d -in fichero.crypted -out fichero -k password123
    ```

La idea aqui es crearnos un script `bruteforce.sh` que nos permite encontrar la contraseña.
