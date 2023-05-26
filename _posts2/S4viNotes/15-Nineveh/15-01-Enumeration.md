## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.43
```
ttl: 63 -> maquina Linux. 
Recordar que en cuanto a ttl respecta 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl 
disminuya en una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.43
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.43 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,443 10.10.10.43 -oN targeted
```

| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 80     | http     | Web, fuzzing       |            |
| 443    | https    | Web, fuzzing       |            |


### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.43
whatweb https://10.10.10.43
```

Los dos resultados son los mismos y no hay nada muy interesante

#### Chequear la web por comparar los 2 puertos {-}

Con firefox navegamos en la web para ver lo que es. 

- el puerto 80 nos muestra una pagina por defecto
- el puerto 443 nos muestra una webapp con una imagen.

El resultado de los 2 puertos muestran resultados diferentes y parece que la buena web app esta en el puerto 443. Delante de esta situacion,
siempre es interesante mirar lo que hay en el certificado

#### Chequear el contenido de el certificado SSL con openssl {-}

```bash
openssl s_client -connect 10.10.10.43:443
```

vemos una direccion de correo `admin@nineveh.htb` lo que quiere decir que tenemos un usuario y un dominio. 
Como no tenemos mucha mas informacion, vamos a fuzzear la web.

#### Fuzzing con WFuzz {-}

Fuzzeamos el puerto 80

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.43/FUZZ
```

Encontramos una ruta `/department`.

y tambien el puerto 443


```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt https://10.10.10.43/FUZZ
```

Encontramos una ruta `/db`.

#### Analizamos el directorio department de puerto 80 {-}

Aqui vemos una pagina de Login. El wappalizer no nos muestra algo nuevo. Poniendo como nombre de usuario **admin**, la web
nos señala un mensaje `invalid password` lo que quiere decir que el usuario existe. Vamos a utilizar fuzzing con **BurpSuite**
para encontrar la contraseña del usuario admin.

#### Analizamos el directorio db de puerto 443 {-}

Aqui vemos una pagina de Login para un servicio `phpLiteAdmin` de version **1.9**. Buscamos en internet si hay un default password para este servicio y
efectivamente el default password del servicio es **admin** pero en este caso no funciona.


