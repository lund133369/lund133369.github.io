## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.239
```
ttl: 127 -> maquina Windows. 
Recordar que en cuanto a ttl respecta 64 = linux y 128 = windows. 
Pero comom estamos en hackthebox hay un nodo intermediario que hace que 
el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.239
```

Si consideras que va muy lento puedes meter los siguientes parametros para que valla mucho mas rapido el escaneo

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.239 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,135,139,443,445,3306,5000,5040,5985,5986,7680,47001,49664,49665,4966,49667,49668,49669,49670 10.10.10.239 -oN targeted
```

| Puerto | Servicio       | Que se nos occure?              | Que falta? |
| ------ | -------------- | ------------------------------- | ---------- |
| 80     | http           | Web, fuzzing                    |            |
| 135    | rpc            |                                 |            |
| 139    | NetBios        |                                 |            |
| 443    | ssl (https)    |                                 |            |
| 445    | SMB            | Null session                    |            |
| 3306   | mssql?         |                                 |            |
| 5000   | http           |                                 |            |
| 5040   | http           |                                 |            |
| 5985   | WinRM          |                                 |            |
| 5986   | WinRM ssl      |                                 |            |
| 7680   | tcp panda-pub? |                                 |            |
| 47001  | http           |                                 |            |
| 49664  | msrpc          | puertos por defectos de windows |            |
| 49665  | msrpc          | puertos por defectos de windows |            |
| 49666  | msrpc          | puertos por defectos de windows |            |
| 49667  | msrpc          | puertos por defectos de windows |            |
| 49668  | msrpc          | puertos por defectos de windows |            |
| 49669  | msrpc          | puertos por defectos de windows |            |
| 49670  | msrpc          | puertos por defectos de windows |            |


### Analizando el SMB {-}

```bash
crackmapexec smb 10.10.10.239
smbclient -L 10.10.10.239 -N
```

Vemos que estamos en frente de una maquina Windows10 pro que se llama **Love** y poco mas

### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.239
whatweb https://10.10.10.239
```

Nada muy interesante aqui

#### Chequear el contenido de el certificado SSL con openssl {-}

```bash
openssl s_client -connect 10.10.10.239:443
```

vemos una direccion de correo `roy@love.htb` lo que quiere decir que tenemos un usuario y un dominio. 
Tambien vemos un dominio `staging.love.htb`, quiere decir que es posible que se aplique virtual hosting.
Lo añadimos al `/etc/hosts` de la maquina de atacante.


```{r, echo = FALSE, fig.cap="love virtual hosting", out.width="90%"}
knitr::include_graphics("images/love-etc-hosts.png")
```

#### Chequear la web los puertos web {-}

```bash
cat targeted | grep "http"
cat targeted | grep "http" | grep -oP '\d{1-5}/tcp'
```

Aqui descartamos el puerto **47001** y los puertos **5985-5986** que ya sabemos que son los **WinRM**.

Con firefox navigamos en la web para ver lo que porque hay mucho por mirar. 

- el puerto 80 nos muestra una pagina de login.
- el puerto 443 nos muestra un **Forbidden**.
- el puerto 5000 nos muestra un **Forbidden**.
- el dominio **staging.love.htb** nos muestra otra web


#### Chequeando el puerto 80 {-}

Aqui como estamos en un panel de inicio de session, intentamos cosas

- admin / admin
- 1 / hola
- 0 / hola
- -1 / hola
- ;" / hola
- 1' or 1=1-- - / #
- ' or sleep(5)-- - / #
- 1 and sleep(5)-- - / #
- 1000 / hola

Aqui no parece que este vulnerable a inyeccion SQL. Vamos a fuzzear la web


#### Fuzzing con WFuzz {-}

Fuzzeamos el puerto 80

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.239/FUZZ
```

Encontramos una ruta `/admin`. En la pagina admin vemos otro panel de inicio de session que no es la misma que la del `index.php`

#### Chequeando la pagina admin {-}

Aqui como estamos en un panel de inicio de session, intentamos cosas

- test / test
- admin / admin

Ya vemos por el mensaje de error quel usuario admin existe.

