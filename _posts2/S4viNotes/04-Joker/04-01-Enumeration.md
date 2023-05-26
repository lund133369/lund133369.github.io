## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.21
```
ttl: 63 -> maquina linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.21 
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.21 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,3128 10.10.10.21 -oN targeted
```

|Puerto|Servicio    | Que se nos occure?              |    Que falta?      |
|------|------------|---------------------------------|--------------------|
|22    |ssh         |Accesso directo                  |usuario y contraseña|
|3128  |squid-proxy |Browsear la web por este puerto  |Checkear el exploit |

#### Browsear la web por el puerto 3128{-}

Browseando la web con el url `http://10.10.10.21:3128` no da un error que es normal porque no pasamos por el **squid-proxy**.

Utilizamos el **FoxyProxy** para añadir las credenciales del Proxy. Como no tenemos el usuario y la contraseña, dejamos estos datos
vacios.

```{r, echo = FALSE, fig.cap="foxyproxy con squid proxy", out.width="90%"}
    knitr::include_graphics("images/squid-foxy-no-creds.png")
```

#### Uso de curl con proxy {-}

La idea aqui es utilizar la herramienta **curl** con en argumento `--proxy` para ver si el puerto 80 esta abierto.

```bash
curl -s http://127.0.0.1 --proxy http://10.10.10.21:3128 | html2text
```

Hay un error de typo **ACCESS DENIED**, quiere decir que necesitamos un usuario y una contraseña.

Como nada esta abierto intentamos scanear la maquina por UDP

#### NMAP UPD Scan {-}

Como los scan de **NMAP** en UDP tarda un buen rato, decidimos ir a por los puertos mas interesantes.

```bash
nmap -sU -p69,161 10.10.10.21 -oN udpScan
```

encontramos el puerto del tftp que esta abierto

#### TFTP {-}

```bash
tftp 10.10.10.21
```

Nos podemos conectar pero no podemos cojer ficheros como `/etc/passwd`, `/etc/hosts` y otros. Tiramos por el fichero de config de squid.

```bash
get /etc/squid/squid.conf
```

#### Check squid.conf file {-}

```bash
cat squid.conf | grep -v "^#" | sed '/^\s*$/d'
```

Vemos que hay un fichero password. Lo descargamos desde el **tftp**

```bash
get /etc/squid/passwords
```

Lo analizamos y encontramos un usuario y una contraseña encriptada.

