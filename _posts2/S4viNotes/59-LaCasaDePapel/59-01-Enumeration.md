## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.131
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.131
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.131 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,22,80,443 10.10.10.131 -oN targeted
```


| Puerto | Servicio | Que se nos occure?          | Que falta? |
| ------ | -------- | --------------------------- | ---------- |
| 21     | ftp      | anonymous                   |            |
| 22     | ssh      | Coneccion directa           |            |
| 80     | http     | Web Fuzzing                 |            |
| 443    | https    | Web Fuzzing                 |            |


Ya aqui podemos ver en el commonName del certificado ssl `lacasadepapel.htb` que añadimos al `/etc/hosts`

### Coneccion Anonoymous con ftp {-}

```bash
ftp 10.10.10.131

Name: anonymous
Password: 

530 Login incorrect.
```

No nos podemos conectar con el usuario anonymous, Pero podemos ver que el servicio es un vsFTPd 2.3.4 que ya sabemos que existe un exploit

```bash
searchsploit vsftpd 2.3.4

#Output
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)
```

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.131
```

No vemos nada interesante aqui.

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.131`, El wappalizer no nos muestra nada. Si entramos con el dominio `http://lacasadepapel.htb` vemos lo mismo.
Intentamos por **https** `https://lacasadepapel.htb` y aqui la cosa cambia. Tenemos un mensaje que dice que tenemos que proporcionar un certificado cliente
para ver mas cosas. Pero aqui necessitamos tener mas informaciones.
