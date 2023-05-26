## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.193
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.193
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.193 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49667,49675,49676,49680,49698,49761 10.10.10.193 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 80     | http       | Web, Fuzzing                             |                           |
| 88     | Kerberos   | asproasting attack                       | lista de usuarios validos |
| 135    | msrpc      |                                          |                           |
| 139    | netbios    |                                          |                           |
| 389    | LDAP       | Bloodhound                               | credenciales              |
| 445    | smb        | Null session                             |                           |
| 464    | kpasswd5?  |                                          |                           |
| 593    | ncacn_http |                                          |                           |
| 636    | tcpwrapped |                                          |                           |
| 3268   | ldap       |                                          |                           |
| 3269   | tcpwrapped |                                          |                           |
| 5985   | WinRM      | evil-winrm                               | credenciales              |
| 9389   | mc-nmf     | Puertos por defecto de windows           |                           |
| 49666  | msrpc      | Puertos por defecto de windows           |                           |
| 49667  | msrpc      | Puertos por defecto de windows           |                           |
| 49675  | msrpc      | Puertos por defecto de windows           |                           |
| 49676  | ncacn_http | Puertos por defecto de windows           |                           |
| 49680  | msrpc      | Puertos por defecto de windows           |                           |
| 49698  | msrpc      | Puertos por defecto de windows           |                           |
| 49761  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.193
smbclient -L 10.10.10.193 -N
```

Vemos que estamos en frente de una maquina Windows Server 2016 Standard de 64 bit pro que se llama **FUSE** en el dominio **fabricorp.local**.
No vemos ningun recursos compartidos a nivel de red.
Añadimos el dominio a nuestro `/etc/hosts`.

### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.193 -N

rpcclient $> enumdomusers
```

Aqui vemos un Access Denied.

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.193
```

Vemos una vez mas que estamos en frente de una IIS pero nada mas. Seguimos checkeando la web.


#### Checkear la web {-}

Sabemos que es un IIS 10.0 con asp.net. Hay una redireccion automatica a fuzse.fabricorp.local y vemos que estamos en frente
de un servicio de impressora. Miramos los logs print y vemos una columna interesante que es la de **Users**.

Nos creamos un fichero users y copiamos los usuarios de la web.

Ya que tenemos un fichero con contraseñas, intentamos fuerza bruta con **crackmapexec**.


