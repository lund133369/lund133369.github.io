## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.z
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.111
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.111 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,139,445,1880,9999 10.10.10.111 -oN targeted
```


| Puerto | Servicio     | Que se nos occure?          | Que falta? |
| ------ | ------------ | --------------------------- | ---------- |
| 22     | ssh          | Coneccion directa           |            |
| 139    | NetBios      |                             |            |
| 445    | Samba        | Conneccion con Null session |            |
| 1880   | http Node.js | Fuzzing                     |            |
| 9999   | http nginx   |                             |            |


### Analyzando el Samba {-}

```bash
smbclient -L 10.10.10.111 -N
smbmap -H 10.10.10.111 
```

Vemos un recurso `Printer Driver` y `IPC` pero no tenemos accesso.

### Analyzando la web {-}

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.111:1880`. Vemos un panel de inicio de session **Node-Red**. Intentamos login por defectos como `admin:admin` pero no va.
Miramos por internet si existen credenciales por defecto con **Node-Red** pero por el momento no encontramos nada.

Checkeamos la url `http://10.10.10.111:9999` y vemos la pagina por defecto de **Nginx**. En esta pagina vemos una url `http://forlic.htb:1880`. Nos parece turbio porque
la url es **forlic** y no **frolic**, pero ya nos hace pensar que se puede aplicar virtual hosting. Lo añadimos al `/etc/hosts` y probamos pero no vemos ninguna diferencia.

#### Aplicando Fuzzing {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.111:9999/FUZZ
```

Aqui encontramos routas como

- admin
- test
- dev
- backup

Si vamos a la url `http://10.10.10.111:9999/admin` vemos un panel de inicio de session que nos dice *c'mon i m hackable*.

Intentamos nuevamente `admin:admin` y nos sale un mensaje **you have 2 more left attempts**, controlamos si esto es general o solo para el usuario admin `test:test`
y vemos que es general. 










