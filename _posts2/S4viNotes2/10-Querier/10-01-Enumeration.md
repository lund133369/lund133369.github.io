## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.125
```
ttl: 127 -> maquina Windows.
Recuerda que tratandose de ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.125 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669,49670,49671 10.10.10.125 -oN targeted
```

| Puerto | Servicio        | Que se nos occure?                                | Que falta?           |
| ------ | --------------- | ------------------------------------------------- | -------------------- |
| 135    | rpc             |                                                   |                      |
| 139    | netbios-ssn     |                                                   |                      |
| 445    | smb             | crackmapexec, smbclient, smbmap                   |                      |
| 1433   | mssql           | Intento de connexion con credenciales por defecto | usuario y contraseña |
| 5985   | winrm           | connexion directa con evil-winrm                  | usuario y contraseña |
| 47001  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49664  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49665  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49666  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49667  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49668  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49669  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49670  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49671  | windows puertos | Puertos windows que no nos lleva a nada           |                      |


### Analizando el smb 445 {-}

1. Scannear el servicio smb

    ```bash
    crackmapexec smb 10.10.10.125
    ```

1. Listar los recursos compartido a nivel de red usando un NULL session

    ```bash
    smbclient -L 10.10.10.125 -N
    ```

1. Intentamos conectarnos al recurso Reports

    ```bash
    smbclient "//10.10.10.125/Reports" -N
    dir
    get "Currency Volume Report.xlsm"
    ```

Que vemos:

- nombre             : QUERIER
- maquina            : Windows 10 x64
- domain             : HTB.LOCAL
- recurso compartido : Reports
- archivo encontrado : Currency Volume Report.xlsm

### Conexion por MSSQL credenciales por defecto {-}

Intentamos conectarnos al servicio MSQL con credenciales por defecto usando `mssqlclient.py`

```bash
locate mssqlclient.py
/usr/bin/mssqlclient.py WORKGROUP/sa:sa@10.10.10.125
/usr/bin/mssqlclient.py WORKGROUP/sa@10.10.10.125
```

El usuario por defecto **sa** no nos va con la contraseña **sa** y sin contraseña. Intentamos volverlo a intentar
con el parametro `-windows-auth`

```bash
/usr/bin/mssqlclient.py WORKGROUP/sa:sa@10.10.10.125 -windows-auth
/usr/bin/mssqlclient.py WORKGROUP/sa@10.10.10.125 -windows-auth
```

Bueno aqui no esta functionado
