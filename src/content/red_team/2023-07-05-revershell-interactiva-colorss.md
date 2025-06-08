---
title: "Revershell Interativa-colores"
description: "Revershell Interativa-colores"
published: true
pubDate: "2024-06-01"
updatedDate: "2024-06-01"
heroImage: /assets/posts1/xterm_color/xterm_color.jpg
---

- Esta es la forma de realizar un tratamiento de la TTY o revershell adecuado
- paratener una mejor movilidad al momento de ejecutar programas:

  ```console
  user@pc:~$ hostname -I #verificamps si estamos en el servidor.
  user@pc:~$ script /dev/null -c bash
  user@pc:~$ ^Z # ctrl + z
  user@pc:~$ stty raw -echo; fg
  user@pc:~$ reset xterm
  user@pc:~$ export TERM=xterm-256color #indicamos una terminal con colores
  user@pc:~$ export SHELL=bash
  user@pc:~$ stty size #vemos tamaño de la terminal , filas-columnas , ejecuta el mismo comando en una ventana nueva .
  user@pc:~$ stty rows <rownb> columns <colnb> # luego de haber revisado el tamaño de tu propia terminal.
  ```

<span>
<i class="fa fa-copy"></i>
</span>
