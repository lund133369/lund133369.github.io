## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.83
```
ttl: 63 -> maquina linux
Recuerda que en cuanto a ttl 64 es igual a linux y 128 es igual a windows
pero como estamos en hackthebox hay un nodo intermediario que hace que disminuya el ttl en una unidad 

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.83
```

Si consideras que va muy lento, puedes utilizar los siguientes parametros para que valla mucho mas rapido
```bash
nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.10.83 -oG allPorts
extractPorts allPorts
nmap -sC -sV -p53,80,2222 10.10.10.83 -oN targeted
```

|Puerto|Servicio| Que se nos occure?    |    Que falta?      |
|------|--------|-----------------------|--------------------|
|53    |domain  |Domain zone transfer   |Un nombre de dominio|
|80    |http    |whatweb, http-enum     |Checkear la web     |
|2222  |ssh     |conexion a la maquina  |Usuario contraseña  |


### Empezamos por el puerto 80 {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.83
```

Nada interesante

#### Browsear la web {-}

Hay una imagen, se nos occure steganografia pero no hay nada.

El Wappalyzer no dice que el servidor web empleado es un Apache. 

#### WFuzz {-}

Como no hay mucho mas que ver, aplicaremos **fuzzing** para descubrir si hay mas rutas.

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.83/FUZZ
```

No hay nada, creamos un fichero de extensiones txt, php, html y fuzzeamos otravez.

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w extensions http://10.10.10.83/FUZZ.FUZ2Z
```

No hay nada.

#### Dig {-}

**Dig** a no confundir con dick ;) es una utilidad que nos permite recojer informaciones a nivel de dns.

1. Añadir la ip y el hostname en el /etc/hosts

    ```bash
    10.10.10.83 olympus.htb
    ```

1. Lanzar **Dig** para recojer informaciones

    ```bash
    dig @10.10.10.83 olympus.htb
    ```

No hay respuesta valida lo que quiere decir que el dominio no es valido

#### Checkear las cabezeras de las respuestas a lado del servidor {-}

```bash
curl -X GET -s "http://10.10.10.83/" -I
```

```{r, echo = FALSE, fig.cap="curl xdebug", out.width="90%"}
    knitr::include_graphics("images/curl-xdebug.png")
```

Algo interessante en la respuesta es el Xdebug 2.5.5. Xdebug es una extension de PHP para hacer debug con haremientas
depuracion tradicionales, desde el editor, tal como se hace en lenguajes de programacion clasicos. Mas informaciones sobre
Xdebug en [desarolloweb.com](https://desarrolloweb.com/articulos/que-es-instalar-configurar-xdebug.html)



