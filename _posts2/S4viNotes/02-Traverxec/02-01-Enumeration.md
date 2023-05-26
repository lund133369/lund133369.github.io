## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.165
```
ttl: 63 -> maquina linux. 
Recuerda que en cuanto a ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.165
```

Va un poquito lento...

```bash
nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.10.165 -oG allPorts
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.165 -oN targeted
```

|Puerto|Servicio| Que se nos occure?    |    Que falta?      |
|------|--------|-----------------------|--------------------|
|22    |ssh     |conneccion a la maquina|Usuario contraseña  |
|80    |http    |whatweb, http-enum     |Checkear la web     |


### Empezamos por el puerto 80 {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.165
```

- nostromo 1.9.6

#### Chequear la cabecera {-}

```bash
curl -s -X GET -I http://10.10.10.165
```

- nostromo 1.9.6

#### Browsear la web {-}

Nada interessante.

#### WFuzz {-}

Como no hay mucho mas que ver, aplicaremos **fuzzing** para descubrir si hay mas rutas.

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.233/FUZZ
```

No hay nada, creamos un fichero de extensiones txt, php, html y fuzzeamos otravez.

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w extensions http://10.10.10.233/FUZZ.FUZ2Z
```

No hay nada.


