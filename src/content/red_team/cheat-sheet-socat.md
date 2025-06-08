---
title: "cheat-sheet-socat"
description: "cheat-sheet-socat"
published: true
pubDate: "2024-06-01"
updatedDate: "2024-06-01"
heroImage: /assets/posts1/xterm_color/xterm_color.jpg
---


- ESTE COMANDO DE SOCAT SIRVE PARA SERVIR BINARIOS ATRAVEZ DE UNA RED.
- O con socat puedes tunelizar el funcionanmiento del binario atravez de un puerto para el EXTERIOR para que sea usado en la red.

```bash
socat TCP-LISTEN:5000 EXEC:/ruta/binario
socat UDP-LISTEN:<PORT> EXEC:/ruta/binario
```

 ---

#### 1. 🔧 Parámetros útiles para tunear `TCP-LISTEN` + `EXEC`

#### En ***TCP-LISTEN:5000*** puedes añadir

| Parámetro       | Descripción                                                  |
| --------------- | ------------------------------------------------------------ |
| `reuseaddr`     | Permite reutilizar el puerto sin esperar TIME_WAIT           |
| `fork`          | Acepta múltiples conexiones (sino se cierra tras la primera) |
| `backlog=N`     | Número máximo de conexiones en espera                        |
| `range=IP1-IP2` | Solo permite conexiones desde cierto rango IP                |
| `bind=IP`       | Escucha solo en una IP específica (por defecto todas)        |
| `delay`         | Espera a que el cliente conecte antes de ejecutar            |

 ---

#### En **EXEC:/binario** puedes añadir

| Parámetro | Descripción                                                     |
| --------- | --------------------------------------------------------------- |
| `pty`     | Usa pseudoterminal (útil si es shell o binario interactivo)     |
| `stderr`  | Redirige stderr junto con stdout                                |
| `setsid`  | Crea una sesión separada (mejora compatibilidad de terminales)  |
| `sigint`  | Acepta señales como Ctrl+C correctamente                        |
| `sane`    | Configura terminal en modo estándar                             |
| `nofork`  | Ejecuta directamente sin hacer fork (solo una instancia activa) |

 ---

#### 2. 🧠 Variantes prácticas

#### ✅ Shell interactiva (como reverse shell listener)

```bash
socat TCP-LISTEN:5000,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

 ---

### 📁 Transferencia de archivo desde cliente a `/tmp/archivo`

```bash
socat TCP-LISTEN:5000,reuseaddr,fork EXEC:"tee /tmp/archivo"
```

> Cliente:  
> `cat archivo.bin | socat - TCP:<IP>:5000`

 ---

### 📡 Escuchar y ejecutar script Python

```bash
socat TCP-LISTEN:5000,reuseaddr,fork EXEC:"python3 /tmp/script.py",pty
```

  ---

### 🔒 Restringir por IP

```bash
socat TCP-LISTEN:5000,reuseaddr,fork,range=192.168.1.0/24 EXEC:/binario
```

 ---

### 👾 Simular servicio malicioso o honeypot

```bash
socat TCP-LISTEN:21,reuseaddr,fork EXEC:"/usr/sbin/vsftpd"
```

 ---

## 3. 📋 Cheat Sheet rápida de variantes útiles

|Escenario|Comando socat|
|---|---|
|Shell interactiva|`socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane`|
|Transferencia de archivo|`socat TCP-LISTEN:5000,reuseaddr EXEC:"tee /tmp/file"`|
|Script Python al conectar|`socat TCP-LISTEN:9999,reuseaddr EXEC:"python3 /tmp/handler.py"`|
|Servicio falso (honeypot)|`socat TCP-LISTEN:23,reuseaddr,fork EXEC:/bin/echo`|
|IP restricta|`socat TCP-LISTEN:1337,reuseaddr,range=192.168.1.0/24 EXEC:/binario`|

 ---

¿Quieres que te genere un script con varias de estas configuraciones, como un arsenal de `socat` para red team o labs?
