## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.242
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.242
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.242 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.242 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | tcp      | Web, Fuzzing       |            |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.242
```

Es un Apache 2.4.41 en un Ubuntu Con una version 8.1.0-dev de PHP. 


#### Checkear la web {-}

Si entramos en la url `http://10.10.10.242`, No vemos gran cosas tenemos que aplicar Fuzzing.

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.242/FUZZ
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z list,txt-php http://10.10.10.242/FUZZ.FUZ2Z
```

Tampoco encontramos gran cosa por aqui.

#### Analyzamos las cabezeras de la respuesta al lado del servidor {-}

```bash
curl -s -X GET http://10.10.10.242 -I
```

No vemos nada. Miramos por la version de php que parece un poco rara.


