#!/bin/bash
grep -iRn images * | while read -r file;do
echo $file ;echo $(echo $file | awk -F':' 'NR==1 {print $1}' ) ; #aqui_obtienes la cadena completa
echo $(echo $file | awk -F':' 'NR==1 {print $2}' ); #aqui obtienes el numero de linea a cambiar
echo $(echo $file | awk -F'[(]' 'NR==1 {print $2}'| tr -d ')"') ; #aqui obtienes el nombre de la imagen
done


