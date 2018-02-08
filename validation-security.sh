#!/bin/bash
H1=Content-Security-Policy: 
H2=X-Frame-Options:
H3=X-XSS-Protection:
H4=X-Content-Type-Options:
H5=Referrer-Policy:
H6=Strict-Transport-Security:
USER=$(whoami)
PORTS="80/tcp|443/tcp"
DATE=$(date --date='+ 1 month' +"%Y-%m-%d""%T")

echo "Introduzca la URL a analizar:"
read IN
	
		
######### Analiza las cabeceras de seguridad ###########
if [ "$USER" = "root" ]; then 
	echo -e "Analizando cabeceras..."    
	sleep 1s 
	echo | curl -I "$IN" | grep -E --ignore-case "$H1|$H2|$H3|$H4|$H5|$H6" | awk '{print $1}' | tr [:upper:] [:lower:] > /home/cabeceras.txt
	(echo "$H1" && echo "$H2" && echo "$H3" && echo "$H4" && echo "$H5" && echo "$H6") | tr [:upper:] [:lower:] > /home/cabeceras-bases.txt 
	diff -B /home/cabeceras-bases.txt /home/cabeceras.txt > /home/diferencias.txt
	sed -i 's/<//g' /home/diferencias.txt && sed -i 's/>//g' /home/diferencias.txt
	cat /home/diferencias.txt | sort | uniq -u | grep -E -i "$H1|$H2|$H3|$H4|$H5|$H6" > /home/diferencias2.txt
	sed -i -e 's/^[ \t]*//; s/[ \t]*$//; /^$/d' /home/diferencias2.txt
	echo -e "\n"
	echo -e "*** Cabeceras de Seguridad Detectadas ***"    
	cat /home/cabeceras.txt
	echo -e "\n"
	echo -e "\e[1;31m*** Faltan las siguientes Cabeceras de Seguridad ***\e[0m"    
	cat /home/diferencias2.txt
else
	echo -e "Analizando cabeceras..."
	sleep 1s
	echo | curl -I "$IN" | grep -E --ignore-case "$H1|$H2|$H3|$H4|$H5|$H6" | awk '{print $1}' | tr [:upper:] [:lower:] > /home/"$USER"/cabeceras.txt
	(echo "$H1" && echo "$H2" && echo "$H3" && echo "$H4" && echo "$H5"  && echo "$H6") | tr [:upper:] [:lower:] > /home/"$USER"/cabeceras-bases.txt
	diff -B /home/"$USER"/cabeceras-bases.txt /home/"$USER"/cabeceras.txt > /home/"$USER"/diferencias.txt
	sed -i 's/<//g' /home/"$USER"/diferencias.txt && sed -i 's/>//g' /home/"$USER"/diferencias.txt
	cat /home/"$USER"/diferencias.txt | sort | uniq -u | grep -E -i "$H1|$H2|$H3|$H4|$H5|$H6" > /home/"$USER"/diferencias2.txt
	sed -i -e 's/^[ \t]*//; s/[ \t]*$//; /^$/d' /home/"$USER"/diferencias2.txt
	echo -e "\n"
	echo -e "*** Cabeceras de Seguridad Detectadas ****"    
	cat /home/"$USER"/cabeceras.txt
	echo -e "\n"
	echo -e "\e[1;31m*** Faltan las siguientes Cabeceras de Seguridad ***\e[0m"    
	cat /home/"$USER"/diferencias2.txt
fi
	echo -e "\n"
	echo "Analizando Certificado Digital..."

######## Comprueba quien corre el script "root" o "single user" ###########
	if 	[ "$USER" = "root" ]; then 
		echo $IN > /home/filtralo.txt
	    sed -i 's/http:\/\///g;s/https:\/\///g' /home/filtralo.txt && sed -i 's/\//\n\//g' /home/filtralo.txt
	    less /home/filtralo.txt | grep -v "/" > /home/url-filtrada.txt
	    URL2=$(cat /home/url-filtrada.txt)
	    echo "Analizando la URL" "$IN"
		a=$(echo | nmap "$URL2" -p443 | awk '{print $2}' | grep open)
			## comprueba si tiene un certificado digital ###
			if [[ "$a" = "open" ]]; then 
				echo -e "\n"
				echo "Comprobando Algoritmos del Cifrado...."
				echo | nmap -sS -Pn -d --script=ssl-enum-ciphers.nse "$URL2" | grep -E "3DES|RC4" > /home/vulnerable.txt
			   	##### comprobando certificados algoritmos de cifrado ######
			   	if [[ -s /home/vulnerable.txt ]]; then 
			   		echo -e "\n"
			   		echo -e "\e[1;31mAlgoritmos de Cifrado Débiles \e[0m "
			   		echo -e "\e[1;31mVulnerable a ataque de cumpleaños \e[0m "
			   		cat /home/vulnerable.txt 
			  	else
			   		echo "Certificado Digital con Algoritmos de Certificado Correctos!!!"
			   	fi
			   	##### Validando fecha de valides del certificado ####
			   	echo -e "\n"
			   	echo "Validando Fechas de Validez del Certificado Digital..."
			   	echo | nmap -sS -Pn --script=ssl-cert.nse "$URL2" -p443 | awk '{print $3 $4 $5}' | grep validafter > /home/hora.txt
				sed -i 's/validafter://g;s/T//g' /home/hora.txt
				DATER=$(cat /home/hora.txt)
				if [[ "$DATER" > "$DATE" ]]; then
					echo "Certicado Digital Vigente!!!"
					echo "Fecha de Vencimiento:" "$DATER"
				else
					echo -e "\e[1;31mCertificado Digital vencido o pronto en vencer!!! \e[0m "
					echo -e "Fecha de Vencimiento:" "$DATER"
				fi
			   	##### Validando protocolos deprecados #####
			   	##### Validando protocolos deprecados #####
				
			else 
				echo -e "\e[1;31mNO EXISTE UN CERTIFICADO DIGITAL!!! \e[0m "
				echo -e "\e[1;31mVULNERABLE A ATAQUE MitM \e[0m "
			fi
	else
		echo $IN > /home/"$USER"/filtralo.txt
	    sed -i 's/http:\/\///g;s/https:\/\///g' /home/"$USER"/filtralo.txt && sed -i 's/\//\n\//g' /home/"$USER"/filtralo.txt
	    less /home/"$USER"/filtralo.txt | grep -v "/" > /home/"$USER"/url-filtrada.txt
	    URL3=$(cat /home/"$USER"/url-filtrada.txt)
	    echo "Analizando la URL" "$IN"
		a=$(echo | nmap "$URL3" -p443 | awk '{print $2}' | grep open)
			## comprueba si tiene un certificado digital ###
			if [[ "$a" = "open" ]]; then 
				echo -e "\n"
				echo "Comprobando Algoritmos de Cifrados..."
				echo | nmap --script=ssl-enum-ciphers.nse "$URL3" | grep -E "3DES|RC4" > /home/"$USER"/vulnerable.txt
			   	##### comprobando certificados algoritmos de cifrado ######
			   	if [[ -s /home/"$USER"/vulnerable.txt ]]; then 
			   		echo -e "\n"
			   		echo -e "\e[1;31mAlgoritmos de Cifrado Débiles \e[0m "
			   		echo -e "\e[1;31mVulnerable a ataque de cumpleaños \e[0m "
			   		cat /home/"$USER"/vulnerable.txt 
			  	else
			   		echo "Certificado Digital con Algoritmos de Certificado Correctos!!!"
			   	fi
			   	##### Validando fecha de valides del certificado ####
			   	echo -e "\n"
			   	echo "Validando Fechas de Validez del Certificado Digital"
			   	echo | nmap --script=ssl-cert.nse "$URL3" -p443 | awk '{print $3 $4 $5}' | grep validafter > /home/"$USER"/hora.txt
				sed -i 's/validafter://g;s/T//g' /home/"$USER"/hora.txt
				DATER=$(cat /home/"$USER"/hora.txt)
				if [[ $DATER > $DATE ]]; then
					echo "Certicado Digital Vigente!!!"
					echo "Fecha de Vencimiento:" "$DATER"
				else
					echo -e "\e[1;31mCertificado Digital vencido o pronto en vencer!!! \e[0m "
					echo -e "Fecha de Vencimiento:" "$DATER"
				fi
			   	##### Validando protocolos deprecados #####
			   	##### Validando protocolos deprecados #####
				
			else 
				echo -e "\e[1;31mNO EXISTE UN CERTIFICADO DIGITAL!!! \e[0m "
				echo -e "\e[1;31mVULNERABLE A ATAQUE MitM \e[0m "
			fi
	
	fi
######## Comprueba quien corre el script "root" o "single user" ###########

######## Revisando servicios innecesarios ########
if 	[ "$USER" = "root" ]; then 
	echo -e "\n"
	echo "Analizando servicios activos"
	echo "Analizando la URL" "$IN"
    echo | nmap -sS -Pn "$URL2" | awk '{print $1}' | grep tcp | grep -E -v "$PORTS" > /home/servicios-innesarios.txt
   	echo -e "\n"
   	if [[ -s /home/servicios-innesarios.txt ]]; then 
   		echo -e "\n"
   		echo -e "\e[1;31m**** Servicios innecesarios corriendo ****\e[0m "
   		cat /home/servicios-innesarios.txt
   	else 
   		echo "No hay servicios innecesarios"
   		echo "Proceso Completado!!!"
   	fi
else
	echo | nmap "$URL3" | awk '{print $1}' | grep tcp | grep -E -v "$PORTS" > /home/"$USER"/servicios-innesarios.txt
   	echo -e "\n"
   	if [[ -s /home/"$USER"/servicios-innesarios.txt ]]; then 
   		echo -e "\n"
   		echo -e "\e[1;31m**** Servicios innecesarios corriendo ****\e[0m "
   		cat /home/"$USER"/servicios-innesarios.txt
   		echo "Proceso Completado!!!"
   	else 
   		echo -e "\n"
   		echo "No hay servicios innecesarios"
   		echo "Proceso Completado!!!"
   	fi
fi

######## Borrando archivos usados ########## 

if 	[ "$USER" = "root" ]; then 
	rm -rf /home/vulnerable.txt
	rm -rf /home/url-filtrada.txt
	rm -rf /home/cabeceras-bases.txt
	rm -rf /home/cabeceras.txt
	rm -rf /home/diferencias.txt
	rm -rf /home/diferencias2.txt
	rm -rf /home/servicios-innesarios.txt
	rm -rf /home/"$USER"/hora.txt
else
	rm -rf /home/"$USER"/vulnerable.txt
	rm -rf /home/"$USER"/filtralo.txt
	rm -rf /home/"$USER"/url-filtrada.txt
	rm -rf /home/"$USER"/cabeceras-bases.txt
	rm -rf /home/"$USER"/cabeceras.txt
	rm -rf /home/"$USER"/diferencias.txt
	rm -rf /home/"$USER"/diferencias2.txt
	rm -rf /home/"$USER"/servicios-innesarios.txt
	rm -rf /home/"$USER"/hora.txt
fi

