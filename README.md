🔎 UNIMap: Sistema para la Detección y Gestión de Vulnerabilidades de Seguridad con Python,2024. En este presente repositorio se encuentra los códigos que forman parte del proyecto del curso de POO por parte de estudiantes de la Facultad de Ingenieria Electrica y Electrónica de la Universidad Nacional de Ingenieria (UNI), Lima, Perú. 

# UNIMAP

UNIMAP es un código hecho en python en el cual se ha implemando [NMAP](https://nmap.org/ "NMAP"), con el cual se podrá realizar escaneos de conectividad y vulnerabilidades a los dispositivos conectados en una misma red. Genera reportes en formato HTML, TXT y CSV. Enviado una notificación (en caso el usuario lo desee) con una copia del reporte generado en ese instante por parte del programa, detallando los puertos con sus respectivo grado de riesgo de cada IP escaneada dentro del rango ingresado. 

# Ejecución del código

Para la ejecución del código se implementó flask como un intermediario entre el frontend y el backend (escanerNMAP.py), con el nombre "app.py". Para poder hacer uso del código,  la carpeta del proyecto se deberá encontrar en el escritorio y usar la extensión "ESCANER.bat" de está manerá se estaria activando el servidor Flask. En caso no se desee usar está extensión se deberá activar el servidor Flask de manera manual desde el CMD, o sea que deberá encontrarse en el mismo lugar donde halla descargado la carpeta del proyecto en el CMD y activar el servidor flask con el comando:
```bash
python app.py
```
Es importante aclarar que la ventana del CMD deberá estar abierta para que el código pueda ser ejecutado.
# Libreria
Para el uso del código deberá tener la siguiente libreria:
- NMAP:
Este paquete permite interactuar con Nmap, una herramienta de escaneo de redes. Deberá instalarse desde la consola y ademas se deberá tener instalado NMAP en el sistema. Puede descargarlo desde [nmap](https://nmap.org/ "nmap").

```bash
pip install python-nmap

```

# Atención

Para la redacción de correos se usó una cuenta GMAIL creada unicamente para la presentación del proyecto, el cual posiblemente sea borrada, si se desea enviar los reportes hacia los correos se tendrá que modificar las lineas **273** (en ésta parte se ubica el correo gmail que se creó para la presentación del proyecto) y **314** (en esta parte se ubica la contraseña de aplicación y ésta se deberá generar de la cuenta a usar). Pueden ser modificadas con los usuarios de remitente a emplear. 

# Autores

- Zahid Franschesco Palomino Pimpinco - zahid.palomino.p@uni.pe
- Luis Javier Villegas Noblecilla - luis.villegas.n@uni.pe
- Fatima Lizeth Toscano Velasquez
- Adrian Mayta Nuñez 
