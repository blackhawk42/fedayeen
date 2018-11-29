# Especificaciones del sistema

ADVERTENCIA: todo aquí es el primer borrador y sujeto a cambios basados
en futura discución y requerimientos.

## Descripción general de la architectura

El sistema está conformada por tres susbsistemas generales:

* La Interfaz de Usuario (IU)
* El Sistema de Administración de Contraseñas (SAC)
* La Base de Datos (BD)

### La Interfáz de Usuario (IU)

Esta es escencialmente una terminal boba. Su habilidad principal es la
habilidad de comunicarse con el SAC y recibir respuestas de él. Su verdadero
valor radica en:

* Solicitar la creación, recuperación, edición y eliminación de datos en la
base de datos por medio del protocolo y el SAC.

* La modificación local de los datos, antes de consolidar los cambios en la
base de datos.

* La presentación de los datos y toda acción que pueda facilitar esto (e.g.,
buscar y filtrar).

* La solicitación de servicios criptográficos proveidos por el SAC.

Toda su comunicación depende de protocolos estandarizados (ya sea verdaderos
estándares o los establecidos en este documento). También se asume muy poco
sobre la plataforma en la que estará: puede estar situada local o remotamente
y la habilidad de establecer un socket SSL es la única funcionalidad criptográfica
requerida. Debido a esto, hay mucha libertad sobre cómo implementarlo.

Para propósitos del prototipo, será una simple aplicación gráfica para una
computadora de escritorio.

### El Sistema de Administración de Contraseñas (SAC)

El verdadero cerebro de la operación. Este sistema provee dos funcionalidades:

* Interacción con la base de datos.
* "Servicios criptográficos", como la generación de contraseñas.

Esta parte del sistema depende de un servidor centralizado con
funcionalidades criptográficas y de red básicas (sockets SSL, generación segura de
numeros aleatorios) y no tan básicas (criptografía simétrica, generación de llaves,
hashes).

Las generacion de contraseñas se basará en implementar diferentes esquemas.
Para la versión actual, se provera:

* Alfanumerica aleatoria en minúsculas.
* Diceware en español.

El sistema también se encarga de realizar toda la criptografía necesaria para
el manejo de cuentas (hashes, generación de llaves, etc.). Bajo el diseño
actual, no se requiere la capacidad de manejar sesiones.

### La Base de Datos (BD)

La memoria del sistema. Manejado por el SAC a petición de la IU,
se encarga de recordar y editar cuentas de usuario y contraseñas.

El esquema es:

* user(string, primary key). Simplemente el nombre de usuario. Único y el
identificador de la cuenta.

* salt(blob). La sal para la generación de la llave.

* master_key(blob). El hash de la llave generada a base de la contraseña
maestra, la que el usuario definitivamente debe recordar. Cada vez que el usuario
quiere entrar, derivamos una llave en base a un algoritmo de derivación de
llave con una sal dada, aplicamos un hash a esa llave, y finalmente guradamos
ese hash en este lugar.

* passwords(blob). Un string en JSON que ha sido cifrado con un algoritmo
simétrico usando la llave generada, conteniendo todas las contraseñas del usuario.

* blocked(bool). Está el usuario bloqueado? Dadod que esto es SQLite,
esto será un 1 para sí, 0 para no.

El algoritmo de derivación de llave es pbkdf2_hmac con 100,000 iteraciones.
El algoritmo de hash es SHA256. El tamaño de la sal es 16 bits. El algoritmo
simétrico es el especificado en la implementación "Fernet" del modulo
de Python "Cryptography".

La base de datos en sí será implementada en SQLite.

Aunque técnicamente es factible poner la BD en su propio espacio remoto,
por el momento se asumirá que la base de datos siempre estará en el
mismo lugar que el SAC.

## Protocolos

### Formato en JSON de Almacenamiento de Contraseñas

Este es un formato para codificar contraseñas e información relevante,
ya sea para su transmisión o para su almacenamiento pre-cifrado.


El formato está basado en JSON (ECMA-404). En términos de dicho estándar,
consiste en un arreglo conteniendo varios objetos, cada objeto
representando una contraseña individual con su información relevante.
Como mínimo, esta información será:

* "service": el nombre del servicio en el que esta contraseña se usa (e.g., Facebook).
* "user": usuario con el que esta contraseña se usa en el servicio.
* "password": la contraseña en sí.
* “lastmodified”: última hora y fecha de modificación de “password”, codificado en un
	número representando los segundos transcurridos desde el Tiempo Unix (IEEE 103.1)


Por supuesto, es posible extender estos campos, pero los aquí definidos son los obligatorios y necesarios para la funcionalidad de nuestra aplicación.
Un ejemplo de FJAC siendo usado para codificar dos hipotéticas contraseñas con su información:


```JSON
[
	{
		"service": "Facebook",
		"user": "mail@example.com",
		"password": "u5p1duddt63fb2ma1t7y",
		“lastmodified”: 1539147600
	},
	
	{
		"service": "Reddit",
		"user": "acleverusername",
		"password": "custompassword",
		“lastmodified”: 1539233270
	}
]
```

### Protocolo de comunicación

La comunicación entre la IU y el SAC depende de un protocolo de
comandos y respuestas sin estado, cada socket siendo usado para (desde la
perspectiva de la IU) enviar un comando, recibir una respuesta y
subsecuentemente descartar el socket, muy similar a HTTP.

Los sockets, por supuesto, usaran SSL para proteger comunicaciones. En teoría,
esto es seguridad suficiente durante comuncaciones, así que una vez establecida
la conexión, no hay que preocuparse por criptografía en esta etapa: toda
la criptografía la realizará el SAC antes de consolidar cambios en la BD
o de enviar información por el socket.

Todos los comandos son un arreglo de bytes en orden big (red)-endian. Todos
empiezan con un encabezado de 4 bytes (incluido en los siguientes listados),
un signed int indicando el número asignado a cada comando o respuesta
(entre paréntesis)

Los comandos son:

#### CREATE (1)

Crear un usuario nuevo.

##### Estructura:

* 1 (signed int, 4 bytes): código numérico del comando.
* UserSize (unsigned int, 4 bytes): tamaño de la cadena conteniendo al usuario.
* PasswordSize (unsigned int, 4 bytes): tamaño de la cadena conteniendo a la contraseña.
* User (UTF-8, tamaño variable): cadena conteniedo el usuario del tamaño especificado
* Password (UTF-8, tamaño variable): cadena conteniendo la contraseña maestra del tamaño especificado

Formato de struct.pack: '@iII' + User + Password

##### Posibles respuestas:

* Ok (200) (signed int, 4 bytes): usuario creado correctamente.
* Bad Request (400) (signed int, 4 bytes): error al parsear la petición.
* Conflict (409) (signed int, 4 bytes): el usuario solicitado ya existe en la BD.

#### RETRIEVE (2)

Recuperar las contraseñas de un dado usuario.

##### Estructura:

* 2 (signed int, 4 bytes): código numérico del comando.
* UserSize (unsigned int, 4 bytes): tamaño de la cadena conteniendo al usuario.
* PasswordSize (unsigned int, 4 bytes): tamaño de la cadena conteniendo a la contraseña.
* User (UTF-8, tamaño variable): cadena conteniedo el usuario del tamaño especificado.
* Password (UTF-8, tamaño variable): cadena conteniendo la contraseña maestra del tamaño especificado.

Formato de struct.pack: '@iII' + User + Password

##### Posibles respuestas:

* Ok (200) (signed int de 4 bytes seguido de un valor variable): contraseñas recuperadas exitosamente. Después del
código de respuesta sigue una cadena codificada en UTF-8 conteniendo el JSON
con las contraseñas.
* Bad Request (400) (signed int, 4 bytes): error al parsear la petición.
* Not Found (404) (singed int, 4 bytes): no se encontró el usuario o la contraseña es
incorrecta.

#### UPDATE (3)

Consolidar cambios hechos en las contraseñas por la IU.

##### Estructura:

* 3 (signed int, 4 bytes): código numérico del comando.
* UserSize (unsigned int, 4 bytes): tamaño de la cadena conteniendo al usuario.
* PasswordSize (unsigned int, 4 bytes): tamaño de la cadena conteniendo a la contraseña.
* User (UTF-8, tamaño variable): cadena conteniedo el usuario del tamaño especificado.
* Password (UTF-8, tamaño variable): cadena conteniendo la contraseña maestra del tamaño especificado.
* Json (UTF-8, tamaño variable): cadena conteniendo el JSON de todas las contraseñas, tal como se quieren consolidar.

Formato de struct.pack: '@iII' + User + Password + Json

##### Posibles respuestas:

* Ok (200) (signed int, 4 bytes): cambios consolidados exitosamente.
* Bad Request (400) (signed int, 4 bytes): error al parsear la petición.
* Not Found (404) (singed int, 4 bytes): no se encontró el usuario o la contraseña es
incorrecta.

#### DELETE (4)

Borrar un usuario y todas sus contraseñas del sistema.

##### Estructura:

* 4 (signed int, 4 bytes): código numérico del comando.
* UserSize (unsigned int, 4 bytes): tamaño de la cadena conteniendo al usuario.
* PasswordSize (unsigned int, 4 bytes): tamaño de la cadena conteniendo a la contraseña.
* User (UTF-8, tamaño variable): cadena conteniedo el usuario del tamaño especificado.
* Password (UTF-8, tamaño variable): cadena conteniendo la contraseña maestra del tamaño especificado.

Formato de struct.pack: '@iII' + User + Password

##### Posibles respuestas:

* Ok (200) (signed int, 4 bytes): usuario borrado con éxito del sistema.
* Bad Request (400) (signed int, 4 bytes): error al parsear la petición.
* Not Found (404) (singed int, 4 bytes): no se encontró el usuario o la contraseña es
incorrecta.

#### GENERATE (5)

Generar una contraseña basada en un esquema.

##### Estructura:

* 5 (signed int, 4 bytes): código numérico del comando.
* Scheme (signed int, 4 bytes): código numérico del esquema.
* Size (unsigned int, 4 bytes): tamaño de la contraseña. Qué es un "tamaño" exactamente depende del esquema.

Los esquemas implementados en el prototipo serán:

* Alfanumerica aleatoria en minúsculas (1). Longitud se refiere a cuántos
carácteres hay en la cadena.
* Diceware en español (2). Longitud se refiere a cuántas palabras contiene la contraseña.

Formato de struct.pack: '@iiI'

##### Posibles respuestas:

* Ok (200) (signed int de 4 bytes seguido de un valor variable): contraseña generada exitosamente, .
* Bad Request (400) (signed int, 4 bytes): error al parsear la petición.
* Not implemented (505) (singed int, 4 bytes): el esquema solicitado no está implementado.
