import struct
import enum

class Command(enum.IntEnum):
	"""Comandos reconocidos por el protocolo. Estos son:
	
	CREATE (1): Crear un nuevo usuario.
	RETRIEVE (2): Recuperar las contraseñas de un usuario existente.
	UPDATE (3): Actualizar las contraseñas de un usuario existente.
	DELETE (4): Eliminar a un usuario, con toda su información.
	GENERATE (5): Generar una nueva contraseña con un esquema dado.
	"""
	
	CREATE = 1
	RETRIEVE = 2
	UPDATE = 3
	DELETE = 4
	GENERATE = 5

class StatusCode(enum.IntEnum):
	"""Posibles códigos de estado. Su significado exacto depende de qué
	comando lo arroja."""
	
	OK = 200
	BAD_REQUEST = 400
	NOT_FOUND = 404
	CONFLICT = 409
	NOT_IMPLEMENTED = 505

class PasswordScheme(enum.IntEnum):
	"""Posibles esquemas utilizables para la generación de contraseña."""
	LOWER_ALPHA = 1
	DICEWARE_SPANISH = 2


# Excepciones

class StatusException(Exception):
	def __init__(self, message, statusCode):
		super().__init__(message)
		self.statusCode = statusCode

class BadRequestException(StatusException):
	def __init__(self, message):
		super().__init__(message, StatusCode.BAD_REQUEST)


class PCMessage:
	"""Mensaje del protocolo"""
	
	def __init__(self, command):
		self.command = command
	
	def __repr__(self):
		return 'PCMessage(command: {})'.format(self.command)
	
	def __str__(self):
		return self.__repr__()
		
class CreateMessage(PCMessage):
	def __init__(self, user, password):
		super().__init__(Command.CREATE)
		
		self.user = user
		self.password = password
		self.userSize = len(user)
		self.passwordSize = len(password)
	
	def __repr__(self):
		return 'CreateMessage(user: {}, password: {})'.format(self.user, self.password)

class RetrieveMessage(PCMessage):
	def __init__(self, user, password):
		super().__init__(Command.RETRIEVE)
		
		self.user = user
		self.password = password
		self.userSize = len(user)
		self.passwordSize = len(password)

class UpdateMessage(PCMessage):
	def __init__(self, user, password, json):
		super().__init__(Command.UPDATE)
		
		self.user = user
		self.password = password
		self.userSize = len(user)
		self.passwordSize = len(password)
		self.json = json

class DeleteMessage(PCMessage):
	def __init__(self, user, password):
		super().__init__(Command.DELETE)
		
		self.user = user
		self.password = password
		self.userSize = len(user)
		self.passwordSize = len(password)
	
	def __repr__(self):
		return 'DeleteMessage(user: {}, password: {})'.format(self.user, self.password)

class GenerateMessage(PCMessage):
	def __init__(self, scheme, size):
		self.scheme = scheme
		self.size = size


# Loading functions for serialization

def __loadCreate__(binary_message):
	userSize = struct.unpack('@I', binary_message[4:8])[0]
	passwordSize = struct.unpack('@I', binary_message[8:12])[0]
	user = binary_message[12:12+userSize].decode('utf-8')
	password = binary_message[12+userSize:12+userSize+passwordSize].decode('utf-8')
	
	return CreateMessage(user, password)

def __loadDelete__(binary_message):
	userSize = struct.unpack('@I', binary_message[4:8])[0]
	passwordSize = struct.unpack('@I', binary_message[8:12])[0]
	user = binary_message[12:12+userSize].decode('utf-8')
	password = binary_message[12+userSize:12+userSize+passwordSize].decode('utf-8')
	
	return DeleteMessage(user, password)



def load(binary_message):
	"""Deserialize a bytes-like objetc into a message"""
	
	command = struct.unpack('@i', binary_message[0:4])[0]
	
	loadFunction = None
	
	if command == Command.CREATE:
		loadFunction = __loadCreate__
	elif command == Command.DELETE:
		loadFunction = __loadDelete__
	
	if not loadFunction:
		raise BadRequestException('Not a valid command')
	
	return loadFunction(binary_message)


if __name__ == '__main__':
	message = b'\x04\x00\x00\x00\x07\x00\x00\x00\x04\x00\x00\x00usuariohola'
	
	print(load(message))
