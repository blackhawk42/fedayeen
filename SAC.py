import socket
import threading
import sqlite3
import os
import hashlib
import pc

DEFAULT_PORT = 4444
DEFAULT_BUFFER_SIZE = 4096

DEFAULT_RNG = os.urandom

SQLITE_TRUE = 1
SQLITE_FALSE = 0


def readallsocket(sock, sock_buffer_size=DEFAULT_BUFFER_SIZE):
	with io.BytesIO() as buf:
		while True:
			chunk = sock.recv(sock_buffer_size)
			if not chunk:
				break
				
			buf.write(chunk)
		
		return buf.getvalue()

class MasterKey:
	def __init__(self, message, salt):
		self.message = message
		self.salt = salt
		
		hashlib.pbkdf2_hmac('sha256', self.message.password, self.salt, 100000, 32)
	
	def getSalt(self):
		return self.salt
	
	def getKey(self):
		return self.key
	
	def getMasterKey(self):
		return hashlib.sha256(self.key).digest()

class MasterKeyGenerator(MasterKey):
	def __init__(self, rng, CreateMessage):
		self.rng = rng
		super().__init__(rng, message, self.rng(16))
		

class MasterKeyValidator(MasterKey):
	def __init__(self, message, hashedMasterKey, salt):
		self.hashedPassword = hashedPassword
		super().__init__(message, salt)
	
	def validate(self):
		return self.getMasterKey() == self.hashedMasterKey

class DBManager:
	def __init__(self, connection):
		self.connection = connection
	
	def getHashedMasterPassword(message):
		with self.connection.cursor() as cur:
			HashedMasterPassword, salt = cur.execute('SELECT hashed_master_password, salt FROM users WHERE user=?', message.user).fetchone()
		
		return HashedMasterPassword, salt
	
	def addUser(createMessage, keyGenerator):
		with self.connection.cursor() as cur:
			cur.execute('INSERT INTO users(user, salt, master_key, passwords, blocked) VALUES (?, ?, ?, ?, ?)',
			            createMessage.user,
			            keyGenerator.getSalt(),
			            keyGenerator.getMasterKey(),
			            b'',
			            SQLITE_FALSE)
		
		return pc.StatusCode.OK
	
	def deleteUser(deleteMessage):
		with self.connection.cursor() as cur:
			cur.execute('DELETE FROM users WHERE user=?', deleteMessage.user)
		
		return pc.StatusCode.OK

class UserCreator:
	def __init__(self, dbManager):
		self.dbManager = dbManager
	
	def createUser(self, createMessage):
		keyGenerator = MasterKeyGenerator(DEFAULT_RNG, createMessage)
		
		statusCode = dbManager.addUser(createMessage, keyGenerator)
		
		return statusCode
		

class UserRemover:
	def __init__(self, dbManager):
		self.dbManager = dbManager
	
	def removeUser(self, deleteMessage):
		hashedMasterKey, salt = dbManager.getMasterPassword(deleteMessage)
		
		keyValidator = MasterKeyValidator(deleteMessage, hashedMasterKey, salt)
		
		if keyValidator.validate():
			return dbManager.deleteUser(deleteMessage)
		else:
			return pc.StatusCode.NOT_FOUND


class MessageManager(threading.Thread):
	def __init__(self,
	             socket,
	             userCreator,
	             userRemover):
		
		self.socket = socket
		self.userCreator = userCreator
		self.userRemover = userRemover
		
	def run(self):
		binary_message = readallsocket(socket)
		message = pc.load(binary_message)
		
		status = None
		if message.command == pc.Command.CREATE:
			status = self.userCreator.createUser(message)
			
		elif message.command == pc.Command.DELETE:
			status = self.userRemover(message)
		
		self.socket.sendall( struct.pack('@i', status) )
		self.scoket.shutdown(socket.SHUTDOWN_RW)
		self.socket.close()
