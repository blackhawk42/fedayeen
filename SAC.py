import socket
import threading
import sqlite3
import os
import hashlib
import pc
import genpassword
import io
import struct

from cryptography.fernet import Fernet
import base64

DEFAULT_PORT = 4444
DEFAULT_BUFFER_SIZE = 4096

DEFAULT_RNG = os.urandom

SQLITE_TRUE = 1
SQLITE_FALSE = 0


def readallsocket(sock, sock_buffer_size=DEFAULT_BUFFER_SIZE):
	'''Read all information in a socket'''
	with io.BytesIO() as buf:
		while True:
			chunk = sock.recv(sock_buffer_size)
			if not chunk:
				break
				
			buf.write(chunk)
		
		return buf.getvalue()

class MasterKey:
	'''Reperesents a master key, already salted and PBKDF2\'d'''
	def __init__(self, message, salt):
		self.message = message
		self.salt = salt
		
		self.key = hashlib.pbkdf2_hmac('sha256', self.message.password.encode('utf-8'), self.salt, 100000, 32)
	
	def getSalt(self):
		return self.salt
	
	def getKey(self):
		'''Get key for encryption'''
		return self.key
	
	def getKeyBase64(self):
		'''Get key, in base64, url-safe'''
		return base64.urlsafe_b64encode(self.key)
	
	def getMasterKey(self):
		'''The master key differs from the key. The key is used in encryption,
		the master key is what is actually saved in the database'''
		return hashlib.sha256(self.key).digest()

class MasterKeyGenerator(MasterKey):
	'''Generate a new master key with a new random salt'''
	def __init__(self, rng, message):
		self.rng = rng
		super().__init__(message, self.rng(16))
		

class MasterKeyValidator(MasterKey):
	'''Validate a hashed master key'''
	def __init__(self, message, hashedMasterKey, salt):
		self.hashedMasterKey = hashedMasterKey
		super().__init__(message, salt)
	
	def validate(self):
		return self.getMasterKey() == self.hashedMasterKey

class DBManager:
	"""Makes the actual database manipulation"""
	def __init__(self, database_file):
		self.connection = sqlite3.connect(database_file)
	
	def getMasterPassword(self, message):
		cur = self.connection.cursor()
		HashedMasterPassword, salt = cur.execute('SELECT master_key, salt FROM users WHERE user=?', (message.user,)).fetchone()
		cur.close()
		
		return HashedMasterPassword, salt
	
	def addUser(self, createMessage, keyGenerator):
		f = Fernet(keyGenerator.getKeyBase64())
		initJson = f.encrypt(b'')
		
		cur = self.connection.cursor()
		cur.execute('INSERT INTO users(user, salt, master_key, passwords, blocked) VALUES (?, ?, ?, ?, ?)',
		            (createMessage.user,
		            keyGenerator.getSalt(),
		            keyGenerator.getMasterKey(),
		            initJson,
		            SQLITE_FALSE))
		            
		self.connection.commit()
		cur.close()
		
		return pc.StatusCode.OK
	
	def deleteUser(self, deleteMessage):
		cur = self.connection.cursor()
		cur.execute('DELETE FROM users WHERE user=?', (deleteMessage.user,))
		self.connection.commit()
		cur.close()
		
		return pc.StatusCode.OK
	
	def updatePasswords(self, updateMessage, encrypted_json):
		cur = self.connection.cursor()
		cur.execute('UPDATE users SET passwords=? WHERE user=?', (encrypted_json, updateMessage.user))
		self.connection.commit()
		cur.close()
		
		return pc.StatusCode.OK
	
	def retrievePasswords(self, retrieveMessage):
		cur = self.connection.cursor()
		encrypted_json = cur.execute('SELECT passwords FROM users WHERE user=?', (retrieveMessage.user,)).fetchone()[0]
		cur.close()
		
		return encrypted_json, pc.StatusCode.OK

class UserCreator:
	def __init__(self, dbManager):
		self.dbManager = dbManager
	
	def createUser(self, createMessage):
		keyGenerator = MasterKeyGenerator(DEFAULT_RNG, createMessage)
		
		statusCode = self.dbManager.addUser(createMessage, keyGenerator)
		
		return statusCode
		

class UserDeleter:
	def __init__(self, dbManager):
		self.dbManager = dbManager
	
	def deleteUser(self, deleteMessage):
		hashedMasterKey, salt = self.dbManager.getMasterPassword(deleteMessage)
		
		keyValidator = MasterKeyValidator(deleteMessage, hashedMasterKey, salt)
		
		if keyValidator.validate():
			return self.dbManager.deleteUser(deleteMessage)
		else:
			return pc.StatusCode.NOT_FOUND


class PasswordsUpdater:
	def __init__(self, dbManager):
		self.dbManager = dbManager
		
	def updatePasswords(self, updateMessage):
		hashedMasterKey, salt = self.dbManager.getMasterPassword(updateMessage)
		
		keyValidator = MasterKeyValidator(updateMessage, hashedMasterKey, salt)
		
		if keyValidator.validate():
			
			f = Fernet(keyValidator.getKeyBase64())
			
			return self.dbManager.updatePasswords(updateMessage, f.encrypt(updateMessage.json))
			
		else:
			return pc.StatusCode.NOT_FOUND

class PasswordsRetriever:
	def __init__(self, dbManager):
		self.dbManager = dbManager
		
	def retrievePasswords(self, retrieveMessage):
		hashedMasterKey, salt = self.dbManager.getMasterPassword(retrieveMessage)
	
		keyValidator = MasterKeyValidator(retrieveMessage, hashedMasterKey, salt)
		
		if keyValidator.validate():
			encrypted_json, status = self.dbManager.retrievePasswords(retrieveMessage)
			
			if status == pc.StatusCode.OK:
				f = Fernet(keyValidator.getKeyBase64())
				return f.decrypt(encrypted_json), status
			else:
				return b'', status
		
		else:
			return b'', pc.StatusCode.NOT_FOUND

class PasswordGenerator:
	def __init__(self):
		pass
	
	def generatePassword(generateMessage):
		if generateMessage.scheme == pc.PasswordScheme.DICEWARE_SPANISH:
			return genpassword.diceware(generateMessage.size), pc.StatusCode.OK
		
		elif generateMessage.scheme == pc.PasswordScheme.LOWER_ALPHA:
			return genpassword.randomAlpha(generatePassword.size), pc.StatusCode.OK
		
		else:
			return '', pc.StatusCode.NOT_IMPLEMENTED

class MessageManager(threading.Thread):
	def __init__(self,
	             conn,
	             database):
		
		super().__init__()
		
		self.conn = conn
		self.database = database
		
	def run(self):
		self.dbManager = DBManager(self.database)
		
		self.userCreator = UserCreator(self.dbManager)
		self.userDeleter = UserDeleter(self.dbManager)
		self.passwordsUpdater = PasswordsUpdater(self.dbManager)
		self.passwordsRetriever = PasswordsRetriever(self.dbManager)
		self.passwordGenerator = PasswordGenerator()
		
		
		binary_message = readallsocket(conn)
		message = pc.load(binary_message)
		
		finalStatus = None # Status code plus any information, correctly packaged
		
		if message.command == pc.Command.CREATE:
			status = struct.pack('!i', self.userCreator.createUser(message) )
			
		elif message.command == pc.Command.DELETE:
			status = struct.pack('!i', self.userDeleter.deleteUser(message) )
		
		elif message.command == pc.Command.UPDATE:
			status = struct.pack('!i', self.passwordsUpdater.updatePasswords(message))
			
		elif message.command == pc.Command.RETRIEVE:
			json, statusCode = self.passwordsRetriever.retrievePasswords(message)
			status = struct.pack('!i', statusCode) + json
		
		elif message.command == pc.Command.GENERATE:
			password, status = passwordGenerator.generatePassword(message)
			status = struct.pack('!i', status) + password.encode('utf-8')
		
		if not status:
			status = struct.pack('!i', pc.StatusCode.BAD_REQUEST)
		
		self.conn.sendall( status )
		self.conn.shutdown(socket.SHUT_RDWR)
		self.conn.close()

if __name__ == '__main__':
	print('|--------------------- | SAC | ----------------------|')
	
	PORT = DEFAULT_PORT
	
	print('Port: {}'.format(PORT))
	
	DATABASE = 'main.db'
	
	print('Database file: {}'.format(DATABASE))
	
	dbConnection = sqlite3.connect('main.db')
	cursor = dbConnection.cursor()
	cursor.execute('CREATE TABLE IF NOT EXISTS users(user TEXT PRIMARY KEY, salt BLOB, master_key BLOB, passwords BLOB, blocked INTEGER)')
	cursor.close()
	dbConnection.commit()
	dbConnection.close()
	
	print('Connection successful')
	
	
	print('Creating experts...', end='')
	
	passwordGenerator = PasswordGenerator()
	
	print(' Done')
	
	
	
	print('Creating socket...', end='')
	
	sock = socket.socket()
	sock.bind( ('', PORT) )
	sock.listen()
	
	print('Done and listening. Entering main loop')
	
	while True:
		conn, addr = sock.accept()
		
		print('Connection accepted from {}'.format(addr))
		
		manager = MessageManager(conn, DATABASE)
		manager.start()
		
		print('Manager started')
