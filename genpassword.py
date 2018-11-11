import secrets
import string
import sqlite3

diceware_wordlists = {
'DW_english': 5,
'DW_english_beale': 5,
'DW_espanol': 5,
'DW_espanol_alternative': 5,
'eff_large': 5,
'eff_short': 4,
'eff_short_alternative': 4
}

def secureChoice(n, alphabet):
	l = []
	
	for i in range(n):
		l.append( secrets.choice(alphabet) )
	
	return l
	
	
def randomAlpha(n):
	return ''.join( secureChoice(n, string.ascii_letters) )

def randomAlphaDigits(n):
	return ''.join( secureChoice(n, string.ascii_letters + string.digits) )
	
def randomDigits(n):
	return ''.join( secureChoice(n, string.digits) )
	
def dieRoll():
	return secrets.randbelow(6) + 1

def diceware(n, wordlist='DW_espanol_alternative'):
	if wordlist not in diceware_wordlists:
		raise ValueError('{} not in avaiable diceware wordlists'.format(wordlist))
	
	l = []
	
	with sqlite3.connect('diceware.db') as db:
		cur = db.cursor()
		for _ in range(n):
			word_id = ''.join( [str(dieRoll()) for i in range( diceware_wordlists[wordlist] )] )
			
			l.append( cur.execute('SELECT palabra FROM {} WHERE id=?'.format(wordlist), (word_id,)).fetchone()[0] )
	
	return ' '.join(l)
	
	
if __name__ == '__main__':
	fl = [randomAlpha, randomAlphaDigits, randomDigits, diceware]
	
	for f in fl:
		print( f(10) )
