from cryptography.fernet import Fernet
import os.path

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
APP_STATIC = os.path.join(APP_ROOT, 'static')

if not os.path.exists(os.path.join(APP_STATIC,'key.enc')):
	key = Fernet.generate_key()

	fp = open(os.path.join(APP_STATIC,'key.enc'),'w')
	
	fp.write(key)

	print "key.enc created!  Make sure to backup this file just in case something happens!"
	print "If this key is deleted, the password entries in your database will become unreadable"
else:
	print "key.enc already exists!  If you overwrite the key, you will make previous database passwords unreadable!!"
