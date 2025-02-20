import sys
import json
import hashlib
import libs.ccl_leveldb
from Crypto.Hash import keccak
from Crypto.Cipher import AES
from Crypto.Util import Counter


def hash_password(password, salt, iterations=20000, key_length=512):
    """
    Hashes a password using PBKDF2-HMAC-SHA512.
    """
    hash = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, iterations, dklen=key_length)
    return "0x" + hash.hex()


def derive_key(password, type, params):
    """
    Derives a key using either scrypt or PBKDF2.
    """
    if type == "scrypt":
        return hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(params["salt"]), n=params["n"], r=params["r"], p=params["p"], dklen=params["dklen"])
    elif type == "pbkdf2":
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(params["salt"]), params["c"], dklen=params["dklen"])
    else:
        raise Exception('Key derivation function "{}" is unknown'.format(type))


def aes_key_context(algo, key):
    """
    Creates an AES key context based on the encryption algorithm.
    """
    if algo == "aes-128-ctr":
        key_length = 16
        mode = AES.MODE_CTR
    elif algo == "aes-128-cbc":
        key_length = 16
        mode = AES.MODE_CBC
    elif algo == "aes-256-ctr":
        key_length = 32
        mode = AES.MODE_CTR
    else:
        raise Exception('Encryption algorithm "{}" is unknown'.format(algo))
    return {"encryption": key[:key_length], "mac": key[-key_length:], "mode": mode}


def create_mac(data, key):
    """
    Creates a MAC (Message Authentication Code) using Keccak-256.
    """
    mac = keccak.new(digest_bits=256)
    mac.update(key)
    mac.update(data)
    return mac.digest().hex()


def decrypt_aes(mode, data, key, iv):
    """
    Decrypts data using AES encryption.
    """
    if mode == AES.MODE_CTR:
        cipher = AES.new(key, mode, counter=Counter.new(128, initial_value=int.from_bytes(iv, "big")))
    elif mode == AES.MODE_CBC:
        cipher = AES.new(key, mode, iv=iv)
    else:
        raise Exception('Decryption mode "{}" is unknown'.format(mode))
    return cipher.decrypt(data)


def decrypt_wallet(crypto, password, salt=None):
    """
    Decrypts a wallet using the provided password and salt.
    """
    if salt is not None:
        password = hash_password(password, salt)
    data = bytes.fromhex(crypto["ciphertext"])
    context = aes_key_context(crypto["cipher"], derive_key(password, crypto["kdf"], crypto["kdfparams"]))
    if not create_mac(data, context["mac"]) == crypto["mac"]:
        raise Exception("Invalid password")
    return decrypt_aes(context["mode"], data, context["encryption"], bytes.fromhex(crypto["cipherparams"]["iv"]))


def extract_wallets(folder):
    """
    Extracts wallet data from a LevelDB database.
    """
    leveldb_records = libs.ccl_leveldb.RawLevelDb(folder)
    salts_list = []
    crypto_list = []
    for record in leveldb_records.iterate_records_raw():
        if b"trust:pbkdf2" in record.key:
            try:
                current_salt = json.loads(json.loads(record.value))["salt"]
                if current_salt is not None:
                    salts_list.append(current_salt[2:])
            except:
                pass
        elif b"ciphertext" in record.value and b"kdfparams" in record.value:
            try:
                current_crypto = json.loads(record.value)["crypto"]
                if current_crypto is not None:
                    crypto_list.append(current_crypto)
            except:
                pass
    return {"salts": salts_list, "cryptos": crypto_list}


def trst_decode(wallets: dict, passwords: list):
    """
    Decrypts wallets using a list of passwords.
    """
    try:
        salts_list = wallets["salts"]
        crypto_list = wallets["cryptos"]
        seeds_list = []
        for i in range(len(salts_list)):
            for j in range(len(crypto_list)):
                if crypto_list[j] is None:
                    continue
                for password in passwords:
                    try:
                        current_seed = decrypt_wallet(crypto_list[j], password, bytes.fromhex(salts_list[i]))
                        seeds_list.append(current_seed.decode())
                        crypto_list[j] = None
                    except:
                        pass
        auth_list = list(set(seeds_list))
        if auth_list:
            return {"status": True, "txt": "Successful", "pwd": password, "data": auth_list}
        else:
            return {"status": False, "txt": "Bad password", "pwd": None, "data": []}
    except:
        return {"status": False, "txt": "Something went wrong", "pwd": None, "data": []}
