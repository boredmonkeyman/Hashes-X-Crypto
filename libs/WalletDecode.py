#!/usr/bin/python3
# -*- coding: utf-8 -*-

__all__ = ['extensionWalletDecrypt']

# Import modules
import json
import base64
import hashlib
from ast import literal_eval
from Crypto.Cipher import AES


class extensionWalletDecrypt:
    """
    A class for decrypting wallet data from browser extensions.
    """

    def __keyfrom_password(self, password, salt, iterations=10000):
        """
        Derives a key from a password using PBKDF2-HMAC-SHA256.
        """
        saltBuffer = base64.b64decode(salt)
        passwordBuffer = password.encode('utf-8')
        key = hashlib.pbkdf2_hmac('sha256', passwordBuffer, saltBuffer, iterations, dklen=32)
        return key

    def __decryptWith_key(self, key, payload):
        """
        Decrypts data using AES-GCM.
        """
        encrypted_data = base64.b64decode(payload["data"])
        vector = base64.b64decode(payload["iv"])
        data = encrypted_data[:-16]
        cipher = AES.new(key, AES.MODE_GCM, nonce=vector)
        decrypted_data = cipher.decrypt(data)
        return decrypted_data

    def toDoinput(self, d):
        """
        Normalizes input data (converts string to dict if necessary).
        """
        try:
            if type(d) != dict:
                data = literal_eval(d)
                return {"s": True, "m": None, "d": data}
            else:
                return {"s": True, "m": None, "d": d}
        except Exception as ex:
            return {"s": False, "m": ex, "d": d}

    def extractMnemonic(self, result):
        """
        Extracts a mnemonic phrase from the decrypted data.
        """
        try:
            if type(result) == int:
                return {"status": False, "data": result}

            elif len(result) == 0:
                return {"status": False, "data": result}

            elif type(result) == list:  # Metamask
                if type(result[0]) != list:
                    if "data" in result[0]:
                        if "mnemonic" in result[0]["data"]:
                            mnemonic = result[0]["data"]["mnemonic"]
                            if type(mnemonic) is list:
                                mnemonic = bytes(mnemonic).decode("utf-8")
                            return {"status": True, "data": mnemonic}
                        else:
                            return {"status": False, "data": result}
                    else:
                        return {"status": False, "data": result}
                elif type(result[0]) == list:
                    mnemonic = result[0][1]["mnemonic"]
                    return {"status": True, "data": mnemonic}
                else:
                    return {"status": False, "data": result}

            elif type(result) == str:  # Ronin
                raw = json.loads(result)
                if type(raw) != bool:
                    mnemonic = raw["mnemonic"]
                    return {"status": True, "data": mnemonic}
                else:
                    return {"status": False, "data": result}

            elif type(result) == dict:  # Binance + Tron
                if "version" in result:
                    if result["accounts"]:
                        mnemonic = result["accounts"][0]['mnemonic']
                        return {"status": True, "data": mnemonic}
                    else:
                        return {"status": False, "data": result}
                else:
                    for address in result:
                        if "mnemonic" in result[address]:
                            mnemonic = result[address]["mnemonic"]
                            return {"status": True, "data": mnemonic}
                        else:
                            # Save private key and address to file (optional)
                            privKey = result[address]["privateKey"]
                            address = result[address]["address"]
                            saveLine = f"{address}:{privKey}"
                            # with open("tronSave.txt", "a", encoding="utf-8") as f: f.write(saveLine + "\n")
                            return {"status": False, "data": result}

            else:
                return {"status": False, "data": result}

        except Exception as ex:
            return {"status": False, "data": result, "ex": ex}

    def decryptSingle(self, password, data, iterations):
        """
        Decrypts wallet data using a single password.
        """
        try:
            res = self.toDoinput(data)
            if res['s']:
                payload = res['d']
                salt = payload['salt']
                key = self.__keyfrom_password(password, salt, iterations)
                decrypted_string = self.__decryptWith_key(key, payload).decode('utf-8')
                return {"s": True, "m": None, "r": json.loads(decrypted_string)}
            else:
                return {"s": False, "m": res['m'], "r": None}

        except UnicodeDecodeError:
            return {"s": False, "m": "bad password", "r": None}

        except Exception as ex:
            return {"s": False, "m": ex, "r": None}

    def decryptList(self, passwords, data, iterations):
        """
        Decrypts wallet data using a list of passwords.
        """
        res = self.toDoinput(data)
        if res['s']:
            payload = res['d']
            if type(passwords) == list:
                for password in passwords:
                    try:
                        salt = payload['salt']
                        key = self.__keyfrom_password(password, salt, iterations)
                        decrypted_string = self.__decryptWith_key(key, payload).decode('utf-8')
                        return {"s": True, "m": None, "r": json.loads(decrypted_string)}
                    except UnicodeDecodeError:
                        continue  # Bad password, try the next one
                    except Exception as ex:
                        return {"s": False, "m": ex, "r": res['d']}
                return {"s": False, "m": f"Hash not cracked, tried [{len(passwords)}] passwords.", "r": None}
            else:
                return {"s": False, "m": "It's not a passwords list", "r": type(passwords)}
        else:
            return {"s": False, "m": "Error converting input: " + res['m'], "r": res['d']}
