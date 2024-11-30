# Import modules included in standard libraries
import multiprocessing
import base64
import signal
import os
import hashlib
import pickle
import time

from functools import wraps
from itertools import islice

import Crypto.Cipher.AES


new_aes = Crypto.Cipher.AES.new
aes256_cbc_decrypt = lambda key, iv, ciphertext: new_aes(key, Crypto.Cipher.AES.MODE_CBC, iv).decrypt(ciphertext)

correct_b58_privkey = b'KyjedtqPNK5kd24A'
incorrect_b58_privkey = b'K\xbdf\xf9\x9d4\xb1\x93P\xa9\xe2\x02\xb7\xc9[\xe4\xbc'

### FOR BENCHMARK ###
def runtime_timer(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()  # Start the high-precision timer
        result = func(*args, **kwargs)
        end_time = time.perf_counter()  # End the timer
        runtime = end_time - start_time
        print(f"Function '{func.__name__}' executed in {1000*runtime:.10f} ms.")
        return result
    return wrapper

@runtime_timer
def is_base58_set_matching(private_key):
    base58_chars = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    return all(char in base58_chars for char in private_key)

@runtime_timer
def is_base58_comparison_ord(private_key):
    for c in private_key:
        if c > ord("z") or c < ord("1") or ord("9") < c < ord("A") or ord("Z") < c < ord("a") or chr(c) in "IOl":
            return False
    else:
        return True

@runtime_timer
def find_b58_string_islice(private_key, start_index=1):
    for c in islice(private_key, start_index, None):
        # If it's outside of the base58 set [1-9A-HJ-NP-Za-km-z], break
        if c > ord("z") or c < ord("1") or ord("9") < c < ord("A") or ord("Z") < c < ord("a") or chr(c) in "IOl":
            return False
    return True

@runtime_timer
def find_b58_string_slice(private_key, start_index=1):
    for c in private_key[start_index:]:
        # If it's outside of the base58 set [1-9A-HJ-NP-Za-km-z], break
        if c > ord("z") or c < ord("1") or ord("9") < c < ord("A") or ord("Z") < c < ord("a") or chr(c) in "IOl":
            return False
    return True

### END BENCHMARK ###

def load_multibit_key_file(key_filename):
    with open(key_filename) as f:
        # Multibit privkey files contain base64 text split into multiple lines;
        # we need the first 48 bytes after decoding, which translates to 64 before.
        data = "".join(f.read().split())  # join multiple lines into one

    if len(data) < 64: raise EOFError("Expected at least 64 bytes of text in the MultiBit private key file")
    data = base64.b64decode(data)
    assert data.startswith(b"Salted__"), "WalletBitcoinCore.load_from_filename: file starts with base64 'Salted__'"
    if len(data) < 48:  raise EOFError("Expected at least 48 bytes of decoded data in the MultiBit private key file")
    encrypted_block = data[16:48]  # the first two 16-byte AES blocks
    encrypted_wallet = data[16:]
    salt = data[8:16]
    breakpoint()
    print(f"{encrypted_block}")

    return encrypted_block, encrypted_wallet, salt


def check_password(list_password, encrypted_block, salt): # Multibit
    # Copy a few globals into local for a small speed boost
    l_md5                 = hashlib.md5
    l_aes256_cbc_decrypt  = aes256_cbc_decrypt

    # Convert Unicode strings (lazily) to UTF-16 bytestrings, truncating each code unit to 8 bits
    passwords = map(lambda p: p.encode("utf_16_le", "ignore")[::2], list_password)

    for password in passwords:
        salted = password + salt
        key1   = l_md5(salted).digest()
        key2   = l_md5(key1 + salted).digest()
        iv     = l_md5(key2 + salted).digest()
        b58_privkey = l_aes256_cbc_decrypt(key1 + key2, iv, encrypted_block[:16])

        # (all this may be fragile, e.g. what if comments or whitespace precede what's expected in future versions?)
        breakpoint()
        # if type(b58_privkey) == str:
        #     b58_privkey = b58_privkey.encode()
        # Heuristic: private key starts with LK5
        # Does it look like a base58 private key (MultiBit, MultiDoge, or oldest-format Android key backup)?
        if b58_privkey[0] in b"LK5":  # private keys always start with L, K, or 5
            for c in b58_privkey[1:]:
                # If it's outside of the base58 set [1-9A-HJ-NP-Za-km-z], break
                if c > ord("z") or c < ord("1") or ord("9") < c < ord("A") or ord("Z") < c < ord("a") or chr(c) in "IOl":
                    break
            # If the loop above doesn't break, it's base58-looking so far
            else:
                # If another AES block is available, decrypt and check it as well to avoid false positives
                if len(encrypted_block) >= 32:
                    b58_privkey = l_aes256_cbc_decrypt(key1 + key2, encrypted_block[:16], encrypted_block[16:32])
                    for c in b58_privkey:
                        if c > ord("z") or c < ord("1") or ord("9") < c < ord("A") or ord("Z") < c < ord("a") or chr(c) in "IOl":
                            print(f"False positive: {password}")
                            break  # not base58
                    # If the loop above doesn't break, it's base58; we've found it
                    else:
                        return password
                else:
                    # when no second block is available, there's a 1 in 300 billion false positive rate here
                    return password
    return False


def main():
    list_password = [""]
    encrypted_block, encrypted_wallet, salt = load_multibit_key_file(os.path.join("keys", "test_lama.key"))
    password, count = check_password(list_password, encrypted_block, salt)
    print(password, count)

    is_base58_set_matching(incorrect_b58_privkey)
    is_base58_comparison_ord(incorrect_b58_privkey)

    find_b58_string_islice(correct_b58_privkey)
    find_b58_string_slice(correct_b58_privkey)


if __name__ == "__main__":
    main()