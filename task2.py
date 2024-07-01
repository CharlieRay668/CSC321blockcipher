from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from task1 import encode_data_cbc

key = get_random_bytes(16)
iv = get_random_bytes(16)

def submit(user_str):
    user_str = user_str.replace(';', '%3B').replace('=', '%3D')
    user_str = "userid=456; userdata=" + user_str + ";session-id=31337"
    user_str = user_str.encode('utf-8')
    user_str = pad(user_str, AES.block_size)
    user_str = encode_data_cbc(user_str, iv, key)
    return user_str

def verify(enc_user_str):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    user_str = cipher.decrypt(enc_user_str)
    try:
        user_str = unpad(user_str, AES.block_size)
        if b';admin=true;' in user_str:
            return True
        else:
            return False
    except (ValueError, UnicodeDecodeError):
        return False
    
def bypass(cypher):
    block_size = AES.block_size
    target = b";admin=true;"

    start_block = 2
    start_byte = start_block * block_size

    mutated_cypher = bytearray(cypher)

    for i in range(len(target)):
        # XOR with the previous block's corresponding byte to inject the target
        mutated_cypher[start_byte - block_size + i] ^= target[i] ^ ord('A')

    return bytes(mutated_cypher)

cypher = submit('A'*105)
verified = verify(cypher)
print(verified)
bypassed = bypass(cypher)
verified = verify(bypassed)
print(verified)
# print(verified)
