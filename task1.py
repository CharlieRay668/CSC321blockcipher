from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


# Encode the cp-logo.bmp file using AES in ECB mode
def encode_ecb(plaintext_file, key=None):
    if key is None:
        key = get_random_bytes(8)
    cipher = AES.new(key, AES.MODE_ECB)
    with open(plaintext_file, 'rb') as f:
        data = f.read()
        header = data[:54]
        data = data[54:]
        ct = cipher.encrypt(pad(data, AES.block_size))

    with open(plaintext_file.replace('.bmp', '-ecb-enc.bmp'), 'wb') as f:
        f.write(header)
        f.write(ct)


def encode_data_cbc(data, iv=None, key=None):
    if iv is None:
        iv = get_random_bytes(16)
    if key is None:
        key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    ct = b''
    for i in range(0, len(data), AES.block_size):
        block = data[i:i+AES.block_size]
        block = pad(block, AES.block_size)
        block = bytes([block[j] ^ prev[j] for j in range(AES.block_size)])
        block = cipher.encrypt(block)
        ct += block
        prev = block

    return ct

# Encode the cp-logo.bmp file using AES in CBC mode
# Without using the built in CBC mode
def encode_cbc(plaintext_file):
    with open(plaintext_file, 'rb') as f:
        data = f.read()
        header = data[:54]
        data = data[54:]
        ct = encode_data_cbc(data)


    with open(plaintext_file.replace('.bmp', '-cbc-enc.bmp'), 'wb') as f:
        f.write(header)
        f.write(ct)



encode_cbc('cp-logo.bmp')
encode_ecb('cp-logo.bmp')