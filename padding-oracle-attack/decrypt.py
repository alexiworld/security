from Crypto.Cipher import AES
import sys
import random
import subprocess
import tempfile

def padding_oracle(ciphertext):
    return padding_oracle_external(ciphertext)

def padding_oracle_internal(ciphertext):
    key = b'super secret key'
    iv = b'CMPT 403 Test IV'

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    #last byte tells us how much padding there is
    padnum = plaintext[-1]
    if padnum <= 0 or padnum >= 17:
        return 0
    passed_check = True
    for i in range(padnum-1):
        if plaintext[-i-2] != 0:
            passed_check = False
            break
    #last byte check is not necessary
    if passed_check == True:
        return 1
    else:
        return 0


def padding_oracle_external(ciphertext):
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(ciphertext)
        temp_file.flush()
        temp_file_name = temp_file.name

    result = subprocess.check_output(['python3', 'oracle.py', temp_file_name])
    return int(result.strip())

def decrypt_byte(yn, y_17th_last_byte):
    # initialize always_yes
    always_yes = True
    
    r1_15=list(random.getrandbits(8) for _ in range(15))
    for i in range (256):
        # generate random block r with 15 random bytes followed by initial i = 0
        r = bytearray(r1_15 + [i])

        # call the oracle and ask if r|y_n is valid 
        r_yn = r + yn
        padding = padding_oracle(r_yn)

        if padding:
            break

    for k in range (15):
        # replace r_n where 1 <= n >= 15 and ask oracle if padding is valid
        r[k] = random.getrandbits(8)
        r_yn = r + yn
        padding2 = padding_oracle(r_yn)
        if not padding2:
            always_yes = False
            break

    if always_yes:
        D_yn_16 = i ^ 1
    else:
        D_yn_16 = i ^ (17 - k)
    
    # Convert y_17th_last_byte to an integer
    y_17th_last_byte = int(y_17th_last_byte)

    xn_16 = D_yn_16 ^ y_17th_last_byte

    # Debug print statement for the last byte
    # print(f"Decrypted last byte: {xn_16}")

    # return D_yn_16
    return (D_yn_16, xn_16)

def decrypt_block(ciphertext, block_index):
    block_size = 16
    start = block_index * block_size
    end = start + block_size
    yN = ciphertext[start:end]
    yN_minus_1 = ciphertext[start - block_size:start]

    decrypted_block = bytearray(1)
    plaintext_block = bytearray(1)
    
    (D_yn_16, xn_16) = decrypt_byte(yN, yN_minus_1[-1])
    y_17th_last_byte = int(yN_minus_1[-1])

    decrypted_block[-1] = D_yn_16
    plaintext_block[-1] = xn_16

    for k in range (block_size - 1, 0, -1):
        r = bytearray(random.getrandbits(8) for _ in range(0, k-1))
        r.append(0)
        
        index = len(r) - 1
        #print(f"index={index}")
        
        r_decrypted = bytearray()
        r_decrypted = r_decrypted + decrypted_block 
        r_decrypted[-1] = D_yn_16 ^ (17 - k)
        
        r = r + r_decrypted
        #print(f"len r: {len(r)}")

        for i in range(0, 255):
            padding = padding_oracle(r + yN)
            if padding:   
                break
            
            r[index] = r[index] + 1
        
        D_yn_k = i
        xn_k = D_yn_k ^ yN_minus_1[k-1]
        
        decrypted_block.insert(0, D_yn_k)
        plaintext_block.insert(0, xn_k)
    
    print(f"Decrypted block {block_index}: {decrypted_block}")
    print(f"Plaintext block {block_index}: {plaintext_block}")

    return plaintext_block

def decrypt(ciphertext):
    block_size = 16
    num_blocks = len(ciphertext) // block_size

    plaintext = bytearray()

    for i in range(num_blocks-1, 0, -1):
        plaintext_block = decrypt_block(ciphertext, i)
        plaintext = plaintext_block + plaintext
    
    return plaintext

if __name__ == "__main__":
    with open('ciphertext', 'rb') as f:
        ciphertext = f.read()

    # print(ciphertext)
    # print(ciphertext.hex())
    # print(bytes.fromhex(ciphertext.hex()))
    # print(bytearray.fromhex(ciphertext.hex()))
    # oracle = padding_oracle(ciphertext)
    # print(oracle)
    # sys.exit(0)

    plaintext = decrypt(ciphertext)
    
    with open('plaintext.txt', 'wb') as f:
        f.write(plaintext)