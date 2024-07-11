from Crypto.Cipher import AES
import sys

key = b'super secret key'
iv = b'CMPT 403 Test IV'
f = open(sys.argv[1], "rb")
ciphertext = f.read()
f.close()

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
#last byte tells us how much padding there is
padnum = plaintext[-1]
if padnum <= 0 or padnum >= 17:
    print("0")
    sys.exit(0)
passed_check = True
for i in range(padnum-1):
    if plaintext[-i-2] != 0:
        passed_check = False
        break
#last byte check is not necessary
if passed_check == True:
    print("1")
else:
    print("0")