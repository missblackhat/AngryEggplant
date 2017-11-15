#!/usr/bin/python

from Crypto.Cipher import AES
import base64, random, string, sys, os

def randKey(bytes):
    return str().join(random.choice(string.ascii_letters + string.digits + "{}!@#$^&()*&[]|,./?") for x in range(bytes))

def randVar():
    return str().join(random.choice(string.ascii_letters) for x in range(3)) + "_" + ''.join(random.choice("0123456789") for x in range(3))

BLOCK_SIZE = 32
PADDING = '{'
imports = list()
output = list()

pad = lambda s: str(s) + (BLOCK_SIZE - len(str(s)) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

key = randKey(32)
iv = randKey(16)
input = open(sys.argv[1]).readlines()
outputName = '_' + os.path.basename(sys.argv[0])

if len(sys.argv) == 3:
    outputName = sys.argv[2]

f = open(outputName, 'w')

if os.path.splitext(sys.argv[1])[1] == ".py":
    for line in input:
        if not line.startswith("#"):
            if "import" in line:
                imports.append(line.strip())
            else:
                output.append(line)

    cipherEnc = AES.new(key)
    encrypted = EncodeAES(cipherEnc, str().join(output))
    b64var = randVar()
    aesvar = randVar()
    imports.append("from base64 import b64decode as %s" %(b64var))
    imports.append("from Crypto.Cipher import AES as %s" %(aesvar))
    random.shuffle(imports)
    f.write(";".join(imports) + "\n")
    f.write("exec(%s(\"%s\"))" % (b64var,base64.b64encode("exec(%s.new(\"%s\").decrypt(%s(\"%s\")).rstrip('{'))\n" %(aesvar,key,b64var,encrypted))))
    f.close()
    print os.path.abspath(outputName)

sys.exit(0)
