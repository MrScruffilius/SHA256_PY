# METHOD:
# https://qvault.io/cryptography/how-sha-2-works-step-by-step-sha-256/
#
# https://www.w3schools.com/python/python_datatypes.asp
# https://www.rapidtables.com/convert/number/hex-to-decimal.html
# https://docs.python.org/3/library/stdtypes.html#int.to_bytes
#
# TODO 1: long & numbers to hex
hash = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
def sha256(text):
    text_in_bytes = bytearray(text, 'utf-8')
    size_of_input = len(text_in_bytes) * 8
    text_in_bytes.append(128)
    while (((len(text_in_bytes) + 8) % 64) != 0):
        text_in_bytes.append(0)
    tempInt = size_of_input.to_bytes(8, 'big')
    for i in tempInt:
        text_in_bytes.append(i)
    list_of_32bit_int = []
    c = 0
    for i in range(int(len(text_in_bytes) / 4)):
        list_of_32bit_int.append(
            (text_in_bytes[c] << 24) ^ (text_in_bytes[c + 1] << 16) ^ (text_in_bytes[c + 2] << 8) ^ (
                text_in_bytes[c + 3]))
        c += 4
    ret = hash.copy()
    c = 0
    while (c < len(list_of_32bit_int)):
        retList = chunkloop(list_of_32bit_int[c:c + 16])
        ret[0] = (ret[0] + retList[0]) % 0x100000000
        ret[1] = (ret[1] + retList[1]) % 0x100000000
        ret[2] = (ret[2] + retList[2]) % 0x100000000
        ret[3] = (ret[3] + retList[3]) % 0x100000000
        ret[4] = (ret[4] + retList[4]) % 0x100000000
        ret[5] = (ret[5] + retList[5]) % 0x100000000
        ret[6] = (ret[6] + retList[6]) % 0x100000000
        ret[7] = (ret[7] + retList[7]) % 0x100000000
        c += 16
    retStr = ""
    retStr += str(hex(ret[0])[2:])
    retStr += str(hex(ret[1])[2:])
    retStr += str(hex(ret[2])[2:])
    retStr += str(hex(ret[3])[2:])
    retStr += str(hex(ret[4])[2:])
    retStr += str(hex(ret[5])[2:])
    retStr += str(hex(ret[6])[2:])
    retStr += str(hex(ret[7])[2:])
    return (str(retStr).upper())
def chunkloop(chunklist):
    counter = 0
    while (counter < 48):
        chunklist.append(0)
        counter += 1
    counter = 16
    while (counter < 64):
        c15 = (chunklist[counter - 15] % 0x100000000)
        c2 = (chunklist[counter - 2] % 0x100000000)
        s0 = (((c15>> 7) & 33554431) ^ ((chunklist[counter - 15] << 25) & 4261412864)) ^ (((c15 >> 18) & 16383) ^ ((chunklist[counter - 15] << 14) & 4294950912)) ^ ((c15 >> 3) & 536870911)
        s1 = (((c2 >> 17) & 32767) ^ ((chunklist[counter - 2] << 15) & 4294934528)) ^ (((c2 >> 19) & 8191) ^ ((chunklist[counter - 2] << 13) & 4294959104)) ^ ((c2 >> 10) & 4194303)
        chunklist[counter] = (chunklist[counter - 16] + s0 + chunklist[counter - 7] + s1) % 0x100000000
        counter += 1
    a = hash[0]
    b = hash[1]
    c = hash[2]
    d = hash[3]
    e = hash[4]
    f = hash[5]
    g = hash[6]
    h = hash[7]
    counter = 0
    while (counter < 64):
        et=(e%0x100000000)
        at =(a % 0x100000000)
        S1 = (((et >> 6) & 67108863) ^ ((e << 26) & 4227858432)) ^ (((et >> 11) & 2097151) ^ ((e << 21) & 4292870144)) ^ (((et >> 25) & 127) ^ ((e << 7) & 4294967168))
        ch = (e & f) ^ ((~ e) & g)
        temp1 = (h + S1 + ch + k[counter] + chunklist[counter]) % 4294967296
        S0 = (((at >> 2) & 1073741823) ^ ((a << 30) & 3221225472)) ^ (((at >> 13) & 524287) ^ ((a << 19) & 4294443008)) ^ (((at >> 22) & 1023) ^ ((a << 10) & 4294966272))
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) % 4294967296
        h = g
        g = f
        f = e
        e = (d + temp1) % 4294967296
        d = c
        c = b
        b = a
        a = (temp1 + temp2) % 4294967296
        counter += 1
    retList = [a, b, c, d, e, f, g, h]
    return (retList)
if __name__ == '__main__':
    userInput = input("Please input the text:\n")
    print(sha256(str(userInput)))