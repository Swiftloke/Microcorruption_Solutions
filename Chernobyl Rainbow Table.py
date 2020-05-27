import codecs
import random
from numpy import uint16 as u16
from string import ascii_lowercase as alphabetL, ascii_uppercase as alphabetC
alphabet = alphabetL + alphabetC

import warnings #Suppress RuntimeErrors about overflows
warnings.filterwarnings("ignore")

def bitrep16(number):
	"""16-bit representation, with leading 0s."""
    binstr = str(bin(number))[2:] #Remove 0b
    bitcount = len(binstr)
    leading0s = 16 - bitcount
    return ('0' * leading0s) + binstr

def mchash(username):
    """Microcorruption's hash function, originally in MSP430 assembly,
    decompiled to Python! :D"""
    hashres = u16(0)
    for abyte in username:
        #Ugly, but it does the job of char->u16
        byte = u16(int(codecs.encode(abyte.encode(), "hex"), 16))
        byte += hashres
        hashres = byte
        hashres += hashres
        hashres += hashres
        hashres += hashres
        hashres += hashres
        hashres += hashres
        hashres -= byte
    return hashres

box0res = []
box1res = []
box2res = []
box3res = []
box4res = []
box5res = []
box6res = []
box7res = []

while len(box0res) < 5 or len(box1res) < 5 or len(box2res) < 5 or \
len(box3res) < 5 or len(box4res) < 5 or len(box5res) < 5 or \
len(box6res) < 5 or len(box7res) < 5:
    username = random.choice(alphabet)
    print(username)
    res = mchash(username)
    #3 LSBs
    boxres = int('0b' + bitrep16(res)[-3:], 2)
    if boxres == 0 and len(box0res) < 5 and username not in box0res:
        box0res.append(username)
    elif boxres == 1 and len(box1res) < 5 and username not in box1res:
        box1res.append(username)
    elif boxres == 2 and len(box2res) < 5 and username not in box2res:
        box2res.append(username)
    elif boxres == 3 and len(box3res) < 5 and username not in box3res:
        box3res.append(username)
    elif boxres == 4 and len(box4res) < 5 and username not in box4res:
        box4res.append(username)
    elif boxres == 5 and len(box5res) < 5 and username not in box5res:
        box5res.append(username)
    elif boxres == 6 and len(box6res) < 5 and username not in box6res:
        box6res.append(username)
    elif boxres == 7 and len(box7res) < 5 and username not in box7res:
        box7res.append(username)
print("Box 0 matches:", box0res)
print("Box 1 matches:", box1res)
print("Box 2 matches:", box2res)
print("Box 3 matches:", box3res)
print("Box 4 matches:", box4res)
print("Box 5 matches:", box5res)
print("Box 6 matches:", box6res)
print("Box 7 matches:", box7res)
print("")
print("Box 0 matches:")
for res in box0res:
    print("new " + res)
print("")
print("Box 2 matches:")
for res in box2res:
    print("new " + res)
