def bitrep16(number):
    binstr = str(bin(number))[2:] #Remove 0b
    bitcount = len(binstr)
    leading0s = 16 - bitcount
    return ('0' * leading0s) + binstr
if __name__ == "__main__":
    print(bitrep16(int(input("Enter a number: "), 16)))
