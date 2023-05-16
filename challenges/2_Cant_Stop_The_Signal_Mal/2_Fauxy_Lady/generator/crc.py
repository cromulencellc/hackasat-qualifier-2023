# generate crc-16/xmodem
def gen(data, poly = 0x11021):
    input = 0x0
    mask=0x0
    for b in data:
        input = input << 8
        input = input ^ b
        mask = mask << 8
        mask = mask | 0xFF

    input = input << (poly.bit_length()-1)
    mask = mask << (poly.bit_length()-1)
    poly  = poly << (input.bit_length() - poly.bit_length())

    while (input & mask):
        input = input ^ poly
        poly = poly >> (poly.bit_length() - input.bit_length())

    crc = input
    return crc

# check crc-16/xmodem
def check(data, crc, poly = 0x11021):   
    input = 0x0
    mask=0x0
    for b in data:
        input = input << 8
        input = input ^ b
        mask = mask << 8
        mask = mask | 0xFF

    input = input << (poly.bit_length()-1)
    input = input ^ crc
    mask = mask << (poly.bit_length()-1)
    poly  = poly << (input.bit_length() - poly.bit_length())

    while (input & mask):
        input = input ^ poly
        poly = poly >> (poly.bit_length() - input.bit_length())
    crc = input
    return crc