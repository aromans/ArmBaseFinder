#!/usr/bin/env python3

# Algorithm implemented from https://onlinelibrary.wiley.com/doi/epdf/10.1155/2021/4664882

from collections import defaultdict

def printBytes(_bin, offset):
    print(format(_bin[offset+0] & 0xff, '02X'))
    print(format(_bin[offset+1] & 0xff, '02X'))
    print(format(_bin[offset+2] & 0xff, '02X'))
    print(format(_bin[offset+3] & 0xff, '02X'))

def getBytes(_bin, offset, thumb=False):
    b1 = format(_bin[offset+0] & 0xff, '02X')
    b2 = format(_bin[offset+1] & 0xff, '02X')
    b3 = format(_bin[offset+2] & 0xff, '02X')
    b4 = format(_bin[offset+3] & 0xff, '02X')
    if thumb:
        return [b1, b2]
    return [b1, b2, b3, b4]

def is_armv7_func_start(_bin, offset):
    prologues = {
        b'\x2d\xe9',
        b'\x4d\xe2',
        b'\x2d\xe9'
    }

    instruction = _bin[offset:offset + 2]

    if (instruction == b''):
        return True
    return False

    #print(instruction)

    #for prologue in prologues:
    #    if instruction.startswith(prologue):
    #        return True
    #return False

def createMatrix(rows, cols, fill_value=0):
    return [[fill_value for _ in range(cols)] for _ in range(rows)]

def countOccurences(matrix):
    counts = defaultdict(int)
    for row in matrix:
        for value in row:
            counts[value] += 1
    return counts

def sortOccurencesDesc(counts):
    sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return sorted_counts

_bin = None
with open('./xb6.bin', 'rb') as f:
    _bin = f.read()

size = len(_bin)
offset = 0

memory = set()

# Collect LDR addresses 
#while (offset < size):
#    offset_2 = format(_bin[offset + 2] & 0xff, '02X')
#    offset_3 = format(_bin[offset + 3] & 0xff, '02X')
#    if (offset_2 == "9F" and offset_3 == "E5"):
#        _bytes = getBytes(_bin, offset)
#        pc = offset + 8
#        immed_12 = format(_bytes[1][0] + _bytes[0])
#        address = hex((int(hex(pc), 16) & 0xfffffffc) + int(immed_12, 16))
#        memory.add(''.join(reversed(getBytes(_bin, int(address, 16)))))
#    offset += 4

offset = 0

# Collected Thumb LDR addresses
while (offset < size):
    opcode = format(_bin[offset + 1] & 0xff, '02X')
    opcode = format(int(opcode, 16) & 0b11111000, '08b')
    if (opcode == '01001000'):
        _bytes = getBytes(_bin, offset, True)
        pc = offset + 4
        immed_8 = format(_bytes[0])
        address = hex((int(hex(pc), 16) & 0xfffffffc) + (int(immed_8, 16) * 4))
        rd = ''.join(reversed(getBytes(_bin, int(address, 16))))
        if (f"{rd[:2]}{rd[2:4]}" == "1367"):
            offset += 2
            continue    
        memory.add(rd)
        #memory.add(''.join(reversed(getBytes(_bin, int(address, 16)))))
    offset += 2

print("Reading Offsets . . . ")

# Get binary function offsets from Ghidra plugin
func_content = None
with open('./func_offsets.txt', 'r') as f:
    func_content = f.read()

offsets = func_content.split(',')[:-1]
ldr = memory
file_size = size
M = createMatrix(len(ldr), len(offsets), -1)
Max = 0xffffffff - file_size

print("Enumerating differences . . . ")

for j, a in enumerate(ldr):
    for i, o in enumerate(offsets):
        diff = int(a, 16) - int(o, 16)
        if (0 < diff and diff < Max):
            M[j][i] = diff

print("Calculating results . . . ")

occurences = countOccurences(M)
sorted_occ = dict(sortOccurencesDesc(occurences))

with open('./results.txt', 'w') as f:
    for val, count in sorted_occ.items():
        if (val == -1 or count == 1):
            continue
        f.write(f'{hex(val)}: {count}\n')

print("DONE!")
