def andBlocks(block1: bytearray, block2: bytearray):
    new_block = block1.copy()
    for i in range(0, len(block1)):
        new_block[i] = block1[i] & block2[i]
    return new_block 

def xorBlocks(block1: bytearray, block2: bytearray):
    new_block = block1.copy()
    for i in range(0, len(block1)):
        new_block[i] = block1[i] ^ block2[i]
    return new_block 

def ShiftLeft(block: bytearray):
    first_bit = 0
    new_block = block.copy()
    for i in range(len(new_block) - 1, -1, -1):
        new_block[i]  = (new_block[i] << 1) | first_bit
        first_bit = (new_block[i] & 0x100) >> 8
        new_block[i] = new_block[i] & 0xFF
    return new_block

def MSB(Block: bytearray, bits: int):
    block_size = len(Block) * 8
    shiftAmount = block_size - bits
    num = ((2**bits) - 1) << shiftAmount
    andArray = bytearray(num.to_bytes(len(Block),byteorder="big"))
    return andBlocks(Block, andArray)

def LSB(Block: bytearray, bits: int):
    num = (2**bits) - 1
    andArray = bytearray(num.to_bytes(len(Block),byteorder="big"))
    return andBlocks(Block, andArray)

def TruncateLeft(Block: bytearray):
    new_block = Block.copy()
    value = new_block.pop()
    while (value == 0):
        value = new_block.pop()
    new_block.append(value)
    return new_block

def TruncateRight(Block: bytearray):
    new_block = Block.copy()
    i = 0
    value = new_block[i]
    while (value == 0):
        i += 1
        value = new_block[i]
    new_block = new_block[i:]
    return new_block

def printByteArray(byteArray: bytearray):
    for o in byteArray:
        print("{0:02x}".format(o),end='')
    print()

def printByteArrayGrouped(byteArray: bytearray):
    i = 0
    for o in byteArray:
        i += 1
        print("{0:02x}".format(o),end='')
        if (i % 4 == 0):
            print(" ",end='')
    print()

def increment_counter(counter: bytearray, counter_len: int = 16):
    new_counter = counter.copy()
    i = len(new_counter) - 1
    stop = i - counter_len
    overflow = False
    value = new_counter[i] + 1
    if (value > 255):
        overflow = True
        value = 0
    new_counter[i] = value
    while (overflow and i >= stop):
        i -= 1
        if (i == stop):
            break
        overflow = False
        value = new_counter[i] + 1
        if (value > 255):
            overflow = True
            value = 0
        new_counter[i] = value
    return new_counter

def isEqual(Tag1: bytearray, Tag2: bytearray):
    if (len(Tag1) != len(Tag2)):
        return False 
    for i in range(0, len(Tag1)):
        if (Tag1[i] != Tag2[i]):
            return False
    return True