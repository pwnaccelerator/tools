
import sys

BLOCKLEN=16

def blocks(data):
    return [data[i:i+BLOCKLEN] for i in range(0, len(data), BLOCKLEN)]

def reorder(cipher, order):
    cipher_blocks = blocks(cipher)
    block_ranges = order.split(",")
    print block_ranges
    ret_blocks = []
    for r in block_ranges:
        i,j = r.split("-", 1)
        i = int(i)
        j = int(j)
        ret_blocks.append("".join(cipher_blocks[i:j+1]))
    return "".join(ret_blocks)

with open(sys.argv[1], mode='rb') as file:
#    print "reading file "+sys.argv[1]
    cipher = file.read()

blks = blocks(cipher)
sys.stderr.write("total blocks: "+str(len(blks))+"\n")
shuffled = reorder(cipher, sys.argv[2])
print shuffled
