import os

# Source dump
SRC = "dump.bin"
# Remove dump interleave (0x40 bytes every 0x800)
REMOVE_INTERLEAVE = True
# Dump alternate block
# Currently, there is no way of telling which version of the block is the valid one,
# so you may need to fine tune it
# Dumps alternate blocks to folders block_sys and block_usr
DUMP_ALT = True
# Use an alternate block for file systems, dictionnary of format BLOCK: ALT
# You can check alternate blocks in dumped alt folders
ALT_SYS = {}
ALT_USR = {}

with open(SRC, "rb") as file:
    base_data = file.read()

if REMOVE_INTERLEAVE:
    data = []
    for i in range(0, len(base_data), 0x840):
        data.append(base_data[i : i + 0x800])
    data = b"".join(data)
else:
    data = base_data

# SYSTEM PARTITION  0x0000: This is where some system files are located
# USER PARTITION    0x0B00: This is where the user file system is located
# UNKNOWN DATA      0x9C00: Unknown purpose

block_sys = {}
for i in range(0x0000, 0x0B00):
    offset = i * 0x800
    if data[offset + 0x7F8 : offset + 0x800] != bytes([0xFF] * 8) and data[
        offset + 0x7FB : offset + 0x800
    ] == bytes([0xFF] * 5):
        block_id = int.from_bytes(data[offset + 0x7F9 : offset + 0x7FB], "big")
        block_alt = block_sys.get(block_id, [])
        element = data[offset : offset + 0x7F8]
        if element not in block_alt:
            block_alt.append(element)
        block_sys[block_id] = block_alt

block_usr = {}
for i in range(0x0B00, 0x9C00, 2):
    offset = i * 0x800
    if data[offset + 0x7F8 : offset + 0x800] != bytes([0xFF] * 8) and data[
        offset + 0x7FB : offset + 0x800
    ] == bytes([0xFF] * 5):
        block_id = int.from_bytes(data[offset + 0x7F9 : offset + 0x7FB], "big")
        block_id2 = int.from_bytes(data[offset + 0xFF9 : offset + 0xFFB], "big")
        assert block_id == block_id2
        block_alt = block_usr.get(block_id, [])
        element = data[offset : offset + 0x7F8] + data[offset + 0x800 : offset + 0xFF8]
        if element not in block_alt:
            block_alt.append(element)
        block_usr[block_id] = block_alt

# Create dump folders if used
if DUMP_ALT:
    os.makedirs("block_sys", exist_ok=True)
    os.makedirs("block_usr", exist_ok=True)

vspace_sys = bytearray(0x0B00 * 0x7F8)
vspace_usr = bytearray(0x9100 * 0x7F8)
for i, b in block_sys.items():
    vspace_sys[i * 0x7F8 : (i + 1) * 0x7F8] = b[ALT_SYS.get(i, 0)]
    if DUMP_ALT:
        if len(b) > 1:
            for j, x in enumerate(b):
                with open("block_sys/block_%d_%d.bin" % (i, j), "wb") as file:
                    file.write(x)
for i, b in block_usr.items():
    vspace_usr[i * 0xFF0 : (i + 1) * 0xFF0] = b[ALT_USR.get(i, 0)]
    if DUMP_ALT:
        if len(b) > 1:
            for j, x in enumerate(b):
                with open("block_usr/block_%d_%d.bin" % (i, j), "wb") as file:
                    file.write(x)
with open("vspace_sys.bin", "wb") as file:
    file.write(vspace_sys)
with open("vspace_usr.bin", "wb") as file:
    file.write(vspace_usr)
with open("unknown_data.bin", "wb") as file:
    file.write(data[0x9C00 * 0x800 :])
