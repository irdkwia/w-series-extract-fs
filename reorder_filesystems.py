import os

# Source dump
SRC = "dump.bin"
# Mode (W51, W53, W42, W42R)
MODE = "W51"
# Remove dump interleave (0x40 bytes every 0x800)
REMOVE_INTERLEAVE = False
# Dump alternate block
# Currently, there is no way of telling which version of the block is the valid one,
# so you may need to fine tune it
# Dumps alternate blocks to folders block_sys and block_usr
DUMP_ALT = False
# Use an alternate block for file systems, dictionary of format BLOCK: ALT
# You can check alternate blocks in dumped alt folders
ALT_SYS = {}
ALT_USR = {}
ADD_ALT_AT = {}

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
if MODE == "W51":
    partitions = (0x00B00, 0x09C00)
elif MODE in ["W42", "W42R"]:
    partitions = (0x00B00, 0x0B600)
elif MODE == "W53":
    partitions = (0x01940, 0x17000)

block_sys = {}
for i in range(0x00000, partitions[0]):
    offset = i * 0x800
    if (
        data[offset + 0x7F9 : offset + 0x800] != bytes([0xFF] * 7)
        and data[offset + 0x7FB] == 0xFF
    ):
        block_id = int.from_bytes(data[offset + 0x7F9 : offset + 0x7FB], "big")
        if block_id in [0x00FF, 0xFF00, 0xFFFF]:
            continue
        block_alt = block_sys.get(block_id, [])
        element = data[offset : offset + 0x7F8]
        try:
            v = block_alt.index(element)
        except IndexError:
            v = len(block_alt)
            block_alt.append(element)
        block_sys[block_id] = block_alt
        if any(offset <= x < offset + 0x800 for x in ADD_ALT_AT):
            ALT_SYS[block_id] = v

block_usr = {}
for i in range(partitions[0], partitions[1], 2):
    offset = i * 0x800
    if (
        data[offset + 0x7F9 : offset + 0x800] != bytes([0xFF] * 7)
        and data[offset + 0x7FB] == 0xFF
    ):
        block_id = int.from_bytes(data[offset + 0x7F9 : offset + 0x7FB], "big")
        if block_id in [0x00FF, 0xFF00, 0xFFFF]:
            continue
        block_id2 = int.from_bytes(data[offset + 0xFF9 : offset + 0xFFB], "big")
        assert block_id == block_id2, "%d vs %d at %08X" % (block_id, block_id2, offset)
        block_alt = block_usr.get(block_id, [])
        element = data[offset : offset + 0x7F8] + data[offset + 0x800 : offset + 0xFF8]
        try:
            v = block_alt.index(element)
        except:
            v = len(block_alt)
            block_alt.append(element)
        if any(offset <= x < offset + 0x1000 for x in ADD_ALT_AT):
            print("ALT", block_id, v)
            ALT_USR[block_id] = v
        block_usr[block_id] = block_alt

# Create dump folders if used
if DUMP_ALT:
    os.makedirs("block_sys", exist_ok=True)
    os.makedirs("block_usr", exist_ok=True)

vspace_sys = bytearray(partitions[0] * 0x7F8)
sectors_sys = bytearray(partitions[0])
vspace_usr = bytearray((partitions[1] - partitions[0]) * 0x7F8)
sectors_usr = bytearray(partitions[1] - partitions[0])
for i, b in block_sys.items():
    sectors_sys[i] = 0xFF
    vspace_sys[i * 0x7F8 : (i + 1) * 0x7F8] = b[
        max(0, min(len(b) - 1, ALT_SYS.get(i, 0)))
    ]
    if DUMP_ALT:
        if len(b) > 1:
            for j, x in enumerate(b):
                with open("block_sys/block_%d_%d.bin" % (i, j), "wb") as file:
                    file.write(x)
for i, b in block_usr.items():
    sectors_usr[i] = 0xFF
    vspace_usr[i * 0xFF0 : (i + 1) * 0xFF0] = b[
        max(0, min(len(b) - 1, ALT_USR.get(i, 0)))
    ]
    if DUMP_ALT:
        if len(b) > 1:
            for j, x in enumerate(b):
                with open("block_usr/block_%d_%d.bin" % (i, j), "wb") as file:
                    file.write(x)
with open("vspace_sys.bin", "wb") as file:
    file.write(vspace_sys)
with open("sectors_sys.bin", "wb") as file:
    file.write(sectors_sys)
with open("vspace_usr.bin", "wb") as file:
    file.write(vspace_usr)
with open("sectors_usr.bin", "wb") as file:
    file.write(sectors_usr)
with open("unknown_data.bin", "wb") as file:
    file.write(data[partitions[1] * 0x800 :])
