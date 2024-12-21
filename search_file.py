import math
import os

# Analyse filesystems to find sets of alt block that produce specified files
# reorder_filesystems.py with dumped blocks must be executed before that
# System is USR or SYS depending on which partition to analyse
PARTITION = "USR"
MODE = "W51"

LIST_KEEP = []  # Specified files

if PARTITION == "USR":
    block_size = 0xFF0
    if MODE == "W51":
        file_table_info = [
            (0x05FA00, 0x13FBF0, 0xDB744, 0x034E, 0xA0),
            (0x21FDE0, 0x25DA00, 0x3C004, 0x216E, 0xA0),
            (0x29B620, 0x2AA530, 0x0DAC4, 0x2793, 0xA0),
            (0x2B9440, 0x2E31A0, 0x27104, 0x308F, 0xA0),
        ]
        directory_table_name = (0x30CF00, 0x32BD10, 800, 0x9C, 0x18)
    elif MODE == "W42":
        file_table_info = [
            (0x05FA00, 0x141BD0, 0xDB744, 0x0318, 0xA0),
            (0x223DA0, 0x2619C0, 0x3C004, 0x357C, 0xA0),
            (0x29F5E0, 0x2A25B0, 0x01F44, 0x3BA1, 0xA0),
            (0x2A5580, 0x2BE3F0, 0x17704, 0x3DF9, 0xA0),
        ]
        directory_table_name = (0x2D7260, 0x2F6070, 800, 0x9C, 0x18)
    elif MODE == "W42R":
        file_table_info = [
            (0x05FA00, 0x141BD0, 0xDB744, 0x0316, 0xA0),
            (0x223DA0, 0x2619C0, 0x3C004, 0x357A, 0xA0),
            (0x29F5E0, 0x2A15C0, 0x00FA4, 0x3B9F, 0xA0),
            (0x2A35A0, 0x2BC410, 0x17704, 0x3DB3, 0xA0),
        ]
        directory_table_name = (0x2D5280, 0x2F4090, 800, 0x9C, 0x18)
    elif MODE == "W53":
        file_table_info = [
            (0x0FF000, 0x1ED110, 0xE0F0C, 0x0412, 0xA4),
            (0x2DB220, 0x319E30, 0x3D804, 0x6877, 0xA4),
            (0x358A40, 0x368940, 0x0E03C, 0x6E9C, 0xA4),
            (0x378840, 0x3A3590, 0x280A4, 0x78C4, 0xA4),
        ]
        directory_table_name = (0x3CE2E0, 0x3EE0E0, 800, 0xA0, 0x1C)
    virtual_space = "vspace_usr.bin"
    virtual_block = "block_usr"
elif PARTITION == "SYS":
    block_size = 0x7F8
    if MODE in ["W51", "W42", "W42R"]:
        file_table_info = [
            (0x05FA00, 0x06C930, 0x0BB84, 0x0112, 0xA0),
        ]
        directory_table_name = (0x079860, 0x080FE8, 200, 0x98, 0x14)
    elif MODE == "W53":
        file_table_info = [
            (0x0FF000, 0x10F6F8, 0xE03C, 0x260, 0xA4),
        ]
        directory_table_name = (0x11FDF0, 0x127578, 200, 0x98, 0x14)
    virtual_space = "vspace_sys.bin"
    virtual_block = "block_sys"
else:
    raise ValueError(f"Unknown PARTITION value '{PARTITION}'")

with open(virtual_space, "rb") as file:
    data = bytearray(file.read())

block_list = os.listdir(virtual_block)

block_dict = {}

LIST_KEEP = [x.encode("ascii") for x in LIST_KEEP]

for file_table in file_table_info:
    print("===================================================")
    set_results = [[], []]
    set_count = [[], []]
    for i in range(file_table[0] // block_size, file_table[1] // block_size):
        block_entry = [x for x in block_list if x.startswith("block_%d_" % i)]

        if len(block_entry) > 0:
            block_entry.sort(key=lambda x: int(x.split(".")[0].split("_")[-1]))
            for j in range(len(block_entry)):
                with open(f"{virtual_block}/" + block_entry[j], "rb") as file:
                    block_entry[j] = file.read()
            block_dict[i] = block_entry
        else:
            block_dict[i] = [data[i * block_size : i * block_size + block_size]]

    keep = {}
    files = {}
    for i in range(
        file_table[0] // block_size, (file_table[0] + file_table[2]) // block_size
    ):
        block_entry = block_dict[i]
        best_count = 0
        for j, b in enumerate(block_entry):
            count = [x in b for x in LIST_KEEP].count(True)
            if count > best_count:
                best_count = count
                keep[i] = j
                data[i * block_size : i * block_size + block_size] = b
    ft = {}
    for l in LIST_KEEP:
        offset = file_table[0]
        table_base = file_table[0] + file_table[2]
        while int.from_bytes(data[offset + 4 : offset + 8], "little") != 0:
            file_name = (
                data[offset + file_table[4] - 0x80 : offset + file_table[4]]
                .replace(b"\x00", b"")
                .replace(b"\x05", b"~")
                .decode("ascii")
            )
            if file_name == l.decode("ascii"):
                block = int.from_bytes(data[offset + 4 : offset + 8], "little")
                if block != 0x3F9F:
                    file_size = int.from_bytes(
                        data[offset + 12 : offset + 16], "little"
                    )
                    file_blocks = [block]
                    while len(file_blocks) < max(math.ceil(file_size / block_size), 1):
                        z = table_base + 2 * (file_blocks[-1] - file_table[3])
                        pp = int.from_bytes(data[z : z + 2], "little")
                        b = z // block_size
                        t = 0
                        while len(block_dict[b]) > t and pp >= 0x8888:
                            data[b * block_size : b * block_size + block_size] = (
                                block_dict[b][t]
                            )
                            pp = int.from_bytes(data[z : z + 2], "little")
                            keep[b] = t
                            t += 1
                        if b not in keep:
                            for i, e in enumerate(block_dict[b]):
                                if (
                                    e
                                    == data[
                                        b * block_size : b * block_size + block_size
                                    ]
                                ):
                                    keep[b] = i
                        if pp >= 0x8888:
                            print("INVALID!")
                            break
                        file_blocks.append(pp)
                    ft[file_name] = file_blocks
            offset += file_table[4]
    print(keep)
    print(ft)
