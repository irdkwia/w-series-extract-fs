import math
import os

# Analyse filesystems to find sets of alt block that produce a consistent file table
# reorder_filesystems.py with dumped blocks must be executed before that
# System is USR or SYS depending on which partition to analyse
PARTITION = "USR"

if PARTITION == "USR":
    block_size = 0xFF0
    file_table_info = [
        (0x05FA00, 0x13FBF0, 0xDB744, 0x034E),
        (0x21FDE0, 0x25DA00, 0x3C004, 0x216E),
        (0x29B620, 0x2AA530, 0x0DAC4, 0x2793),
        (0x2B9440, 0x2E31A0, 0x27104, 0x308F),
    ]
    virtual_space = "vspace_usr.bin"
    virtual_block = "block_usr"
elif PARTITION == "SYS":
    block_size = 0x7F8
    file_table_info = [
        (0x05FA00, 0x06C930, 0x0BB84, 0x0112),
    ]
    virtual_space = "vspace_sys.bin"
    virtual_block = "block_sys"
else:
    raise ValueError(f"Unknown PARTITION value '{PARTITION}'")

with open(virtual_space, "rb") as file:
    data = bytearray(file.read())

block_list = os.listdir(virtual_block)

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
            test = 0 if i < ((file_table[0] + file_table[2]) // block_size) else 1
            set_results[test].append((i, block_entry))
            set_count[test].append(0)
    left = {}
    right = {}
    for test in range(2):
        ending = False
        while not ending:
            for i, count in enumerate(set_count[test]):
                block_id, blocks = set_results[test][i]
                data[block_id * block_size : block_id * block_size + block_size] = (
                    blocks[count]
                )
            result = []
            if test == 0:
                offset = file_table[0]
                while int.from_bytes(data[offset + 4 : offset + 8], "little") != 0:
                    file_name = (
                        data[offset + 0x20 : offset + 0xA0]
                        .replace(b"\x00", b"")
                        .replace(b"\x05", b"~")
                        .decode("ascii")
                    )
                    block_id = int.from_bytes(data[offset + 4 : offset + 8], "little")
                    if not file_name.startswith("~") and block_id != 0x3F9F:
                        file_size = int.from_bytes(
                            data[offset + 12 : offset + 16], "little"
                        )
                        result.append(
                            (block_id, max(math.ceil(file_size / block_size) - 1, 0))
                        )
                    offset += 0xA0
            else:
                ref = [
                    False
                    for _ in range((file_table[1] - file_table[0] - file_table[2]) // 2)
                ]
                for index, offset in enumerate(
                    range(file_table[0] + file_table[2], file_table[1], 2)
                ):
                    previous = (
                        int.from_bytes(data[offset : offset + 2], "little")
                        - file_table[3]
                    )
                    if 0 <= previous < len(ref):
                        ref[previous] = True
                for index, offset in enumerate(
                    range(file_table[0] + file_table[2], file_table[1], 2)
                ):
                    if ref[index]:
                        continue
                    previous = int.from_bytes(data[offset : offset + 2], "little")
                    if previous != 0x8888:
                        count = 0
                        while previous != 0xFFFF and previous >= file_table[3]:
                            z = (
                                file_table[0]
                                + file_table[2]
                                + 2 * (previous - file_table[3])
                            )
                            previous = int.from_bytes(data[z : z + 2], "little")
                            count += 1
                        result.append((index + file_table[3], count))
            result = tuple(sorted(result))
            if test == 0:
                xl = left.get(result, [])
            else:
                xl = right.get(result, [])
            xl.append(
                {
                    set_results[test][i][0]: set_count[test][i]
                    for i in range(len(set_count[test]))
                }
            )
            if test == 0:
                left[result] = xl
            else:
                right[result] = xl

            if len(set_count[test]) == 0:
                ending = True
            else:
                add = True
                block_id = 0
                while add:
                    set_count[test][block_id] += 1
                    if set_count[test][block_id] >= len(set_results[test][block_id][1]):
                        set_count[test][block_id] = 0
                        block_id += 1
                        if block_id >= len(set_count[test]):
                            add = False
                            ending = True
                    else:
                        add = False
    for k1, v1 in left.items():
        for k2, v2 in right.items():
            if k1 == k2[: len(k1)]:
                for y in v1:
                    for x in v2:
                        d = dict(y)
                        d.update(x)
                        print(d)
