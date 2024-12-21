import math
import os

# Extract file system to specified folder
# reorder_filesystems.py must be executed before that
# System is USR or SYS depending on which partition to extract
PARTITION = "USR"
MODE = "W51"
FOLDER = "files"
# Extract deleted files (marked with a \x05 byte at beginning of file name)
EXTRACT_DELETED = False
# Extract partial files (missing blocks)
EXTRACT_PARTIAL = False

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
    sectors_list = "sectors_usr.bin"
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
    sectors_list = "sectors_sys.bin"
else:
    raise ValueError(f"Unknown PARTITION value '{PARTITION}'")

with open(virtual_space, "rb") as file:
    data = file.read()
with open(sectors_list, "rb") as file:
    sectors = list(file.read())

directory_table = [{}, {}]
base_a, base_b = directory_table_name[0], directory_table_name[1]
for copy, o in enumerate((base_a, base_b)):
    for i in range(directory_table_name[2]):
        offset = o + i * directory_table_name[3]
        directory_index = int.from_bytes(data[offset : offset + 4], "little")
        if directory_index in [0xFFFFFFFF, 0]:
            continue

        directory_table[copy][
            int.from_bytes(data[offset + 4 : offset + 8], "little")
        ] = (
            directory_index,
            data[
                offset + directory_table_name[4] : offset + directory_table_name[3]
            ]
            .replace(b"\x00", b"")
            .replace(b"\x05", b"~")
            .decode("ascii"),
        )
if directory_table[0] != directory_table[1]:
    print("WARNING! Different folder table detected!")
    print("Please check alternate blocks!")
    print("First copy of the file table will be used.")
directory_list = {}
for k, v in directory_table[0].items():
    prefix, directory_path = v
    while prefix in directory_table[0]:
        st = f"{directory_table[0][prefix][1]}/{directory_path}"
        prefix = directory_table[0][prefix][0]
    directory_path = f"{prefix}/{directory_path}"
    os.makedirs(f"{FOLDER}/{directory_path}", exist_ok=True)
    directory_list[k] = directory_path
file_table = [[], []]
for base_a, base_b, table_offset, start_block, entry_size in file_table_info:
    for copy, offset in enumerate((base_a, base_b)):
        table_base = offset + table_offset
        while int.from_bytes(data[offset + 4 : offset + 8], "little") != 0:
            file_name = (
                data[offset + entry_size - 0x80 : offset + entry_size]
                .replace(b"\x00", b"")
                .replace(b"\x05", b"~")
                .decode("ascii")
            )
            if not file_name.startswith("~") or EXTRACT_DELETED:
                block = int.from_bytes(data[offset + 4 : offset + 8], "little")
                if block != 0x3F9F:
                    file_size = int.from_bytes(
                        data[offset + 12 : offset + 16], "little"
                    )
                    file_blocks = [block]
                    while file_blocks[-1] != 0xFFFF and len(file_blocks) < max(
                        math.ceil(file_size / block_size), 1
                    ):
                        z = table_base + 2 * (file_blocks[-1] - start_block)

                        file_blocks.append(int.from_bytes(data[z : z + 2], "little"))
                    file_table[copy].append(
                        (
                            file_blocks,
                            file_size,
                            int.from_bytes(data[offset + 10 : offset + 12], "little"),
                            file_name,
                        )
                    )
            offset += entry_size

if file_table[0] != file_table[1]:
    print("WARNING! Different file table detected!")
    print("Please check alternate blocks!")
    print("First copy of the file table will be used.")

for file_blocks, file_size, directory_entry, file_name in file_table[0]:
    if file_name.startswith("~") and not EXTRACT_DELETED:
        continue
    directory_path = directory_list.get(directory_entry, f"{directory_entry}")
    os.makedirs(f"{FOLDER}/{directory_path}", exist_ok=True)
    file_name = directory_path + "/" + file_name
    print("Extracted:", file_name)
    missing = [x for x in file_blocks if x >= len(sectors) or sectors[x] == 0]
    if missing:
        print("WARNING! Damaged file! Missing blocks:", missing)
        if not EXTRACT_PARTIAL:
            continue
    file_data = b"".join(
        [data[x * block_size : x * block_size + block_size] for x in file_blocks]
    )[:file_size]
    if len(file_data) != file_size:
        print("WARNING! Truncated size:", len(file_data), "vs", file_size)
        if not EXTRACT_PARTIAL:
            continue
    # assert len(file_data) == file_size
    with open(f"{FOLDER}/{file_name}", "wb") as file:
        file.write(file_data)
