import math
import os

# Extract file system to specified folder
# reorder_filesystems.py must be executed before that
# System is USR or SYS depending on which partition to extract
PARTITION = "USR"
FOLDER = "files"

if PARTITION == "USR":
    block_size = 0xFF0
    file_table_info = [
        (0x05FA00, 0x13FBF0, 0xDB744, 0x034E),
        (0x21FDE0, 0x25DA00, 0x3C004, 0x216E),
        (0x29B620, 0x2AA530, 0x0DAC4, 0x2793),
        (0x2B9440, 0x2E31A0, 0x27104, 0x308F),
    ]
    directory_table_name = (0x30CF00, 0x32BD10, 800, 0x9C, 0x18)
    virtual_space = "vspace_usr.bin"
elif PARTITION == "SYS":
    block_size = 0x7F8
    file_table_info = [
        (0x05FA00, 0x06C930, 0x0BB84, 0x0112),
    ]
    directory_table_name = (0x079860, 0x080FE8, 200, 0x98, 0x14)
    virtual_space = "vspace_sys.bin"
else:
    raise ValueError(f"Unknown PARTITION value '{PARTITION}'")

with open(virtual_space, "rb") as file:
    data = file.read()

directory_table = [{}, {}]
base_a, base_b = directory_table_name[0], directory_table_name[1]
for copy, o in enumerate((base_a, base_b)):
    for i in range(directory_table_name[2]):
        offset = o + i * directory_table_name[3]
        if int.from_bytes(data[offset : offset + 4], "little") == 0xFFFFFFFF:
            continue
        directory_table[copy][
            int.from_bytes(data[offset + 4 : offset + 8], "little")
        ] = (
            int.from_bytes(data[offset : offset + 4], "little"),
            data[offset + directory_table_name[4] : offset + directory_table_name[3]]
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
for base_a, base_b, table_offset, start_block in file_table_info:
    for copy, offset in enumerate((base_a, base_b)):
        table_base = offset + table_offset
        while int.from_bytes(data[offset + 4 : offset + 8], "little") != 0:
            file_name = (
                data[offset + 0x20 : offset + 0xA0]
                .replace(b"\x00", b"")
                .replace(b"\x05", b"~")
                .decode("ascii")
            )
            if not file_name.startswith("~"):
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
            offset += 0xA0

if file_table[0] != file_table[1]:
    print("WARNING! Different file table detected!")
    print("Please check alternate blocks!")
    print("First copy of the file table will be used.")

for file_blocks, file_size, directory_entry, file_name in file_table[0]:
    if file_name.startswith("~"):
        continue
    directory_path = directory_list.get(directory_entry, f"{directory_entry}")
    os.makedirs(f"{FOLDER}/{directory_path}", exist_ok=True)
    file_name = directory_path + "/" + file_name
    file_data = b"".join(
        [data[x * block_size : x * block_size + block_size] for x in file_blocks]
    )[:file_size]
    assert len(file_data) == file_size
    with open(f"{FOLDER}/{file_name}", "wb") as file:
        file.write(file_data)
