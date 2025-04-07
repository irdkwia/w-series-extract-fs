import argparse
import json
import os

parser = argparse.ArgumentParser(description="W Series Extractor")
parser.add_argument("input")
parser.add_argument("output")
parser.add_argument("config")
parser.add_argument(
    "-u",
    "--try-undelete",
    help="Try to undelete files",
    action=argparse.BooleanOptionalAction,
)
parser.add_argument(
    "-p",
    "--partition",
    help="Also write partition bin file.",
    action=argparse.BooleanOptionalAction,
)
parser.add_argument(
    "-w",
    "--warnings",
    help="Show warnings.",
    action=argparse.BooleanOptionalAction,
)
parser.add_argument(
    "-e",
    "--end",
    help="Use last blocks instead of first.",
    action=argparse.BooleanOptionalAction,
)
parser.add_argument(
    "-l",
    "--lower",
    help="Lower case file names.",
    action=argparse.BooleanOptionalAction,
)

args = parser.parse_args()

with open(args.input, "rb") as file:
    data = file.read()

with open(args.config, encoding="utf-8") as file:
    config = json.load(file)


def get_blocks(blocks, size, start=None, end=None):
    if start is None:
        start = 0
    if end is None:
        end = max(blocks) + 1 if len(blocks) else 0
    part = bytearray()
    for c in range(start, end):
        if c in blocks:
            part += blocks[c][-1 if args.end else 0]
        else:
            part += bytes(size)
    return part


for partition_name, partition_data in config.items():
    final_blocks = {}
    for offset in range(
        partition_data["start"],
        partition_data["end"],
        partition_data["block_size"] * partition_data["block_unit"],
    ):
        block_id = None
        current = bytearray()
        for x in range(partition_data["block_unit"]):
            pos = data[
                offset
                + x * partition_data["block_size"] : offset
                + (x + 1) * partition_data["block_size"]
            ]
            if (
                pos[
                    partition_data["block_size"]
                    - 7 : offset
                    + partition_data["block_size"]
                ]
                != bytes([0xFF] * 7)
                and pos[partition_data["block_size"] - 5] == 0xFF
            ):
                block_id_current = int.from_bytes(
                    pos[
                        partition_data["block_size"]
                        - 7 : partition_data["block_size"]
                        - 5
                    ],
                    "big",
                )
                if block_id_current in [0x00FF, 0xFF00, 0xFFFF]:
                    block_id = None
                    break
                assert (
                    block_id is None or block_id == block_id_current
                ), "Different blocks %08X: %04X, %04X" % (
                    offset,
                    block_id,
                    block_id_current,
                )
                block_id = block_id_current
                current += pos[: partition_data["block_size"] - 8]
            else:
                block_id = None
                break
        if block_id is not None:
            # print("%08X\t%04X"%(offset, block_id))
            final_blocks[block_id] = final_blocks.get(block_id, [])
            final_blocks[block_id].append(current)
    block_size = (partition_data["block_size"] - 8) * partition_data["block_unit"]
    if args.partition:
        os.makedirs(args.output, exist_ok=True)
        with open(os.path.join(args.output, partition_name + ".bin"), "wb") as file:
            file.write(get_blocks(final_blocks, block_size))
    if partition_data["directory_table"] is not None:
        dir_data = get_blocks(
            final_blocks,
            block_size,
            partition_data["directory_table"]["main"],
            partition_data["directory_table"]["backup"],
        )
        directory_table = {}
        for i in range(partition_data["directory_table"]["entry_nb"]):
            ent_data = dir_data[
                i
                * partition_data["directory_table"]["entry_size"] : (i + 1)
                * partition_data["directory_table"]["entry_size"]
            ]
            directory_parent = int.from_bytes(ent_data[:4], "little")
            directory_index = int.from_bytes(ent_data[4:8], "little")
            if directory_parent == 0xFFFFFFFF or directory_index == 0:
                continue

            name_at = (
                partition_data["directory_table"]["name_at"]
                if "name_at" in partition_data["directory_table"]
                else -0x84
            )
            dir_name = (
                ent_data[name_at:-0x4]
                .replace(b"\x00", b"")
                .replace(b"\x05", b"~")
                .decode("ascii")
            )
            if args.lower:
                dir_name = dir_name.lower()
            directory_table[directory_index] = (
                directory_parent,
                dir_name,
            )

        for f in partition_data["file_tables"]:
            file_data = get_blocks(final_blocks, block_size, f["main"], f["backup"])
            for i in range(f["entry_nb"]):
                ent_data = file_data[
                    i * f["entry_size"] + 4 : (i + 1) * f["entry_size"] + 4
                ]
                layout = f.get("layout", "DEFAULT")
                if layout == "W32":
                    file_name = (
                        (
                            ent_data[0x18:-0x4]
                            .replace(b"\x00", b"")
                            .replace(b"\x05", b"~")
                            .decode("ascii")
                        ).strip()
                        + "."
                        + (
                            ent_data[-0x4:].replace(b"\x00", b"").decode("ascii")
                        ).strip()
                    )
                else:
                    file_name = (
                        ent_data[-0x84:-0x4]
                        .replace(b"\x00", b"")
                        .replace(b"\x05", b"~")
                        .decode("ascii")
                    )
                if (
                    not file_name.startswith("~") or args.try_undelete
                ) and file_name not in ("", "."):
                    if args.lower:
                        file_name = file_name.lower()
                    block = int.from_bytes(ent_data[:4], "little")
                    file_dir = int.from_bytes(ent_data[6:8], "little")
                    if layout == "W32":
                        file_size = int.from_bytes(ent_data[16:20], "little")
                    else:
                        file_size = int.from_bytes(ent_data[8:12], "little")
                    current = bytearray()
                    invalid = False
                    while len(current) < file_size:
                        if block not in final_blocks:
                            invalid = True
                            print(
                                f"{file_name}: Invalid block {block}, couldn't extract"
                            )
                            break
                        if len(final_blocks[block]) > 1 and args.warnings:
                            print(f"{file_name}: Warning duplicate blocks {block}")
                        current += final_blocks[block][-1 if args.end else 0]
                        z = (
                            (block - f["system"]) * 2
                            + f["entry_size"] * f["entry_nb"]
                            + 4
                        )
                        block = int.from_bytes(file_data[z : z + 2], "little")
                    if not invalid:
                        ospath = ""
                        while file_dir in directory_table:
                            ospath = os.path.join(directory_table[file_dir][1], ospath)
                            file_dir = directory_table[file_dir][0]
                        ospath = os.path.join(
                            args.output, partition_name, str(file_dir), ospath
                        )
                        os.makedirs(ospath, exist_ok=True)
                        with open(os.path.join(ospath, file_name), "wb") as file:
                            file.write(current[:file_size])
