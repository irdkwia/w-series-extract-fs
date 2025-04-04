import argparse

parser = argparse.ArgumentParser(description="Check .BAR resource file integrity")
parser.add_argument("input")

args = parser.parse_args()

with open(args.input, "rb") as file:
    data = file.read()

base = int.from_bytes(data[16:20], "little")
nb = int.from_bytes(data[20:24], "little")

for i in range(nb):
    off = int.from_bytes(data[base + i * 4 : base + i * 4 + 4], "little")
    if off >= len(data):
        print("INVALID! At 0x%08X" % (base + i * 4))
        break
    if data[off : off + 4] == b"MMMD":
        print("MMMD")
        continue
    length = int.from_bytes(data[off : off + 2], "little")
    if length in [0xFEFD, 0xFFFE, 0xFEFF] or length & 0xFF == 3:
        off2 = int.from_bytes(data[base + i * 4 + 4 : base + i * 4 + 8], "little")
        if off2 > len(data):
            print("INVALID! At 0x%08X" % (base + i * 4))
            break
        if length in [0xFEFD, 0xFFFE, 0xFEFF]:
            string = data[off + 2 : off2]
        else:
            string = data[off + 1 : off2]
        try:
            if length == 0xFEFD:
                print(string.decode("shift-jis"))
            elif length == 0xFEFF:
                print(string.decode("utf-16-le"))
            elif length == 0xFFFE:
                print(string.decode("utf-16-be"))
            else:
                print(string.decode("ascii"))
        except:
            print("INVALID! At 0x%08X" % off)
            break

    else:
        if length + off > len(data) or length == 0:
            print("INVALID! At 0x%08X" % off)
            break
        try:
            string = data[off + 2 : off + length - 1].decode("ascii")
            print(i, string)
        except:
            print("INVALID! At 0x%08X" % off)
            break
