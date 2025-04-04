import argparse

parser = argparse.ArgumentParser(description="Remove Inverleave")
parser.add_argument("input")
parser.add_argument("output")
parser.add_argument(
    "-s",
    "--data-block-size",
    help="Chunk ID that starts app system. Varies by phone model.",
    default=2048,
    type=int,
)

args = parser.parse_args()

with open(args.input, "rb") as infile:
    with open(args.output, "wb") as outfile:
        s = b"0"
        while s:
            outfile.write(infile.read(args.data_block_size))
            s = infile.read(args.data_block_size // 0x20)
