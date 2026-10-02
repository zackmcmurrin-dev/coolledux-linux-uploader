#!/usr/bin/env python3

import importlib.util
import asyncio
import sys

spec = importlib.util.spec_from_file_location(
    "coolledux", "coolledux-upload.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def extract_content_block(program):
    # Current native-program envelope:
    #
    #   0..7   reserved
    #   8      content count
    #   9      reserved
    #   10..   length-prefixed content block(s)
    #
    if len(program) < 14:
        raise ValueError("program too short")

    count = program[8]

    if count != 1:
        raise ValueError(
            f"expected single-content source program, got {count}"
        )

    block_len = int.from_bytes(program[10:14], "big")
    block = program[10:10 + block_len]

    if len(block) != block_len:
        raise ValueError(
            f"incomplete content block: expected {block_len}, "
            f"got {len(block)}"
        )

    return block


async def main():
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: test-two-content.py FIRST.gif SECOND.gif BLE_ADDRESS"
        )

    first_path = sys.argv[1]
    second_path = sys.argv[2]
    address = sys.argv[3]

    first_program, _, _ = m.build_native_program_from_gif(
        first_path, 64, 16, 40, 1.0, True
    )

    second_program, _, _ = m.build_native_program_from_gif(
        second_path, 64, 16, 40, 1.0, True
    )

    first_block = extract_content_block(first_program)
    second_block = extract_content_block(second_program)

    combined = bytearray()
    combined += b"\x00" * 8
    combined += b"\x02"       # TEST: two content blocks
    combined += b"\x00"
    combined += first_block
    combined += second_block
    combined = bytes(combined)

    print("FIRST content block: ", len(first_block))
    print("SECOND content block:", len(second_block))
    print("combined program:     ", len(combined))
    print("content-count byte:   ", combined[8])
    print()

    class Args:
        pass

    args = Args()
    args.address = address
    args.auto = False
    args.scan_timeout = 8
    args.quiet = False
    args.brightness = None
    args.index = 0

    await m.upload_program(
        args,
        combined,
        "EXPERIMENT: two-content native program",
        [
            ("first:", first_path),
            ("second:", second_path),
            ("content count:", 2),
        ],
    )


asyncio.run(main())
