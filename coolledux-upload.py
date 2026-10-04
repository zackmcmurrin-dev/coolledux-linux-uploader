#!/usr/bin/env python3

import argparse
import asyncio
import time
import json
from datetime import datetime
from pathlib import Path

from bleak import BleakClient, BleakScanner
from PIL import Image, ImageSequence


VERSION = "0.3.0"
DEFAULT_ADDR = "01:00:00:54:EC:17"
CHAR = "0000fff1-0000-1000-8000-00805f9b34fb"

N = 512
F = 18
THRESHOLD = 2
NIL = N

ack_queue = asyncio.Queue()


def u16(n):
    return int(n).to_bytes(2, "big")


def u32(n):
    return int(n).to_bytes(4, "big", signed=False)


def wrap(payload: bytes) -> bytes:
    data = u16(len(payload)) + payload

    out = bytearray([0x01])
    for b in data:
        if 0x00 < b < 0x04:
            out += bytes([0x02, b ^ 0x04])
        else:
            out.append(b)
    out.append(0x03)
    return bytes(out)


def unwrap(packet: bytes) -> bytes:
    if packet and packet[0] == 0x01 and packet[-1] == 0x03:
        packet = packet[1:-1]

    out = bytearray()
    i = 0
    while i < len(packet):
        if packet[i] == 0x02 and i + 1 < len(packet):
            out.append(packet[i + 1] ^ 0x04)
            i += 2
        else:
            out.append(packet[i])
            i += 1

    return bytes(out[2:]) if len(out) >= 2 else bytes(out)


def crc32_coolledux(data: bytes) -> int:
    poly = 0x04C11DB7
    crc = 0xFFFFFFFF

    for b in data:
        for _ in range(8):
            crc_high = crc & 0x80000000
            data_high = b & 0x80

            crc = (crc << 1) & 0xFFFFFFFF

            if crc_high:
                crc ^= poly
            if data_high:
                crc ^= poly

            b = (b << 1) & 0xFF

    return crc & 0xFFFFFFFF


def xor_checksum(data: bytes) -> int:
    x = 0
    for b in data:
        x ^= b
    return x & 0xFF


def lzss_compress(src: bytes) -> bytes:
    text_buf = bytearray(N + F - 1)
    lson = [NIL] * (N + 1)
    rson = [NIL] * (N + 257)
    dad = [NIL] * (N + 1)
    match_position = 0
    match_length = 0

    def insert_node(r):
        nonlocal match_position, match_length

        p = text_buf[r] + N + 1
        lson[r] = NIL
        rson[r] = NIL
        match_length = 0
        cmp_val = 1

        while True:
            if cmp_val >= 0:
                if rson[p] != NIL:
                    p = rson[p]
                else:
                    rson[p] = r
                    dad[r] = p
                    return
            else:
                if lson[p] != NIL:
                    p = lson[p]
                else:
                    lson[p] = r
                    dad[r] = p
                    return

            i = 1
            while i < F:
                cmp_val = text_buf[r + i] - text_buf[p + i]
                if cmp_val != 0:
                    break
                i += 1

            if i > match_length:
                match_position = p
                match_length = i

                if i >= F:
                    dad[r] = dad[p]
                    lson[r] = lson[p]
                    rson[r] = rson[p]
                    dad[lson[p]] = r
                    dad[rson[p]] = r
                    if rson[dad[p]] == p:
                        rson[dad[p]] = r
                    else:
                        lson[dad[p]] = r
                    dad[p] = NIL
                    return

        # unreachable

    def delete_node(p):
        if dad[p] == NIL:
            return

        if rson[p] == NIL:
            q = lson[p]
        elif lson[p] == NIL:
            q = rson[p]
        else:
            q = lson[p]
            if rson[q] != NIL:
                while rson[q] != NIL:
                    q = rson[q]
                rson[dad[q]] = lson[q]
                dad[lson[q]] = dad[q]
                lson[q] = lson[p]
                dad[lson[p]] = q
            rson[q] = rson[p]
            dad[rson[p]] = q

        dad[q] = dad[p]
        if rson[dad[p]] == p:
            rson[dad[p]] = q
        else:
            lson[dad[p]] = q
        dad[p] = NIL

    out = bytearray()
    code_buf = bytearray(17)
    code_buf[0] = 0
    code_buf_ptr = 1
    mask = 1

    s = 0
    r = N - F
    for i in range(s, r):
        text_buf[i] = 0x20

    src_i = 0
    length = 0
    while length < F and src_i < len(src):
        text_buf[r + length] = src[src_i]
        src_i += 1
        length += 1

    if length == 0:
        return bytes(out)

    for i in range(1, F + 1):
        insert_node(r - i)
    insert_node(r)

    while True:
        if match_length > length:
            match_length = length

        if match_length <= THRESHOLD:
            match_length = 1
            code_buf[0] |= mask
            code_buf[code_buf_ptr] = text_buf[r]
            code_buf_ptr += 1
        else:
            code_buf[code_buf_ptr] = match_position & 0xFF
            code_buf[code_buf_ptr + 1] = ((match_position >> 4) & 0xF0) | (match_length - (THRESHOLD + 1))
            code_buf_ptr += 2

        mask = (mask << 1) & 0xFF
        if mask == 0:
            out += code_buf[:code_buf_ptr]
            code_buf[0] = 0
            code_buf_ptr = 1
            mask = 1

        last_match_length = match_length
        i = 0
        while i < last_match_length and src_i < len(src):
            delete_node(s)
            text_buf[s] = src[src_i]
            if s < F - 1:
                text_buf[s + N] = src[src_i]
            s = (s + 1) & (N - 1)
            r = (r + 1) & (N - 1)
            src_i += 1
            insert_node(r)
            i += 1

        while i < last_match_length:
            delete_node(s)
            s = (s + 1) & (N - 1)
            r = (r + 1) & (N - 1)
            length -= 1
            if length:
                insert_node(r)
            i += 1

        if length <= 0:
            break

    if code_buf_ptr > 1:
        out += code_buf[:code_buf_ptr]

    return bytes(out)


def rgb444(r, g, b):
    return bytes([r // 16, ((g // 16) << 4) | (b // 16)])


def color_name_to_rgb(name):
    colors = {
        "white": (255, 255, 255),
        "red": (255, 0, 0),
        "green": (0, 255, 0),
        "blue": (0, 0, 255),
        "cyan": (0, 255, 255),
        "yellow": (255, 255, 0),
        "magenta": (255, 0, 255),
        "orange": (255, 128, 0),
    }
    if name.startswith("#") and len(name) == 7:
        return int(name[1:3], 16), int(name[3:5], 16), int(name[5:7], 16)
    return colors.get(name.lower(), colors["white"])


def b_from_csv(s):
    if not s.strip():
        return b""
    return bytes(int(x.strip()) & 0xFF for x in s.replace("\n", ",").split(",") if x.strip())



# Official 16x32 clock geometry extracted from ILedClockClockTimeFragment.java.
# This panel reports 16x64, but the clock payload geometry uses the 32-column clock canvas.
CLOCK_LAYOUTS_1632 = {
    1: {'isSpaceShing': True, 'numHeight': 12, 'numWidth': 7, 'hourStartColumn': 1, 'hourStartRow': 0, 'hourWidth': 14, 'hourHeight': 12, 'spaceHourStartColumn': 15, 'spaceHourStartRow': 0, 'spaceHourWidth': 2, 'spaceHourHeight': 12, 'minuteStartColumn': 18, 'minuteStartRow': 0, 'minuteWidth': 14, 'minuteHeight': 12},
    2: {'isSpaceShing': True, 'numHeight': 16, 'numWidth': 7, 'hourStartColumn': 1, 'hourStartRow': 3, 'hourWidth': 14, 'hourHeight': 16, 'spaceHourStartColumn': 15, 'spaceHourStartRow': 3, 'spaceHourWidth': 2, 'spaceHourHeight': 16, 'minuteStartColumn': 18, 'minuteStartRow': 3, 'minuteWidth': 14, 'minuteHeight': 16},
    3: {'isSpaceShing': True, 'numHeight': 10, 'numWidth': 6, 'hourStartColumn': 3, 'hourStartRow': 3, 'hourWidth': 12, 'hourHeight': 10, 'spaceHourStartColumn': 15, 'spaceHourStartRow': 3, 'spaceHourWidth': 1, 'spaceHourHeight': 10, 'minuteStartColumn': 17, 'minuteStartRow': 3, 'minuteWidth': 12, 'minuteHeight': 10},
    4: {'isSpaceShing': True, 'numHeight': 10, 'numWidth': 8, 'hourStartColumn': 1, 'hourStartRow': 4, 'hourWidth': 16, 'hourHeight': 10, 'spaceHourStartColumn': 15, 'spaceHourStartRow': 4, 'spaceHourWidth': 2, 'spaceHourHeight': 10, 'minuteStartColumn': 18, 'minuteStartRow': 4, 'minuteWidth': 16, 'minuteHeight': 10},
    5: {'isSpaceShing': True, 'numHeight': 10, 'numWidth': 7, 'hourStartColumn': 1, 'hourStartRow': 6, 'hourWidth': 14, 'hourHeight': 10, 'spaceHourStartColumn': 15, 'spaceHourStartRow': 6, 'spaceHourWidth': 2, 'spaceHourHeight': 10, 'minuteStartColumn': 18, 'minuteStartRow': 6, 'minuteWidth': 14, 'minuteHeight': 10},
    6: {'isSpaceShing': True, 'numHeight': 10, 'numWidth': 6, 'hourStartColumn': 0, 'hourStartRow': 0, 'hourWidth': 12, 'hourHeight': 10, 'spaceHourStartColumn': 12, 'spaceHourStartRow': 0, 'spaceHourWidth': 1, 'spaceHourHeight': 10, 'minuteStartColumn': 14, 'minuteStartRow': 0, 'minuteWidth': 12, 'minuteHeight': 10},
    7: {'isSpaceShing': True, 'numHeight': 10, 'numWidth': 7, 'hourStartColumn': 1, 'hourStartRow': 0, 'hourWidth': 14, 'hourHeight': 10, 'spaceHourStartColumn': 15, 'spaceHourStartRow': 0, 'spaceHourWidth': 2, 'spaceHourHeight': 10, 'minuteStartColumn': 18, 'minuteStartRow': 0, 'minuteWidth': 14, 'minuteHeight': 10, 'showSpaceMinuteColor': True, 'showAmpm': False},
    8: {'isSpaceShing': True, 'numHeight': 12, 'numWidth': 7, 'hourStartColumn': 1, 'hourStartRow': 2, 'hourWidth': 14, 'hourHeight': 12, 'spaceHourStartColumn': 15, 'spaceHourStartRow': 2, 'spaceHourWidth': 2, 'spaceHourHeight': 12, 'minuteStartColumn': 18, 'minuteStartRow': 2, 'minuteWidth': 14, 'minuteHeight': 12},
    9: {'isSpaceShing': True, 'numHeight': 10, 'numWidth': 7, 'hourStartColumn': 0, 'hourStartRow': 0, 'hourWidth': 14, 'hourHeight': 10, 'spaceHourStartColumn': 15, 'spaceHourStartRow': 0, 'spaceHourWidth': 2, 'spaceHourHeight': 10, 'minuteStartColumn': 19, 'minuteStartRow': 0, 'minuteWidth': 14, 'minuteHeight': 10},
    10: {'isSpaceShing': True, 'numHeight': 5, 'numWidth': 6, 'hourStartColumn': 1, 'hourStartRow': 9, 'hourWidth': 12, 'hourHeight': 5, 'spaceHourStartColumn': 15, 'spaceHourStartRow': 9, 'spaceHourWidth': 2, 'spaceHourHeight': 5, 'minuteStartColumn': 20, 'minuteStartRow': 9, 'minuteWidth': 12, 'minuteHeight': 5},
    11: {'isSpaceShing': True, 'numHeight': 10, 'numWidth': 7, 'hourStartColumn': 1, 'hourStartRow': 0, 'hourWidth': 14, 'hourHeight': 10, 'spaceHourStartColumn': 15, 'spaceHourStartRow': 0, 'spaceHourWidth': 2, 'spaceHourHeight': 10, 'minuteStartColumn': 18, 'minuteStartRow': 0, 'minuteWidth': 14, 'minuteHeight': 10},
    12: {'isSpaceShing': True, 'numHeight': 10, 'numWidth': 7, 'hourStartColumn': 1, 'hourStartRow': 5, 'hourWidth': 14, 'hourHeight': 10, 'spaceHourStartColumn': 15, 'spaceHourStartRow': 5, 'spaceHourWidth': 2, 'spaceHourHeight': 10, 'minuteStartColumn': 18, 'minuteStartRow': 5, 'minuteWidth': 14, 'minuteHeight': 10},
    13: {'isSpaceShing': True, 'numHeight': 11, 'numWidth': 7, 'hourStartColumn': 1, 'hourStartRow': 2, 'hourWidth': 14, 'hourHeight': 11, 'spaceHourStartColumn': 15, 'spaceHourStartRow': 2, 'spaceHourWidth': 1, 'spaceHourHeight': 11, 'minuteStartColumn': 17, 'minuteStartRow': 2, 'minuteWidth': 14, 'minuteHeight': 11},
    14: {'isSpaceShing': True, 'numHeight': 7, 'numWidth': 6, 'hourStartColumn': 1, 'hourStartRow': 0, 'hourWidth': 12, 'hourHeight': 7, 'spaceHourStartColumn': 13, 'spaceHourStartRow': 4, 'spaceHourWidth': 1, 'spaceHourHeight': 7, 'minuteStartColumn': 1, 'minuteStartRow': 9, 'minuteWidth': 12, 'minuteHeight': 7},
    15: {'isSpaceShing': True, 'numHeight': 7, 'numWidth': 6, 'hourStartColumn': 4, 'hourStartRow': 0, 'hourWidth': 12, 'hourHeight': 7, 'spaceHourStartColumn': 2, 'spaceHourStartRow': 9, 'spaceHourWidth': 1, 'spaceHourHeight': 7, 'minuteStartColumn': 4, 'minuteStartRow': 9, 'minuteWidth': 12, 'minuteHeight': 7},
    16: {'isSpaceShing': True, 'numHeight': 7, 'numWidth': 6, 'hourStartColumn': 19, 'hourStartRow': 0, 'hourWidth': 12, 'hourHeight': 7, 'spaceHourStartColumn': 17, 'spaceHourStartRow': 9, 'spaceHourWidth': 1, 'spaceHourHeight': 7, 'minuteStartColumn': 19, 'minuteStartRow': 9, 'minuteWidth': 12, 'minuteHeight': 7},
    17: {'isSpaceShing': True, 'numHeight': 7, 'numWidth': 6, 'hourStartColumn': 20, 'hourStartRow': 0, 'hourWidth': 12, 'hourHeight': 7, 'spaceHourStartColumn': 18, 'spaceHourStartRow': 4, 'spaceHourWidth': 1, 'spaceHourHeight': 7, 'minuteStartColumn': 20, 'minuteStartRow': 9, 'minuteWidth': 12, 'minuteHeight': 7},
    18: {'isSpaceShing': True, 'numHeight': 7, 'numWidth': 6, 'hourStartColumn': 21, 'hourStartRow': 0, 'hourWidth': 12, 'hourHeight': 7, 'spaceHourStartColumn': 19, 'spaceHourStartRow': 4, 'spaceHourWidth': 1, 'spaceHourHeight': 7, 'minuteStartColumn': 21, 'minuteStartRow': 9, 'minuteWidth': 12, 'minuteHeight': 7},
    19: {'isSpaceShing': True, 'numHeight': 7, 'numWidth': 6, 'hourStartColumn': 20, 'hourStartRow': 1, 'hourWidth': 12, 'hourHeight': 7, 'spaceHourStartColumn': 18, 'spaceHourStartRow': 9, 'spaceHourWidth': 1, 'spaceHourHeight': 7, 'minuteStartColumn': 20, 'minuteStartRow': 9, 'minuteWidth': 12, 'minuteHeight': 7},
    20: {'isSpaceShing': True, 'numHeight': 7, 'numWidth': 5, 'hourStartColumn': 10, 'hourStartRow': 1, 'hourWidth': 10, 'hourHeight': 7, 'spaceHourStartColumn': 20, 'spaceHourStartRow': 1, 'spaceHourWidth': 1, 'spaceHourHeight': 7, 'minuteStartColumn': 22, 'minuteStartRow': 1, 'minuteWidth': 10, 'minuteHeight': 7},
    21: {'isSpaceShing': True, 'numHeight': 7, 'numWidth': 5, 'hourStartColumn': 0, 'hourStartRow': 0, 'hourWidth': 10, 'hourHeight': 7, 'spaceHourStartColumn': 10, 'spaceHourStartRow': 0, 'spaceHourWidth': 1, 'spaceHourHeight': 7, 'minuteStartColumn': 12, 'minuteStartRow': 0, 'minuteWidth': 10, 'minuteHeight': 7},
    22: {'isSpaceShing': True, 'numHeight': 5, 'numWidth': 4, 'hourStartColumn': 14, 'hourStartRow': 1, 'hourWidth': 8, 'hourHeight': 5, 'spaceHourStartColumn': 22, 'spaceHourStartRow': 1, 'spaceHourWidth': 1, 'spaceHourHeight': 5, 'minuteStartColumn': 24, 'minuteStartRow': 1, 'minuteWidth': 8, 'minuteHeight': 5},
    23: {'isSpaceShing': True, 'numHeight': 5, 'numWidth': 4, 'hourStartColumn': 2, 'hourStartRow': 9, 'hourWidth': 8, 'hourHeight': 5, 'spaceHourStartColumn': 10, 'spaceHourStartRow': 9, 'spaceHourWidth': 1, 'spaceHourHeight': 5, 'minuteStartColumn': 12, 'minuteStartRow': 9, 'minuteWidth': 8, 'minuteHeight': 5},
    24: {'isSpaceShing': False, 'numHeight': 5, 'numWidth': 4, 'hourStartColumn': 2, 'hourStartRow': 5, 'hourWidth': 8, 'hourHeight': 5, 'spaceHourStartColumn': 10, 'spaceHourStartRow': 5, 'spaceHourWidth': 1, 'spaceHourHeight': 5, 'minuteStartColumn': 12, 'minuteStartRow': 5, 'minuteWidth': 8, 'minuteHeight': 5, 'showSpaceMinuteColor': True, 'spaceMinuteStartColumn': 20, 'spaceMinuteStartRow': 5, 'spaceMinuteWidth': 1, 'spaceMinuteHeight': 5, 'secondsStartColumn': 22, 'secondsStartRow': 5, 'secondsWidth': 8, 'secondsHeight': 5},
    25: {'isSpaceShing': True, 'numHeight': 5, 'numWidth': 4, 'hourStartColumn': 14, 'hourStartRow': 1, 'hourWidth': 8, 'hourHeight': 5, 'spaceHourStartColumn': 22, 'spaceHourStartRow': 1, 'spaceHourWidth': 1, 'spaceHourHeight': 5, 'minuteStartColumn': 24, 'minuteStartRow': 1, 'minuteWidth': 8, 'minuteHeight': 5},
    26: {'isSpaceShing': False, 'numHeight': 5, 'numWidth': 4, 'hourStartColumn': 3, 'hourStartRow': 1, 'hourWidth': 8, 'hourHeight': 5, 'spaceHourStartColumn': 11, 'spaceHourStartRow': 1, 'spaceHourWidth': 1, 'spaceHourHeight': 5, 'minuteStartColumn': 13, 'minuteStartRow': 1, 'minuteWidth': 8, 'minuteHeight': 5, 'showSpaceMinuteColor': True, 'spaceMinuteStartColumn': 21, 'spaceMinuteStartRow': 1, 'spaceMinuteWidth': 1, 'spaceMinuteHeight': 5, 'secondsStartColumn': 23, 'secondsStartRow': 1, 'secondsWidth': 8, 'secondsHeight': 5},
    27: {'isSpaceShing': True, 'numHeight': 5, 'numWidth': 4, 'hourStartColumn': 2, 'hourStartRow': 2, 'hourWidth': 8, 'hourHeight': 5, 'spaceHourStartColumn': 10, 'spaceHourStartRow': 2, 'spaceHourWidth': 1, 'spaceHourHeight': 5, 'minuteStartColumn': 12, 'minuteStartRow': 2, 'minuteWidth': 8, 'minuteHeight': 5},
}

# 16x64 digit font strings pulled from ILedClockUtils.getDataWithClockCombineProgram().
DIGIT_FONT_1664_NARROW = (
    "127, 128, 255, 192, 192, 192, 192, 192, 255, 192, 127, 128, 0, 0, "
    "32, 192, 96, 192, 255, 192, 255, 192, 0, 192, 0, 192, 0, 0, "
    "97, 192, 227, 192, 198, 192, 204, 192, 248, 192, 120, 192, 0, 0, "
    "97, 128, 225, 192, 204, 192, 204, 192, 255, 192, 115, 128, 0, 0, "
    "30, 0, 62, 0, 102, 0, 255, 192, 255, 192, 6, 0, 0, 0, "
    "249, 128, 249, 192, 216, 192, 216, 192, 223, 192, 207, 128, 0, 0, "
    "31, 128, 63, 192, 108, 192, 204, 192, 143, 192, 7, 128, 0, 0, "
    "224, 0, 224, 0, 199, 192, 207, 192, 248, 0, 240, 0, 0, 0, "
    "115, 128, 255, 192, 204, 192, 204, 192, 255, 192, 115, 128, 0, 0, "
    "121, 128, 253, 192, 204, 192, 204, 192, 255, 192, 127, 128, 0, 0"
)

DIGIT_FONT_1664_WIDE = (
    "127, 224, 255, 240, 192, 48, 192, 48, 255, 240, 127, 224, 0, 0, "
    "32, 48, 96, 48, 255, 240, 255, 240, 0, 48, 0, 48, 0, 0, "
    "96, 240, 225, 240, 195, 48, 198, 48, 252, 48, 120, 48, 0, 0, "
    "96, 96, 224, 112, 198, 48, 198, 48, 255, 240, 121, 224, 0, 0, "
    "31, 128, 63, 128, 97, 128, 255, 240, 255, 240, 1, 128, 0, 0, "
    "252, 96, 252, 112, 204, 48, 204, 48, 207, 240, 199, 224, 0, 0, "
    "127, 224, 255, 240, 204, 48, 204, 48, 207, 240, 199, 224, 0, 0, "
    "192, 0, 192, 0, 199, 240, 207, 240, 248, 0, 240, 0, 0, 0, "
    "123, 224, 255, 240, 198, 48, 198, 48, 255, 240, 123, 224, 0, 0, "
    "124, 96, 254, 112, 198, 48, 198, 48, 255, 240, 127, 224, 0, 0"
)



# First custom native-clock font experiment.
# Format: 10 digits, each digit = numWidth columns, each column = 16-bit vertical bitmap.
CUSTOM_5X7_DIGITS = {
    "0": ["11111","10001","10011","10101","11001","10001","11111"],
    "1": ["00100","01100","00100","00100","00100","00100","01110"],
    "2": ["11110","00001","00001","11110","10000","10000","11111"],
    "3": ["11110","00001","00001","01110","00001","00001","11110"],
    "4": ["10010","10010","10010","11111","00010","00010","00010"],
    "5": ["11111","10000","10000","11110","00001","00001","11110"],
    "6": ["01111","10000","10000","11110","10001","10001","01110"],
    "7": ["11111","00001","00010","00100","01000","01000","01000"],
    "8": ["01110","10001","10001","01110","10001","10001","01110"],
    "9": ["01110","10001","10001","01111","00001","00001","11110"],
}

def load_clock_digits_file(path):
    path = Path(path)

    if not path.exists():
        raise SystemExit(f"ERROR: clock digit file not found: {path}")

    raw_lines = path.read_text(encoding="utf-8").splitlines()

    # Find the first digit heading. Anything before it is header/comment text.
    start_index = None
    for i, line in enumerate(raw_lines):
        if line.strip() == "0":
            start_index = i
            break

    if start_index is None:
        raise SystemExit(f"ERROR: digit 0 not found in {path}")

    # From digit 0 onward, '#' is pixel data, NOT a comment character.
    lines = [
        line.strip()
        for line in raw_lines[start_index:]
        if line.strip()
    ]

    digits = {}
    i = 0

    for expected_digit in "0123456789":
        if i >= len(lines):
            raise SystemExit(
                f"ERROR: missing digit {expected_digit} in {path}"
            )

        if lines[i] != expected_digit:
            raise SystemExit(
                f"ERROR: expected digit {expected_digit} in {path}, "
                f"got {lines[i]!r}"
            )

        i += 1
        rows = []

        for _ in range(8):
            if i >= len(lines):
                raise SystemExit(
                    f"ERROR: digit {expected_digit} in {path} "
                    f"does not contain 8 rows"
                )

            row = lines[i]
            i += 1

            if len(row) != 5 or any(ch not in ".#" for ch in row):
                raise SystemExit(
                    f"ERROR: invalid row for digit {expected_digit} "
                    f"in {path}: {row!r}"
                )

            rows.append(
                "".join("1" if ch == "#" else "0" for ch in row)
            )

        digits[expected_digit] = rows

    if i != len(lines):
        raise SystemExit(
            f"ERROR: unexpected extra data in {path}: {lines[i:]}"
        )

    return digits



def custom_font_from_5x7(name="pipboy"):
    num_w = 7
    num_h = 16
    out = bytearray()

    font_path = Path(name)

    if font_path.is_dir():
        font_path = font_path / "digits.txt"
    elif not font_path.exists():
        candidate = Path("clock_faces") / name / "digits.txt"
        if candidate.exists():
            font_path = candidate

    if font_path.exists():
        digit_patterns = load_clock_digits_file(font_path)
    else:
        # Backward-compatible fallback for the original experimental font.
        digit_patterns = CUSTOM_5X7_DIGITS

    # center 5-wide glyph inside 7 columns
    x_pad = 1

    # Scale 8-high clock-face font exactly 2x vertically.
    # 8 source rows x 2 = all 16 physical panel rows.
    for d in "0123456789":
        pat = digit_patterns[d]
        cols = [0] * num_w

        for py, row in enumerate(pat):
            for px, bit in enumerate(row):
                if bit != "1":
                    continue

                x = px + x_pad
                y1 = py * 2
                y2 = y1 + 1

                # Custom native clock columns are vertically inverted
                # relative to the human-readable top-to-bottom source rows.
                cols[x] |= 1 << (15 - y1)
                cols[x] |= 1 << (15 - y2)

        for col in cols:
            out += col.to_bytes(2, "big")

    return num_h, num_w, bytes(out)

def clock_digit_font(style, custom_font=None):
    if custom_font:
        return custom_font_from_5x7(custom_font)

    narrow = {1, 4, 5, 7, 12, 13, 15, 16}
    wide = {2, 3, 6, 8, 9, 10, 11, 14, 17, 18}
    if style in wide:
        return 16, 8, b_from_csv(DIGIT_FONT_1664_WIDE)
    return 16, 7, b_from_csv(DIGIT_FONT_1664_NARROW)


def load_colon_file(path):
    path = Path(path)

    if not path.exists():
        raise SystemExit(f"ERROR: clock colon file not found: {path}")

    raw_lines = path.read_text(encoding="utf-8").splitlines()

    # Header comments are allowed before the 16x2 bitmap.
    rows = []
    bitmap_started = False

    for line in raw_lines:
        line = line.strip()

        if not line:
            continue

        if not bitmap_started:
            if len(line) == 2 and all(ch in ".#" for ch in line):
                bitmap_started = True
            else:
                continue

        if len(line) != 2 or any(ch not in ".#" for ch in line):
            raise SystemExit(
                f"ERROR: invalid colon row in {path}: {line!r}"
            )

        rows.append(line)

    if len(rows) != 16:
        raise SystemExit(
            f"ERROR: colon in {path} must contain exactly 16 bitmap rows; "
            f"found {len(rows)}"
        )

    # Custom native clock columns are vertically inverted
    # relative to the human-readable top-to-bottom source rows.
    cols = [0, 0]

    for y, row in enumerate(rows):
        for x, ch in enumerate(row):
            if ch == "#":
                cols[x] |= 1 << (15 - y)

    out = bytearray()
    for col in cols:
        out += col.to_bytes(2, "big")

    return bytes(out)


def clock_colon_font(style):
    narrow = {1, 4, 5, 7, 8, 10, 12, 13, 15, 16}
    if style in narrow:
        return b_from_csv("51, 0, 51, 0")
    return b_from_csv("48, 192, 48, 192")


def add_rect(buf, color, x, y, w, h):
    buf += color
    buf += u16(x)
    buf += u16(y)
    buf += u16(w)
    buf += u16(h)


def build_clock_combine_block(style=1, color_rgb=(255, 255, 255), is_24h=True, blink_colon=True, geometry=None, custom_font=None, custom_colon=None):
    layout = dict(CLOCK_LAYOUTS_1632.get(style, CLOCK_LAYOUTS_1632[1]))

    if geometry:
        if geometry.get("hour_x") is not None:
            layout["hourStartColumn"] = geometry["hour_x"]
        if geometry.get("colon_x") is not None:
            layout["spaceHourStartColumn"] = geometry["colon_x"]
        if geometry.get("minute_x") is not None:
            layout["minuteStartColumn"] = geometry["minute_x"]
        if geometry.get("clock_y") is not None:
            layout["hourStartRow"] = geometry["clock_y"]
            layout["spaceHourStartRow"] = geometry["clock_y"]
            layout["minuteStartRow"] = geometry["clock_y"]
        if geometry.get("colon_w") is not None:
            layout["spaceHourWidth"] = geometry["colon_w"]

    num_h = layout.get("numHeight", 12)
    num_w = layout.get("numWidth", 7)
    num_h, num_w, digit_font = clock_digit_font(style, custom_font=custom_font)
    if custom_colon:
        colon_font = load_colon_file(custom_colon)
    else:
        colon_font = clock_colon_font(style)

    color = rgb444(*color_rgb)

    hour_x = layout.get("hourStartColumn", 1)
    hour_y = layout.get("hourStartRow", 0)

    # Custom fonts must use geometry matching the custom glyph dimensions,
    # rather than the factory style's original rectangle dimensions.
    if custom_font:
        hour_w = num_w * 2
        hour_h = num_h
        minute_w = num_w * 2
        minute_h = num_h
    else:
        hour_w = layout.get("hourWidth", num_w * 2)
        hour_h = layout.get("hourHeight", num_h)
        minute_w = layout.get("minuteWidth", num_w * 2)
        minute_h = layout.get("minuteHeight", num_h)

    colon_x = layout.get("spaceHourStartColumn", hour_x + hour_w)
    colon_y = layout.get("spaceHourStartRow", hour_y)
    colon_w = layout.get("spaceHourWidth", 2)
    colon_h = num_h if custom_font else layout.get("spaceHourHeight", hour_h)

    minute_x = layout.get("minuteStartColumn", colon_x + colon_w + 1)
    minute_y = layout.get("minuteStartRow", hour_y)

    body = bytearray()
    body += b"\x07"              # clock combine content type
    body += b"\x00" * 7          # reserved
    body += b"\x00"              # layerType

    mode = 0
    if is_24h:
        mode |= 0x01
    if blink_colon:
        mode |= 0x02
    body += bytes([mode])

    body += u16(0)               # showTime
    body += u16(num_h)
    body += u16(num_w)

    body += u16(len(digit_font))
    body += digit_font

    add_rect(body, color, hour_x, hour_y, hour_w, hour_h)
    add_rect(body, color, colon_x, colon_y, colon_w, colon_h)

    body += u16(len(colon_font))
    body += colon_font

    add_rect(body, color, minute_x, minute_y, minute_w, minute_h)

    # SpaceMinute block. Used by official seconds styles such as 24 and 26.
    add_rect(
        body, color,
        layout.get("spaceMinuteStartColumn", 0),
        layout.get("spaceMinuteStartRow", 0),
        layout.get("spaceMinuteWidth", 0),
        layout.get("spaceMinuteHeight", 0),
    )

    if layout.get("showSpaceMinuteColor", False):
        body += u16(len(colon_font))
        body += colon_font
    else:
        body += u16(0)

    # Seconds block.
    add_rect(
        body, color,
        layout.get("secondsStartColumn", 0),
        layout.get("secondsStartRow", 0),
        layout.get("secondsWidth", 0),
        layout.get("secondsHeight", 0),
    )

    # AM/PM geometry.
    add_rect(body, color, 0, 0, 0, 0)

    body += u16(0)               # AM/PM bitmap len

    return u32(len(body) + 4) + bytes(body)


def build_native_clock_program(style=1, color_rgb=(255, 255, 255), is_24h=False, geometry=None, custom_font=None, custom_colon=None, force=False):
    clock_block = build_clock_combine_block(
        style=style,
        color_rgb=color_rgb,
        is_24h=is_24h,
        geometry=geometry,
        custom_font=custom_font,
        custom_colon=custom_colon,
    )

    program = bytearray()

    # The first outer program-header byte is normally zero. Hardware testing
    # shows that values 0x01, 0x02, and 0xff are accepted without changing
    # native clock rendering. Use it as a nonce for --force so the program CRC
    # changes and the panel does not reject the upload as already present.
    force_nonce = 0
    if force:
        force_nonce = 1 + (int(time.time() * 1000) % 255)

    program += bytes([force_nonce])
    program += b"\x00" * 7
    program += b"\x01"           # contentNumber: one clock combine program
    program += b"\x00"
    program += clock_block
    return bytes(program)


def frame_to_native_bytes(img, width, height):
    """Convert one image frame to the panel's native pixel format."""
    img = img.convert("RGBA").resize(
        (width, height),
        Image.Resampling.NEAREST,
    )

    data = bytearray()

    # Known-good v0.1 native pixel ordering.
    for x in range(width):
        for y in range(height):
            r, g, b, a = img.getpixel((x, y))

            if a < 128:
                r = g = b = 0

            data += rgb444(r, g, b)

    return bytes(data)


def load_gif_frames(path, width, height, max_frames, speed=1.0, force=False):
    """Load GIF frames using the known-good v0.1 conversion behavior."""
    if speed <= 0:
        raise ValueError("--speed must be greater than 0")

    src = Image.open(path)
    frames = []
    delays = []

    for frame in ImageSequence.Iterator(src):
        if len(frames) >= max_frames:
            break

        duration = frame.info.get("duration", 100)

        if duration <= 0:
            duration = 100

        duration = int(duration / speed)
        duration = max(20, min(65535, duration))

        frames.append(
            frame_to_native_bytes(frame, width, height)
        )
        delays.append(duration)

    if not frames:
        raise RuntimeError("No frames loaded from GIF")

    # Preserve the v0.1 --force behavior exactly.
    if force and delays:
        delays[0] = 20 + (int(time.time() * 1000) % 500)

    return frames, delays


def build_native_program_from_gif(
    path,
    width=64,
    height=16,
    max_frames=40,
    speed=1.0,
    force=False,
):
    frames, delays = load_gif_frames(
        path,
        width,
        height,
        max_frames,
        speed,
        force,
    )

    inner = bytearray()
    inner += b"\x03\x01"
    inner += b"\x00" * 6
    inner += b"\x00"
    inner += u16(0)
    inner += u16(0)
    inner += u16(width)
    inner += u16(height)
    inner += b"\x00"
    inner += u16(len(frames))

    for d in delays:
        inner += u16(d)

    for frame in frames:
        inner += frame

    content_block = u32(len(inner) + 4) + inner

    program = bytearray()
    program += b"\x00" * 8
    program += b"\x01"
    program += b"\x00"
    program += content_block

    return bytes(program), len(frames), delays


def make_start_packet(program, index=0, count=1, show_count=1):
    payload = b"\x02"
    payload += u32(crc32_coolledux(program))
    payload += u32(len(program))
    payload += bytes([index, count, show_count])
    return wrap(payload)


def make_chunk_packet(compressed, chunk_index, chunk):
    body = b"\x00"
    body += u32(len(compressed))
    body += u16(chunk_index)
    body += u16(len(chunk))
    body += chunk
    body += bytes([xor_checksum(body)])
    return wrap(b"\x03" + body)


def make_brightness_packet(level):
    return wrap(bytes([0x04, level & 0xFF]))


def make_flip_packet(mode):
    """Build panel orientation packet exactly as captured from official app."""

    packets = {
        "none": bytes.fromhex("01 00 02 06 0c 00 03"),
        "x":    bytes.fromhex("01 00 02 06 0c 02 06 03"),
        "y":    bytes.fromhex("01 00 02 06 0c 02 07 03"),
        "xy":   bytes.fromhex("01 00 02 06 0c 02 05 03"),
    }

    return packets[mode]



def make_sync_time_packet(now=None):
    if now is None:
        now = datetime.now()

    payload = bytes([
        0x09,
        now.year - 2000,
        now.month,
        now.day,
        now.weekday() + 1,
        now.hour,
        now.minute,
        now.second,
    ])
    return wrap(payload)


def chunks(data, size=240):
    for i in range(0, len(data), size):
        yield data[i:i + size]


def notification_handler(sender, data):
    payload = unwrap(data)

    if not getattr(notification_handler, "quiet", False):
        print("notify:", payload.hex(" "))

    try:
        ack_queue.put_nowait(payload)
    except RuntimeError:
        pass


notification_handler.quiet = False


async def write_ble_packet(client, packet):
    await client.write_gatt_char(CHAR, packet, response=False)


async def wait_for_ack(kind, timeout=8):
    while True:
        payload = await asyncio.wait_for(ack_queue.get(), timeout=timeout)
        if kind == "login" and len(payload) >= 1 and payload[0] == 0x0D:
            return payload
        if kind == "start" and len(payload) >= 1 and payload[0] == 0x02:
            return payload
        if kind == "chunk" and len(payload) >= 1 and payload[0] == 0x03:
            return payload
        if kind == "brightness" and len(payload) >= 1 and payload[0] == 0x04:
            return payload
        if kind == "flip" and len(payload) >= 2 and payload[0] == 0x0C:
            return payload
        if kind == "sync" and len(payload) >= 1 and payload[0] == 0x09:
            return payload


async def scan_devices(timeout=8):
    print(f"scanning BLE devices ({timeout}s)...")
    devices = await BleakScanner.discover(timeout=timeout)
    for d in devices:
        print(f"{d.address}  {d.name}")


async def find_coolledux(timeout=8):
    print(f"scanning for CoolLEDUX panel ({timeout}s)...")
    devices = await BleakScanner.discover(timeout=timeout)
    matches = [d for d in devices if d.name and "CoolLEDUX" in d.name]

    if not matches:
        raise RuntimeError("No CoolLEDUX panel found.")

    if len(matches) > 1:
        print("multiple CoolLEDUX panels found:")
        for d in matches:
            print(f"  {d.address}  {d.name}")
        print("using first match")

    print(f"found CoolLEDUX: {matches[0].address}")
    return matches[0].address


async def connect_login(args):
    if args.auto:
        args.address = await find_coolledux(timeout=args.scan_timeout)

    async with BleakClient(args.address) as client:
        print("connected")
        await client.start_notify(CHAR, notification_handler)
        await asyncio.sleep(0.2)

        print("sending login")
        await write_ble_packet(client, wrap(bytes.fromhex("0d 55 55 55 55 55 55 55 00")))
        await wait_for_ack("login")
        print("login ACK OK")
        yield client


async def sync_time(args):
    notification_handler.quiet = args.quiet
    async for client in connect_login(args):
        now = datetime.now()
        print("sending synchronize time:", now.strftime("%Y-%m-%d %H:%M:%S"))
        packet = make_sync_time_packet(now)
        print("sync packet:", unwrap(packet).hex(" "))
        await write_ble_packet(client, packet)
        payload = await wait_for_ack("sync")
        print("time sync ACK:", payload.hex(" "))
        print("done")


async def set_brightness(args):
    notification_handler.quiet = args.quiet
    async for client in connect_login(args):
        print(f"setting brightness: {args.brightness}")
        await write_ble_packet(client, make_brightness_packet(args.brightness))
        await wait_for_ack("brightness")
        print("done")


async def set_flip(args):
    notification_handler.quiet = args.quiet

    async for client in connect_login(args):
        print(f"setting panel orientation: {args.flip}")

        packet = make_flip_packet(args.flip)
        print("flip packet:", unwrap(packet).hex(" "))

        await write_ble_packet(client, packet)

        # The panel echoes the orientation command on FFF1.
        payload = await wait_for_ack("flip")
        print("flip ACK:", payload.hex(" "))

        print("done")



async def upload_program(args, program, label, details=None):
    notification_handler.quiet = args.quiet

    if args.auto:
        args.address = await find_coolledux(timeout=args.scan_timeout)

    compressed = lzss_compress(program)
    chunk_list = list(chunks(compressed))

    print(f"{label}")
    print(f"address:             {args.address}")
    if details:
        for k, v in details:
            print(f"{k:<20}{v}")
    print(f"native program size: {len(program)}")
    print(f"compressed size:     {len(compressed)}")
    print(f"crc:                 {crc32_coolledux(program):08x}")
    print(f"chunks:              {len(chunk_list)}")

    async with BleakClient(args.address) as client:
        print("connected")
        await client.start_notify(CHAR, notification_handler)
        await asyncio.sleep(0.2)

        print("sending login")
        await write_ble_packet(client, wrap(bytes.fromhex("0d 55 55 55 55 55 55 55 00")))
        await wait_for_ack("login")
        print("login ACK OK")

        if args.brightness is not None:
            print(f"setting brightness {args.brightness}")
            await write_ble_packet(client, make_brightness_packet(args.brightness))
            await wait_for_ack("brightness")
            print("brightness ACK OK")

        print("sending start")
        await write_ble_packet(client, make_start_packet(program, index=args.index))
        start_ack = await wait_for_ack("start")
        print("start ACK OK")

        if len(start_ack) >= 2 and start_ack[1] == 1:
            print("panel says program already exists / no need to resend")
            print("done, watch panel")
            await asyncio.sleep(3)
            return

        if len(start_ack) >= 2 and start_ack[1] == 3:
            print("panel requested retransmit from chunk 0")

        if len(start_ack) >= 2 and start_ack[1] not in (0, 3):
            print(f"ERROR: panel rejected start packet with status {start_ack[1]:02x}.")
            return

        for idx, chunk in enumerate(chunk_list):
            percent = int(((idx + 1) / len(chunk_list)) * 100)
            print(f"sending chunk {idx + 1}/{len(chunk_list)} ({percent}%), raw {len(chunk)}")
            await write_ble_packet(client, make_chunk_packet(compressed, idx, chunk))
            await wait_for_ack("chunk")
            if idx == len(chunk_list) - 1:
                print("final chunk ACK OK")
            await asyncio.sleep(0.03)

        print("done, watch panel")
        await asyncio.sleep(3)


async def upload_multiple(args, gif_paths):
    notification_handler.quiet = args.quiet

    if args.auto:
        args.address = await find_coolledux(timeout=args.scan_timeout)

    count = len(gif_paths)

    if count < 2:
        raise SystemExit("ERROR: --multi requires at least two GIF files.")

    programs = []

    print(f"multi-program set:    {count} GIFs")
    print(f"address:              {args.address}")

    for index, gif_path in enumerate(gif_paths):
        program, frame_count, delays = build_native_program_from_gif(
            gif_path,
            args.width,
            args.height,
            args.max_frames,
            args.speed,
            False,
        )

        compressed = lzss_compress(program)
        chunk_list = list(chunks(compressed))

        programs.append(
            (
                gif_path,
                program,
                compressed,
                chunk_list,
                frame_count,
                delays,
            )
        )

        print()
        print(f"slot {index}:")
        print(f"  gif:                {gif_path}")
        print(f"  frames:             {frame_count}")
        print(f"  first delay:        {delays[0]} ms")
        print(f"  native size:        {len(program)}")
        print(f"  compressed size:    {len(compressed)}")
        print(f"  crc:                {crc32_coolledux(program):08x}")
        print(f"  index/count/show:   {index}/{count}/1")
        print(f"  chunks:             {len(chunk_list)}")

    async with BleakClient(args.address) as client:
        print()
        print("connected")

        await client.start_notify(CHAR, notification_handler)
        await asyncio.sleep(0.2)

        print("sending login")
        await write_ble_packet(
            client,
            wrap(bytes.fromhex("0d 55 55 55 55 55 55 55 00")),
        )
        await wait_for_ack("login")
        print("login ACK OK")

        if args.brightness is not None:
            print(f"setting brightness {args.brightness}")
            await write_ble_packet(
                client,
                make_brightness_packet(args.brightness),
            )
            await wait_for_ack("brightness")
            print("brightness ACK OK")

        for index, item in enumerate(programs):
            (
                gif_path,
                program,
                compressed,
                chunk_list,
                frame_count,
                delays,
            ) = item

            print()
            print(f"=== SLOT {index}/{count - 1}: {gif_path} ===")
            print(f"sending start ({index}/{count}/1)")

            await write_ble_packet(
                client,
                make_start_packet(
                    program,
                    index=index,
                    count=count,
                    show_count=1,
                ),
            )

            start_ack = await wait_for_ack("start")
            print("start ACK:", start_ack.hex(" "))

            if len(start_ack) >= 2 and start_ack[1] == 1:
                print("panel already contains program; using cached copy")
                await asyncio.sleep(0.2)
                continue

            if len(start_ack) >= 2 and start_ack[1] == 3:
                print("panel requested retransmit from chunk 0")

            elif len(start_ack) >= 2 and start_ack[1] != 0:
                raise RuntimeError(
                    f"panel rejected slot {index} start packet "
                    f"with status {start_ack[1]:02x}"
                )

            for chunk_index, chunk in enumerate(chunk_list):
                percent = int(
                    ((chunk_index + 1) / len(chunk_list)) * 100
                )

                print(
                    f"sending slot {index} chunk "
                    f"{chunk_index + 1}/{len(chunk_list)} "
                    f"({percent}%)"
                )

                await write_ble_packet(
                    client,
                    make_chunk_packet(
                        compressed,
                        chunk_index,
                        chunk,
                    ),
                )

                ack = await wait_for_ack("chunk")

                if len(ack) >= 2 and ack[1] != 0:
                    raise RuntimeError(
                        f"slot {index} chunk {chunk_index} "
                        f"rejected: {ack.hex(' ')}"
                    )

                await asyncio.sleep(0.03)

            print(f"slot {index} upload complete")
            await asyncio.sleep(0.2)

        print()
        print("multi-program set complete")
        print("done, watch panel")
        await asyncio.sleep(3)


async def upload(args):
    program, frame_count, delays = build_native_program_from_gif(
        args.gif,
        args.width,
        args.height,
        args.max_frames,
        args.speed,
        args.force,
    )

    await upload_program(
        args,
        program,
        f"gif file:            {args.gif}",
        [
            ("frames:", frame_count),
            ("first delay:", f"{delays[0]} ms"),
            ("speed multiplier:", f"{args.speed}x"),
        ],
    )


async def upload_clock(args):
    rgb = color_name_to_rgb(args.color)
    geometry = {
        "hour_x": args.hour_x,
        "colon_x": args.colon_x,
        "minute_x": args.minute_x,
        "clock_y": args.clock_y,
        "colon_w": args.colon_w,
    }
    program = build_native_clock_program(
        style=args.style,
        color_rgb=rgb,
        is_24h=args.twentyfour,
        geometry=geometry,
        custom_font=args.custom_font,
        custom_colon=args.custom_colon,
        force=args.force,
    )

    await upload_program(
        args,
        program,
        "native clock program",
        [
            ("style:", args.style),
            ("color:", args.color),
            ("custom font:", args.custom_font if args.custom_font else "no"),
            ("custom colon:", args.custom_colon if args.custom_colon else "no"),
            ("24-hour:", "yes" if args.twentyfour else "no"),
            ("blink colon:", "yes"),
            ("hour-x:", args.hour_x if args.hour_x is not None else "auto"),
            ("colon-x:", args.colon_x if args.colon_x is not None else "auto"),
            ("minute-x:", args.minute_x if args.minute_x is not None else "auto"),
            ("clock-y:", args.clock_y if args.clock_y is not None else "auto"),
            ("colon-w:", args.colon_w if args.colon_w is not None else "auto"),
        ],
    )



# ---------------------------------------------------------------------------
# Custom 64x16 clock PNG renderer test.
# Milestone: generate preview.png only. No BLE upload happens in this path.
# ---------------------------------------------------------------------------

FONT_5X7 = {
    "0": ["111", "101", "101", "101", "101", "101", "111"],
    "1": ["010", "110", "010", "010", "010", "010", "111"],
    "2": ["111", "001", "001", "111", "100", "100", "111"],
    "3": ["111", "001", "001", "111", "001", "001", "111"],
    "4": ["101", "101", "101", "111", "001", "001", "001"],
    "5": ["111", "100", "100", "111", "001", "001", "111"],
    "6": ["111", "100", "100", "111", "101", "101", "111"],
    "7": ["111", "001", "001", "010", "010", "010", "010"],
    "8": ["111", "101", "101", "111", "101", "101", "111"],
    "9": ["111", "101", "101", "111", "001", "001", "111"],
    ":": ["0", "1", "1", "0", "1", "1", "0"],
    " ": ["0", "0", "0", "0", "0", "0", "0"],
}


def draw_bitmap_char(px, ch, x, y, color, scale=2):
    glyph = FONT_5X7.get(ch, FONT_5X7[" "])

    for gy, row in enumerate(glyph):
        for gx, bit in enumerate(row):
            if bit != "1":
                continue

            for sy in range(scale):
                for sx in range(scale):
                    xx = x + gx * scale + sx
                    yy = y + gy * scale + sy
                    if 0 <= xx < 64 and 0 <= yy < 16:
                        px[xx, yy] = color

    return x + len(glyph[0]) * scale


def render_custom_clock_png(path="preview.png", text="12:34", color_rgb=(0, 255, 0)):
    """
    Render a custom 64x16 clock preview PNG.

    This is intentionally PNG-only. It does not scan, connect, login, or upload.
    """
    W, H = 64, 16
    img = Image.new("RGB", (W, H), (0, 0, 0))
    px = img.load()

    scale = 2
    spacing = 2

    widths = []
    for ch in text:
        glyph = FONT_5X7.get(ch, FONT_5X7[" "])
        widths.append(len(glyph[0]) * scale)

    total_w = sum(widths) + spacing * (len(text) - 1)
    x = max(0, (W - total_w) // 2)
    y = 1

    for ch in text:
        old_x = x
        x = draw_bitmap_char(px, ch, x, y, color_rgb, scale=scale)
        x += spacing

    img.save(path)
    print(f"saved {path} ({W}x{H})")



CLOCK_FACES = {
    "pipboy": {
        "custom_font": "pipboy",
        "color": "#00ff66",
        "style": 2,
        "hour_x": 17,
        "colon_x": 31,
        "minute_x": 34,
        "clock_y": 0,
        "colon_w": None,
    },
}


def load_clock_face(name_or_path):
    path = Path(name_or_path)

    if not path.exists():
        path = Path("clock_faces") / name_or_path

    face_json = path / "face.json"

    if face_json.exists():
        with open(face_json, "r", encoding="utf-8") as f:
            return json.load(f)

    if name_or_path in CLOCK_FACES:
        return CLOCK_FACES[name_or_path]

    raise SystemExit(f"ERROR: clock face not found: {name_or_path}")

def brightness_value(value):
    try:
        value = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("brightness must be an integer from 5 to 255")

    if not 5 <= value <= 255:
        raise argparse.ArgumentTypeError("brightness must be between 5 and 255")

    return value


def parse_args():
    p = argparse.ArgumentParser(
        prog="coolledux-upload",
        description="Upload GIF animations or native clock programs to a CoolLEDUX BLE LED panel.",
    )

    p.add_argument("gif", nargs="?", help="GIF file to upload")
    p.add_argument(
        "--multi",
        nargs="+",
        metavar="GIF",
        help="Upload multiple GIFs as one cycling program set",
    )
    p.add_argument("--clock", action="store_true", help="Upload native live clock program")
    p.add_argument("--style", type=int, default=None, help="Clock style number")
    p.add_argument("--color", default=None, help="Clock color name or #RRGGBB")
    p.add_argument("--custom-font", default=None, help="Use custom native live clock font, example: pipboy")
    p.add_argument("--custom-colon", default=None, help="Use custom native clock colon bitmap file")
    p.add_argument("--clock-face", default=None, help="Apply clock face name or folder path")
    p.add_argument("--24-hour", dest="twentyfour", action="store_true", help="Use 24-hour clock mode. Default is 12-hour.")
    p.add_argument("--hour-x", type=int, help="Override clock hour X position")
    p.add_argument("--colon-x", type=int, help="Override clock colon X position")
    p.add_argument("--minute-x", type=int, help="Override clock minute X position")
    p.add_argument("--clock-y", type=int, help="Override clock Y position for hour/colon/minute")
    p.add_argument("--colon-w", type=int, help="Override clock colon width")
    p.add_argument("--address", default=DEFAULT_ADDR, help="BLE MAC address")
    p.add_argument("--auto", action="store_true", help="Auto-scan for a CoolLEDUX panel")
    p.add_argument("--scan", action="store_true", help="List nearby BLE devices and exit")
    p.add_argument("--scan-timeout", type=int, default=8, help="BLE scan timeout in seconds")
    p.add_argument("--width", type=int, default=64, help="Panel width")
    p.add_argument("--height", type=int, default=16, help="Panel height")
    p.add_argument("--max-frames", type=int, default=40, help="Maximum GIF frames to upload")
    p.add_argument("--index", type=int, default=0, help="Program index to upload")
    p.add_argument("--speed", type=float, default=1.0, help="Playback speed multiplier. 2.0 is twice as fast, 0.5 is half speed")
    p.add_argument("--quiet", action="store_true", help="Hide notify ACK spam")
    p.add_argument("--force", action="store_true", help="Force re-upload even if the panel already contains the program")
    p.add_argument("--brightness", type=brightness_value, metavar="5-255", help="Set panel brightness (5-255)")
    p.add_argument("--flip", choices=("none", "x", "y", "xy"), help="Set persistent panel orientation")
    p.add_argument("--sync-time", action="store_true", help="Synchronize panel clock from system time")
    p.add_argument("--render-clock", action="store_true", help="Render custom 64x16 clock PNG only; no BLE upload")
    p.add_argument("--upload-render-clock", action="store_true", help="Render custom clock and upload it as a static 64x16 program")
    p.add_argument("--save", default="preview.png", help="Output PNG path for --render-clock")
    p.add_argument("--render-text", default=None, help="Text to render. Default: current system time")
    p.add_argument("--version", action="version", version=f"CoolLEDUX Linux Uploader v{VERSION}")

    return p.parse_args()


def apply_clock_face(args):
    if not args.clock_face:
        return

    face = load_clock_face(args.clock_face)

    if args.custom_font is None:
        face_path = Path(args.clock_face)

        if not face_path.exists():
            face_path = Path("clock_faces") / args.clock_face

        digits_file = face_path / "digits.txt"

        if digits_file.exists():
            args.custom_font = str(digits_file)
        else:
            args.custom_font = face.get("custom_font")

    # Automatically use colon.txt from the clock-face folder.
    face_path = Path(args.clock_face)

    if not face_path.exists():
        face_path = Path("clock_faces") / args.clock_face

    colon_file = face_path / "colon.txt"

    if args.custom_colon is None and colon_file.exists():
        args.custom_colon = str(colon_file)

    # Apply theme defaults only when user did not override them.
    if args.color is None:
        args.color = face.get("color", "white")
    if args.style is None:
        args.style = face.get("style", 1)

    if args.hour_x is None:
        args.hour_x = face.get("hour_x")
    if args.colon_x is None:
        args.colon_x = face.get("colon_x")
    if args.minute_x is None:
        args.minute_x = face.get("minute_x")
    if args.clock_y is None:
        args.clock_y = face.get("clock_y")
    if args.colon_w is None:
        args.colon_w = face.get("colon_w")


def main():
    args = parse_args()
    apply_clock_face(args)

    # Normal defaults when no clock face supplied them.
    if args.color is None:
        args.color = "white"
    if args.style is None:
        args.style = 1

    if args.render_clock:
        rgb = color_name_to_rgb(args.color)
        text = args.render_text or datetime.now().strftime("%I:%M").lstrip("0")
        render_custom_clock_png(args.save, text=text, color_rgb=rgb)
        return

    if args.upload_render_clock:
        rgb = color_name_to_rgb(args.color)
        text = args.render_text or datetime.now().strftime("%I:%M").lstrip("0")
        temp_png = ".render-clock-temp.png"
        temp_gif = ".render-clock-temp.gif"

        render_custom_clock_png(temp_png, text=text, color_rgb=rgb)

        img = Image.open(temp_png).convert("RGB")
        img.save(
            temp_gif,
            save_all=True,
            append_images=[img.copy()],
            duration=[1000, 1000],
            loop=0,
        )

        args.gif = temp_gif
        asyncio.run(upload(args))
        return

    if args.scan:
        asyncio.run(scan_devices(timeout=args.scan_timeout))
        return

    if args.sync_time:
        asyncio.run(sync_time(args))
        return

    if args.brightness is not None and not args.gif and not args.clock:
        asyncio.run(set_brightness(args))
        return

    if args.flip is not None and not args.gif and not args.clock:
        asyncio.run(set_flip(args))
        return

    if args.multi:
        if args.gif:
            raise SystemExit(
                "ERROR: use either a single positional GIF or --multi, not both."
            )

        if args.clock:
            raise SystemExit(
                "ERROR: --multi cannot be combined with --clock."
            )

        if args.force:
            raise SystemExit(
                "ERROR: --force is not supported with --multi because "
                "forced GIF uploads alter loop timing."
            )

        if len(args.multi) < 2:
            raise SystemExit(
                "ERROR: --multi requires at least two GIF files."
            )

        for gif_path in args.multi:
            if not Path(gif_path).exists():
                raise SystemExit(
                    f"ERROR: GIF file not found: {gif_path}"
                )

        asyncio.run(upload_multiple(args, args.multi))
        return

    if args.clock:
        if args.style < 1 or args.style > 27:
            raise SystemExit("ERROR: official clock styles supported: 1-27.")
        asyncio.run(upload_clock(args))
        return

    if not args.gif:
        raise SystemExit("ERROR: missing GIF file. Example: coolledux-upload animation.gif --auto")

    if not Path(args.gif).exists():
        raise SystemExit(f"ERROR: GIF file not found: {args.gif}")

    asyncio.run(upload(args))


if __name__ == "__main__":
    main()
