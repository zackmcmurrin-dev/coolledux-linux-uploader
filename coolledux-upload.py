#!/usr/bin/env python3
import argparse
import asyncio
import time
from pathlib import Path

from bleak import BleakClient, BleakScanner
from PIL import Image, ImageSequence


VERSION = "0.1.0"
DEFAULT_ADDR = "01:00:00:54:EC:17"
CHAR = "0000fff1-0000-1000-8000-00805f9b34fb"

N = 512
F = 18
THRESHOLD = 2
NIL = N

ack_queue = asyncio.Queue()


def u16(n): return int(n).to_bytes(2, "big")
def u32(n): return int(n).to_bytes(4, "big", signed=False)


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

    if not src:
        return b""

    for i in range(N + 1, N + 257):
        rson[i] = NIL
    for i in range(N):
        dad[i] = NIL

    out = bytearray()
    code_buf = bytearray(17)
    code_buf[0] = 0
    code_buf_ptr = 1
    mask = 1

    s = 0
    r = N - F
    src_pos = 0
    length = 0

    while length < F and src_pos < len(src):
        text_buf[r + length] = src[src_pos]
        length += 1
        src_pos += 1

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
            code_buf[code_buf_ptr + 1] = ((match_position >> 4) & 0xF0) | (match_length - 3)
            code_buf_ptr += 2

        mask = (mask << 1) & 0xFF

        if mask == 0:
            out.extend(code_buf[:code_buf_ptr])
            code_buf = bytearray(17)
            code_buf[0] = 0
            code_buf_ptr = 1
            mask = 1

        last_match_length = match_length
        i = 0

        while i < last_match_length and src_pos < len(src):
            delete_node(s)
            c = src[src_pos]
            src_pos += 1

            text_buf[s] = c
            if s < F - 1:
                text_buf[s + N] = c

            s = (s + 1) & (N - 1)
            r = (r + 1) & (N - 1)
            insert_node(r)
            i += 1

        while i < last_match_length:
            delete_node(s)
            s = (s + 1) & (N - 1)
            r = (r + 1) & (N - 1)
            length -= 1
            if length > 0:
                insert_node(r)
            i += 1

        if length <= 0:
            break

    if code_buf_ptr > 1:
        out.extend(code_buf[:code_buf_ptr])

    return bytes(out)


def transfer(v):
    if v >= 238:
        return 15
    if v <= 47:
        return 0
    return ((v - 47) // 14) + 1


def rgb444(r, g, b):
    rr = transfer(r)
    gg = transfer(g)
    bb = transfer(b)
    return bytes([rr, (gg << 4) | bb])


def frame_to_native_bytes(img, width, height):
    img = img.convert("RGBA").resize((width, height), Image.Resampling.NEAREST)
    data = bytearray()

    for x in range(width):
        for y in range(height):
            r, g, b, a = img.getpixel((x, y))
            if a < 128:
                r = g = b = 0
            data += rgb444(r, g, b)

    return bytes(data)


def load_gif_frames(path, width, height, max_frames, speed=1.0, force=False):
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

        frames.append(frame_to_native_bytes(frame, width, height))
        delays.append(duration)

    if not frames:
        raise RuntimeError("No frames loaded from GIF")

    if force and delays:
        delays[0] = 20 + (int(time.time() * 1000) % 500)

    return frames, delays


def build_native_program_from_gif(path, width, height, max_frames, speed=1.0, force=False):
    frames, delays = load_gif_frames(path, width, height, max_frames, speed, force)

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
    return wrap(bytes([0x04, level & 0x0F]))


def chunks(data, size=1024):
    for i in range(0, len(data), size):
        yield data[i:i + size]


def notification_handler(sender, data):
    payload = unwrap(data)
    if not getattr(notification_handler, "quiet", False):
        print("notify:", payload.hex(" "))
    ack_queue.put_nowait(payload)


async def scan_devices(timeout=8):
    print(f"scanning for BLE devices ({timeout}s)...")
    devices = await BleakScanner.discover(timeout=timeout)

    if not devices:
        print("no BLE devices found")
        return

    for d in devices:
        print(f"{d.address}  {d.name or '(no name)'}")


async def find_coolledux(timeout=8):
    print(f"scanning for CoolLEDUX panel ({timeout}s)...")
    devices = await BleakScanner.discover(timeout=timeout)

    matches = []
    for d in devices:
        name = d.name or ""
        if name.lower() == "coolledux":
            matches.append(d)

    if not matches:
        print("no CoolLEDUX devices found")
        print("nearby BLE devices:")
        for d in devices:
            print(f"  {d.address}  {d.name or '(no name)'}")
        raise RuntimeError("No CoolLEDUX panel found. Try --address XX:XX:XX:XX:XX:XX")

    if len(matches) > 1:
        print("multiple CoolLEDUX panels found:")
        for d in matches:
            print(f"  {d.address}  {d.name}")
        print("using first match")

    panel = matches[0]
    print(f"found CoolLEDUX: {panel.address}")
    return panel.address


async def wait_for_ack(kind, chunk_index=None, timeout=5.0):
    while True:
        payload = await asyncio.wait_for(ack_queue.get(), timeout=timeout)

        if kind == "login" and len(payload) >= 2 and payload[0] == 0x0D and payload[-1] == 0:
            return payload

        if kind == "start" and len(payload) >= 2 and payload[0] == 0x02:
            return payload

        if kind == "chunk" and len(payload) >= 5 and payload[0] == 0x03:
            idx = (payload[2] << 8) | payload[3]
            status = payload[4]

            if idx == chunk_index:
                if status != 0:
                    raise RuntimeError(f"chunk {chunk_index} error {status}")
                return payload


async def write_ble_packet(client, packet, mtu_payload=180):
    for i in range(0, len(packet), mtu_payload):
        await client.write_gatt_char(CHAR, packet[i:i + mtu_payload], response=False)
        await asyncio.sleep(0.01)


async def upload(args):
    notification_handler.quiet = args.quiet

    if args.auto:
        args.address = await find_coolledux(timeout=args.scan_timeout)

    program, frame_count, delays = build_native_program_from_gif(
        args.gif,
        args.width,
        args.height,
        args.max_frames,
        args.speed,
        args.force,
    )

    compressed = lzss_compress(program)
    chunk_list = list(chunks(compressed))

    print(f"gif file:            {args.gif}")
    print(f"address:             {args.address}")
    print(f"frames:              {frame_count}")
    print(f"first delay:         {delays[0]} ms")
    print(f"speed multiplier:    {args.speed}x")
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
            await asyncio.sleep(0.2)

        print("sending start")
        await write_ble_packet(client, make_start_packet(program, index=args.index))
        start_ack = await wait_for_ack("start")
        print("start ACK OK")

        if len(start_ack) >= 2 and start_ack[1] == 1:
            print("device says program already exists; skipping chunk upload")
            print("Use --force to change timing and force a re-upload.")
            return

        for idx, chunk in enumerate(chunk_list):
            percent = int(((idx + 1) / len(chunk_list)) * 100)
            print(f"sending chunk {idx + 1}/{len(chunk_list)} ({percent}%), raw {len(chunk)}")
            await write_ble_packet(client, make_chunk_packet(compressed, idx, chunk))

            if idx == len(chunk_list) - 1:
                try:
                    await wait_for_ack("chunk", idx, timeout=2)
                    print("final chunk ACK OK")
                except TimeoutError:
                    print("final chunk no ACK; possible success")
            else:
                await wait_for_ack("chunk", idx)
                print(f"chunk {idx} ACK OK")

            await asyncio.sleep(0.03)

        print("done, watch panel")
        await asyncio.sleep(3)


def parse_args():
    p = argparse.ArgumentParser(description="Upload GIF animations to a CoolLEDUX BLE LED panel.")
    p.add_argument("gif", nargs="?", help="GIF file to upload")
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
    p.add_argument("--force", action="store_true", help="Force re-upload by changing first frame delay")
    p.add_argument("--brightness", type=int, choices=range(0, 16), metavar="0-15", help="Set brightness before upload")
    p.add_argument("--version", action="version", version=f"CoolLEDUX Linux Uploader v{VERSION}")
    return p.parse_args()


def main():
    args = parse_args()

    if args.scan:
        asyncio.run(scan_devices(timeout=args.scan_timeout))
        return

    if not args.gif:
        raise SystemExit("ERROR: missing GIF file. Example: coolledux-upload animation.gif --auto")

    if not Path(args.gif).exists():
        raise FileNotFoundError(args.gif)

    asyncio.run(upload(args))


if __name__ == "__main__":
    main()
