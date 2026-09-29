"""Synthetic offline fixture bytes only; never opens a network interface."""
from pathlib import Path
import struct


def beacon(ssid=b"test-wifi", sequence=17, rssi=-47):
    mac = bytes.fromhex("020000000001")
    header = struct.pack("<HH", 0x0080, 0) + b"\xff" * 6 + mac + mac + struct.pack("<H", sequence << 4)
    body = struct.pack("<QHH", 0, 100, 1) + bytes([0, len(ssid)]) + ssid + b"\x01\x01\x82"
    radio = struct.pack("<BBHI", 0, 0, 9 if rssi is not None else 8, 0x20 if rssi is not None else 0)
    if rssi is not None:
        radio += struct.pack("b", rssi)
    return radio + header + body


def write_pcap(path, packets=None, *, count=3, linktype=127, nanoseconds=False):
    """Write (seconds, fractional ticks, packet) records without packet libraries."""
    path = Path(path)
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", magic, 2, 4, 0, 0, 65535, linktype))
        if packets is None:
            packets = ((1_700_000_000 + i // 1000, i % 1000, beacon(sequence=i % 4096)) for i in range(count))
        for seconds, fraction, packet in packets:
            stream.write(struct.pack("<IIII", seconds, fraction, len(packet), len(packet)))
            stream.write(packet)
    return path
