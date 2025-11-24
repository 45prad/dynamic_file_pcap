# helper_ccsds.py
import struct
from typing import Iterator, Tuple, Dict
from helper_crc16 import crc16_ccitt

SYNC_WORD = 0x1ACFFC1D

def find_sync_offsets(stream: bytes) -> Iterator[int]:
    sync_bytes = struct.pack(">I", SYNC_WORD)
    idx = 0
    while True:
        off = stream.find(sync_bytes, idx)
        if off == -1:
            break
        yield off
        idx = off + 1

def parse_primary_header(header: bytes) -> Dict[str, int]:
    if len(header) != 6:
        raise ValueError("Primary header must be 6 bytes")
    first_two, second_two, length_field = struct.unpack(">HHH", header)

    version      = (first_two >> 13) & 0x7
    pkt_type     = (first_two >> 12) & 0x1
    sec_hdr_flag = (first_two >> 11) & 0x1
    apid         = first_two & 0x7FF

    seq_flags = (second_two >> 14) & 0x3
    seq_count = second_two & 0x3FFF

    return {
        "version": version,
        "type": pkt_type,
        "sec_hdr_flag": sec_hdr_flag,
        "apid": apid,
        "seq_flags": seq_flags,
        "seq_count": seq_count,
        "length": length_field,  # payload_len - 1
    }

def iter_packets(stream: bytes) -> Iterator[Tuple[Dict[str, int], bytes]]:
    for off in find_sync_offsets(stream):
        hdr_start = off + 4
        if hdr_start + 6 > len(stream):
            continue

        header = stream[hdr_start:hdr_start+6]
        hdr = parse_primary_header(header)

        payload_len = hdr["length"] + 1
        payload_start = hdr_start + 6
        payload_end = payload_start + payload_len
        crc_start = payload_end
        crc_end = crc_start + 2
        if crc_end > len(stream):
            continue

        payload = stream[payload_start:payload_end]
        (crc_stream,) = struct.unpack("<H", stream[crc_start:crc_end])
        crc_calc = crc16_ccitt(header + payload)
        if crc_calc != crc_stream:
            continue

        yield hdr, payload
