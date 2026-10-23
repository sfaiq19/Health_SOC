"""Structural PCAPNG checks and trusted tshark re-export binding."""
import csv
import io
from pathlib import Path
import shutil
import struct
import subprocess

FIELDS = ['frame.number', 'frame.time_epoch', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
          'http.request.method', 'http.request.uri', 'http.response.code', 'http.content_length', 'http.request.line']


def validate_pcapng(path: Path) -> int:
    packets, interfaces = 0, 0
    endian = None
    with path.open('rb') as stream:
        while prefix := stream.read(12):
            if len(prefix) != 12:
                raise ValueError('Truncated capture block header')
            if prefix[:4] == bytes.fromhex('0a0d0d0a'):
                if prefix[8:12] == bytes.fromhex('4d3c2b1a'):
                    endian = '<'
                elif prefix[8:12] == bytes.fromhex('1a2b3c4d'):
                    endian = '>'
                else:
                    raise ValueError('Invalid PCAPNG byte-order magic')
                interfaces = 0
            if endian is None:
                raise ValueError('PCAPNG must begin with a section')
            kind, length = struct.unpack(endian + 'II', prefix[:8])
            if length < 16 or length % 4 or length > 64 * 1024 * 1024:
                raise ValueError('Invalid PCAPNG block size')
            rest = stream.read(length - 12)
            if len(rest) != length - 12 or struct.unpack(endian + 'I', rest[-4:])[0] != length:
                raise ValueError('Truncated capture block or length disagreement')
            data = prefix + rest
            if kind == 0x0a0d0d0a and (length < 28 or struct.unpack(endian + 'H', data[12:14])[0] != 1):
                raise ValueError('Invalid section header')
            if kind == 1:
                if length < 20:
                    raise ValueError('Invalid interface block')
                interfaces += 1
            elif kind == 6:
                if length < 32:
                    raise ValueError('Invalid enhanced packet block')
                interface, _, _, captured, original = struct.unpack(endian + 'IIIII', data[8:28])
                if interface >= interfaces or captured == 0 or captured > original or captured > length - 32:
                    raise ValueError('Invalid captured packet')
                packets += 1
            elif kind == 3:
                if not interfaces or length <= 16:
                    raise ValueError('Invalid simple packet block')
                packets += 1
    if packets == 0:
        raise ValueError('Capture contains no packet blocks')
    return packets


def verified_packet_rows(capture: Path, fields_file: Path) -> list[dict]:
    executable = shutil.which('tshark')
    known = Path('C:/Program Files/Wireshark/tshark.exe')
    if not executable and known.is_file():
        executable = str(known)
    if not executable:
        raise ValueError('tshark unavailable: packet export cannot be independently verified')
    command = [executable, '-r', str(capture), '-d', 'tcp.port==8080,http', '-d', 'tcp.port==9080,http',
               '-d', 'tcp.port==9081,http', '-T', 'fields', '-E', 'header=y', '-E', 'separator=,', '-E', 'quote=d']
    for field in FIELDS:
        command += ['-e', field]
    result = subprocess.run(command, capture_output=True, timeout=120, check=False)
    if result.returncode:
        raise ValueError('tshark could not parse the collected capture')
    actual = result.stdout.decode('utf-8').replace('\r\n', '\n')
    supplied = fields_file.read_text(encoding='utf-8-sig').replace('\r\n', '\n')
    if actual != supplied:
        raise ValueError('Packet CSV differs from a fresh export of this capture')
    return list(csv.DictReader(io.StringIO(actual)))
