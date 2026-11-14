"""Regression and adversarial tests for cross-version tshark packet CSV verification."""
import socket
import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from hospital_soc.packets import FIELDS, validate_pcapng, verified_packet_rows

HEADER = ','.join(FIELDS)
REQ_LINE = 'Host: 10.77.0.1:8080\\r\\n,X-Lab-Run-ID: 00000000-0000-0000-0000-000000000001\\r\\n'

SYN_ROW = '"1","1794604224.112314812","10.77.0.10","10.77.0.1","60628","8080",,,,,'
REQ_ROW = f'"2","1794604224.113002152","10.77.0.10","10.77.0.1","60628","8080","GET","/health",,,"{REQ_LINE}"'
RESP_ROW_422 = '"3","1794604224.119404789","10.77.0.1","10.77.0.10","8080","60628",,,"200","65",'
RESP_ROW_469 = '"3","1794604224.119404789","10.77.0.1","10.77.0.10","8080","60628",,"/health","200","65",'

CSV_422 = '\n'.join([HEADER, SYN_ROW, REQ_ROW, RESP_ROW_422]) + '\n'
CSV_469 = '\n'.join([HEADER, SYN_ROW, REQ_ROW, RESP_ROW_469]) + '\n'


def _stub_tshark(monkeypatch, stdout_text: str):
    """Patch subprocess/executable discovery for hermetic CSV comparison tests."""
    monkeypatch.setattr('hospital_soc.packets.shutil.which', lambda name: 'tshark')
    monkeypatch.setattr(
        'hospital_soc.packets.subprocess.run',
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=stdout_text.encode('utf-8'), stderr=b''),
    )


def _write_csv(tmp_path: Path, text: str) -> tuple[Path, Path]:
    capture = tmp_path / 'traffic.pcapng'
    capture.write_bytes(b'placeholder')
    csv_path = tmp_path / 'frames.csv'
    csv_path.write_text(text, encoding='utf-8')
    return capture, csv_path


def _find_local_tshark() -> str | None:
    import shutil

    executable = shutil.which('tshark')
    if executable:
        return executable
    known = Path('C:/Program Files/Wireshark/tshark.exe')
    return str(known) if known.is_file() else None


def _ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    total = sum(int.from_bytes(data[i:i + 2], 'big') for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def _tcp_frame(src_mac: bytes, dst_mac: bytes, src_ip_s: str, dst_ip_s: str, sport: int, dport: int,
               seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    src_ip = socket.inet_aton(src_ip_s)
    dst_ip = socket.inet_aton(dst_ip_s)
    tcp_no_ck = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 << 4), flags, 65535, 0, 0)
    pseudo = src_ip + dst_ip + struct.pack('!BBH', 0, 6, len(tcp_no_ck) + len(payload))
    ck = _ip_checksum(pseudo + tcp_no_ck + payload)
    tcp_hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 << 4), flags, 65535, ck, 0)
    total_len = 20 + len(tcp_hdr) + len(payload)
    ip_no_ck = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, 1, 0, 64, 6, 0, src_ip, dst_ip)
    ip_hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, 1, 0, 64, 6, _ip_checksum(ip_no_ck), src_ip, dst_ip)
    return dst_mac + src_mac + struct.pack('!H', 0x0800) + ip_hdr + tcp_hdr + payload


def _build_synthetic_http_pcapng(target: Path) -> None:
    """Create a valid IPv4/TCP/HTTP GET+200 PCAPNG for real tshark parsing tests."""
    mac_c = b'\x02\x00\x00\x00\x00\x01'
    mac_s = b'\x02\x00\x00\x00\x00\x02'
    req = b'GET /health HTTP/1.1\r\nHost: 10.77.0.1:8080\r\nX-Lab-Run-ID: 00000000-0000-0000-0000-000000000001\r\n\r\n'
    resp = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'
    frames = [
        _tcp_frame(mac_c, mac_s, '10.77.0.10', '10.77.0.1', 50000, 8080, 1, 0, 0x02, b''),
        _tcp_frame(mac_s, mac_c, '10.77.0.1', '10.77.0.10', 8080, 50000, 1, 2, 0x12, b''),
        _tcp_frame(mac_c, mac_s, '10.77.0.10', '10.77.0.1', 50000, 8080, 2, 2, 0x10, b''),
        _tcp_frame(mac_c, mac_s, '10.77.0.10', '10.77.0.1', 50000, 8080, 2, 2, 0x18, req),
        _tcp_frame(mac_s, mac_c, '10.77.0.1', '10.77.0.10', 8080, 50000, 2, 2 + len(req), 0x18, resp),
        _tcp_frame(mac_c, mac_s, '10.77.0.10', '10.77.0.1', 50000, 8080, 2 + len(req), 2 + len(resp), 0x11, b''),
    ]
    shb = struct.pack('<IIIHHqI', 0x0a0d0d0a, 28, 0x1a2b3c4d, 1, 0, -1, 28)
    idb = struct.pack('<IIHHII', 1, 20, 1, 0, 65535, 20)
    blocks = [shb, idb]
    base_us = 1_790_000_000_000_000
    for idx, frame in enumerate(frames):
        ts = base_us + idx * 1_000
        padded = frame + b'\x00' * ((-len(frame)) % 4)
        body = struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(frame), len(frame)) + padded
        total = 12 + len(body)
        blocks.append(struct.pack('<II', 6, total) + body + struct.pack('<I', total))
    target.write_bytes(b''.join(blocks))


def test_exact_csv_match_passes(tmp_path, monkeypatch):
    _stub_tshark(monkeypatch, CSV_469)
    capture, csv_path = _write_csv(tmp_path, CSV_469)
    rows = verified_packet_rows(capture, csv_path)
    assert len(rows) == 3
    assert rows[1]['http.request.uri'] == '/health'


def test_469_actual_accepts_422_empty_response_uri(tmp_path, monkeypatch):
    _stub_tshark(monkeypatch, CSV_469)
    capture, csv_path = _write_csv(tmp_path, CSV_422)
    rows = verified_packet_rows(capture, csv_path)
    assert len(rows) == 3
    assert rows[1]['http.request.method'] == 'GET'
    assert rows[2]['http.response.code'] == '200'


def test_422_actual_accepts_469_paired_response_uri(tmp_path, monkeypatch):
    _stub_tshark(monkeypatch, CSV_422)
    capture, csv_path = _write_csv(tmp_path, CSV_469)
    rows = verified_packet_rows(capture, csv_path)
    assert len(rows) == 3


@pytest.mark.parametrize('tampered_csv,actual_csv', [
    # Forged response URI when local tshark has actual '/health'
    ('\n'.join([HEADER, SYN_ROW, REQ_ROW, RESP_ROW_469.replace('/health', '/forged')]) + '\n', CSV_469),
    # Forged response URI when local tshark 4.2.2 leaves response URI empty
    ('\n'.join([HEADER, SYN_ROW, REQ_ROW, RESP_ROW_469.replace('/health', '/forged')]) + '\n', CSV_422),
    # Stripped request URI on an HTTP request frame
    ('\n'.join([HEADER, SYN_ROW, REQ_ROW.replace('"/health"', ''), RESP_ROW_422]) + '\n', CSV_469),
    # Injected URI on a non-HTTP TCP frame (no response code)
    ('\n'.join([HEADER, '"1","1794604224.112314812","10.77.0.10","10.77.0.1","60628","8080",,"/health",,,', REQ_ROW, RESP_ROW_422]) + '\n', CSV_469),
    # Tampered HTTP response code on a response frame
    ('\n'.join([HEADER, SYN_ROW, REQ_ROW, RESP_ROW_422.replace('"200"', '"401"')]) + '\n', CSV_469),
    # Tampered content length
    ('\n'.join([HEADER, SYN_ROW, REQ_ROW, RESP_ROW_422.replace('"65"', '"99"')]) + '\n', CSV_469),
    # Unquoted field formatting change on differing response row ('' replaced by '""')
    ('\n'.join([HEADER, SYN_ROW, REQ_ROW, RESP_ROW_422.replace(',,,"200"', ',"",,"200"')]) + '\n', CSV_469),
    # Truncated trailing newline
    (CSV_422.rstrip('\n'), CSV_469),
    # Swapped / dropped row
    ('\n'.join([HEADER, SYN_ROW, REQ_ROW]) + '\n', CSV_469),
])
def test_tampered_or_malformed_csv_still_rejected(tmp_path, monkeypatch, tampered_csv, actual_csv):
    _stub_tshark(monkeypatch, actual_csv)
    capture, csv_path = _write_csv(tmp_path, tampered_csv)
    with pytest.raises(ValueError, match='Packet CSV differs'):
        verified_packet_rows(capture, csv_path)


def test_real_tshark_verifies_422_and_469_exports_of_http_pcapng(tmp_path):
    tshark = _find_local_tshark()
    if not tshark:
        pytest.skip('tshark binary not installed on host')
    capture = tmp_path / 'traffic.pcapng'
    _build_synthetic_http_pcapng(capture)
    assert validate_pcapng(capture) == 6

    cmd = [tshark, '-r', str(capture), '-d', 'tcp.port==8080,http', '-d', 'tcp.port==9080,http',
           '-d', 'tcp.port==9081,http', '-T', 'fields', '-E', 'header=y', '-E', 'separator=,', '-E', 'quote=d']
    for field in FIELDS:
        cmd += ['-e', field]
    exported = subprocess.run(cmd, capture_output=True, check=True).stdout.decode('utf-8').replace('\r\n', '\n')

    # Exact local tshark export passes
    csv_exact = tmp_path / 'frames.csv'
    csv_exact.write_text(exported, encoding='utf-8')
    rows = verified_packet_rows(capture, csv_exact)
    assert len(rows) == 6
    assert any(r['http.request.method'] == 'GET' and r['http.request.uri'] == '/health' for r in rows)

    # Verify cross-version equivalence: both 4.2.2 (empty response URI) and 4.6.9 (inherited request URI) pass
    lines = exported.splitlines()
    lines_422 = [lines[0]]
    lines_469 = [lines[0]]
    lines_forged = [lines[0]]
    replaced_response = False
    for line in lines[1:]:
        if ',"200","2",' in line:
            replaced_response = True
            if ',"/health","200","2",' in line:
                lines_422.append(line.replace(',"/health","200","2",', ',,"200","2",', 1))
                lines_469.append(line)
                lines_forged.append(line.replace(',"/health","200","2",', ',"/evil","200","2",', 1))
            elif ',,"200","2",' in line:
                lines_422.append(line)
                lines_469.append(line.replace(',,"200","2",', ',"/health","200","2",', 1))
                lines_forged.append(line.replace(',,"200","2",', ',"/evil","200","2",', 1))
            else:
                raise AssertionError(f'Unexpected HTTP response row format: {line}')
        else:
            lines_422.append(line)
            lines_469.append(line)
            lines_forged.append(line)
    assert replaced_response

    csv_422 = tmp_path / 'frames_422.csv'
    csv_422.write_text('\n'.join(lines_422) + '\n', encoding='utf-8')
    assert len(verified_packet_rows(capture, csv_422)) == 6

    csv_469 = tmp_path / 'frames_469.csv'
    csv_469.write_text('\n'.join(lines_469) + '\n', encoding='utf-8')
    assert len(verified_packet_rows(capture, csv_469)) == 6

    # Forged URI on response still fails under real tshark
    forged_csv = tmp_path / 'frames_forged.csv'
    forged_csv.write_text('\n'.join(lines_forged) + '\n', encoding='utf-8')
    with pytest.raises(ValueError, match='Packet CSV differs'):
        verified_packet_rows(capture, forged_csv)
