# IPMI_enumeration

**IPMI 2.0 RAKP hash grabber & username enumerator** — pure Python, no dependencies.

Sends two crafted UDP packets to an IPMI 2.0 (RMCP+) BMC on port 623 and captures the
HMAC-SHA1 password hash returned during the RAKP key exchange. Works against Dell iDRAC,
HP iLO, Supermicro, Lenovo XCC, and any other BMC exposing IPMI 2.0 — **regardless of
authentication settings**, since the hash is returned during pre-authentication.

The same request/response pattern doubles as a **username enumerator**: a valid user gets
a hash back, an invalid user gets an RAKP2 error code.

## Output

Hashcat format, mode **7300** (IPMI2 RAKP HMAC-SHA1):

```
user:salt:hmac
```

## Usage

```bash
# grab with default username list (admin, ADMIN, Administrator, root)
python3 ipmi_rakp_grab.py <IP>

# specific username(s)
python3 ipmi_rakp_grab.py <IP> -u admin sysadmin

# username wordlist (one per line) + save results
python3 ipmi_rakp_grab.py <IP> -U users.txt -o hash.txt

# crack offline — output is `user:salt:hash` (metasploit-style), so strip the
# username first: hashcat -m 7300 expects only `salt:hash`.
# (do NOT use process substitution <() — hashcat can't read pipe hashfiles)
cut -d: -f2- hash.txt > hashcat_ready.txt
hashcat -m 7300 hashcat_ready.txt /usr/share/wordlists/rockyou.txt
```

Options: `-p` UDP port (default 623), `-t` timeout in seconds (default 5).

## How it works

```
attacker                        BMC (UDP 623)
   |--- Open Session Request ------->|
   |<-- Open Session Reply ----------|
   |--- RAKP Message 1 (username) -->|
   |<-- RAKP Message 2               |   contains BMC random + GUID +
   |                                 |   HMAC-SHA1(password)  <-- the hash
```

No login is attempted, so account lockout is not triggered.

## Requirements

- Python 3.6+ (stdlib only: `socket`, `argparse`, `os`)
- Network reachability to the target on UDP 623

## Notes

- BMCs that only speak IPMI 1.5 do not answer the RMCP+ Open Session (different attack).
- Some BMCs return a hash even for nonexistent users — enumeration is then unreliable,
  but the hash still cracks.
- HP iLO may answer with a session-id error on the first RAKP attempt; this is retried
  automatically.

## Credits

- Protocol bytes ported from Metasploit `auxiliary/scanner/ipmi/ipmi_dumphashes`
  (`Rex::Proto::IPMI`)
- Offline cracking: [hashcat](https://hashcat.net/hashcat/) mode 7300

## Author

**raflesiait** — [github.com/raflesiait](https://github.com/raflesiait)

## Disclaimer

This tool is provided for **authorized security testing only** — your own lab
(Hack The Box, TryHackMe, home lab) or engagements with explicit written permission.
Grabbing credentials from systems you do not own or lack permission to test is illegal.
