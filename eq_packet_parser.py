#!/usr/bin/env python3
"""
EverQuest RoF2 / EQEmu Packet Parser
Parses a Wireshark JSON export and decodes app-layer opcodes using RoF2.xml.

════════════════════════════════════════════════════════════════
 Confirmed UDP payload layout  (EQEmu zone server, RoF2 client)
════════════════════════════════════════════════════════════════

 raw[0]   = 0x00        EQNet marker
 raw[1]   = EQNet type  (see below)
 raw[2]   = sequence byte
 raw[3:]  = zlib-compressed body  (magic 78 01 / 78 9c / 78 da)

After decompression, the body layout differs by outer type:

 ┌─────────────────────────────────────────────────────────────┐
 │ Type 0x03  "Combined" — multiple sub-packets                │
 │                                                             │
 │  Repeat:                                                    │
 │    [1B  sub_len]                                            │
 │    [sub_len bytes:                                          │
 │      [0x00]         inner EQNet marker                      │
 │      [0x09]         inner type (always Packet/Fragment)     │
 │      [1B  seq]      inner sequence                          │
 │      [1B  flags]    flags / sub-sequence byte               │
 │      [2B  opcode]   app opcode, little-endian               │
 │      [N B payload]  app data                                │
 │    ]                                                        │
 │  Until sub_len == 0 or end of buffer.                       │
 └─────────────────────────────────────────────────────────────┘

 ┌─────────────────────────────────────────────────────────────┐
 │ Type 0x09  "Fragment" — oversized-packet chunk              │
 │                                                             │
 │  First fragment:                                            │
 │    [2B  CRC/prefix]   (skip)                                │
 │    [2B  opcode]       app opcode, little-endian             │
 │    [N B payload]      partial app data                      │
 │                                                             │
 │  Continuation fragments:                                    │
 │    [2B  CRC/prefix]   (skip)                                │
 │    [N B raw bytes]    continuation of previous payload      │
 └─────────────────────────────────────────────────────────────┘

 Session-control types (0x01, 0x02, 0x04, 0x05, 0x06, 0x11):
   No app opcode — just EQNet transport bookkeeping.

════════════════════════════════════════════════════════════════
 Usage
════════════════════════════════════════════════════════════════

  python eq_packet_parser.py <capture.json> [options]

  --xml PATH        RoF2.xml opcode file   (default: RoF2.xml)
  --port PORT       Filter to this UDP port
  --raw-bytes N     Show N hex bytes of payload (default: 0)
  --filter NAME     Only show packets whose opcode name contains NAME
  --probe           Print header byte pattern table and exit
  --stats           Print opcode frequency table at end
  --output PATH     Output file (default: <input>_parsed.txt)
  --no-fragments    Hide fragment-continuation packets

Requires Python 3.10+, stdlib only.
"""

import json
import xml.etree.ElementTree as ET
import argparse
import sys
import zlib
import struct
from pathlib import Path
import math
from collections import Counter, defaultdict


# ─────────────────────────────────────────────────────────────────────────────
# 1.  Opcode table  (RoF2.xml — wire format)
# ─────────────────────────────────────────────────────────────────────────────

def load_opcodes(xml_path: str) -> dict:
    tree = ET.parse(xml_path)
    return {
        int(el.get("id", "0x0000"), 16): el.get("name", "OP_Unknown")
        for el in tree.findall("opcode")
    }


# ─────────────────────────────────────────────────────────────────────────────
# 2.  UDP payload extraction
# ─────────────────────────────────────────────────────────────────────────────

def get_udp_payload(pkt: dict):
    layers = pkt.get("_source", {}).get("layers", {})
    val = layers.get("udp", {}).get("udp.payload", "")
    if val:
        return bytes.fromhex(val.replace(":", ""))
    data = layers.get("data", {})
    for key in ("data.data", "data"):
        val = data.get(key, "")
        if val:
            return bytes.fromhex(val.replace(":", ""))
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 3.  EQNet type table
# ─────────────────────────────────────────────────────────────────────────────

EQNET_TYPES = {
    0x01: "SessionRequest",
    0x02: "SessionResponse",
    0x03: "Combined",      # zlib → [1B len][0x00][0x09][seq][flags][op 2B][data] ×N
    0x04: "Disconnect",
    0x05: "KeepAlive",
    0x06: "KeepAliveAck",
    0x09: "Fragment",      # zlib → [CRC 2B][op 2B][data]  (first frag only)
    0x0D: "OutOfOrder",
    0x11: "Ack",
}


# ─────────────────────────────────────────────────────────────────────────────
# 4.  Decoders
# ─────────────────────────────────────────────────────────────────────────────

def _op(body: bytes, offset: int, opcodes: dict) -> tuple:
    """Read a LE uint16 opcode from body[offset:offset+2]."""
    op = struct.unpack_from("<H", body, offset)[0]
    return op, opcodes.get(op, f"OP_Unknown(0x{op:04x})")


def decode_combined(body: bytes, opcodes: dict) -> list[dict]:
    """
    Type 0x03 Combined body.
    Format: [1B sub_len] [0x00][0x09][seq][flags][opcode 2B LE][payload] …
    Terminates on sub_len == 0 or buffer exhaustion.
    """
    results = []
    offset = 0
    sub_idx = 0
    while offset < len(body):
        sub_len = body[offset]; offset += 1
        if sub_len == 0 or offset + sub_len > len(body):
            break
        inner = body[offset:offset + sub_len]; offset += sub_len
        sub_idx += 1
        # Two inner-packet formats observed in captures:
        #
        # Format A (most common):
        #   [0x00][0x09][seq 1B][flags 1B][opcode 2B LE][payload]
        #   Used for: OP_Damage, OP_Action, OP_FormattedMessage, etc.
        #
        # Format B (bare opcode, no EQNet inner header):
        #   [opcode 2B LE][payload]
        #   Used for: OP_ClientUpdate, OP_Animation, OP_MobHealth, etc.
        if len(inner) >= 6 and inner[0] == 0x00:
            inner_type = inner[1]
            if inner_type == 0x09:
                # Format A — full inner EQNet header: [0x00][0x09][seq][flags][op 2B][payload]
                op, name = _op(inner, 4, opcodes)
                results.append({
                    "sub_index":        sub_idx,
                    "inner_seq":        inner[2],
                    "opcode_id":        op,
                    "opcode_name":      name,
                    "payload":          inner[6:],
                    "is_fragment_cont": False,
                    "error":            None,
                })
            else:
                # EQNet control packet inside Combined (Ack=0x11, KeepAlive=0x05, etc.)
                # These carry no app opcode — label them by their EQNet type name.
                type_name = EQNET_TYPES.get(inner_type, f"0x{inner_type:02x}")
                results.append({
                    "sub_index":        sub_idx,
                    "inner_seq":        inner[2] if len(inner) > 2 else None,
                    "opcode_id":        None,
                    "opcode_name":      f"EQNet:{type_name}",
                    "payload":          inner[3:],
                    "is_fragment_cont": False,
                    "error":            None,
                })
        elif len(inner) >= 2:
            # Format B — bare opcode, no EQNet inner header
            # Used by OP_ClientUpdate, OP_Animation, OP_MobHealth, etc.
            op, name = _op(inner, 0, opcodes)
            results.append({
                "sub_index":        sub_idx,
                "inner_seq":        None,
                "opcode_id":        op,
                "opcode_name":      name,
                "payload":          inner[2:],
                "is_fragment_cont": False,
                "error":            None,
            })
        else:
            results.append({
                "sub_index":        sub_idx,
                "inner_seq":        None,
                "opcode_id":        None,
                "opcode_name":      "?",
                "payload":          inner,
                "is_fragment_cont": False,
                "error":            f"Inner packet too short ({len(inner)}B)",
            })
    return results


def decode_fragment(body: bytes, opcodes: dict, is_first: bool) -> dict:
    """
    Type 0x09 Fragment body.
    First fragment:  [CRC 2B][opcode 2B LE][payload]
    Continuation:    [CRC 2B][raw bytes]
    """
    if is_first and len(body) >= 4:
        op, name = _op(body, 2, opcodes)
        return {"opcode_id": op, "opcode_name": name,
                "payload": body[4:], "is_fragment_cont": False, "error": None}
    if not is_first:
        return {"opcode_id": None, "opcode_name": "Fragment(continuation)",
                "payload": body[2:], "is_fragment_cont": True, "error": None}
    return {"opcode_id": None, "opcode_name": "?",
            "payload": body, "is_fragment_cont": False,
            "error": f"Fragment too short ({len(body)}B)"}


# ─────────────────────────────────────────────────────────────────────────────
# 5.  Fragment tracker
# ─────────────────────────────────────────────────────────────────────────────

class FragmentTracker:
    """Identifies first vs continuation fragments by per-stream sequence."""
    def __init__(self):
        self._last: dict = {}

    def is_first(self, stream_key: tuple, seq: int) -> bool:
        prev = self._last.get(stream_key)
        self._last[stream_key] = seq
        if prev is None:
            return True
        return seq != (prev + 1) & 0xFF


# ─────────────────────────────────────────────────────────────────────────────
# 6.  Top-level dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def decode_packet(raw: bytes, opcodes: dict,
                  frag: FragmentTracker, stream_key: tuple) -> list[dict]:
    """Decode one UDP payload → list of result dicts."""
    BASE = {"eqnet_type": "?", "seq": None, "compressed": False,
            "opcode_id": None, "opcode_name": "?", "payload": b"",
            "sub_index": None, "inner_seq": None,
            "is_fragment_cont": False, "error": None}

    if len(raw) < 3:
        return [{**BASE, "error": f"Too short ({len(raw)}B)"}]
    if raw[0] != 0x00:
        return [{**BASE, "eqnet_type": "non-EQNet?", "payload": raw,
                 "error": f"First byte 0x{raw[0]:02x}"}]

    net_type  = raw[1]
    seq_byte  = raw[2]
    type_name = EQNET_TYPES.get(net_type, f"Unknown(0x{net_type:02x})")
    body      = raw[3:]
    compressed = False

    # zlib decompress
    if len(body) >= 2 and body[0] == 0x78:
        try:
            body = zlib.decompress(body, 15)
            compressed = True
        except zlib.error as e:
            return [{**BASE, "eqnet_type": type_name, "seq": seq_byte,
                     "error": f"zlib: {e}", "payload": body}]

    common = {"eqnet_type": type_name, "seq": seq_byte, "compressed": compressed}

    if net_type == 0x03:                          # Combined
        subs = decode_combined(body, opcodes)
        return [{**BASE, **common, **s} for s in subs] if subs \
               else [{**BASE, **common}]

    if net_type == 0x09:                          # Fragment
        is_first = frag.is_first(stream_key, seq_byte)
        r = decode_fragment(body, opcodes, is_first)
        return [{**BASE, **common, **r}]

    # Session-control types — no app opcode
    return [{**BASE, **common, "opcode_name": "N/A", "payload": body}]


# ─────────────────────────────────────────────────────────────────────────────
# 7.  Formatting
# ─────────────────────────────────────────────────────────────────────────────

def hex_dump(data: bytes, n: int) -> str:
    chunk = data[:n]
    hp = " ".join(f"{b:02x}" for b in chunk)
    ap = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    tail = f"  +{len(data)-n} more" if len(data) > n else ""
    return f"{hp:<{n*3}}  |{ap}|{tail}"


def fmt(idx: int, ts: str, src: str, dst: str,
        r: dict, raw_len: int, show_bytes: int) -> str:
    op   = r["opcode_id"]
    ops  = f"0x{op:04x}" if op is not None else "  N/A"
    sub  = f" sub={r['sub_index']}" if r.get("sub_index") else ""
    iseq = f" iseq=0x{r['inner_seq']:02x}" if r.get("inner_seq") is not None else ""
    seq  = f" seq=0x{r['seq']:02x}" if r["seq"] is not None else ""
    cmp  = " [z]" if r["compressed"] else ""
    err  = f"  !! {r['error']}" if r["error"] else ""
    lines = [
        f"[{idx:>5}]  {ts:<18}  {src:<22} -> {dst:<22}  "
        f"raw={raw_len:<5}  EQNet={r['eqnet_type']}{seq}{cmp}{sub}{iseq}",
        f"          opcode={ops}  {r['opcode_name']}{err}",
    ]
    if show_bytes > 0 and r["payload"]:
        lines.append(f"          payload: {hex_dump(r['payload'], show_bytes)}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# 8.  Probe
# ─────────────────────────────────────────────────────────────────────────────

def probe(packets: list) -> None:
    seen = {}
    for pkt in packets:
        raw = get_udp_payload(pkt)
        if raw and len(raw) >= 3:
            k = (raw[0], raw[1])
            seen.setdefault(k, [])
            if len(seen[k]) < 2:
                seen[k].append(raw)
    print(f"\n{'='*80}\n Structure Probe — {len(seen)} patterns\n{'='*80}\n")
    for (b0, b1), exs in sorted(seen.items()):
        label = EQNET_TYPES.get(b1, f"Unknown(0x{b1:02x})") if b0==0 else "non-EQNet"
        zlb   = "zlib" if len(exs[0])>3 and exs[0][3]==0x78 else "raw"
        print(f"  [0x{b0:02x} 0x{b1:02x}]  {label:<20}  {zlb}")
        for ex in exs:
            print(f"    {hex_dump(ex, 24)}")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# 9.  Main parser
# ─────────────────────────────────────────────────────────────────────────────

def parse(packets, opcodes, port_filter, raw_bytes,
          name_filter, show_stats, hide_frags) -> tuple:
    counter   = Counter()              # overall opcode totals
    per_sec   = defaultdict(Counter)   # second -> opcode -> count
    total_udp = 0
    shown     = 0
    frag      = FragmentTracker()

    print("\n" + "="*100)
    print(" EQ RoF2 / EQEmu Packet Summary")
    print("="*100 + "\n")

    for i, pkt in enumerate(packets):
        layers   = pkt.get("_source", {}).get("layers", {})
        frame    = layers.get("frame", {})
        ts       = frame.get("frame.time_relative",
                             frame.get("frame.time", f"#{i}"))
        try:
            ts_sec = math.floor(float(ts))
        except (ValueError, TypeError):
            ts_sec = 0
        ip       = layers.get("ip", {})
        udp      = layers.get("udp", {})
        src_ip   = ip.get("ip.src", "?")
        dst_ip   = ip.get("ip.dst", "?")
        src_port = udp.get("udp.srcport", "?")
        dst_port = udp.get("udp.dstport", "?")
        src      = f"{src_ip}:{src_port}"
        dst      = f"{dst_ip}:{dst_port}"

        if port_filter is not None:
            try:
                if int(src_port) != port_filter and int(dst_port) != port_filter:
                    continue
            except (ValueError, TypeError):
                pass

        raw = get_udp_payload(pkt)
        if raw is None:
            continue
        total_udp += 1

        stream_key = (src_ip, dst_ip, src_port, dst_port)
        results    = decode_packet(raw, opcodes, frag, stream_key)

        for r in results:
            if hide_frags and r["is_fragment_cont"]:
                continue
            if name_filter and name_filter.lower() not in r["opcode_name"].lower():
                continue
            shown += 1
            if r["opcode_id"] and not r["is_fragment_cont"]:
                counter[r["opcode_name"]] += 1
                per_sec[ts_sec][r["opcode_name"]] += 1
            print(fmt(i+1, ts, src, dst, r, len(raw), raw_bytes))

    print("\n" + "="*100)
    print(f" UDP packets processed : {total_udp}")
    print(f" Lines shown           : {shown}")
    if show_stats and counter:
        print(f"\n Opcode frequency (top 30):")
        for name, cnt in counter.most_common(30):
            print(f"   {cnt:>6}x  {name}")
    print("="*100)
    return counter, per_sec


# ─────────────────────────────────────────────────────────────────────────────
# 10. Summary writer
# ─────────────────────────────────────────────────────────────────────────────

def write_summary(path: str, overall: Counter, per_sec: dict) -> None:
    """Write a two-section summary file: overall counts + per-second breakdown."""
    all_names = [name for name, _ in overall.most_common()]
    seconds   = sorted(per_sec.keys())
    col_w     = 8  # column width for per-second table

    with open(path, "w", encoding="utf-8") as f:
        def w(line=""):
            f.write(line + "\n")

        # ── Section 1: Overall opcode counts ──────────────────────────────────
        w("=" * 62)
        w(" SECTION 1 — OVERALL OPCODE COUNTS")
        w("=" * 62)
        w(f"  {'Opcode':<40} {'Count':>8}  {'%':>6}")
        w(f"  {'-'*40} {'-'*8}  {'-'*6}")
        total = sum(overall.values())
        for name, cnt in overall.most_common():
            pct = cnt / total * 100 if total else 0
            w(f"  {name:<40} {cnt:>8}  {pct:>5.1f}%")
        w(f"  {'-'*40} {'-'*8}  {'-'*6}")
        w(f"  {'TOTAL':<40} {total:>8}  100.0%")

        w()
        w()

        # ── Section 2: Per-second breakdown ───────────────────────────────────
        sec_labels = [f"t={s}s" for s in seconds]
        table_w    = 42 + col_w * len(seconds)
        w("=" * table_w)
        w(" SECTION 2 — OPCODES PER SECOND  (floor of frame.time_relative)")
        w("=" * table_w)
        hdr = f"  {'Opcode':<40}" + "".join(f"{lbl:>{col_w}}" for lbl in sec_labels)
        w(hdr)
        w("  " + "-" * 40 + "-" * (col_w * len(seconds)))
        for name in all_names:
            row = f"  {name:<40}" + "".join(
                f"{per_sec[s].get(name, 0):>{col_w}}" for s in seconds
            )
            w(row)
        w("  " + "-" * 40 + "-" * (col_w * len(seconds)))
        sec_totals = f"  {'TOTAL':<40}" + "".join(
            f"{sum(per_sec[s].values()):>{col_w}}" for s in seconds
        )
        w(sec_totals)

    print(f"# Summary written to: {path}", file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────
# 11. Tee
# ─────────────────────────────────────────────────────────────────────────────

class Tee:
    def __init__(self, path):
        self._out  = sys.stdout
        self._file = open(path, "w", encoding="utf-8")
    def write(self, d):
        self._out.write(d); self._file.write(d)
    def flush(self):
        self._out.flush(); self._file.flush()
    def close(self):
        sys.stdout = self._out; self._file.close()


# ─────────────────────────────────────────────────────────────────────────────
# 12. CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Parse EQ RoF2/EQEmu Wireshark JSON and decode app opcodes.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("--xml",          default="RoF2.xml")
    ap.add_argument("--port",         type=int, default=None)
    ap.add_argument("--raw-bytes",    type=int, default=0)
    ap.add_argument("--filter",       default=None)
    ap.add_argument("--probe",        action="store_true")
    ap.add_argument("--stats",        action="store_true")
    ap.add_argument("--output",       default=None)
    ap.add_argument("--no-fragments", action="store_true")
    ap.add_argument("--summary",      default=None,
                                      help="Summary file path (default: <input>_summary.txt)")
    args = ap.parse_args()

    for p in (args.input, args.xml):
        if not Path(p).exists():
            sys.exit(f"ERROR: not found: {p}")

    out_path = args.output or (Path(args.input).stem + "_parsed.txt")
    tee = Tee(out_path)
    sys.stdout = tee
    print(f"# Output: {out_path}", file=sys.stderr)

    print(f"Loading opcodes ...", file=sys.stderr)
    opcodes = load_opcodes(args.xml)
    print(f"  {len(opcodes)} opcodes.", file=sys.stderr)

    print(f"Loading capture ...", file=sys.stderr)
    with open(args.input, encoding="utf-8") as f:
        packets = json.load(f)
    print(f"  {len(packets)} packets.", file=sys.stderr)

    summary_path = args.summary or (Path(args.input).stem + "_summary.txt")

    if args.probe:
        probe(packets)
    else:
        overall, per_sec = parse(packets, opcodes, args.port, args.raw_bytes,
                                 args.filter, args.stats, args.no_fragments)
        tee.close()
        write_summary(summary_path, overall, per_sec)
        return

    tee.close()

if __name__ == "__main__":
    main()
