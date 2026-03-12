#!/usr/bin/env python3
"""
Magic Number File Type Identifier — identifies files by their binary signature,
not their extension. Signatures are loaded from signatures.txt so you can add
new formats without touching this file.

Run: python3 magic_identifier.py <file>
     python3 magic_identifier.py --scan <directory>
     python3 magic_identifier.py --demo
"""

import sys
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from collections import Counter


@dataclass
class Signature:
    offset:      int
    magic:       bytes
    file_type:   str
    mime_type:   str
    category:    str
    description: str


def load_signatures(path: str) -> list[Signature]:
    sigs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 6:
                continue
            offset, hex_str, ft, mime, cat, desc = parts
            magic = bytes(int(b, 16) for b in hex_str.split())
            sigs.append(Signature(int(offset), magic, ft, mime, cat, desc))
    return sigs


def disambiguate(file_type: str, data: bytes) -> Optional[tuple]:
    # Some containers need a second read to know exactly what they hold

    if file_type == "RIFF":
        sub = data[8:12]
        return {
            b"WEBP": ("WEBP", "image/webp",     "WebP Image"),
            b"WAVE": ("WAV",  "audio/wav",       "WAV Audio"),
            b"AVI ": ("AVI",  "video/x-msvideo", "AVI Video"),
        }.get(sub, ("RIFF", "application/octet-stream", f"RIFF/{sub}"))

    if file_type == "ZIP_BASED":
        # ZIP is a container — DOCX, EPUB, APK, JAR all start with PK\x03\x04
        s = data[:2048]
        if   b"word/"               in s: return ("DOCX", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "Microsoft Word")
        elif b"xl/"                 in s: return ("XLSX", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",       "Microsoft Excel")
        elif b"ppt/"                in s: return ("PPTX", "application/vnd.openxmlformats-officedocument.presentationml.presentation","Microsoft PowerPoint")
        elif b"AndroidManifest.xml" in s: return ("APK",  "application/vnd.android.package-archive", "Android APK")
        elif b"META-INF/"           in s: return ("JAR",  "application/java-archive",                "Java Archive")
        elif b"epub"          in s.lower(): return ("EPUB","application/epub+zip",                   "EPUB eBook")
        return ("ZIP", "application/zip", "ZIP Archive")

    if file_type == "MP4_FTYP":
        brand = data[8:12]
        if   brand in (b"M4A ", b"M4B "): return ("M4A", "audio/mp4",       "MPEG-4 Audio")
        elif brand == b"qt  ":            return ("MOV", "video/quicktime",  "QuickTime Movie")
        elif brand[:2] == b"3g":          return ("3GP", "video/3gpp",       "3GPP Video")
        return ("MP4", "video/mp4", "MPEG-4 Video")

    if file_type == "CFB":
        # Compound File Binary — old Office format. Type is buried in the content.
        s = data[:2048]
        if   b"W\x00o\x00r\x00d"      in s: return ("DOC", "application/msword",           "Word 97-2003")
        elif b"W\x00o\x00r\x00k\x00b" in s: return ("XLS", "application/vnd.ms-excel",     "Excel 97-2003")
        elif b"P\x00o\x00w\x00e\x00r" in s: return ("PPT", "application/vnd.ms-powerpoint","PowerPoint 97-2003")
        return ("CFB", "application/msword", "Compound File Binary")

    return None


def identify(path: str, signatures: list[Signature]) -> dict:
    p = Path(path)
    result = {
        "path": path, "size": 0,
        "file_type": "UNKNOWN", "mime_type": "application/octet-stream",
        "description": "Unknown", "category": "Unknown",
        "extension": p.suffix.lower(), "extension_match": None,
        "hex_preview": "", "confidence": "none",
    }

    if not p.exists():
        result["error"] = "not found"
        return result

    result["size"] = p.stat().st_size

    try:
        data = p.read_bytes()[:4096]
    except PermissionError:
        result["error"] = "permission denied"
        return result

    if not data:
        result.update(file_type="EMPTY", description="empty file", confidence="high")
        return result

    result["hex_preview"] = " ".join(f"{b:02x}" for b in data[:16])

    matched = next(
        (s for s in signatures
         if len(data) >= s.offset + len(s.magic)
         and data[s.offset: s.offset + len(s.magic)] == s.magic),
        None
    )

    if matched:
        resolved = disambiguate(matched.file_type, data)
        ft, mime, desc = resolved if resolved else (matched.file_type, matched.mime_type, matched.description)
        result.update(file_type=ft, mime_type=mime, description=desc,
                      category=matched.category, confidence="high")

        ext_map = {
            ".png":"PNG", ".jpg":"JPEG", ".jpeg":"JPEG", ".gif":"GIF",
            ".pdf":"PDF", ".zip":"ZIP",  ".gz":"GZIP",   ".7z":"7ZIP",
            ".mp3":"MP3", ".flac":"FLAC",".wav":"WAV",   ".mp4":"MP4",
            ".mkv":"MKV", ".exe":"PE",   ".dll":"PE",
            ".docx":"DOCX", ".xlsx":"XLSX", ".pptx":"PPTX", ".epub":"EPUB",
            ".sqlite":"SQLITE", ".woff":"WOFF", ".woff2":"WOFF2",
        }
        expected = ext_map.get(result["extension"])
        result["extension_match"] = (ft == expected) if expected else None
    else:
        try:
            data[:512].decode("utf-8")
            result.update(file_type="TEXT", mime_type="text/plain",
                          description="plain text", category="Text", confidence="medium")
        except UnicodeDecodeError:
            result.update(file_type="BINARY", confidence="low")

    return result


def fmt_size(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def print_result(r: dict):
    mismatch = "  ⚠  EXTENSION MISMATCH" if r.get("extension_match") is False else ""
    print(f"\n  {r['path']}")
    if r.get("error"):
        print(f"  error: {r['error']}")
        return
    print(f"  {r['file_type']}  —  {r['description']}")
    print(f"  {r['mime_type']}  |  {r['category']}  |  {fmt_size(r['size'])}{mismatch}")
    print(f"  hex: {r['hex_preview']}")


def create_demo_files(tmp="/tmp/magic_demo") -> list:
    os.makedirs(tmp, exist_ok=True)
    samples = {
        "image.png":      bytes.fromhex("89504e470d0a1a0a") + b"\x00" * 20,
        "photo.jpg":      bytes.fromhex("ffd8ffe0")         + b"\x00" * 20,
        "archive.gz":     bytes.fromhex("1f8b")             + b"\x00" * 20,
        "binary.elf":     bytes.fromhex("7f454c46")         + b"\x00" * 20,
        "program.exe":    bytes.fromhex("4d5a")             + b"\x00" * 20,
        "document.pdf":   b"%PDF-1.7\n"                     + b"\x00" * 20,
        "database.sqlite":b"SQLite format 3\x00"            + b"\x00" * 20,
        "not_text.txt":   bytes.fromhex("89504e470d0a1a0a") + b"\x00" * 20,  # PNG with .txt extension
    }
    paths = []
    for name, content in samples.items():
        p = Path(tmp) / name
        p.write_bytes(content)
        paths.append(str(p))
    return paths


def main():
    sig_path = Path(__file__).parent / "signatures.txt"
    if not sig_path.exists():
        print(f"signatures.txt not found at {sig_path}")
        sys.exit(1)

    sigs = load_signatures(str(sig_path))
    print(f"[*] {len(sigs)} signatures loaded\n")

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("  python3 magic_identifier.py <file>")
        print("  python3 magic_identifier.py --scan <directory>")
        print("  python3 magic_identifier.py --demo")
        return

    if sys.argv[1] == "--demo":
        for p in create_demo_files():
            print_result(identify(p, sigs))
        return

    if sys.argv[1] == "--scan" and len(sys.argv) > 2:
        files   = [f for f in sorted(Path(sys.argv[2]).rglob("*")) if f.is_file()]
        results = [identify(str(f), sigs) for f in files]

        for r in results:
            print_result(r)

        freq       = Counter(r["category"] for r in results)
        mismatches = [r for r in results if r.get("extension_match") is False]

        print(f"\n  {len(results)} files")
        for cat, n in sorted(freq.items()):
            print(f"    {cat}: {n}")
        if mismatches:
            print(f"\n  ⚠  {len(mismatches)} extension mismatch(es):")
            for r in mismatches:
                print(f"     {r['path']}  →  {r['file_type']}")
        return

    print_result(identify(sys.argv[1], sigs))


if __name__ == "__main__":
    main()
