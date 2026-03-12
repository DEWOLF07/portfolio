# Magic Identifier

Identifies files by their binary signature rather than their extension. A file named `invoice.pdf` might actually be an executable — the first bytes tell the truth.

## How it works

Every file format starts with a known byte sequence at a fixed position. PNG always begins with `89 50 4E 47 0D 0A 1A 0A`. ELF binaries start with `7F 45 4C 46`. PDF starts with `%PDF-`. These are called magic numbers, and they're how tools like Unix's `file(1)` have worked since 1973.

The tool reads the first 4096 bytes of a file, walks `signatures.txt` from top to bottom, and returns the first match. Signatures are ordered so more specific ones come first — that ordering is what makes the matching reliable.

Some formats are containers that hold other formats inside them. A ZIP file could be a DOCX, XLSX, EPUB, APK, or plain ZIP — they all start with the same four bytes (`PK\x03\x04`). To tell them apart the tool reads deeper, looking at filenames embedded inside the ZIP's local file header. `word/` means DOCX, `AndroidManifest.xml` means APK, and so on. RIFF containers work the same way — WAV, WEBP, and AVI all share the same magic number and get resolved by reading offset 8.

After identifying the real type it compares against the file's extension. A mismatch gets flagged — that's how you catch a renamed executable or a misconfigured upload handler letting the wrong file type through.

The signatures live in a plain text file so new formats can be added without touching the code at all.

## Files

```
magic_identifier.py   — the tool
signatures.txt        — the signature database
```

`signatures.txt` format:
```
offset | hex bytes | type | mime | category | description
0 | 89 50 4E 47 0D 0A 1A 0A | PNG | image/png | Image | Portable Network Graphics
```

## Run

```bash
python3 magic_identifier.py report.pdf
python3 magic_identifier.py --scan /path/to/folder
python3 magic_identifier.py --demo
```

## Adding a format

One line in `signatures.txt` is all it takes. If the format is a container that needs deeper inspection, add a branch to `disambiguate()`.

