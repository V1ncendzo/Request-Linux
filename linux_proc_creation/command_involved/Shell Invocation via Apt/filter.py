#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
from pathlib import Path

# Match: optional indent + "33. " + rest of line
NUM_PREFIX_RE = re.compile(r'^(\s*)\d+\.\s*(.*)$')

def clean_line(line: str) -> str:
    # giữ nguyên newline
    nl = "\n" if line.endswith("\n") else ""
    core = line[:-1] if nl else line

    # 1) bỏ "33. " ở đầu dòng (nếu có)
    m = NUM_PREFIX_RE.match(core)
    if m:
        indent, rest = m.group(1), m.group(2)
    else:
        indent, rest = "", core

    # 2) gỡ 1 cặp backtick ngoài cùng nếu cả dòng là `...`
    stripped = rest.strip()
    if stripped.startswith("`") and stripped.endswith("`") and len(stripped) >= 2:
        stripped = stripped[1:-1].strip()
        rest = indent + stripped
    else:
        rest = indent + rest

    return rest + nl


def read_text_safely(p: Path) -> str:
    # ưu tiên utf-8-sig để xử lý BOM, fallback cp1252 nếu cần
    try:
        return p.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        return p.read_text(encoding="cp1252", errors="replace")


def main():
    if len(sys.argv) != 3:
        print("Usage: python filter.py <input.txt> <output.txt>")
        sys.exit(2)

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    raw = read_text_safely(in_path)

    lines = raw.splitlines(True)  # keep line endings
    cleaned_lines = [clean_line(l) for l in lines]
    cleaned = "".join(cleaned_lines)

    out_path.write_text(cleaned, encoding="utf-8")

    # LOG để bạn biết có đọc/ghi thật hay không
    print(f"Read  : {in_path} ({len(lines)} lines, {len(raw)} chars)")
    print(f"Wrote : {out_path} ({len(cleaned_lines)} lines, {len(cleaned)} chars)")

    # nếu vẫn rỗng thì in 5 dòng đầu input để debug ngay
    if len(raw.strip()) == 0:
        print("WARNING: input file is empty/blank.")
    if len(cleaned.strip()) == 0 and len(raw.strip()) > 0:
        print("WARNING: output became blank unexpectedly. First 5 input lines:")
        for i, l in enumerate(lines[:5], 1):
            print(f"{i:02d}: {l.rstrip()}")

if __name__ == "__main__":
    main()
