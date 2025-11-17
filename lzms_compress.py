#!/usr/bin/env python3
"""
lzms_compress.py

Usage:
    python lzms_compress.py input.bin [--raw]

- input.bin      : path to the original binary file
- --raw          : use COMPRESS_RAW | LZMS (block/raw stream mode). Optional.

Behavior:
- ALWAYS writes the output header as ./shellcode.h (current working directory).
- Fixed bytes-per-line = 16.
- Requires Windows (uses cabinet.dll Compression API).
"""

import sys
import os
import ctypes
from ctypes import wintypes
import argparse
import textwrap

# --------------------------------------------------------------------
# Compression API constants
# --------------------------------------------------------------------
COMPRESS_ALGORITHM_LZMS = 5
COMPRESS_RAW = 1 << 29

# Fixed formatting setting
BYTES_PER_LINE = 16
OUT_FILENAME = "shellcode.h"

# --------------------------------------------------------------------
# Helpers for Windows Compression API (cabinet.dll)
# --------------------------------------------------------------------
def load_cabinet():
    try:
        return ctypes.WinDLL("cabinet.dll")
    except OSError as e:
        raise RuntimeError("Failed to load cabinet.dll. This script must run on Windows.") from e

def _format_win_error(err_code: int) -> str:
    try:
        return ctypes.FormatError(err_code)
    except Exception:
        return f"WinError {err_code}"

def compress_lzms(data: bytes, raw: bool = False) -> bytes:
    """
    Compress bytes with Windows Compression API LZMS via cabinet.dll.
    Returns compressed bytes.
    """
    cabinet = load_cabinet()

    COMPRESSOR_HANDLE = ctypes.c_void_p

    CreateCompressor = cabinet.CreateCompressor
    CreateCompressor.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(COMPRESSOR_HANDLE)]
    CreateCompressor.restype = wintypes.BOOL

    Compress = cabinet.Compress
    Compress.argtypes = [
        COMPRESSOR_HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    Compress.restype = wintypes.BOOL

    CloseCompressor = cabinet.CloseCompressor
    CloseCompressor.argtypes = [COMPRESSOR_HANDLE]
    CloseCompressor.restype = wintypes.BOOL

    GetLastError = ctypes.windll.kernel32.GetLastError
    GetLastError.restype = wintypes.DWORD

    algo = COMPRESS_ALGORITHM_LZMS
    if raw:
        algo |= COMPRESS_RAW

    compressor = COMPRESSOR_HANDLE()
    if not CreateCompressor(algo, None, ctypes.byref(compressor)):
        err = GetLastError()
        raise OSError(f"CreateCompressor failed: {_format_win_error(err)}")

    try:
        # Use create_string_buffer for safe binary pointer handling
        src_buf = ctypes.create_string_buffer(data)
        src_ptr = ctypes.cast(src_buf, ctypes.c_void_p)
        src_len = ctypes.c_size_t(len(data))

        # Query required output size
        required = ctypes.c_size_t(0)
        # First call: NULL output buffer to get required size
        Compress(
            compressor,
            src_ptr, src_len,
            None, ctypes.c_size_t(0),
            ctypes.byref(required),
        )
        if required.value == 0:
            err = GetLastError()
            raise OSError(f"Compress size query failed (no required size). {_format_win_error(err)}")

        # Allocate output buffer
        out_buf = (ctypes.c_ubyte * required.value)()
        out_ptr = ctypes.cast(out_buf, ctypes.c_void_p)
        actual = ctypes.c_size_t(0)

        ok = Compress(
            compressor,
            src_ptr, src_len,
            out_ptr, ctypes.c_size_t(required.value),
            ctypes.byref(actual),
        )
        if not ok:
            err = GetLastError()
            raise OSError(f"Compress failed: {_format_win_error(err)}")

        return bytes(out_buf[: actual.value])
    finally:
        if compressor:
            CloseCompressor(compressor)

# --------------------------------------------------------------------
# Header generation helpers
# --------------------------------------------------------------------
def bytes_to_c_array(b: bytes, bytes_per_line: int = BYTES_PER_LINE) -> str:
    """
    Convert a bytes object to a C initializer interior string.
    """
    if not b:
        return "    0x00,"

    lines = []
    for i in range(0, len(b), bytes_per_line):
        chunk = b[i:i+bytes_per_line]
        hexes = ", ".join(f"0x{byte:02x}" for byte in chunk)
        # keep trailing comma on every line for convenience
        lines.append("    " + hexes + ",")
    return "\n".join(lines)

def make_header(original_size: int, compressed_bytes: bytes, uncompressed_bytes: bytes) -> str:
    """
    Build the final header text matching user's outline, using BYTES_PER_LINE formatting.
    """
    compressed_array = bytes_to_c_array(compressed_bytes)
    uncompressed_array = bytes_to_c_array(uncompressed_bytes)

    header = textwrap.dedent(f"""\
    #pragma once

    // Automatically generated by lzms_compress.py
    // Original (uncompressed) length in bytes:
    //   {original_size}

    SIZE_T SHELLCODE_LENGTH = {original_size};

    UCHAR SHELLCODE[] = {{
    {compressed_array}
    }};

    #ifdef _DECOMPRESS
    UCHAR UNCOMPRESSED_SHELLCODE[] = {{
    {uncompressed_array}
    }};
    #endif
    """)
    return header

# --------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Compress a .bin via LZMS and emit a C header named './shellcode.h' containing compressed + uncompressed arrays.")
    p.add_argument("input", help="input .bin file (original raw bytes)")
    p.add_argument("--raw", action="store_true", help="use COMPRESS_RAW | LZMS (block/raw mode)")
    return p.parse_args()

def main():
    args = parse_args()

    if os.name != "nt":
        print("ERROR: This script uses the Windows Compression API (cabinet.dll). Run it on Windows.", file=sys.stderr)
        return 2

    in_path = args.input
    raw_mode = args.raw

    if not os.path.isfile(in_path):
        print(f"ERROR: input file not found: {in_path}", file=sys.stderr)
        return 2

    # Read original bytes
    with open(in_path, "rb") as f:
        uncompressed = f.read()

    original_size = len(uncompressed)
    print(f"[i] Read input '{in_path}' ({original_size} bytes)")

    # Compress
    compressed = compress_lzms(uncompressed, raw=raw_mode)
    print(f"[i] Compressed to {len(compressed)} bytes (raw_mode={raw_mode})")

    # Build header text
    header_text = make_header(original_size, compressed, uncompressed)

    # Atomic write to current working directory filename OUT_FILENAME
    cwd = os.getcwd()
    out_path = os.path.join(cwd, OUT_FILENAME)
    tmp_path = out_path + ".tmp"

    with open(tmp_path, "w", newline="\n") as f:
        f.write(header_text)
    os.replace(tmp_path, out_path)

    print(f"[+] Wrote header to '{out_path}' (formatted {BYTES_PER_LINE} bytes/line)")

if __name__ == "__main__":
    sys.exit(main())

