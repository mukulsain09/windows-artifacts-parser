# parsers/recycle_parser.py
import os
import struct
import datetime

def _filetime_to_dt(ft):
    # Convert Windows FILETIME (100-ns intervals since Jan 1, 1601) to datetime
    if not ft or ft == 0:
        return None
    try:
        us = ft / 10  # to microseconds
        epoch = datetime.datetime(1601, 1, 1)
        return epoch + datetime.timedelta(microseconds=us)
    except Exception:
        return None

def parse_i_file(path):
    """
    Parse a $I... Recycle Bin metadata file. Best-effort parse:
    Common layout for many Windows versions:
      - 8 bytes: version or flags (uint64)
      - 8 bytes: original file size (uint64)
      - 8 bytes: deletion time FILETIME (uint64)
      - remainder: original path in UTF-16-LE (null-terminated)
    Returns list with a single record dict when parse succeeds.
    """
    records = []
    try:
        with open(path, "rb") as f:
            data = f.read()
        if len(data) < 32:
            return []
        # unpack the first three Q values (little-endian)
        try:
            version, orig_size, filetime = struct.unpack_from("<QQQ", data, 0)
            path_offset = 24
        except struct.error:
            # try safer approach if structure differs
            return []
        # parse path from offset 24 as UTF-16-LE
        raw = data[path_offset:]
        try:
            s = raw.decode("utf-16le", errors="ignore")
            # split on double-null if present
            s = s.split("\x00\x00", 1)[0]
            original_path = s.strip("\x00")
        except Exception:
            original_path = None

        dt = _filetime_to_dt(filetime)
        ts = dt.isoformat() + "Z" if dt else None

        rec = {
            "artifact_type": "recycle_i",
            "name": os.path.basename(path),
            "path": path,
            "timestamp": ts,
            "extra": f"orig_size={orig_size};orig_path={original_path}"
        }
        records.append(rec)
    except Exception as e:
        print(f"Failed to parse $I file {path}: {e}")
    return records
