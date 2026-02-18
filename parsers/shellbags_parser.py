# parsers/shellbags_parser.py
import winreg
import datetime
import os
import traceback

from utils import normalize_timestamp  # requires utils.py in project root

# Mapping for well-known CLSIDs to their common names
CLSID_MAP = {
    "00000000000000000000000000000000": "Desktop",
    "208D2C603AEA1069A2D708002B30309D": "My Network Places",
    "20D04FE03AEA1069A2D808002B30309D": "This PC",
    "450D8FBAAD2548299CFC1567F35CE80": "Documents",
    "645FF0405081101B9F0800AA002F954E": "Recycle Bin",
    "F02C1A07BE214350A9E7AA4861A8E2E3": "Network",
    "F3361BAE6A654F3184CC2877E972B68C": "Control Panel",
    "871C538042A01069A2EA08002B30309D": "Internet Explorer",
    "E21CE7EF8AB449348ED8C45A1B13E940": "Downloads",
    "FDD39AD0238F46AFADAC6367BD85EE32": "Pictures",
    "3DFDF9E0CD6E471FA06C4CA807ACDED3": "Music",
    "B4BFCC3A0C614276BFC428F4E2442403": "Videos",
    "5E5F7973000948A08151EE8DDC8ED1AB": "Users",
    # add more if needed
}


def _regtime_to_iso(raw_time):
    """
    Convert a registry QueryInfoKey last-write value to ISO8601 Z.
    Heuristic:
      - If raw_time looks very large (>1e12) treat as FILETIME (100-ns since 1601)
      - Else treat as UNIX epoch seconds
    Returns ISO string with trailing Z, or None.
    """
    if raw_time is None:
        return None
    try:
        v = int(raw_time)
    except Exception:
        return None

    try:
        if v > 10**12:
            # FILETIME -> microseconds
            microseconds = v / 10
            epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
            dt = epoch + datetime.timedelta(microseconds=microseconds)
        else:
            # treat as epoch seconds (or milliseconds)
            # if value looks like milliseconds (v > 1e10), convert accordingly
            if v > 10**10:
                # milliseconds
                dt = datetime.datetime.fromtimestamp(v / 1000.0, tz=datetime.timezone.utc)
            else:
                dt = datetime.datetime.fromtimestamp(v, tz=datetime.timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _filetime_to_iso(filetime):
    """
    Backwards-compatible helper in case other parts of code call this.
    Keep previous behavior: expects FILETIME.
    """
    try:
        if not filetime or filetime == 0:
            return None
        us = filetime / 10
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return (epoch + datetime.timedelta(microseconds=us)).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def parse_shellbags(max_depth=25):
    """
    Top-level entry point. Walks the common BagMRU/Bags registry paths and returns a list
    of artifact dicts compatible with insert_artifact/insert_artifacts_bulk:
      {
        "artifact_type": "shellbag",
        "name": "...",
        "path": "...",
        "timestamp": None,
        "last_access": "<ISO Z>",
        "extra": "key_path=...;source=registry"
      }
    """
    artifacts = []
    registry_paths = [
        r"Software\Microsoft\Windows\Shell\BagMRU",
        r"Software\Microsoft\Windows\Shell\Bags",
        r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
        r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
    ]

    for reg_path in registry_paths:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path) as root_key:
                _walk_registry_tree(root_key, reg_path, [], artifacts, depth=0, max_depth=max_depth)
        except FileNotFoundError:
            continue
        except Exception as e:
            # Don't abort whole parse on one inaccessible root; log and continue
            print(f"[!] Could not read registry path {reg_path}: {e}")
            print(traceback.format_exc())
            continue

    return artifacts


def _walk_registry_tree(key, key_path, parent_path_segments, artifacts, depth=0, max_depth=25):
    """
    Recursive traversal that builds folder paths and appends artifact dicts to artifacts list.
    Added safety: max recursion depth and robust value parsing.
    """
    if depth > max_depth:
        return

    # MRUListEx may not exist; gracefully return
    try:
        mru_data, _ = winreg.QueryValueEx(key, "MRUListEx")
        # mru_data is a sequence of 4-byte ints (little endian)
        mru_list = [int.from_bytes(mru_data[i:i+4], 'little') for i in range(0, len(mru_data), 4)]
    except (FileNotFoundError, OSError):
        return
    except Exception:
        # malformed MRUListEx: bail out this subtree
        return

    for index in mru_list:
        val_name = str(index)
        try:
            segment_data, _ = winreg.QueryValueEx(key, val_name)
            if not isinstance(segment_data, (bytes, bytearray)):
                continue

            current_segments = _parse_shell_item_list(segment_data, f"{key_path}\\{val_name}")
            if not current_segments:
                continue

            # Build path using single backslash join
            full_path_segments = parent_path_segments + current_segments
            full_path_str = "\\".join(full_path_segments)
            full_path_str = full_path_str.replace("\\\\", "\\")  # normalize

            # determine display name robustly
            name = os.path.basename(full_path_str) or (full_path_segments[-1] if full_path_segments else "")

            # attempt to get last-write time of the subkey (serves as last_access)
            last_access_iso = None
            try:
                with winreg.OpenKey(key, val_name) as sub_key_for_time:
                    key_info = winreg.QueryInfoKey(sub_key_for_time)
                    raw_time = key_info[2]
                    last_access_iso = _regtime_to_iso(raw_time)
            except Exception:
                last_access_iso = None

            # normalize timestamp string (strict Z format)
            last_access_iso = normalize_timestamp(last_access_iso) if last_access_iso else None

            rec = {
                "artifact_type": "shellbag",
                "name": name,
                "path": full_path_str,
                "timestamp": None,
                "last_access": last_access_iso,
                "extra": f"key_path={key_path}\\{val_name};source=registry"
            }
            artifacts.append(rec)

            # Recurse into subkey if present
            try:
                with winreg.OpenKey(key, val_name) as sub_key:
                    _walk_registry_tree(sub_key, f"{key_path}\\{val_name}", full_path_segments, artifacts, depth=depth+1, max_depth=max_depth)
            except FileNotFoundError:
                pass
            except Exception:
                # if recursion fails for this node, continue with others
                continue

        except (FileNotFoundError, OSError):
            continue
        except Exception as e:
            print(f"[!] Error processing shellbag entry {key_path}\\{val_name}: {e}")
            print(traceback.format_exc())
            continue


def _parse_shell_item_list(data, reg_path):
    """
    Parse a SHELL_ITEM_LIST blob and return a list of path segments.
    This function is resilient: if a specific item can't be parsed it skips it and proceeds.
    """
    if not data:
        return []

    path_segments = []
    offset = 0
    total_len = len(data)

    while offset < total_len:
        try:
            if offset + 2 > total_len:
                break
            item_size = int.from_bytes(data[offset:offset+2], 'little')
            if item_size == 0:
                break
            if item_size < 3 or offset + item_size > total_len:
                break

            item_data = data[offset+2: offset+item_size]
            item_type = item_data[0]
            segment = None

            # (same parsing logic as before but wrapped in try/except to avoid crashes)
            try:
                # 0x1f: Root Folder (CLSID)
                if item_type == 0x1f and len(item_data) >= 0x12:
                    clsid_bytes = item_data[2:18]
                    clsid_hex = "".join([f"{b:02X}" for b in clsid_bytes]).upper()
                    segment = CLSID_MAP.get(clsid_hex, f"CLSID\\{{{clsid_hex}}}")

                # 0x31, 0x32: File entry (long/short names)
                elif item_type in (0x31, 0x32) and len(item_data) > 0x14:
                    long_name = None
                    try:
                        ext_block_sig_offset = item_data.find(b'\xbe\xef')
                        if ext_block_sig_offset != -1:
                            long_name_offset = ext_block_sig_offset + 20
                            if long_name_offset < len(item_data):
                                long_name_end = item_data.find(b'\x00\x00', long_name_offset)
                                if long_name_end != -1:
                                    long_name_bytes = item_data[long_name_offset:long_name_end]
                                    if len(long_name_bytes) % 2 == 0:
                                        long_name = long_name_bytes.decode('utf-16le', errors='ignore')
                    except Exception:
                        long_name = None

                    if long_name:
                        segment = long_name
                    else:
                        try:
                            short_name_offset = 0x14
                            short_name_end = item_data.find(b'\x00', short_name_offset)
                            if short_name_end != -1:
                                segment = item_data[short_name_offset:short_name_end].decode('ascii', errors='ignore')
                        except Exception:
                            segment = None

                # 0x2e/0x2f: Volume / Drive
                elif item_type in (0x2e, 0x2f) and len(item_data) > 1:
                    try:
                        segment = item_data[1:].decode('ascii', errors='ignore').strip('\x00')
                    except Exception:
                        segment = None

                # URI types 0x41-0x4f
                elif 0x41 <= item_type <= 0x4f and len(item_data) > 8:
                    try:
                        uri_len_bytes = item_data[4:8]
                        uri_len = int.from_bytes(uri_len_bytes, 'little') * 2
                        if uri_len > 0 and len(item_data) >= 8 + uri_len:
                            uri_bytes = item_data[8:8+uri_len]
                            segment = uri_bytes.decode('utf-16le', errors='ignore')
                    except Exception:
                        segment = None

                # Delegate folder 0x61 / UsersPropertyView 0x71 etc.
                elif item_type == 0x61 and len(item_data) > 16:
                    delegate_clsid_bytes = item_data[4:20]
                    delegate_clsid_hex = "".join([f"{b:02X}" for b in delegate_clsid_bytes]).upper()
                    segment = f"Delegate:{{{delegate_clsid_hex}}}"
                elif item_type == 0x71 and len(item_data) > 20:
                    guid_start = 4
                    guid_bytes = item_data[guid_start:guid_start+16]
                    guid_hex = guid_bytes.hex()
                    segment = f"UsersPropertyView:{{{guid_hex}}}"
                elif item_type in (0xc3, 0xc4) and len(item_data) > 4:
                    try:
                        end = item_data.find(b'\x00\x00', 4)
                        if end != -1:
                            segment = item_data[4:end+1].decode('utf-16le', errors='ignore')
                    except Exception:
                        segment = None

            except Exception:
                # skip this item and continue parsing the list
                segment = None

            if segment:
                path_segments.append(segment)

            offset += item_size

        except Exception as e:
            # stop parsing this blob on unexpected errors to avoid infinite loops
            print(f"[!] Shell item parsing failed at offset {offset} for {reg_path}: {e}")
            break

    return path_segments


if __name__ == "__main__":
    results = parse_shellbags()
    for r in results[:50]:
        print(f"{r['last_access']} | {r['path']} ({r['extra']})")
