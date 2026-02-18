# parsers/lnk_parser.py
"""
Improved .lnk parser wrapper.

- Uses pylnk3 when available and extracts many common attributes.
- Falls back to file metadata (os.stat) and computes MD5 hash of the file bytes.
- Uses utils.normalize_timestamp() for timestamp normalization.
"""

import os
import hashlib
import datetime

from utils import normalize_timestamp, safe_read

try:
    import pylnk3
    HAS_PYPLNK3 = True
except Exception:
    HAS_PYPLNK3 = False


def _md5_of_bytes(data):
    try:
        h = hashlib.md5()
        h.update(data)
        return h.hexdigest()
    except Exception:
        return None


def _stat_times_iso(path):
    try:
        st = os.stat(path)
        # os.stat returns seconds since epoch (float)
        m = normalize_timestamp(datetime.datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z")
        a = normalize_timestamp(datetime.datetime.utcfromtimestamp(st.st_atime).isoformat() + "Z")
        c = normalize_timestamp(datetime.datetime.utcfromtimestamp(st.st_ctime).isoformat() + "Z")
        return {"mtime": m, "atime": a, "ctime": c, "size": st.st_size}
    except Exception:
        return {"mtime": None, "atime": None, "ctime": None, "size": None}


def _extra_kv_string(d):
    """
    Build a compact key=value;key2=value2 string for the `extra` column.
    """
    parts = []
    for k, v in (d or {}).items():
        if v is None:
            continue
        # convert booleans/ints to str, truncate long strings for DB readability
        s = str(v)
        if len(s) > 400:
            s = s[:380] + "..."
        parts.append(f"{k}={s}")
    return ";".join(parts)


def parse_lnk(path):
    """
    Return list with a single dict record for the given .lnk file path.
    Attempt to use pylnk3 to extract rich metadata. Fall back to filesystem metadata.
    """
    out = []

    data = safe_read(path)

    # try pylnk3 if installed
    if HAS_PYPLNK3:
        try:
            # pylnk3.parse returns an object; attribute names can vary between versions
            lnk_obj = pylnk3.parse(path)
            # Best-effort extraction of common attributes
            target = getattr(lnk_obj, "path", None) or getattr(lnk_obj, "local_path", None) or getattr(lnk_obj, "TargetPath", None) or ""
            mtime = getattr(lnk_obj, "modified", None) or getattr(lnk_obj, "mtime", None)
            atime = getattr(lnk_obj, "accessed", None) or getattr(lnk_obj, "atime", None)
            ctime = getattr(lnk_obj, "created", None) or getattr(lnk_obj, "ctime", None)
            working_dir = getattr(lnk_obj, "working_dir", None) or getattr(lnk_obj, "WorkingDirectory", None)
            description = getattr(lnk_obj, "description", None) or getattr(lnk_obj, "desc", None)
            args = getattr(lnk_obj, "arguments", None) or getattr(lnk_obj, "cmd", None)
            icon = getattr(lnk_obj, "icon_location", None) or getattr(lnk_obj, "IconLocation", None)

            times = {}
            if mtime:
                try:
                    times["mtime"] = normalize_timestamp(mtime.isoformat() + "Z") if hasattr(mtime, "isoformat") else normalize_timestamp(str(mtime))
                except Exception:
                    times["mtime"] = normalize_timestamp(str(mtime))
            if atime:
                try:
                    times["atime"] = normalize_timestamp(atime.isoformat() + "Z") if hasattr(atime, "isoformat") else normalize_timestamp(str(atime))
                except Exception:
                    times["atime"] = normalize_timestamp(str(atime))
            if ctime:
                try:
                    times["ctime"] = normalize_timestamp(ctime.isoformat() + "Z") if hasattr(ctime, "isoformat") else normalize_timestamp(str(ctime))
                except Exception:
                    times["ctime"] = normalize_timestamp(str(ctime))

            # enrich with fs-level times/size if missing
            st = _stat_times_iso(path)
            for k in ("mtime", "atime", "ctime", "size"):
                if not times.get(k) and st.get(k) is not None:
                    times[k] = st.get(k)

            extra_map = {
                "target": target,
                "working_dir": working_dir,
                "description": description,
                "arguments": args,
                "icon": icon,
                "size": st.get("size"),
                "source": "pylnk3"
            }
            extra_map.update({k: times.get(k) for k in ("mtime", "atime", "ctime") if times.get(k)})

            rec = {
                "artifact_type": "lnk",
                "name": os.path.basename(path),
                "path": path,
                # prefer embedded mtime from LNK, else file mtime
                "timestamp": times.get("mtime") or st.get("mtime"),
                "last_access": times.get("atime"),
                "extra": _extra_kv_string(extra_map)
            }
            out.append(rec)
            return out
        except Exception as e:
            # if pylnk3 fails, fall back gracefully
            print(f"[lnk_parser] pylnk3 parse failed for {path}: {e}")

    # fallback: minimal info from file metadata + file hash
    st = _stat_times_iso(path)
    md5 = _md5_of_bytes(data) if data else None
    extra_map = {
        "size": st.get("size"),
        "md5": md5,
        "source": "fallback_minimal"
    }
    rec = {
        "artifact_type": "lnk",
        "name": os.path.basename(path),
        "path": path,
        "timestamp": st.get("mtime"),
        "last_access": st.get("atime"),
        "extra": _extra_kv_string(extra_map)
    }
    out.append(rec)
    return out
