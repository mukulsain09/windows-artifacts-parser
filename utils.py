# utils.py
import os
import datetime

def safe_read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception:
        return None

def normalize_timestamp(ts):
    """
    Normalize timestamps to strict ISO8601 UTC with trailing Z.
    Handles:
    - Python datetime objects
    - ISO strings (with or without Z)
    - Epoch int/float
    - None -> None
    """
    if ts is None:
        return None

    # If datetime object
    if isinstance(ts, datetime.datetime):
        dt = ts
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        else:
            dt = dt.astimezone(datetime.timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")

    # If numeric epoch
    try:
        if isinstance(ts, (int, float)) or str(ts).replace(".", "", 1).isdigit():
            dt = datetime.datetime.utcfromtimestamp(float(ts))
            dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        pass

    # If ISO string
    try:
        s = str(ts).strip()
        # Convert trailing Z to +00:00 for fromisoformat()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        else:
            dt = dt.astimezone(datetime.timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        pass

    # Fallback: return raw string
    return str(ts)
