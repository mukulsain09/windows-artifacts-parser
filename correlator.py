# correlator.py
"""
Session-based forensic correlator.

Features:
- Accept either DB path (string) or sqlite3.Connection.
- Prefer DB run_count column, fallback to parsing extra (key=value;...).
- Parse extra into dict for reliable lookups (exe_path, target, run_count, etc).
- Group events into sessions (gap > 120s).
- Link LNK -> Prefetch when target/exe match.
- Return list of dicts with keys:
    timestamp, artifact_type, detail, anomaly, session
- Defensive: returns an error record instead of raising on top-level failures.
"""

import sqlite3
import datetime
import re
import traceback
from typing import Union, List, Dict, Any

_SESSION_GAP_SECONDS = 120  # new session if gap larger than this
_RUNCOUNT_RE = re.compile(r"run_count\s*=\s*(\d+)", flags=re.IGNORECASE)

def _debug(msg: str):
    # Small debug logger; change to real logger if you have one
    print(f"[correlator DEBUG] {msg}")

def _parse_iso_flexible(ts) -> Union[datetime.datetime, None]:
    """Parse timestamp value robustly into timezone-aware UTC datetime or None."""
    if not ts:
        return None
    try:
        s = str(ts).strip()
        if s.lower() in ("none", "null", ""):
            return None
        # If ends with Z, strip then parse
        if s.endswith("Z"):
            s2 = s[:-1]
            try:
                dt = datetime.datetime.fromisoformat(s2)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                else:
                    dt = dt.astimezone(datetime.timezone.utc)
                return dt
            except Exception:
                # fall through to other parsers
                pass
        # Try isoformat directly (may be naive)
        try:
            dt = datetime.datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            else:
                dt = dt.astimezone(datetime.timezone.utc)
            return dt
        except Exception:
            pass
        # Numeric heuristics
        v = float(s)
        # FILETIME-like (100-ns since 1601) -> very large >1e14
        if v > 1e14:
            # Convert to seconds since epoch
            seconds = v / 10_000_000.0 - 11644473600.0
            return datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
        # Milliseconds epoch
        if v > 1e12:
            return datetime.datetime.fromtimestamp(v / 1000.0, tz=datetime.timezone.utc)
        # Seconds epoch
        return datetime.datetime.fromtimestamp(v, tz=datetime.timezone.utc)
    except Exception:
        return None

def _format_iso_z(dt: datetime.datetime) -> str:
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

def _parse_extra_to_kv(extra: str) -> Dict[str, str]:
    """
    Parse extra field encoded as "key=value;key2=value2" into dict.
    Handles values that are JSON (keeps as string), trims whitespace.
    """
    out = {}
    if not extra:
        return out
    try:
        parts = [p for p in str(extra).split(";") if p.strip()]
        for p in parts:
            if "=" in p:
                k, v = p.split("=", 1)
                out[k.strip().lower()] = v.strip()
            else:
                # treat as flag
                out[p.strip().lower()] = ""
    except Exception:
        # Fallback — return empty map
        return {}
    return out

def _extract_run_count_from_row(row: Dict[str, Any]) -> Union[int, None]:
    """
    Return run_count preferring explicit DB column 'run_count', else from extra kv string.
    """
    if row is None:
        return None
    # Prefer DB column (if present and numeric)
    if "run_count" in row and row.get("run_count") is not None:
        try:
            return int(row.get("run_count"))
        except Exception:
            pass
    # Fallback: parse extra
    extra = row.get("extra") or ""
    # First try kv parsing
    kv = _parse_extra_to_kv(extra)
    if "run_count" in kv:
        try:
            return int(re.sub(r"[^\d]", "", kv.get("run_count") or ""))
        except Exception:
            pass
    # Last resort: regex
    m = _RUNCOUNT_RE.search(str(extra))
    if m:
        try:
            return int(m.group(1))
        except Exception:
            pass
    return None

def _coerce_row_time(row: Dict[str, Any]) -> Union[datetime.datetime, None]:
    """
    Pick the best timestamp from row (timestamp, last_access, event_time),
    return parsed datetime or None.
    """
    for key in ("timestamp", "last_access", "event_time"):
        val = row.get(key)
        if val:
            dt = _parse_iso_flexible(val)
            if dt:
                return dt
    return None

def correlate_artifacts(db_or_conn: Union[str, sqlite3.Connection]) -> List[Dict[str, Any]]:
    """
    Main correlator.

    Accepts:
      - db_or_conn: path to sqlite DB file OR an open sqlite3.Connection

    Returns: list of dicts { timestamp, artifact_type, detail, anomaly, session }
    """
    conn = None
    close_conn = False
    try:
        # Accept either DB path or connection
        if isinstance(db_or_conn, str):
            conn = sqlite3.connect(db_or_conn)
            close_conn = True
        elif isinstance(db_or_conn, sqlite3.Connection):
            conn = db_or_conn
        else:
            raise TypeError("db_or_conn must be sqlite path or sqlite3.Connection")

        # Friendly rows as dicts
        conn.row_factory = lambda cursor, row: {col[0]: row[idx] for idx, col in enumerate(cursor.description)}
        cur = conn.cursor()

        # Fetch rows with event_time ordering
        cur.execute("""
            SELECT *, COALESCE(timestamp, last_access) AS event_time
            FROM artifacts
            WHERE timestamp IS NOT NULL OR last_access IS NOT NULL
            ORDER BY event_time ASC
        """)
        raw_rows = cur.fetchall()
        rows = [dict(r) for r in raw_rows]

        out: List[Dict[str, Any]] = []
        session_id = 1
        last_time: Union[datetime.datetime, None] = None

        # Indexes to help linking & anomaly detection
        # last_seen_by_name[name] = (datetime, artifact_type, row)
        last_seen_by_name: Dict[str, Any] = {}
        # map exe names/paths -> last seen prefetch row and time
        last_prefetch_by_exe: Dict[str, Any] = {}

        for r in rows:
            try:
                t = _coerce_row_time(r)
                if not t:
                    # skip rows with no parseable time
                    continue

                # session logic
                if last_time is not None:
                    delta = (t - last_time).total_seconds()
                    if delta > _SESSION_GAP_SECONDS:
                        session_id += 1
                last_time = t

                artifact_type_raw = (r.get("artifact_type") or "").lower()
                artifact_type = artifact_type_raw
                name = r.get("name") or ""
                path = r.get("path") or ""
                extra_raw = r.get("extra") or ""
                kv = _parse_extra_to_kv(extra_raw)

                # Prefer run_count DB column else extra
                run_count = _extract_run_count_from_row(r)

                # Detect fields: exe_path (prefetch), target (lnk)
                exe_path = None
                target = None
                # common keys (lowercased by _parse_extra_to_kv)
                exe_path = kv.get("exe") or kv.get("exe_path") or kv.get("executable") or kv.get("targetexe")
                target = kv.get("target") or kv.get("arguments") or kv.get("lnk_target")

                # Build base description and anomaly hints
                base = ""
                anomalies = []

                if "prefetch" in artifact_type or artifact_type.startswith("prefetch"):
                    if run_count is not None:
                        base = f"🚀 Executed Program (runs: {run_count})"
                    else:
                        base = "🚀 Executed Program"
                    # store last prefetch by exe name (and basename)
                    if exe_path:
                        key = exe_path.lower()
                        last_prefetch_by_exe[key] = (t, r)
                        # also store basename
                        last_prefetch_by_exe.setdefault(ntpath_basename(exe_path).lower(), (t, r))

                elif "lnk" in artifact_type or artifact_type.startswith("lnk"):
                    base = "🔗 Shortcut / LNK"
                elif "recycle" in artifact_type or artifact_type.startswith("recycle"):
                    base = "🗑 Recycle Bin (deleted file)"
                elif "shellbag" in artifact_type:
                    base = "📂 Folder Viewed"
                else:
                    base = f"🕵️ {artifact_type or 'artifact'}"

                # relation detection: if LNK and target matches a known prefetch exe seen in the same session (within gap)
                relation_text = ""
                if (("lnk" in artifact_type) or target) and target:
                    # normalize target (strip quotes)
                    target_norm = target.strip().strip('"').lower()
                    # try exact match
                    pref = last_prefetch_by_exe.get(target_norm)
                    if not pref:
                        # try basename match
                        basename = ntpath_basename(target_norm).lower()
                        pref = last_prefetch_by_exe.get(basename)
                    if pref:
                        pref_time, pref_row = pref
                        # if prefetch happened within session gap we assume relation
                        if abs((t - pref_time).total_seconds()) <= _SESSION_GAP_SECONDS:
                            relation_text = f"(Linked to Prefetch: {pref_row.get('name')})"

                # anomaly: deleted then executed soon after
                if "prefetch" in artifact_type:
                    prev = last_seen_by_name.get(name)
                    if prev:
                        prev_time, prev_type, _ = prev
                        if prev_type and "recycle" in prev_type.lower():
                            delta = (t - prev_time).total_seconds()
                            if 0 <= delta <= 300:
                                anomalies.append("⚠ Deleted -> Executed soon after")

                # anomaly: frequent execution
                if run_count is not None and run_count >= 50:
                    anomalies.append("⚠ Frequently executed (high run_count)")

                # Compose detail text
                detail_parts = [f"[Session {session_id}] {base}"]
                if name:
                    detail_parts.append(name)
                if path:
                    detail_parts.append(f"| {path}")
                if exe_path:
                    detail_parts.append(f"| exe={exe_path}")
                if target:
                    detail_parts.append(f"| target={target}")
                if kv:
                    # keep a compact hint of key fields
                    hint_parts = []
                    for k in ("source", "pref_hash", "files_count", "volumes_count"):
                        if k in kv:
                            hint_parts.append(f"{k}={kv[k]}")
                    if hint_parts:
                        detail_parts.append("| " + ", ".join(hint_parts))
                if relation_text:
                    detail_parts.append(relation_text)

                detail = " ".join(p for p in detail_parts if p)

                anomaly_field = "; ".join(anomalies) if anomalies else ""

                # Append output row
                out.append({
                    "timestamp": _format_iso_z(t),
                    "artifact_type": artifact_type,
                    "detail": detail,
                    "anomaly": anomaly_field,
                    "session": session_id
                })

                # update last_seen_by_name
                if name:
                    last_seen_by_name[name] = (t, artifact_type, r)

            except Exception as e:
                # Per-row error should not stop everything
                _debug(f"Error processing row id={r.get('id')}: {e}\n{traceback.format_exc()}")
                continue

        # final sort just in case
        try:
            out_sorted = sorted(out, key=lambda x: _parse_iso_flexible(x.get("timestamp")))
        except Exception:
            out_sorted = out

        return out_sorted

    except Exception as e:
        _debug(f"Top-level correlator failure: {e}\n{traceback.format_exc()}")
        # Return one error row to ensure GUI receives something
        now = datetime.datetime.now(datetime.timezone.utc)
        return [{
            "timestamp": _format_iso_z(now),
            "artifact_type": "error",
            "detail": f"Correlator error: {str(e)} (see logs).",
            "anomaly": "error",
            "session": 0
        }]
    finally:
        if close_conn and conn:
            try:
                conn.close()
            except Exception:
                pass

# Helper: local basename without importing os repeatedly
def ntpath_basename(path_str: str) -> str:
    try:
        # handle None
        if not path_str:
            return ""
        # use rightmost separator
        return path_str.replace("\\", "/").rsplit("/", 1)[-1]
    except Exception:
        return str(path_str)
