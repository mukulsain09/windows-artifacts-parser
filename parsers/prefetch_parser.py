# parsers/prefetch_parser.py
"""
Prefetch parser wrapper that prefers local improved parser, then tries installed libs,
and falls back to file metadata+md5. Encodes extra as key=value;... for correlator.
"""

import os
import json
import datetime
import importlib

from utils import normalize_timestamp, safe_read

# Try local improved prefetched implementation first
try:
    from parsers.prefetch_impl import Prefetch as LocalPrefetch
    HAS_LOCAL_PREFETCH = True
except Exception:
    LocalPrefetch = None
    HAS_LOCAL_PREFETCH = False

# Candidate external modules to try if local not present
PREFETCH_MODULES = [
    "prefetch",
    "prefetch_parser",
    "analyzePF",
    "pyprefetch",
    "python_prefetch",
    "pfparser",
]

def _file_mtime_iso(path):
    try:
        t = os.path.getmtime(path)
        return normalize_timestamp(datetime.datetime.utcfromtimestamp(t).isoformat() + "Z")
    except Exception:
        return None

def _md5_hex(data):
    try:
        import hashlib
        h = hashlib.md5()
        h.update(data)
        return h.hexdigest()
    except Exception:
        return None

def _format_extra(kv):
    parts = []
    for k, v in (kv or {}).items():
        if v is None:
            continue
        if isinstance(v, (list, tuple, dict)):
            try:
                s = json.dumps(v, ensure_ascii=False)
            except Exception:
                s = str(v)
        else:
            s = str(v)
        if len(s) > 600:
            s = s[:590] + "..."
        s = s.replace(";", ",")
        parts.append(f"{k}={s}")
    return ";".join(parts)

def _try_import_prefetch_module():
    for name in PREFETCH_MODULES:
        try:
            mod = importlib.import_module(name)
            return mod
        except Exception:
            continue
    return None

def parse_prefetch(path):
    out = []

    # 1) Try local improved parser
    if HAS_LOCAL_PREFETCH and LocalPrefetch is not None:
        try:
            pf = LocalPrefetch(path)
            parsed = getattr(pf, "parsed", None) or {}
            run_count = parsed.get("run_count")
            pref_hash = parsed.get("pref_hash")
            files_count = parsed.get("files_count")
            volumes_count = parsed.get("volumes_count")
            exe_path = parsed.get("exe")
            timestamp = None
            rts = parsed.get("run_times") or []
            if rts:
                try:
                    timestamp = max(rts)
                except Exception:
                    timestamp = rts[0]
            timestamp = timestamp or _file_mtime_iso(path)
            extra_map = {
                "source": "local:poor_billionaire",
                "run_count": run_count,
                "pref_hash": pref_hash,
                "files_count": files_count,
                "volumes_count": volumes_count,
                "exe_path": exe_path
            }
            rec = {
                "artifact_type": "prefetch",
                "name": os.path.basename(path),
                "path": path,
                "timestamp": timestamp,
                "last_access": None,
                "extra": _format_extra(extra_map),
                "details": json.dumps(parsed)
            }
            out.append(rec)
            return out
        except Exception as e:
            print(f"[prefetch_parser] local parser failed for {path}: {e}")
            # fall through to external module attempt

    # 2) Try installed third-party parser modules (best-effort)
    mod = _try_import_prefetch_module()
    if mod:
        try:
            PrefetchClass = getattr(mod, "Prefetch", None)
            parsed_obj = None
            if PrefetchClass:
                try:
                    parsed_obj = PrefetchClass(path)
                    if hasattr(parsed_obj, "parse") and callable(parsed_obj.parse):
                        try:
                            parsed_obj.parse()
                        except Exception:
                            pass
                except Exception:
                    parsed_obj = None

            if parsed_obj is None and hasattr(mod, "parse"):
                try:
                    parsed_obj = mod.parse(path)
                except Exception:
                    parsed_obj = None

            if parsed_obj is not None:
                def _get(o, *names):
                    for n in names:
                        try:
                            if isinstance(o, dict):
                                if n in o:
                                    return o[n]
                            else:
                                if hasattr(o, n):
                                    return getattr(o, n)
                        except Exception:
                            continue
                    return None

                run_count = _get(parsed_obj, "run_count", "RunCount", "header.run_count", "header_run_count")
                run_times = _get(parsed_obj, "run_times", "last_run_times", "last_run_time", "run_times_list")
                exe_path = _get(parsed_obj, "exe", "filename", "executable", "exe_full_path")
                files = _get(parsed_obj, "files", "referenced_files", "file_list") or []
                volumes = _get(parsed_obj, "volumes", "volume_info") or []
                pref_hash = _get(parsed_obj, "prefetch_hash", "hash", "signature")

                primary_ts = None
                try:
                    if run_times:
                        if isinstance(run_times, (list, tuple)):
                            candidates = []
                            for t in run_times:
                                if t is None:
                                    continue
                                try:
                                    if hasattr(t, "isoformat"):
                                        candidates.append(normalize_timestamp(t.isoformat() + "Z"))
                                    else:
                                        candidates.append(normalize_timestamp(str(t)))
                                except Exception:
                                    continue
                            candidates = [c for c in candidates if c]
                            if candidates:
                                primary_ts = max(candidates)
                        else:
                            t = run_times
                            if hasattr(t, "isoformat"):
                                primary_ts = normalize_timestamp(t.isoformat() + "Z")
                            else:
                                primary_ts = normalize_timestamp(str(t))
                except Exception:
                    primary_ts = None

                extra_map = {
                    "source": f"third_party:{getattr(mod, '__name__', str(mod))}",
                    "run_count": int(run_count) if isinstance(run_count, (int, float, str)) and str(run_count).strip().isdigit() else run_count,
                    "pref_hash": pref_hash,
                    "files_count": len(files) if hasattr(files, "__len__") else None,
                    "volumes_count": len(volumes) if hasattr(volumes, "__len__") else None,
                    "exe_path": exe_path
                }

                rec = {
                    "artifact_type": "prefetch",
                    "name": os.path.basename(path),
                    "path": path,
                    "timestamp": primary_ts or _file_mtime_iso(path),
                    "last_access": None,
                    "extra": _format_extra(extra_map),
                    "details": json.dumps({
                        "run_times": run_times if run_times else [],
                        "files_sample": (files[:200] if files else [])
                    })
                }
                out.append(rec)
                return out

        except Exception as e:
            print(f"[prefetch] third-party parser {getattr(mod,'__name__',str(mod))} failed: {e}")

    # 3) Fallback minimal metadata + md5
    try:
        data = safe_read(path)
    except Exception:
        data = None

    size = None
    try:
        size = os.path.getsize(path)
    except Exception:
        size = None

    md5 = _md5_hex(data) if data else None

    extra_map = {
        "source": "fallback_minimal",
        "size": size,
        "md5": md5
    }

    rec = {
        "artifact_type": "prefetch",
        "name": os.path.basename(path),
        "path": path,
        "timestamp": _file_mtime_iso(path),
        "last_access": None,
        "extra": _format_extra(extra_map)
    }
    out.append(rec)
    return out
