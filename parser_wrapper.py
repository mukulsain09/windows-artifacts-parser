import os
import sqlite3
import threading
import tempfile
import getpass
import platform
import socket
import datetime
import hashlib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Import parsers and schema (try package imports then fallbacks)
try:
    from db.db_utils import open_db, execute_with_retry
    from db.schema import init_db, insert_artifact, query_artifacts, insert_artifacts_bulk
    from parsers import report_gen, prefetch_parser, lnk_parser, recycle_parser, shellbags_parser
    from correlator import correlate_artifacts
except Exception:
    # fallback: maybe modules are at top-level
    from db_utils import open_db, execute_with_retry
    from schema import init_db, insert_artifact, query_artifacts, insert_artifacts_bulk
    import report_gen
    import prefetch_parser
    import lnk_parser
    import recycle_parser
    import shellbags_parser
    from correlator import correlate_artifacts


DB_PATH = "artifacts.db"
TOOL_VERSION = "v1.2.5" # Updated version

def _sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def build_metadata(db_path: str) -> dict:
    meta = {}
    try:
        meta["Examiner"] = getpass.getuser()
    except Exception:
        meta["Examiner"] = ""
    try:
        meta["Source"] = socket.gethostname()
    except Exception:
        meta["Source"] = ""
    meta["OS"] = f"{platform.system()} {platform.release()} ({platform.version()})"
    meta["Tool Version"] = TOOL_VERSION
    meta["Generated"] = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    meta["DB SHA256"] = _sha256_file(db_path)
    meta["Case ID"] = ""
    meta["Notes"] = ""
    return meta


def _make_counts_chart(rows, outpath):
    types = [r.get("artifact_type") or "unknown" for r in rows]
    counts = {}
    for t in types:
        counts[t] = counts.get(t, 0) + 1
    items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    labels = [i[0] for i in items]
    values = [i[1] for i in items]

    fig, ax = plt.subplots(figsize=(6.5, 2.6), dpi=150)
    color_count = max(1, len(labels))
    try:
        colors_map = plt.cm.Set2.colors
        color_list = colors_map[:color_count]
    except Exception:
        color_list = None

    bars = ax.bar(range(len(labels)), values, color=color_list)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.set_ylabel("Count")
    ax.set_title("Artifact counts by type")
    ax.grid(axis="y", linestyle="--", alpha=0.3)
    for rect in bars:
        height = rect.get_height()
        ax.annotate(str(int(height)), xy=(rect.get_x() + rect.get_width() / 2, height), xytext=(0, 2), textcoords="offset points", ha="center", va="bottom", fontsize=7)
    plt.tight_layout()
    fig.savefig(outpath, bbox_inches="tight")
    plt.close(fig)


def _make_timeline_histogram(rows, outpath):
    times = []
    for r in rows:
        t = r.get("timestamp") or r.get("last_access")
        if not t:
            continue
        try:
            s = t
            if s.endswith("Z"):
                s = s[:-1]
            dt = datetime.datetime.fromisoformat(s)
            times.append(dt)
        except Exception:
            continue

    if not times:
        fig, ax = plt.subplots(figsize=(6.5, 2.6), dpi=150)
        ax.text(0.5, 0.5, "No timestamp data available for timeline", ha="center", va="center", fontsize=10)
        ax.axis("off")
        fig.savefig(outpath, bbox_inches="tight")
        plt.close(fig)
        return

    timestamps = [dt.timestamp() for dt in times]
    fig, ax = plt.subplots(figsize=(6.5, 2.6), dpi=150)
    ax.hist(timestamps, bins=24, color="#5DA5A4", edgecolor="white")
    ax.set_title("Events over time (histogram)")
    xlocs = ax.get_xticks()
    xlabels = [datetime.datetime.utcfromtimestamp(x).strftime("%Y-%m-%d\n%H:%M") for x in xlocs]
    ax.set_xticklabels(xlabels, rotation=45, ha="right", fontsize=7)
    ax.set_xlabel("UTC")
    ax.set_ylabel("Events")
    ax.grid(axis="y", linestyle="--", alpha=0.3)
    plt.tight_layout()
    fig.savefig(outpath, bbox_inches="tight")
    plt.close(fig)


def parse_artifacts(folder):
    """
    Parses artifacts from a given folder and stores them in the database.
    """
    init_db(DB_PATH)
    conn = None
    if open_db:
        conn = open_db(DB_PATH)
    else:
        conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    for root, _, files in os.walk(folder):
        root_lower = root.lower()
        for f in files:
            path = os.path.join(root, f)
            low = f.lower()
            try:
                if low.endswith(".pf") or "prefetch" in root_lower:
                    for rec in prefetch_parser.parse_prefetch(path):
                        insert_artifact(conn, rec)
                elif low.endswith(".lnk"):
                    for rec in lnk_parser.parse_lnk(path):
                        insert_artifact(conn, rec)
                elif (low.startswith("$i") or low.startswith("i")) and ("$recycle.bin" in root_lower or "recycle.bin" in root_lower):
                    for rec in recycle_parser.parse_i_file(path):
                        insert_artifact(conn, rec)
            except Exception as e:
                print(f"[!] Failed to parse {path}: {e}")
    try:
        conn.commit()
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass
    print("[+] Parsing complete.")
    return True

def run_correlation():
    """
    Runs the correlation process and generates a PDF report.
    Returns the path to the report.
    """
    file_path = os.path.join('reports', 'correlation_report.pdf')
    try:
        rows = query_artifacts(DB_PATH)
        metadata = build_metadata(DB_PATH)
        tmp_dir = tempfile.mkdtemp(prefix="wab_corr_")
        counts_png = os.path.join(tmp_dir, "counts_corr.png")
        timeline_png = os.path.join(tmp_dir, "timeline_corr.png")
        _make_counts_chart(rows, counts_png)
        _make_timeline_histogram(rows, timeline_png)
        metadata["chart_counts"] = counts_png
        metadata["chart_timeline"] = timeline_png
        report_gen.generate_correlation_pdf(DB_PATH, file_path, title=f"Correlation Report ({socket.gethostname()})", metadata=metadata)
        print(f"[+] Correlation PDF successfully generated: {file_path}")
        return os.path.basename(file_path)
    except Exception as e:
        print(f"[!] Failed to generate correlation PDF: {e}")
        return None


def parse_and_correlate(folder):
    """
    Parses artifacts and then runs correlation.
    """
    parse_artifacts(folder)
    report_path = run_correlation()
    return report_path
