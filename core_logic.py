# core_logic.py
import os
import sqlite3
import threading
import datetime
import hashlib
import json
import tempfile
import getpass
import platform
import socket
import logging
from typing import List, Dict, Any
import csv
import matplotlib
# use a non-interactive backend safe for background threads / servers
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# Configure logging for core_logic
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# Try to import db_utils and schema from package or root
try:
    from db.db_utils import open_db, execute_with_retry
    from db.schema import init_db, insert_artifact, query_artifacts, insert_artifacts_bulk, clear_database
except ImportError:
    logger.warning("Could not import from db/db_utils.py or db/schema.py directly. Trying fallbacks.")
    try:
        from db_utils import open_db, execute_with_retry
        from schema import init_db, insert_artifact, query_artifacts, insert_artifacts_bulk, clear_database
    except ImportError as e:
        logger.error(f"Failed to import DB utilities: {e}")
        open_db = None
        execute_with_retry = None
        init_db = None
        insert_artifact = None
        query_artifacts = None
        insert_artifacts_bulk = None
        clear_database = None

# Import parsers (try package imports then fallbacks)
try:
    from parsers import report_gen, prefetch_parser, lnk_parser, recycle_parser, shellbags_parser
except ImportError:
    logger.warning("Could not import from parsers/ directly. Trying fallbacks.")
    try:
        import report_gen
        import prefetch_parser
        import lnk_parser
        import recycle_parser
        import shellbags_parser
    except ImportError as e:
        logger.error(f"Failed to import parser modules: {e}")
        report_gen = None
        prefetch_parser = None
        lnk_parser = None
        recycle_parser = None
        shellbags_parser = None

# Import correlator
try:
    from correlator import correlate_artifacts
except ImportError:
    logger.warning("Could not import correlator.py directly. Trying fallbacks.")
    try:
        import correlator
        correlate_artifacts = correlator.correlate_artifacts
    except ImportError as e:
        logger.error(f"Failed to import correlator module: {e}")
        correlate_artifacts = None


DB_PATH = "artifacts.db"
TOOL_VERSION = "v1.3.1"


def _sha256_file(path):
    """Calculates the SHA256 hash of a file."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating SHA256 for {path}: {e}")
        return ""


# ---------------------------
# ** FIX: SAFE TIMESTAMP **
# Prevent Windows OSError: [Errno 22] when dt.timestamp() is invalid
# ---------------------------
def safe_timestamp(dt: datetime.datetime):
    """
    Safely convert datetime → POSIX timestamp.
    Returns None if the timestamp cannot be represented on this system.
    """
    try:
        return dt.timestamp()
    except Exception:
        # Windows fails on dates before 1970 or FILETIME-baseline 1601 values.
        return None
# ---------------------------


def build_metadata(db_path: str) -> dict:
    """Builds metadata for reports."""
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


def make_counts_chart(rows: List[Dict[str, Any]], outpath: str):
    """Generates a bar chart of artifact type counts."""
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
        ax.annotate(str(int(height)),
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 2),
                    textcoords="offset points",
                    ha="center", va="bottom", fontsize=7)

    plt.tight_layout()
    fig.savefig(outpath, bbox_inches="tight")
    plt.close(fig)
    logger.info(f"Generated counts chart: {outpath}")


def make_timeline_histogram(rows: List[Dict[str, Any]], outpath: str):
    """Generates a timeline histogram of artifact timestamps."""
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
        except Exception as e:
            logger.warning(f"Could not parse timestamp '{t}': {e}")
            continue

    if not times:
        fig, ax = plt.subplots(figsize=(6.5, 2.6), dpi=150)
        ax.text(0.5, 0.5, "No timestamp data available for timeline",
                ha="center", va="center", fontsize=10)
        ax.axis("off")
        fig.savefig(outpath, bbox_inches="tight")
        plt.close(fig)
        logger.info(f"Generated empty timeline chart: {outpath}")
        return

    # ---------------------------
    # ** FIX APPLIED HERE **
    # Convert datetime → timestamp SAFELY
    # ---------------------------
    timestamps = []
    for dt in times:
        ts = safe_timestamp(dt)
        if ts is not None:     # Skip invalid timestamps
            timestamps.append(ts)

    if not timestamps:
        fig, ax = plt.subplots(figsize=(6.5, 2.6), dpi=150)
        ax.text(0.5, 0.5,
                "No valid timestamp data for timeline (invalid/1601 dates skipped)",
                ha="center", va="center", fontsize=10)
        ax.axis("off")
        fig.savefig(outpath, bbox_inches="tight")
        plt.close(fig)
        logger.info("Timeline had only invalid timestamps; generated fallback chart.")
        return
    # ---------------------------

    fig, ax = plt.subplots(figsize=(6.5, 2.6), dpi=150)
    ax.hist(timestamps, bins=24, color="#5DA5A4", edgecolor="white")
    ax.set_title("Events over time (histogram)")

    xlocs = ax.get_xticks()
    if len(xlocs) > 0:
        xlabels = [
            datetime.datetime.utcfromtimestamp(x).strftime("%Y-%m-%d\n%H:%M")
            for x in xlocs
        ]
        ax.set_xticklabels(xlabels, rotation=45, ha="right", fontsize=7)
    else:
        ax.set_xticklabels([])

    ax.set_xlabel("UTC")
    ax.set_ylabel("Events")
    ax.grid(axis="y", linestyle="--", alpha=0.3)
    plt.tight_layout()
    fig.savefig(outpath, bbox_inches="tight")
    plt.close(fig)
    logger.info(f"Generated timeline chart: {outpath}")


def parse_folder_core(folder_path: str) -> dict:
    """
    Parses artifacts from a given folder path and inserts them into the database.
    Returns a dictionary with status and message.
    """
    if not os.path.isdir(folder_path):
        return {"status": "error", "message": f"Folder not found: {folder_path}"}

    logger.info(f"Starting to parse folder: {folder_path}")
    parsed_records = []
    conn = None
    try:
        conn = open_db(DB_PATH) if open_db else sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        if "prefetch" in folder_path.lower():
            logger.info("Using direct listdir for Prefetch folder.")
            try:
                for f in os.listdir(folder_path):
                    path = os.path.join(folder_path, f)
                    if os.path.isfile(path) and f.lower().endswith('.pf'):
                        try:
                            records = prefetch_parser.parse_prefetch(path)
                            parsed_records.extend(records)
                        except Exception as e:
                            logger.error(f"[!] Failed to parse {path}: {e}")
            except Exception as e:
                logger.error(f"Could not list files in {folder_path}: {e}")
        else:
            for root, _, files in os.walk(folder_path):
                root_lower = root.lower()
                for f in files:
                    path = os.path.join(root, f)
                    low = f.lower()
                    try:
                        if low.endswith(".pf") or "prefetch" in root_lower:
                            records = prefetch_parser.parse_prefetch(path)
                            parsed_records.extend(records)
                        elif low.endswith(".lnk"):
                            records = lnk_parser.parse_lnk(path)
                            parsed_records.extend(records)
                        elif (low.startswith("$i") or low.startswith("i")) and (
                            "$recycle.bin" in root_lower or "recycle.bin" in root_lower
                        ):
                            records = recycle_parser.parse_i_file(path)
                            parsed_records.extend(records)
                    except Exception as e:
                        logger.error(f"[!] Failed to parse {path}: {e}")

        if parsed_records:
            insert_artifacts_bulk(conn, parsed_records)
            conn.commit()
            logger.info(f"Inserted {len(parsed_records)} artifacts from {folder_path}.")
        else:
            logger.info(f"No artifacts found in {folder_path}.")

        return {
            "status": "success",
            "message": f"Finished parsing folder: {folder_path}. "
                       f"Inserted {len(parsed_records)} records."
        }
    except Exception as e:
        logger.error(f"Error during folder parsing: {e}")
        return {"status": "error", "message": f"Error during folder parsing: {e}"}
    finally:
        if conn:
            try:
                conn.close()
            except Exception as e:
                logger.error(f"Error closing DB connection: {e}")


def parse_shellbags_core() -> dict:
    """
    Parses ShellBags artifacts and inserts them into the database.
    """
    logger.info("Starting ShellBags parsing.")
    try:
        if shellbags_parser is None:
            return {"status": "error", "message": "ShellBags parser not available."}

        records = shellbags_parser.parse_shellbags()
        if not records:
            return {"status": "info", "message": "No ShellBag data found or insufficient privileges."}

        conn = None
        try:
            conn = open_db(DB_PATH) if open_db else sqlite3.connect(DB_PATH)
            insert_artifacts_bulk(conn, records)
            conn.commit()
            logger.info(f"Parsed and inserted {len(records)} ShellBag entries.")
            return {"status": "success", "message": f"Parsed and inserted {len(records)} ShellBag entries."}
        except Exception as e:
            logger.error(f"Error inserting ShellBag data: {e}")
            return {"status": "error", "message": f"Error inserting ShellBag data: {e}"}
        finally:
            if conn:
                try:
                    conn.close()
                except Exception as e:
                    logger.error(f"Error closing DB after ShellBags parse: {e}")

    except Exception as e:
        logger.error(f"Failed to parse ShellBags: {e}")
        return {"status": "error", "message": f"Failed to parse ShellBags: {e}"}


def get_all_artifacts_json() -> List[Dict[str, Any]]:
    """Fetches all artifacts and returns them as JSON-safe dictionaries."""
    if query_artifacts is None:
        logger.error("query_artifacts function not available.")
        return []

    rows = query_artifacts(DB_PATH)
    logger.info(f"Fetched {len(rows)} artifacts from DB.")
    for row in rows:
        for k, v in row.items():
            if isinstance(v, datetime.datetime):
                row[k] = v.isoformat()
    return rows


def clear_database_core() -> dict:
    """Clears all artifacts from the database."""
    if clear_database is None:
        logger.error("clear_database function is not available.")
        return {"status": "error", "message": "Clear database function not available."}
    try:
        clear_database(DB_PATH)
        logger.info("Database cleared.")
        return {"status": "success", "message": "Database cleared successfully."}
    except Exception as e:
        logger.error(f"Error clearing database: {e}")
        return {"status": "error", "message": f"Error clearing database: {e}"}


def generate_csv_report(file_path: str) -> dict:
    """Exports all artifacts to CSV."""
    logger.info(f"Generating CSV report at: {file_path}")
    rows = get_all_artifacts_json()
    if not rows:
        return {"status": "info", "message": "No artifacts to export."}

    try:
        headers = list(rows[0].keys())
        with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)
        logger.info(f"CSV saved: {file_path}")
        return {"status": "success", "message": f"CSV saved: {file_path}"}
    except Exception as e:
        logger.error(f"CSV generation failed: {e}")
        return {"status": "error", "message": f"CSV generation failed: {e}"}


def generate_pdf_report_core(file_path: str, report_details: Dict[str, Any]) -> dict:
    """Generates the PDF artifact report."""
    if report_gen is None:
        logger.error("report_gen not available.")
        return {"status": "error", "message": "Report generation module not available."}

    logger.info(f"Generating PDF report at: {file_path}")
    try:
        rows = get_all_artifacts_json()
        metadata = build_metadata(DB_PATH)

        metadata['Case ID'] = report_details.get('caseNumber', '')
        metadata['Evidence ID'] = report_details.get('evidenceNumber', '')
        metadata['Description'] = report_details.get('uniqueDescription', '')
        metadata['Examiner'] = report_details.get('examiner', metadata.get('Examiner', ''))
        metadata['Notes'] = report_details.get('notes', '')

        tmp_dir = tempfile.mkdtemp(prefix="wab_report_")
        counts_png = os.path.join(tmp_dir, "counts.png")
        timeline_png = os.path.join(tmp_dir, "timeline.png")

        make_counts_chart(rows, counts_png)
        make_timeline_histogram(rows, timeline_png)

        metadata["chart_counts"] = counts_png
        metadata["chart_timeline"] = timeline_png

        report_gen.generate_pdf_report(DB_PATH, file_path,
                                       title=f"Artifacts Report ({socket.gethostname()})",
                                       metadata=metadata)

        logger.info(f"PDF report generated: {file_path}")
        return {"status": "success", "message": f"PDF saved: {file_path}"}
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        return {"status": "error", "message": f"PDF generation failed: {e}"}
    finally:
        if 'tmp_dir' in locals() and os.path.exists(tmp_dir):
            try:
                for f in os.listdir(tmp_dir):
                    os.remove(os.path.join(tmp_dir, f))
                os.rmdir(tmp_dir)
            except Exception as e:
                logger.warning(f"Temp cleanup failed: {tmp_dir}: {e}")


def generate_correlation_pdf_core(file_path: str, report_details: Dict[str, Any]) -> dict:
    """Generates correlation PDF report."""
    if report_gen is None:
        logger.error("report_gen not available.")
        return {"status": "error", "message": "Report generation module not available."}

    logger.info(f"Generating correlation PDF at: {file_path}")
    try:
        rows = get_all_artifacts_json()
        metadata = build_metadata(DB_PATH)

        metadata['Case ID'] = report_details.get('caseNumber', '')
        metadata['Evidence ID'] = report_details.get('evidenceNumber', '')
        metadata['Description'] = report_details.get('uniqueDescription', '')
        metadata['Examiner'] = report_details.get('examiner', metadata.get('Examiner', ''))
        metadata['Notes'] = report_details.get('notes', '')

        tmp_dir = tempfile.mkdtemp(prefix="wab_corr_")
        counts_png = os.path.join(tmp_dir, "counts_corr.png")
        timeline_png = os.path.join(tmp_dir, "timeline_corr.png")

        make_counts_chart(rows, counts_png)
        make_timeline_histogram(rows, timeline_png)

        metadata["chart_counts"] = counts_png
        metadata["chart_timeline"] = timeline_png

        report_gen.generate_correlation_pdf(
            DB_PATH, file_path,
            title=f"Correlation Report ({socket.gethostname()})",
            metadata=metadata
        )

        logger.info(f"Correlation PDF saved: {file_path}")
        return {"status": "success", "message": f"Correlation PDF saved: {file_path}"}
    except Exception as e:
        logger.error(f"Correlation PDF failed: {e}")
        return {"status": "error", "message": f"Correlation PDF failed: {e}"}
    finally:
        if 'tmp_dir' in locals() and os.path.exists(tmp_dir):
            try:
                for f in os.listdir(tmp_dir):
                    os.remove(os.path.join(tmp_dir, f))
                os.rmdir(tmp_dir)
            except Exception as e:
                logger.warning(f"Temp cleanup failed: {tmp_dir}: {e}")


def get_correlations_json() -> List[Dict[str, Any]]:
    """Fetches correlated artifacts."""
    if correlate_artifacts is None:
        logger.error("correlate_artifacts not available.")
        return []

    logger.info("Fetching correlations.")
    try:
        correlated_rows = correlate_artifacts(DB_PATH)
        logger.info(f"Fetched {len(correlated_rows)} correlated entries.")

        formatted_rows = []
        for row in correlated_rows:
            row_dict = dict(row) if isinstance(row, sqlite3.Row) else row
            for k, v in row_dict.items():
                if isinstance(v, datetime.datetime):
                    row_dict[k] = v.isoformat()
            formatted_rows.append(row_dict)

        return formatted_rows
    except Exception as e:
        logger.error(f"Error fetching correlations: {e}")
        return []


# Initialize the database when core_logic loads
if init_db:
    init_db(DB_PATH)
    logger.info(f"Database {DB_PATH} initialized.")
else:
    logger.error("Database init not available.")
