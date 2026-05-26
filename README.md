## ⚠️ ARCHIVED / DEPRECATED
   This version is no longer maintained. Please use the updated and significantly improved version here:
   👉 **[Windows Forensic Analysis Suite v2.0](https://github.com/mukulsain09/Windows-Forensic-Analysis-Suite-Version-2.0-)**
     
# Digital Footprint Analyser (Windows Artifacts Parser)

A lightweight digital forensic tool designed to extract, analyze, and correlate key Windows artifacts to reconstruct user activity timelines.
The system focuses on behavioral reconstruction using multi-artifact correlation and provides both a Desktop GUI and a Web Dashboard for investigation and reporting.

---

## Overview

Digital Footprint Analyser automates the forensic examination of Windows artifacts by parsing multiple evidence sources and combining them into a unified timeline.
The tool reduces manual analysis effort and helps investigators quickly understand user actions such as folder navigation, program execution, file access, and deletion events.

The system is designed for:

* Digital Forensics & Incident Response (DFIR)
* Academic research and learning
* Rapid forensic triage
* Offline artifact folder analysis

---

## Key Features

### Multi-Artifact Parsing

Supports extraction and analysis of:

* **Shellbags** – Folder navigation history from registry hives
* **Prefetch (.pf)** – Application execution traces
* **LNK Files (.lnk)** – File and directory access evidence
* **Recycle Bin ($I)** – Deleted file metadata and original paths

---

### Timeline Correlation

* Normalizes timestamps into UTC
* Links events across different artifact types
* Generates a unified chronological activity timeline
* Groups related activities into investigation sessions

---

### Dual Interface

**Desktop GUI (Tkinter)**

* Standalone analysis environment
* Folder selection and parsing
* Quick investigation workflow

**Web Dashboard (Flask)**

* Browser-based interface
* Searchable artifact tables
* Timeline visualization
* Case-style analysis experience

---

### Reporting & Export

* Generate structured **PDF forensic reports**
* Export parsed data to **CSV**
* Timeline histograms and artifact distribution charts
* Compatible with Excel and external forensic tools

---

### Database Backend

* SQLite-based storage
* Efficient querying of large artifact datasets
* Structured schema for artifacts and correlations

---

## How It Works

1. Investigator selects a folder containing Windows artifacts (or extracted evidence).
2. The system automatically detects supported artifact types.
3. Dedicated parsers extract metadata from each source.
4. All timestamps are normalized and stored in a centralized database.
5. A correlation engine aligns events based on:

   * Timestamp proximity
   * File or folder paths
   * Activity type
6. Results are presented through the GUI or Web Dashboard.
7. Reports and CSV exports can be generated for further analysis.

---

## Project Structure

```
windows-artifacts-parser/
│
├── app.py                 # Flask Web Application
├── main.py                # Desktop GUI entry point
├── core_logic.py          # Parsing, database, and correlation logic
│
├── parsers/
│   ├── shellbags_parser.py
│   ├── prefetch_parser.py
│   ├── lnk_parser.py
│   └── recycle_parser.py
│
├── db/
│   └── database utilities and schema
│
├── templates/             # HTML templates for web interface
├── static/                # CSS and JavaScript assets
│
├── requirements.txt
└── docs/images/           # Screenshots and sample outputs
```

---

## Installation

Clone the repository:

```
git clone https://github.com/YOUR_USERNAME/windows-artifacts-parser.git
cd windows-artifacts-parser
```

Create a virtual environment:

**Windows**

```
python -m venv venv
venv\Scripts\activate
```

**Linux / macOS**

```
python -m venv venv
source venv/bin/activate
```

Install dependencies:

```
pip install -r requirements.txt
```

---

## Usage

### Option 1: Desktop GUI

Launch the standalone application:

```
python main.py
```

Steps:

1. Select artifact directory
2. Click **Parse Folder**
3. View results
4. Export PDF or CSV

---

### Option 2: Web Interface

Start the web server:

```
python app.py
```

Open browser:

```
http://127.0.0.1:5000
```

Features:

* Upload / select artifact folder
* View parsed artifacts
* Explore timeline
* Export reports

---

## Screenshots

Place project images inside:

```
docs/images/
```

Recommended files:

* gui_main.png
* web_dashboard.png
* report_sample.png

---

## Performance

* Processes thousands of artifacts in a few seconds
* Supports large datasets using SQLite indexing
* Lightweight memory usage suitable for standard forensic workstations

---

## Future Enhancements

* Offline registry hive support (NTUSER.DAT / USRCLASS.DAT)
* Additional Windows artifacts (Amcache, Jump Lists, Browser data)
* Anti-forensic detection
* Multi-user timeline reconstruction
* Case management features

---

## Contributing

Contributions and improvements are welcome.
You may fork the repository, create a feature branch, and submit a pull request.

---

## Author

Developed as part of a Digital Forensics project focused on automated Windows artifact analysis and behavioral reconstruction.
