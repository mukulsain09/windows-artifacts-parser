# Windows Artifacts Parser (WAP) 🔍

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)

**A comprehensive forensic tool designed to parse, analyze, and correlate critical Windows artifacts.**

WAP simplifies digital forensics investigations by automatically extracting and correlating data from key Windows system files. It offers both a **Desktop GUI** for quick analysis and a **Web Interface** for flexible, browser-based investigations.

---

## 🚀 Key Features

*   **Multi-Artifact Parsing**: Supports parsing of:
    *   **Prefetch (.pf)**: Execution history tracking.
    *   **LNK Files (.lnk)**: File access shortcuts.
    *   **Recycle Bin ($I...)**: Deleted file recovery metadata.
    *   **ShellBags**: Folder access history via Registry hives.
*   **Dual Interface**:
    *   🖥️ **Desktop GUI**: Built with Tkinter for standalone usage.
    *   🌐 **Web Dashboard**: Built with Flask for modern, responsive analysis.
*   **Advanced Correlation**: Automatically links events across different artifacts to build a cohesive timeline.
*   **Visual Reporting**: Generates PDF reports with:
    *   Artifact distribution charts.
    *   Timeline histograms.
    *   Detailed metadata tables.
*   **Data Export**: Exports parsed data to CSV for external analysis (Excel, Timeline Explorer).
*   **Database Backend**: Uses SQLite for efficient storage and querying of large datasets.

---

## 📸 Screenshots

### Desktop GUI
*(Place a screenshot of your Tkinter main window here: `docs/images/gui_main.png`)*

### Web Dashboard
*(Place a screenshot of your Web Interface here: `docs/images/web_dashboard.png`)*

### PDF Report Sample
*(Place a screenshot of a generated PDF report page here: `docs/images/report_sample.png`)*

---

## 🛠️ Installation

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/YOUR_USERNAME/windows-artifacts-parser.git
    cd windows-artifacts-parser
    ```

2.  **Set up a Virtual Environment** (Recommended):
    ```bash
    python -m venv venv
    # Windows:
    venv\Scripts\activate
    # Linux/Mac:
    source venv/bin/activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

---

## 💻 Usage

### Option 1: Desktop GUI
Launch the standalone desktop application:
```bash
python main.py
```
*   **Browse**: Select a folder containing artifacts (e.g., a mounted image or extraction).
*   **Parse**: Click "Parse Folder" or "Parse ShellBags".
*   **Report**: Use "Export PDF Report" or "Correlate / Timeline" buttons.

### Option 2: Web Interface
Start the local web server:
```bash
python app.py
```
*   Open your browser and navigate to: `http://127.0.0.1:5000`
*   Use the upload and analysis tools directly in the browser.

---

## 📂 Project Structure

```
windows-artifacts-parser/
├── app.py              # Flask Web Application entry point
├── main.py             # Tkinter Desktop GUI entry point
├── core_logic.py       # Centralized business logic (Parsing, DB, Reporting)
├── parsers/            # Artifact-specific parsing modules
│   ├── prefetch_parser.py
│   ├── lnk_parser.py
│   ├── recycle_parser.py
│   └── shellbags_parser.py
├── db/                 # Database schema and utility functions
├── templates/          # HTML templates for the Web Interface
├── static/             # CSS/JS assets for the Web Interface
└── requirements.txt    # Python dependencies
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1.  Fork the project
2.  Create your feature branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
