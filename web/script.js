document.addEventListener('DOMContentLoaded', () => {
    // --- Existing variable declarations ---
    const folderPathInput = document.getElementById('folderPathInput');
    const parseFolderBtn = document.getElementById('parseFolderBtn');
    const parseShellbagsBtn = document.getElementById('parseShellbagsBtn');
    const clearDbBtn = document.getElementById('clearDbBtn');
    const refreshBtn = document.getElementById('refreshBtn');
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    const exportPdfBtn = document.getElementById('exportPdfBtn');
    const artifactsTableBody = document.querySelector('#artifactsTable tbody');
    const statusSection = document.getElementById('statusSection');
    const showCorrelationsBtn = document.getElementById('showCorrelationsBtn');

    // --- Modal variable declarations ---
    const pdfReportModal = document.getElementById('pdfReportModal');
    const closeModalBtn = document.querySelector('.close-btn');
    const pdfReportForm = document.getElementById('pdfReportForm');

    // --- Existing functions (showStatus, fetchArtifacts) ---
    function showStatus(message, type = 'info') {
        statusSection.innerHTML = `<p class="${type}">${message}</p>`;
        statusSection.style.display = 'block';
        setTimeout(() => { statusSection.style.display = 'none'; }, 5000);
    }

    async function fetchArtifacts() {
        try {
            const response = await fetch('/api/artifacts');
            const artifacts = await response.json();
            artifactsTableBody.innerHTML = ''; // Clear existing data

            if (artifacts.length === 0) {
                artifactsTableBody.innerHTML = '<tr><td colspan="8">No artifacts found.</td></tr>';
                return;
            }

            artifacts.forEach(artifact => {
                const row = artifactsTableBody.insertRow();
                row.insertCell().textContent = artifact.id || '';
                row.insertCell().textContent = artifact.artifact_type || '';
                row.insertCell().textContent = artifact.name || '';
                row.insertCell().textContent = artifact.path || '';
                row.insertCell().textContent = artifact.timestamp || '';
                row.insertCell().textContent = artifact.last_access || '';
                row.insertCell().textContent = artifact.extra || '';
                row.insertCell().textContent = artifact.details || '';
            });
        } catch (error) {
            console.error('Error fetching artifacts:', error);
            showStatus('Error fetching artifacts.', 'error');
        }
    }

    // --- Initial fetch ---
    fetchArtifacts();

    // --- Modal Event Listeners ---
    exportPdfBtn.addEventListener('click', (e) => {
        e.preventDefault(); // Prevent default link behavior
        pdfReportModal.style.display = 'block';
    });

    closeModalBtn.addEventListener('click', () => {
        pdfReportModal.style.display = 'none';
    });

    window.addEventListener('click', (event) => {
        if (event.target == pdfReportModal) {
            pdfReportModal.style.display = 'none';
        }
    });

    pdfReportForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        showStatus('Generating PDF report...');

        const formData = new FormData(pdfReportForm);
        const reportDetails = Object.fromEntries(formData.entries());

        try {
            const response = await fetch('/api/export_pdf', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(reportDetails)
            });

            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                // Extract filename from Content-Disposition header
                const disposition = response.headers.get('Content-Disposition');
                let filename = 'artifacts_report.pdf'; // Default filename
                if (disposition && disposition.indexOf('attachment') !== -1) {
                    const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
                    const matches = filenameRegex.exec(disposition);
                    if (matches != null && matches[1]) {
                        filename = matches[1].replace(/['"]/g, '');
                    }
                }
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                showStatus('PDF report initiated. Check your downloads.');
            } else {
                const errorData = await response.json();
                showStatus(`Error generating PDF: ${errorData.message}`, 'error');
            }
        } catch (error) {
            console.error('Error exporting PDF:', error);
            showStatus(`Error exporting PDF: ${error.message}`, 'error');
        } finally {
            pdfReportModal.style.display = 'none';
            pdfReportForm.reset();
        }
    });

    // --- Existing Event Listeners ---
    parseFolderBtn.addEventListener('click', async () => {
        const folderPath = folderPathInput.value;
        if (!folderPath) { return showStatus('Please enter a folder path.', 'error'); }
        showStatus('Parsing folder started...');
        // ... (rest of the function is the same)
        try {
            const response = await fetch('/api/parse_folder', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ folder_path: folderPath })
            });
            const data = await response.json();
            if (data.status === 'success') { showStatus(data.message); }
            else { showStatus(`Error: ${data.message}`, 'error'); }
        } catch (error) {
            console.error('Error parsing folder:', error);
            showStatus(`Error parsing folder: ${error.message}`, 'error');
        }
    });

    parseShellbagsBtn.addEventListener('click', async () => {
        showStatus('Parsing ShellBags started...');
        // ... (rest of the function is the same)
        try {
            const response = await fetch('/api/parse_shellbags', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const data = await response.json();
            if (data.status === 'success') { showStatus(data.message); }
            else { showStatus(`Error: ${data.message}`, 'error'); }
        } catch (error) {
            console.error('Error parsing ShellBags:', error);
            showStatus(`Error parsing ShellBags: ${error.message}`, 'error');
        }
    });

    clearDbBtn.addEventListener('click', async () => {
        if (!confirm('Are you sure you want to clear the entire database?')) { return; }
        showStatus('Clearing database...');
        // ... (rest of the function is the same)
        try {
            const response = await fetch('/api/clear_db', { method: 'POST' });
            const data = await response.json();
            if (data.status === 'success') {
                showStatus(data.message);
                fetchArtifacts();
            } else {
                showStatus(`Error: ${data.message}`, 'error');
            }
        } catch (error) {
            console.error('Error clearing database:', error);
            showStatus(`Error clearing database: ${error.message}`, 'error');
        }
    });

    refreshBtn.addEventListener('click', fetchArtifacts);

    showCorrelationsBtn.addEventListener('click', () => {
        window.open('/correlation', '_blank');
    });

    exportCsvBtn.addEventListener('click', () => {
        showStatus('Generating CSV report...');
        window.location.href = '/api/export_csv';
        showStatus('CSV report initiated. Check your downloads.');
    });

    // --- Theme Switcher Logic ---
    const themeToggle = document.getElementById('theme-toggle');

    function setTheme(theme) {
        document.body.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        if (theme === 'dark') {
            themeToggle.checked = true;
        } else {
            themeToggle.checked = false;
        }
    }

    themeToggle.addEventListener('change', () => {
        if (themeToggle.checked) {
            setTheme('dark');
        } else {
            setTheme('light');
        }
    });

    // Apply saved theme on initial load
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        setTheme(savedTheme);
    } else {
        // Default to light theme if no preference is saved
        setTheme('light');
    }
});
