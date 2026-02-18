document.addEventListener('DOMContentLoaded', () => {
    const correlationsTableBody = document.querySelector('#correlationsTable tbody');
    const exportCorrelationPdfBtn = document.getElementById('exportCorrelationPdfBtn');

    // --- Modal variable declarations ---
    const pdfReportModal = document.getElementById('pdfReportModal');
    const closeModalBtn = document.querySelector('.close-btn');
    const pdfReportForm = document.getElementById('pdfReportForm');

    async function fetchCorrelations() {
        try {
            const response = await fetch('/api/correlations');
            const correlations = await response.json();
            correlationsTableBody.innerHTML = ''; // Clear existing data

            if (correlations.length === 0) {
                correlationsTableBody.innerHTML = '<tr><td colspan="4">No correlations found.</td></tr>';
                return;
            }

            correlations.forEach(correlation => {
                const row = correlationsTableBody.insertRow();
                row.insertCell().textContent = correlation.timestamp || '';
                row.insertCell().textContent = correlation.artifact_type || '';
                row.insertCell().textContent = correlation.detail || '';
                row.insertCell().textContent = correlation.anomaly || '';
            });
        } catch (error) {
            console.error('Error fetching correlations:', error);
            correlationsTableBody.innerHTML = '<tr><td colspan="4">Error fetching correlations.</td></tr>';
        }
    }

    fetchCorrelations();

    // --- Modal Event Listeners ---
    exportCorrelationPdfBtn.addEventListener('click', (e) => {
        e.preventDefault();
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
        alert('Generating Correlation PDF report...');

        const formData = new FormData(pdfReportForm);
        const reportDetails = Object.fromEntries(formData.entries());

        try {
            const response = await fetch('/api/export_correlation_pdf', {
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
                const disposition = response.headers.get('Content-Disposition');
                let filename = 'correlation_report.pdf';
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
            } else {
                const errorData = await response.json();
                alert(`Error generating PDF: ${errorData.message}`);
            }
        } catch (error) {
            console.error('Error exporting correlation PDF:', error);
            alert(`Error exporting correlation PDF: ${error.message}`);
        } finally {
            pdfReportModal.style.display = 'none';
            pdfReportForm.reset();
        }
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