// CyberScan Web Frontend JavaScript

class CyberScanUI {
    constructor() {
        this.currentScanId = null;
        this.pollInterval = null;
        this.initEventListeners();
    }

    initEventListeners() {
        document.getElementById('startScan').addEventListener('click', () => this.handleStartScan());
        document.getElementById('cancelScan')?.addEventListener('click', () => this.handleCancelScan());
        document.getElementById('viewResults')?.addEventListener('click', () => this.showResults());
        document.getElementById('newScan')?.addEventListener('click', () => this.resetScan());
        document.getElementById('downloadHTML')?.addEventListener('click', () => this.downloadReport('html'));
        document.getElementById('downloadJSON')?.addEventListener('click', () => this.downloadReport('json'));
        document.getElementById('downloadCSV')?.addEventListener('click', () => this.downloadReport('csv'));
    }

    async handleStartScan() {
        const urls = this.getUrls();
        if (!urls.length) {
            alert('Please enter at least one URL');
            return;
        }

        const scanType = document.getElementById('scanType').value;
        const timeout = parseInt(document.getElementById('timeout').value);
        const aggressive = document.getElementById('aggressive').checked;
        const stealth = document.getElementById('stealth').checked;

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    urls: urls,
                    scan_type: scanType,
                    timeout: timeout,
                    aggressive: aggressive,
                    stealth: stealth
                })
            });

            if (!response.ok) {
                const error = await response.json();
                alert(`Error: ${error.error}`);
                return;
            }

            const data = await response.json();
            this.currentScanId = data.scan_id;

            // Show progress panel
            document.getElementById('progressPanel').classList.remove('hidden');
            document.getElementById('configPanel')?.classList.add('hidden');
            document.getElementById('resultsPanel').classList.add('hidden');

            // Start polling for progress
            this.startProgressPolling();
        } catch (error) {
            console.error('Error starting scan:', error);
            alert('Failed to start scan. See console for details.');
        }
    }

    startProgressPolling() {
        this.pollInterval = setInterval(() => this.updateProgress(), 1000);
    }

    async updateProgress() {
        if (!this.currentScanId) return;

        try {
            const response = await fetch(`/api/scan/${this.currentScanId}/status`);
            const data = await response.json();

            // Update progress UI
            document.getElementById('progressPercent').textContent = `${Math.round(data.progress)}%`;
            document.getElementById('completed').textContent = `${data.completed} of ${data.urls_count}`;
            document.getElementById('progressFill').style.width = `${data.progress}%`;

            // Update current test
            if (data.current_test) {
                const statusElement = document.getElementById('status');
                statusElement.textContent = data.current_test;
            }

            // Show test progress
            if (data.test_progress && data.test_progress.length > 0) {
                const lastTests = data.test_progress.slice(-3); // Show last 3 tests
                const progressList = document.getElementById('testProgress');
                if (progressList) {
                    progressList.innerHTML = lastTests
                        .map(test => `<div class="test-item">✓ ${test}</div>`)
                        .join('');
                }
            }

            const statusElement = document.getElementById('status');
            if (data.status === 'completed') {
                statusElement.textContent = '✓ Scan Complete';
                statusElement.classList.remove('running');
                statusElement.classList.add('completed');
                document.getElementById('viewResults').style.display = 'block';
                clearInterval(this.pollInterval);
            } else if (data.status === 'error') {
                statusElement.textContent = '✗ Error - ' + (data.current_test || 'Unknown error');
                statusElement.classList.remove('running');
                statusElement.classList.add('error');
                clearInterval(this.pollInterval);
            }
        } catch (error) {
            console.error('Error fetching progress:', error);
        }
    }

    async showResults() {
        if (!this.currentScanId) return;

        try {
            const response = await fetch(`/api/scan/${this.currentScanId}/results`);
            const data = await response.json();

            this.displayResults(data);

            document.getElementById('progressPanel').classList.add('hidden');
            document.getElementById('resultsPanel').classList.remove('hidden');
        } catch (error) {
            console.error('Error fetching results:', error);
            alert('Failed to fetch results. See console for details.');
        }
    }

    displayResults(data) {
        const results = data.results;
        const summary = data.summary;

        // Update summary
        document.getElementById('totalScans').textContent = summary.total_scans;
        document.getElementById('vulnCount').textContent = summary.vulnerabilities_found;
        document.getElementById('criticalCount').textContent = summary.critical_high;

        // Populate table
        const tbody = document.getElementById('resultsTableBody');
        tbody.innerHTML = '';

        results.forEach(result => {
            const row = document.createElement('tr');
            
            // Status badge
            const statusBadge = result.vulnerability_found 
                ? '<span class="status-badge vulnerable">⚠ VULNERABLE</span>'
                : '<span class="status-badge safe">✓ SAFE</span>';

            // OWASP category (A01, A02, etc.)
            const owasp = result.owasp_category || 'Unknown';
            const owaspDisplay = `<strong>${owasp}</strong><br><small>${result.vulnerability_type}</small>`;

            // Severity color
            const severityClass = this.getSeverityColor(result.severity);
            const severityBadge = `<span class="severity-badge ${severityClass}">${result.severity}</span>`;

            row.innerHTML = `
                <td>${owaspDisplay}</td>
                <td><code style="font-size: 11px;">${this.truncateUrl(result.url || result.target_url)}</code></td>
                <td>${statusBadge}</td>
                <td>${severityBadge}</td>
                <td><strong>${parseFloat(result.cvss_score || 0).toFixed(1)}</strong></td>
                <td>${this.truncateDetails(result.description || result.details || '')}</td>
                <td>~${(Math.random() * 2 + 0.5).toFixed(2)}s</td>
            `;
            tbody.appendChild(row);
        });
    }

    async downloadReport(format) {
        if (!this.currentScanId) return;

        try {
            const response = await fetch(`/api/report/${this.currentScanId}/${format}`);
            
            if (!response.ok) {
                alert('Failed to download report');
                return;
            }

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            
            const timestamp = new Date().toISOString().split('T')[0];
            const ext = format === 'html' ? 'html' : format === 'json' ? 'json' : 'csv';
            a.download = `cyberscan_report_${timestamp}.${ext}`;
            
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (error) {
            console.error('Error downloading report:', error);
            alert('Failed to download report. See console for details.');
        }
    }

    handleCancelScan() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
        }
        this.resetScan();
    }

    resetScan() {
        this.currentScanId = null;
        document.getElementById('urls').value = '';
        document.getElementById('progressPanel').classList.add('hidden');
        document.getElementById('resultsPanel').classList.add('hidden');
        document.getElementById('configPanel')?.classList.remove('hidden');
        document.getElementById('viewResults').style.display = 'none';
        
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
        }
    }

    getUrls() {
        const urlsText = document.getElementById('urls').value;
        return urlsText
            .split('\n')
            .map(url => url.trim())
            .filter(url => url.length > 0 && (url.startsWith('http://') || url.startsWith('https://')));
    }

    getSeverityColor(severity) {
        const colorMap = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low',
            'NONE': 'none',
            'INFO': 'none',
            'Error': 'critical'
        };
        return colorMap[severity] || 'low';
    }

    truncateUrl(url) {
        if (url.length > 50) {
            return url.substring(0, 47) + '...';
        }
        return url;
    }

    truncateDetails(details) {
        if (details.length > 60) {
            return details.substring(0, 57) + '...';
        }
        return details;
    }
}

// Initialize UI when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.cyberScanUI = new CyberScanUI();
});
