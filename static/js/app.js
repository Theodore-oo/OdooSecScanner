document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const loadingSection = document.getElementById('loading-section');
    const resultsSection = document.getElementById('results-section');
    const scoreValue = document.getElementById('score-value');
    const scoreText = document.getElementById('score-text');
    const scoreDisplay = document.getElementById('score-display');
    const totalIssuesBadge = document.getElementById('total-issues-badge');
    const findingsTableBody = document.getElementById('findings-table-body');
    const noIssuesState = document.getElementById('no-issues-state');
    
    let radarChart = null;

    // Drag and Drop handlers
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => {
            dropZone.classList.add('dragover');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => {
            dropZone.classList.remove('dragover');
        }, false);
    });

    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        handleFiles(files);
    });

    fileInput.addEventListener('change', function() {
        handleFiles(this.files);
    });

    function handleFiles(files) {
        if (files.length === 0) return;
        const file = files[0];
        if (!file.name.endsWith('.zip')) {
            alert('Please upload a valid Odoo Module .zip file.');
            return;
        }
        uploadFile(file);
    }

    async function uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);

        // UI Transition
        dropZone.closest('.row').classList.add('d-none');
        resultsSection.classList.add('d-none');
        loadingSection.classList.remove('d-none');

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Server error occurred');
            }
            
            displayResults(data);
        } catch (error) {
            alert('Scan failed: ' + error.message);
            // Reset UI
            loadingSection.classList.add('d-none');
            dropZone.closest('.row').classList.remove('d-none');
        }
    }

    function displayResults(data) {
        loadingSection.classList.add('d-none');
        resultsSection.classList.remove('d-none');
        
        // Update Score
        animateValue(scoreValue, 0, data.score, 1500);
        const deg = (data.score / 100) * 360;
        scoreDisplay.style.setProperty('--score-deg', `${deg}deg`);
        
        // Update Score Text Color
        if (data.score >= 90) {
            scoreText.textContent = 'Excellent';
            scoreText.className = 'mt-4 text-success font-outfit fw-bold';
            scoreDisplay.style.setProperty('--neon-primary', '#10b981');
        } else if (data.score >= 70) {
            scoreText.textContent = 'Fair';
            scoreText.className = 'mt-4 text-warning font-outfit fw-bold';
            scoreDisplay.style.setProperty('--neon-primary', '#f59e0b');
        } else {
            scoreText.textContent = 'Critical';
            scoreText.className = 'mt-4 text-danger font-outfit fw-bold';
            scoreDisplay.style.setProperty('--neon-primary', '#ef4444');
        }

        totalIssuesBadge.textContent = `${data.total_issues} Issues Found`;
        
        if (data.total_issues === 0) {
            totalIssuesBadge.classList.replace('bg-danger', 'bg-success');
            document.querySelector('.table-responsive').classList.add('d-none');
            noIssuesState.classList.remove('d-none');
        } else {
            totalIssuesBadge.classList.replace('bg-success', 'bg-danger');
            document.querySelector('.table-responsive').classList.remove('d-none');
            noIssuesState.classList.add('d-none');
            
            // Populate Table
            findingsTableBody.innerHTML = '';
            data.findings.forEach(finding => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="ps-4">
                        <span class="category-badge">${finding.category}</span>
                        <div class="small text-muted mt-1">${finding.category_name}</div>
                    </td>
                    <td class="font-monospace small text-info">${finding.file}</td>
                    <td class="text-center"><span class="badge bg-secondary rounded-circle p-2">${finding.line}</span></td>
                    <td class="pe-4 text-wrap">${finding.message}</td>
                `;
                findingsTableBody.appendChild(tr);
            });
        }

        renderChart(data.counts);
    }

    function renderChart(countsData) {
        const ctx = document.getElementById('radarChart').getContext('2d');
        
        const labels = Object.keys(countsData);
        const dataPoints = Object.values(countsData);
        
        if (radarChart) radarChart.destroy();
        
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.font.family = "'Inter', sans-serif";
        
        radarChart = new Chart(ctx, {
            type: 'polarArea',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Vulnerabilities',
                    data: dataPoints,
                    backgroundColor: [
                        'rgba(255, 0, 60, 0.6)',
                        'rgba(0, 240, 255, 0.6)',
                        'rgba(138, 43, 226, 0.6)',
                        'rgba(255, 193, 7, 0.6)',
                        'rgba(32, 201, 151, 0.6)',
                        'rgba(253, 126, 20, 0.6)',
                        'rgba(23, 162, 184, 0.6)'
                    ],
                    borderWidth: 1,
                    borderColor: 'rgba(255,255,255,0.1)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        grid: { color: 'rgba(255, 255, 255, 0.1)' },
                        angleLines: { color: 'rgba(255, 255, 255, 0.1)' },
                        ticks: { display: false, backdropColor: 'transparent' }
                    }
                },
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { padding: 20, font: { size: 11 } }
                    }
                }
            }
        });
    }

    function animateValue(obj, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.innerHTML = Math.floor(progress * (end - start) + start);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }
});
