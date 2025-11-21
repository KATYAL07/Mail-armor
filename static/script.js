
class MailArmor {
    constructor() {
        this.currentTab = 'header-analyzer';
        this.init();
    }

    init() {
        this.setupTabSwitching();
        this.setupFileUpload();
        this.setupKeyboardShortcuts();
    }

    setupTabSwitching() {
        const navItems = document.querySelectorAll('.nav-item');
        navItems.forEach(item => {
            item.addEventListener('click', () => {
                this.switchTab(item.dataset.tab);
            });
        });
    }

    switchTab(tabName) {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        const activeNav = document.querySelector(`[data-tab="${tabName}"]`);
        if (activeNav) activeNav.classList.add('active');

        document.querySelectorAll('.tool-module').forEach(module => {
            module.classList.remove('active');
        });
        const activeModule = document.getElementById(tabName);
        if (activeModule) activeModule.classList.add('active');

        this.currentTab = tabName;
    }

    setupFileUpload() {
        const fileInput = document.getElementById('file-input');
        const uploadArea = document.querySelector('.file-upload-area');

        if (fileInput && uploadArea) {
            fileInput.addEventListener('change', (e) => {
                const fileName = e.target.files[0]?.name || 'No file selected';
                uploadArea.querySelector('p').textContent = fileName;
            });
            
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.style.borderColor = 'var(--cyber-blue)';
                uploadArea.style.background = 'rgba(0, 176, 255, 0.1)';
            });

            uploadArea.addEventListener('dragleave', () => {
                uploadArea.style.borderColor = 'var(--border-color)';
                uploadArea.style.background = 'transparent';
            });

            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.style.borderColor = 'var(--border-color)';
                uploadArea.style.background = 'transparent';
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    fileInput.files = files;
                    uploadArea.querySelector('p').textContent = files[0].name;
                }
            });
        }
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch(e.key) {
                    case '1': e.preventDefault(); this.switchTab('header-analyzer'); break;
                    case '2': e.preventDefault(); this.switchTab('link-xray'); break;
                    case '3': e.preventDefault(); this.switchTab('typosquatting'); break;
                    case '4': e.preventDefault(); this.switchTab('file-sandbox'); break;
                    case '5': e.preventDefault(); this.switchTab('spam-nlp'); break;
                }
            }
        });
    }

    showLoading() {
        const overlay = document.getElementById('loading-overlay');
        if(overlay) overlay.classList.remove('hidden');
    }

    hideLoading() {
        const overlay = document.getElementById('loading-overlay');
        if(overlay) overlay.classList.add('hidden');
    }

    async apiCall(endpoint, data, isFile = false) {
        try {
            this.showLoading();
            let response;
            if (isFile) {
                response = await fetch(endpoint, { method: 'POST', body: data });
            } else {
                response = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
            }

            if (!response.ok) {
                const errorText = await response.text();
                let errorMessage = `Server Error ${response.status}`;
                try {
                    const errorJson = JSON.parse(errorText);
                    if (errorJson.error) errorMessage = errorJson.error;
                } catch (e) {
                    errorMessage = `Server Crash (${response.status}): ${errorText.substring(0, 200)}...`;
                }
                throw new Error(errorMessage);
            }

            const result = await response.json();
            this.hideLoading();
            return result;
        } catch (error) {
            this.hideLoading();
            alert(`Error: ${error.message}`);
            throw error; 
        }
    }
}

const mailArmor = new MailArmor();

async function analyzeHeader() {
    const headerInput = document.getElementById('email-header');
    if (!headerInput) return;
    const headerText = headerInput.value.trim();
    
    if (!headerText) { alert('Please paste email headers to analyze.'); return; }

    try {
        const result = await mailArmor.apiCall('/api/analyze-header', { header: headerText });
        if (result.error) { alert(`Analysis failed: ${result.error}`); return; }
        document.getElementById('header-ip').textContent = result.ip || 'Unknown';
        const locElem = document.getElementById('header-location');
        if (locElem) {
            let locText = `${result.city || 'Unknown'}, ${result.country || 'Unknown'}`;
            if (result.countryCode) {
                const flagEmoji = getFlagEmoji(result.countryCode);
                locText += ` ${flagEmoji}`;
            }
            locElem.textContent = locText;
        }
        document.getElementById('header-isp').textContent = result.isp || 'Unknown';

        const banner = document.getElementById('header-verdict-banner');
        const title = document.getElementById('header-verdict-title');
        const desc = document.getElementById('header-verdict-desc');

        if (banner && title && desc) {
            title.textContent = result.verdict || "UNKNOWN";
            desc.textContent = result.verdict_reason || "Analysis complete";

            banner.className = 'risk-level'; 
            
            if (result.risk_level === 'low') {
                banner.classList.add('low'); 
                banner.style.background = 'rgba(40, 167, 69, 0.1)';
                banner.style.border = '1px solid var(--success-green)';
                title.style.color = 'var(--success-green)';
            } else if (result.risk_level === 'medium') {
                banner.classList.add('high'); 
                banner.style.background = 'rgba(255, 136, 0, 0.1)';
                banner.style.border = '1px solid var(--warning-orange)';
                title.style.color = 'var(--warning-orange)';
            } else {
                banner.classList.add('critical'); 
                banner.style.background = 'rgba(255, 68, 68, 0.1)';
                banner.style.border = '1px solid var(--danger-red)';
                title.style.color = 'var(--danger-red)';
            }
            
            banner.style.display = 'block';
        }

        document.getElementById('header-results').classList.remove('hidden');

    } catch (error) {
        console.error("Header Analysis Error:", error);
    }
}

async function unshortenUrl() {
    const urlInput = document.getElementById('short-url');
    if (!urlInput) return;
    const urlVal = urlInput.value.trim();

    if (!urlVal) { alert('Please enter a URL.'); return; }
    if (!isValidUrl(urlVal)) { alert('Invalid URL format.'); return; }

    try {
        const result = await mailArmor.apiCall('/api/unshorten-url', { url: urlVal });
        
        document.getElementById('original-url').textContent = result.original_url;
        const finalElem = document.getElementById('final-url');
        finalElem.textContent = result.final_url;
        
        if (result.domain_changed) {
            finalElem.style.color = 'var(--danger-red)';
            finalElem.style.fontWeight = 'bold';
        } else {
            finalElem.style.color = 'var(--text-accent)';
        }
        
        document.getElementById('redirect-count').textContent = `${result.redirect_chain ? result.redirect_chain.length : 0} redirects`;

        const statusElem = document.getElementById('url-status');
        if (statusElem) {
            statusElem.textContent = `${result.safety_verdict} (${result.safety_reason})`;
            
            if (result.risk_level === 'low') {
                statusElem.style.color = 'var(--success-green)';
                statusElem.style.borderColor = 'var(--success-green)';
                statusElem.style.background = 'rgba(40, 167, 69, 0.2)';
            } else if (result.risk_level === 'medium') {
                statusElem.style.color = 'var(--warning-orange)';
                statusElem.style.borderColor = 'var(--warning-orange)';
                statusElem.style.background = 'rgba(255, 136, 0, 0.2)';
            } else {
                statusElem.style.color = 'var(--danger-red)';
                statusElem.style.borderColor = 'var(--danger-red)';
                statusElem.style.background = 'rgba(255, 68, 68, 0.2)';
            }
        }
        document.getElementById('url-results').classList.remove('hidden');
    } catch (error) {
        console.error("URL Error:", error);
    }
}

async function checkTyposquatting() {
    const domainInput = document.getElementById('domain-input');
    if (!domainInput) return;
    const domainVal = domainInput.value.trim();

    if (!domainVal) { alert('Enter a domain.'); return; }
    if (!isValidDomain(domainVal)) { alert('Invalid domain format.'); return; }

    try {
        const result = await mailArmor.apiCall('/api/check-typosquatting', { domain: domainVal });
        
        document.getElementById('domains-scanned').textContent = `${result.variations_checked || 0} checked`;
        const domainsList = document.getElementById('fake-domains-list');
        
        if (domainsList) {
            domainsList.innerHTML = '';
            if (result.active_fake_domains && result.active_fake_domains.length > 0) {
                const header = document.createElement('h4');
                header.style.color = 'var(--danger-red)';
                header.style.marginBottom = '1rem';
                header.textContent = '⚠️ Active Fake Domains Found:';
                domainsList.appendChild(header);

                result.active_fake_domains.forEach(domain => {
                    const item = document.createElement('div');
                    item.className = 'fake-domain-item';
                    item.innerHTML = `<span class="fake-domain">${domain.domain}</span><span class="fake-domain-ip">IP: ${domain.ip}</span>`;
                    domainsList.appendChild(item);
                });
            } else {
                domainsList.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--success-green);">✅ No malicious domains detected</div>';
            }
        }
        document.getElementById('typosquatting-results').classList.remove('hidden');
    } catch (error) {
        console.error("Typo Error:", error);
    }
}

async function analyzeFile() {
    const fileInput = document.getElementById('file-input');
    if (!fileInput || !fileInput.files[0]) { alert('Select a file.'); return; }
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    try {
        const result = await mailArmor.apiCall('/api/analyze-file', formData, true);

        document.getElementById('file-name').textContent = result.filename;
        document.getElementById('stated-type').textContent = result.file_extension || 'Unknown';
        document.getElementById('actual-type').textContent = `${result.detected_mime || 'Unknown'}`;
        document.getElementById('magic-bytes').textContent = result.magic_bytes || 'N/A';

        const riskBadge = document.getElementById('file-risk-level');
        if(riskBadge) {
            riskBadge.textContent = result.risk_level.toUpperCase();
            riskBadge.className = `risk-badge ${result.risk_level}`;
        }

        if (result.risk_level === 'critical') {
            setTimeout(() => { alert('🚨 CRITICAL MALWARE ALERT 🚨\n\nFile extension does not match content!'); }, 500);
        }
        document.getElementById('file-results').classList.remove('hidden');
    } catch (error) {
        console.error("File Error:", error);
    }
}

async function analyzeSpam() {
    const contentInput = document.getElementById('email-content');
    if (!contentInput) return;
    const contentText = contentInput.value.trim();
    
    if (!contentText) { alert('Paste email content.'); return; }

    try {
        const result = await mailArmor.apiCall('/api/analyze-spam', { text: contentText });

        document.getElementById('risk-percentage').textContent = result.risk_score;
        const levelElem = document.getElementById('risk-level-text');
        if(levelElem) {
            levelElem.textContent = `${result.risk_level.toUpperCase()} RISK`;
            levelElem.className = `risk-level ${result.risk_level}`;
        }

        const keywordsElem = document.getElementById('keyword-matches');
        if (keywordsElem) {
            keywordsElem.innerHTML = '';
            if (result.keyword_matches && result.keyword_matches.Detected && result.keyword_matches.Detected.length > 0) {
                const header = document.createElement('h4');
                header.style.marginBottom = '1rem';
                header.style.color = 'var(--cyber-blue)';
                header.textContent = 'Detected Keywords:';
                keywordsElem.appendChild(header);

                const list = document.createElement('div');
                list.className = 'keyword-list';
                list.textContent = result.keyword_matches.Detected.join(', ');
                keywordsElem.appendChild(list);
            } else {
                keywordsElem.innerHTML = '<p style="color: var(--text-secondary);">No suspicious keywords detected.</p>';
            }
        }
        document.getElementById('analysis-summary').textContent = result.analysis_summary || '';
        document.getElementById('spam-results').classList.remove('hidden');
    } catch (error) {
        console.error("Spam Error:", error);
    }
}

function isValidUrl(string) {
    try { new URL(string); return true; }
    catch (_) { try { new URL('http://' + string); return true; } catch (_) { return false; } }
}

function isValidDomain(domain) {
    return /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/.test(domain);
}

function getFlagEmoji(countryCode) {
    const flagMap = {'us':'🇺🇸','gb':'🇬🇧','ca':'🇨🇦','au':'🇦🇺','de':'🇩🇪','fr':'🇫🇷','it':'🇮🇹','es':'🇪🇸','jp':'🇯🇵','cn':'🇨🇳','ru':'🇷🇺','br':'🇧🇷','in':'🇮🇳','mx':'🇲🇽','kr':'🇰🇷'};
    return flagMap[countryCode.toLowerCase()] || '🏳️';
}

document.addEventListener('submit', (e) => { e.preventDefault(); });