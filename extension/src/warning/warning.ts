/**
 * Warning Page Script: Handles user actions on phishing interstitial warning.
 */

document.addEventListener('DOMContentLoaded', () => {
  const goBackBtn = document.getElementById('go-back-btn');
  const proceedBtn = document.getElementById('proceed-btn');

  // Load dynamic security alert information
  if (typeof chrome !== 'undefined' && chrome.storage?.local) {
    chrome.storage.local.get(['latestWarning'], (result) => {
      const warning = result?.latestWarning;
      if (warning) {
        const subtitle = document.querySelector('.subtitle');
        if (subtitle && warning.url) {
          subtitle.textContent = `PhishGuard identified high risk signals on "${warning.url}". Risk Score: ${warning.riskScore}/100. Submitting credentials, passwords, or personal identity information on this website may result in account compromise.`;
        }

        const factorsList = document.getElementById('warning-factors');
        if (factorsList && Array.isArray(warning.factors) && warning.factors.length > 0) {
          factorsList.innerHTML = '';
          warning.factors.forEach((f: any) => {
            const li = document.createElement('li');
            const desc = f.description || f.factor;
            const reason = f.reason ? ` — ${f.reason}` : '';
            li.textContent = `${desc}${reason}`;
            factorsList.appendChild(li);
          });
        }
      }
    });
  }

  goBackBtn?.addEventListener('click', () => {
    // Navigate back to browser safety or close tab
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  proceedBtn?.addEventListener('click', () => {
    if (confirm('Warning: This site exhibits active credential theft indicators. Are you sure you wish to proceed?')) {
      window.close();
    }
  });
});
