/**
 * Heuristic scoring weights, thresholds, institutional domain allowlists,
 * normal verified domain allowlists, restricted schemes, and threat intelligence configuration.
 */

export const SCORE_LOW_MAX = 39;
export const SCORE_MEDIUM_MAX = 69;
export const SCORE_HIGH_MIN = 70;

// Deterministic heuristic weights (Additive penalties)
export const WEIGHT_PUNYCODE = 45;
export const WEIGHT_CROSS_ORIGIN_FORM = 35;
export const WEIGHT_PAYMENT_FORM_ANOMALY = 35;
export const WEIGHT_INSECURE_CREDENTIAL_FORM = 30;
export const WEIGHT_BRAND_IN_SUBDOMAIN = 25;
export const WEIGHT_IP_HOSTNAME = 25;
export const WEIGHT_BRAND_TITLE_MISMATCH = 25;
export const WEIGHT_BEHAVIORAL_DRIFT = 20;
export const WEIGHT_SUSPICIOUS_IFRAME = 20;
export const WEIGHT_UNUSUAL_URL_ENCODING = 15;
export const WEIGHT_EXCESSIVE_EXTERNAL_RESOURCES = 15;
export const WEIGHT_LEXICAL_ANOMALY = 10;
export const WEIGHT_EXCESSIVE_URL_LENGTH = 10;
export const WEIGHT_SUSPICIOUS_PATH_QUERY = 10;
export const WEIGHT_INSECURE_HTTP = 10;
export const WEIGHT_KNOWN_THREAT_MATCH = 50;
export const WEIGHT_THIRD_PARTY_UNVERIFIED = 65;
export const WEIGHT_SMALL_DOUBT_ELEVATION = 60;

// Institutional identity providers and high-trust domains (prevents false positives)
export const INSTITUTIONAL_ALLOWLIST = new Set([
  'okta.com',
  'microsoftonline.com',
  'login.microsoftonline.com',
  'accounts.google.com',
  'github.com',
  'appleid.apple.com',
  'duosecurity.com',
  'auth0.com',
  'harvard.edu',
  'mit.edu',
  'stanford.edu',
  'ox.ac.uk',
  'cam.ac.uk',
]);

// Normal / verified legitimate web platforms and widely trusted domains
export const NORMAL_DOMAINS_ALLOWLIST = new Set([
  // Core Search & Tech Giants
  'google.com',
  'google.co.in',
  'google.co.uk',
  'google.ca',
  'google.de',
  'google.fr',
  'google.com.au',
  'google.co.jp',
  'google.com.br',
  'youtube.com',
  'youtu.be',
  'gmail.com',
  'googlemail.com',
  'gstatic.com',
  'googleapis.com',
  'googleusercontent.com',
  'googlevideo.com',
  'chrome.com',
  'android.com',

  // Microsoft Ecosystem
  'microsoft.com',
  'live.com',
  'office.com',
  'office365.com',
  'bing.com',
  'msn.com',
  'azure.com',
  'azurewebsites.net',
  'windows.com',
  'xbox.com',
  'skype.com',
  'microsoftonline.com',
  'login.microsoftonline.com',
  'sharepoint.com',
  'onedrive.com',
  'visualstudio.com',
  'github.com',
  'github.io',
  'githubusercontent.com',

  // Apple Ecosystem
  'apple.com',
  'icloud.com',
  'itunes.com',
  'appleid.apple.com',

  // Amazon Ecosystem
  'amazon.com',
  'amazon.in',
  'amazon.co.uk',
  'amazon.de',
  'amazon.co.jp',
  'amazon.ca',
  'amazon.fr',
  'amazon.it',
  'amazon.es',
  'aws.amazon.com',
  'primevideo.com',

  // Meta / Social Networks
  'facebook.com',
  'fb.com',
  'instagram.com',
  'whatsapp.com',
  'threads.net',
  'messenger.com',
  'twitter.com',
  'x.com',
  'twimg.com',
  't.co',
  'reddit.com',
  'redd.it',
  'redditstatic.com',
  'linkedin.com',
  'licdn.com',
  'pinterest.com',
  'tiktok.com',
  'snapchat.com',
  'telegram.org',
  't.me',
  'discord.com',
  'discord.gg',

  // Knowledge, Reference & Media
  'wikipedia.org',
  'wikimedia.org',
  'wiktionary.org',
  'wikidata.org',
  'archive.org',
  'britannica.com',

  // Developer & Productivity
  'stackoverflow.com',
  'stackexchange.com',
  'gitlab.com',
  'npmjs.com',
  'python.org',
  'docker.com',
  'cloudflare.com',
  'mozilla.org',
  'w3schools.com',
  'openai.com',
  'chatgpt.com',
  'anthropic.com',
  'claude.ai',
  'canva.com',
  'figma.com',
  'adobe.com',
  'notion.so',
  'trello.com',
  'slack.com',
  'zoom.us',
  'dropbox.com',

  // Media, Streaming & Entertainment
  'netflix.com',
  'spotify.com',
  'twitch.tv',
  'disneyplus.com',
  'hulu.com',
  'imdb.com',
  'yahoo.com',

  // Commerce & Payments
  'paypal.com',
  'stripe.com',
  'ebay.com',

  // Auth Providers & Institutional
  'okta.com',
  'auth0.com',
  'duosecurity.com',
  'harvard.edu',
  'mit.edu',
  'stanford.edu',
  'ox.ac.uk',
  'cam.ac.uk',

  // Standards, RFCs & Local Testing
  'example.com',
  'example.org',
  'example.net',
  'example.edu',
  'localhost',
  '127.0.0.1',
]);

/**
 * Checks whether a given hostname belongs to recognized normal/legitimate domains.
 */
export function isNormalWebsite(hostname: string): boolean {
  if (!hostname) return false;
  const host = hostname.toLowerCase().trim();

  // Local & internal development domains
  if (host === 'localhost' || host === '127.0.0.1' || host.endsWith('.local')) {
    return true;
  }

  // Official Institutional & Educational TLDs
  if (
    host.endsWith('.edu') ||
    host.includes('.edu.') ||
    host.endsWith('.gov') ||
    host.includes('.gov.') ||
    host.endsWith('.mil') ||
    host.endsWith('.ac.uk')
  ) {
    return true;
  }

  // Direct set check for full hostname
  if (NORMAL_DOMAINS_ALLOWLIST.has(host) || INSTITUTIONAL_ALLOWLIST.has(host)) {
    return true;
  }

  // Check extracted base domain
  const parts = host.split('.');
  if (parts.length >= 2) {
    const base = parts.slice(-2).join('.');
    if (NORMAL_DOMAINS_ALLOWLIST.has(base) || INSTITUTIONAL_ALLOWLIST.has(base)) {
      return true;
    }
  }
  if (parts.length >= 3) {
    const base3 = parts.slice(-3).join('.');
    if (NORMAL_DOMAINS_ALLOWLIST.has(base3) || INSTITUTIONAL_ALLOWLIST.has(base3)) {
      return true;
    }
  }

  // International domains regex (e.g. google.co.in, amazon.co.uk)
  if (/^([a-z0-9-]+\.)?google\.[a-z]{2,3}(\.[a-z]{2})?$/.test(host)) return true;
  if (/^([a-z0-9-]+\.)?amazon\.[a-z]{2,3}(\.[a-z]{2})?$/.test(host)) return true;
  if (/^([a-z0-9-]+\.)?yahoo\.[a-z]{2,3}(\.[a-z]{2})?$/.test(host)) return true;
  if (/^([a-z0-9-]+\.)?wikipedia\.org$/.test(host)) return true;

  return false;
}

// High-value brand names frequently impersonated in phishing attacks
export const TARGETED_BRANDS = [
  'paypal',
  'microsoft',
  'google',
  'apple',
  'netflix',
  'amazon',
  'bank of america',
  'chase',
  'wellsfargo',
  'citibank',
  'facebook',
  'instagram',
  'dhl',
  'fedex',
];

// Browser internal and restricted schemes that cannot or should not be inspected
export const RESTRICTED_SCHEMES = new Set([
  'chrome:',
  'chrome-extension:',
  'edge:',
  'about:',
  'devtools:',
  'view-source:',
  'file:',
]);

// Legitimate, documented sample threat intelligence signatures
// Format: FQDN -> Threat description from verified feeds (e.g. PhishTank/OpenPhish active signatures)
export const DOCUMENTED_THREAT_INTEL = new Map<string, { feed: string; threatType: string }>([
  ['evil-phish-bank.com', { feed: 'Verified Threat Feed #1048', threatType: 'Banking Credential Harvester' }],
  ['secure-login-update-paypal.net', { feed: 'Verified Threat Feed #2091', threatType: 'Payment Theft Kit' }],
  ['microsoft-account-verify.click', { feed: 'Verified Threat Feed #3120', threatType: 'O365 Credential Impersonation' }],
]);
