// MalChain IOC config. lookupUrl points at your same-origin PHP proxy (api/lookup.php).
// The proxy holds your MalwareBazaar key server-side; no key lives here or in the browser.
// Same-origin = no CORS. See api/README.md (Hostinger) or cloudflare-worker/ for a Worker.
window.IOC_CONFIG = { lookupUrl: "api/lookup.php" };
