# MalChain IOC proxy (PHP — Hostinger / cPanel / any PHP host)

Makes the IOC Lookup page autonomous with **no separate service** and **no CORS**:
the page calls `api/lookup.php` on the same domain, and PHP calls MalwareBazaar
server-side holding your key.

## Setup (once)

1. Copy `config.example.php` to `config.php` and paste your MalwareBazaar Auth-Key
   (free at https://auth.abuse.ch). PHP files are executed, never served as source,
   so the key is not web-readable. Keep `config.php` out of git (see `.gitignore`).
2. Upload the whole site to Hostinger (e.g. `public_html/`), including the `api/`
   folder. That's it.
3. `assets/ioc-config.js` already points at `api/lookup.php`. If you put the site in
   a subfolder, adjust `lookupUrl` accordingly (relative or absolute path).

Open the IOC Lookup page and search any hash — it just works.

## Notes

- Requires PHP with cURL (default on Hostinger). If cURL is off, the script falls
  back to `file_get_contents`.
- Same-origin means no CORS header is needed. If your page is on a different
  (sub)domain than the API, set `Access-Control-Allow-Origin` in `lookup.php`.
- Opening the page from `file://` locally won't run PHP — test on the host, or run
  `php -S localhost:8000` in the site folder.
