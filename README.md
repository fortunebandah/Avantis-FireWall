# Avantis FireWall

Avantis FireWall is a simple Windows desktop app that blocks suspicious websites such as adult, gambling, and similar risky categories.

## What it does

- Lets you enter a site URL or domain
- Uses explainable local risk signals for raw IP addresses, HTTP, punycode, URL shorteners, unusual hostnames, suspicious TLDs, and lookalike domains
- Includes a searchable site and word dictionary for blocked domains, detection keywords, and subdomain prefixes
- Detects suspicious keywords like `porn`, `casino`, `betting`, `adult`, `xxx`, `roulette`, etc.
- Adds the blocked domains to the Windows hosts file so they resolve to `127.0.0.1`
- Saves your custom block list and detection keywords in `rules.json`

## Install and run on Windows

Prerequisites: Python 3.12 and Node.js 18 or newer. Node.js is only needed to build the interface; it is not needed to launch the app after the build completes.

Open PowerShell in the project folder and create a virtual environment:

```powershell
python -m venv .venv
```

Install the Python runtime and desktop UI dependencies into that environment:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Build the React interface:

```powershell
cd web
npm.cmd install
npm.cmd run build
cd ..
```

Launch the desktop app from the project folder:

```powershell
.\.venv\Scripts\python.exe app.py
```

Windows may ask for administrator approval so Avantis can manage hosts-file protection. The React interface runs in a local Qt WebEngine window and calls the Python protection logic; it does not use a web server or remote service.

The interface is organized into four sections: **Protection** for risk analysis and hosts controls, **Import domains** for pasted or file-based lists, **Blocked domains** for managing the active list, and **Insights & rules** for activity, dictionary, and rule editing. Safe Mode continues to restrict editing and hides the admin sections.

The app is organized into four tabs: **Protect** for risk analysis and hosts controls, **Import** for manually pasted or file-based domains, **Domains** for reviewing the active blocklist, and **Insights** for the Safety Center, dictionary, and rule editor.

For enterprise-scale lists, use **Protect → Export DNS Feed**. It creates a clean one-domain-per-line file for a managed DNS service, filtering gateway, or device policy system. Avantis limits Windows hosts application to 1,000 domains because each domain expands into multiple hostnames and sinkhole entries; large feeds belong in managed DNS infrastructure.

## Important

This app is a basic protection tool for learning and personal use. It can help block common suspicious domains, but it is not a full browser-level security system.

## Files

- `app.py` — the desktop application
- `rules.json` — editable block list and keyword configuration

## Customize without changing the code

Open `rules.json` while the app is closed. Add domains to `blocked_domains`, or add words to any category under `categories`:

```json
{
	"blocked_domains": ["example.com"],
	"categories": {
		"my_category": ["keyword-one", "keyword-two"]
	}
}
```

The app reads this file when it starts. The **Add**, **Remove**, and **Clear** buttons update only `blocked_domains` and preserve your custom categories and keywords.

Use **Site Dictionary** in the app to search the current domains, words, and prefixes. The dictionary is read-only; edit rules through **Manage Rules** or `rules.json`.

The starter list includes Zimbabwe-focused and international domains. Review `blocked_domains` before applying it to a shared or production computer, because blocking a domain affects every browser user on that Windows installation.

Windows hosts files do not support wildcard rules. To cover common subdomains, the app also writes the prefixes in `subdomain_prefixes`; add more prefixes there when a site uses a different hostname. After changing the configuration, click **Apply to Hosts** again as Administrator.

## Add many sites at once

Use the **Bulk import** box in the app. Paste domains separated by new lines, commas, semicolons, or spaces, then click **Add All**. Click **Import File** to scan `.txt`, `.csv`, `.json`, or `.docx` files for domain names. Duplicate domains already in the list are ignored automatically. Hold `Ctrl` while selecting domains in the list to remove several at once with **Remove Selected**.

## Browser-independent protection

The desktop app uses Windows hosts-file rules for cross-browser domain blocking. **Apply to Hosts** blocks configured domains and common subdomains in Chrome, Edge, Firefox, and other browsers. For category-level protection and SafeSearch across many laptops, use managed DNS through the router, DHCP, Windows policy, or device management.

Hosts protection cannot read encrypted search words such as `betting` or `casino`. Exact search-keyword filtering requires a managed DNS/SafeSearch service or a managed browser/device policy. Read [WORKPLACE_DEPLOYMENT.md](WORKPLACE_DEPLOYMENT.md) for the browser-independent deployment model.

Use **Check URL** for a local explainable analysis. The result includes a score, matched categories, smart signals, and a recommendation. No domain lookup or external AI service is used, so the analysis stays on the computer.

The browser-independent hosts layer now creates a one-time `hosts.avantis.backup`, uses an atomic update, and includes **Remove Hosts Rules**. It blocks configured domains across browsers without reading search queries; keyword-level search blocking still requires managed DNS/SafeSearch or browser policy.

## Privacy-friendly safety center

The desktop **Safety Center** records manual checks only and does not record successful browsing. Records are stored locally in `activity.json` with 1-hour, 24-hour, and 7-day retention choices plus a clear action. These activity files are excluded from Git by `.gitignore`.

Previously imported public-list domains remain in `rules.json` after public-list downloading is disabled; remove them from the Domains tab if you no longer want them in the local list.

