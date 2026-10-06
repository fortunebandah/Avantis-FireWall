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

## Build a Windows installer

The installable release targets 64-bit Windows. On the build PC, install Python 3.12, Node.js 18 or newer, and Inno Setup 6 or newer, then open PowerShell in the project folder and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build_windows.ps1
```

The script creates a self-contained PyInstaller application directory and compiles `dist\installer\AvantisFireWall-Setup-1.0.0.exe`. To build only the application directory, without compiling an installer, run `.uild_windows.ps1 -SkipInstaller`.

Install the generated setup on a 64-bit Windows PC. End users do not need Python, Node.js, or a browser extension. On first launch, each Windows user must review and accept the Terms of Use and Privacy Notice before the app continues; the agreement checkbox starts unchecked and continuing is disabled until it is selected. Avantis opens without administrator approval. Windows requests approval only when applying or removing hosts rules; these changes affect the hosts file for all users on the PC. Settings and activity are stored per Windows user in `%LOCALAPPDATA%\Avantis FireWall`. On first launch after upgrading, existing settings are copied from `%PROGRAMDATA%\Avantis FireWall` when present. Uninstalling the program leaves local data intact.

The interface is organized into four sections: **Protection** for risk analysis and hosts controls, **Import domains** for pasted or file-based lists, **Blocked domains** for managing the active list, and **Insights & rules** for activity, dictionary, and rule editing. Safe Mode continues to restrict editing and hides the admin sections. Set a Safe Mode password using the password control or when first switching to Safe Mode; the password is stored locally with this user's settings and is needed to unlock administrator controls or return to Admin mode.

The app is organized into four tabs: **Protect** for risk analysis and hosts controls, **Import** for manually pasted or file-based domains, **Domains** for reviewing the active blocklist, and **Insights** for the Safety Center, dictionary, and rule editor.

Avantis limits Windows hosts application to 1,000 domains because each domain expands into multiple hostnames and sinkhole entries. For organization-wide filtering or larger lists, configure a managed DNS service separately.

## Scope

Avantis is a local Windows hosts-file blocker and rule-based domain checker. It is not a cloud-managed endpoint service or a replacement for antivirus, DNS security, or device management.

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

When running from source, the app reads `rules.json` beside `app.py`. An installed copy reads `%LOCALAPPDATA%\Avantis FireWall\rules.json`; the file is created when settings are first saved. The **Add**, **Remove**, and **Clear** buttons update only `blocked_domains` and preserve your custom categories and keywords.

Use **Site Dictionary** in the app to search the current domains, words, and prefixes. The dictionary is read-only; edit rules through **Manage Rules** or `rules.json`.

The starter list includes Zimbabwe-focused and international domains. Review `blocked_domains` before applying it to a shared or production computer, because blocking a domain affects every browser user on that Windows installation.

Windows hosts files do not support wildcard rules. To cover common subdomains, the app also writes the prefixes in `subdomain_prefixes`; add more prefixes there when a site uses a different hostname. A domain saved to the blocklist is blocked on this PC, even if the site is legitimate or safe, once you click **Apply to Hosts** and approve the Windows Administrator prompt. The rules apply across browsers and Windows user accounts on this PC. Remove its blocklist entry and apply the list again, or use **Remove Rules**, to restore access. After changing the configuration, click **Apply to Hosts** again.

Administrator approval runs the hosts-file operation without opening a second Avantis window. A clear confirmation or error notification appears near the top of the app after the operation finishes.

## Add many sites at once

Use the **Bulk import** box in the app. Paste domains separated by new lines, commas, semicolons, or spaces, then click **Add All**. Click **Import File** to scan `.txt`, `.csv`, `.json`, or `.docx` files for domain names. Duplicate domains already in the list are ignored automatically. Hold `Ctrl` while selecting domains in the list to remove several at once with **Remove Selected**.

## Browser-independent protection

The desktop app uses Windows hosts-file rules for cross-browser domain blocking. **Check URL** analyzes a domain locally and reports findings; it does not itself block access. Add the domain and select **Apply to Hosts** to block it and its configured subdomains in Chrome, Edge, Firefox, and other browsers on this PC. For category-level protection and SafeSearch across many laptops, use managed DNS through the router, DHCP, Windows policy, or device management.

Hosts protection cannot read encrypted search words such as `betting` or `casino`. Exact search-keyword filtering requires a managed DNS/SafeSearch service or a managed browser/device policy. Read [WORKPLACE_DEPLOYMENT.md](WORKPLACE_DEPLOYMENT.md) for the browser-independent deployment model.

Use **Check URL** for a local rule-based analysis. The result includes a score, matched categories, additional risk indicators, and a recommendation. The analysis stays on the computer and sends no domain lookup to an external service.

The browser-independent hosts layer now creates a one-time `hosts.avantis.backup`, uses an atomic update, and includes **Remove Hosts Rules**. It blocks configured domains across browsers without reading search queries; keyword-level search blocking still requires managed DNS/SafeSearch or browser policy.

## Local administration

Open **Insights & rules → Administration** to import a JSON policy, restore one of the last 50 saved rule versions, or review up to 500 administrative events. Policy import and rollback require the Safe Mode password when Safe Mode is active. Importing or restoring changes the saved local policy only; select **Apply to Hosts** separately to update Windows protection.

The administrative audit records configuration and hosts-protection actions, not website visits. Manual-check activity is stored locally and can include domains.

## Privacy-friendly safety center

The desktop **Safety Center** records manual checks only and does not record successful browsing. Records are stored locally in `activity.json` with 1-hour, 24-hour, and 7-day retention choices plus a clear action. These activity files are excluded from Git by `.gitignore`.

Previously imported public-list domains remain in `rules.json` after public-list downloading is disabled; remove them from the Domains tab if you no longer want them in the local list.
