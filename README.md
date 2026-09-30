# Avantis FireWall

Avantis FireWall is a simple Windows desktop app that blocks suspicious websites such as adult, gambling, and similar risky categories.

## What it does

- Lets you enter a site URL or domain
- Detects suspicious keywords like `porn`, `casino`, `betting`, `adult`, `xxx`, `roulette`, etc.
- Adds the blocked domains to the Windows hosts file so they resolve to `127.0.0.1`
- Lets you install the app to Windows startup so it runs automatically when you log in
- Saves your custom block list and detection keywords in `rules.json`

## Run the app

1. Open a terminal in this folder.
2. Run:

```powershell
pip install -r requirements.txt
python app.py
```

3. If Windows blocks access to the hosts file, run the app as Administrator.

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

The starter list includes Zimbabwe-focused and international domains. Review `blocked_domains` before applying it to a shared or production computer, because blocking a domain affects every browser user on that Windows installation.

Windows hosts files do not support wildcard rules. To cover common subdomains, the app also writes the prefixes in `subdomain_prefixes`; add more prefixes there when a site uses a different hostname. After changing the configuration, click **Apply to Hosts** again as Administrator.

## Add many sites at once

Use the **Bulk import** box in the app. Paste domains separated by new lines, commas, semicolons, or spaces, then click **Add All**. Click **Import File** to scan `.txt`, `.csv`, `.json`, or `.docx` files for domain names. Duplicate domains already in the list are ignored automatically. Hold `Ctrl` while selecting domains in the list to remove several at once with **Remove Selected**.

## Browser search protection

The desktop app protects domains through Windows hosts rules. To also block search terms such as `betting` or `casino` before search results appear, install the Chrome extension in `browser-extension`:

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked** and choose the `browser-extension` folder.
4. Reload the extension after changing its `rules.json`.

The extension supports Google, Bing, DuckDuckGo, and Yahoo search pages, plus direct blocked-domain visits.

## Startup option

The app includes a button to add itself to the Windows startup folder so it launches automatically.
