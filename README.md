# Suspicious Site Blocker

This project creates a simple Windows desktop app that blocks suspicious websites such as adult, gambling, and similar risky categories.

## What it does

- Lets you enter a site URL or domain
- Detects suspicious keywords like `porn`, `casino`, `betting`, `adult`, `xxx`, `roulette`, etc.
- Adds the blocked domains to the Windows hosts file so they resolve to `127.0.0.1`
- Lets you install the app to Windows startup so it runs automatically when you log in
- Saves your custom block list locally

## Run the app

1. Open a terminal in this folder.
2. Run:

```powershell
python app.py
```

3. If Windows blocks access to the hosts file, run the app as Administrator.

## Important

This app is a basic protection tool for learning and personal use. It can help block common suspicious domains, but it is not a full browser-level security system.

## Files

- `app.py` — the desktop application
- `rules.json` — saved block list

## Startup option

The app includes a button to add itself to the Windows startup folder so it launches automatically.
