# Avantis FireWall

Avantis FireWall is a rule-based website blocker for Windows. Create a focused list of websites to restrict, review site risk with local checks, and manage protection from one simple desktop app.

## What you can do

- Add websites individually or import a list from TXT, CSV, JSON, or DOCX.
- Apply or remove website protection with clear status and confirmation messages.
- Check an address with local, explainable risk indicators.
- Edit detection categories, review activity, and manage a protected Safe Mode profile.
- Keep your rules and activity on this PC.
- Store the Safe Mode password as a salted PBKDF2 hash instead of readable text.

Protection applies to listed domains and their configured common subdomains across browsers and Windows accounts on this PC. A link hosted on a different domain must be added separately. Applying or removing protection requires Windows Administrator approval and changes which websites can be accessed on this PC.

## Install

Download and run the latest Windows installer from the project's [Releases](https://github.com/fortunebandah/Avantis-FireWall/releases) page. On first launch, review and accept the Terms of Use and Privacy Notice. Python and Node.js are not needed to use an installed release.

## Run from source

Requirements: Python 3.12 and Node.js 18 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cd web
npm.cmd install
npm.cmd run build
cd ..
.\.venv\Scripts\python.exe app.py
```

To package the desktop app and its Windows Central service, install Inno Setup 6 or newer and run:

```powershell
.\build_windows.ps1
```

The installer is created at `dist\installer\AvantisFireWall-Setup-1.1.3.exe`. On a fresh installation, enter a one-time enrollment code from FireWall Central Administration. Setup installs the service machine-wide with administrator approval; the desktop app then runs as the signed-in user. The service checks in independently of the desktop window, retries transient policy and network errors, and is configured to restart automatically after an unexpected exit. Reinstalling on a previously enrolled PC keeps its device credential so the existing device record is reused. Use `.\build_windows.ps1 -SkipInstaller` to build the application and service bundles without compiling the installer.

## Your information

Avantis does not require an account for local use. Website checks run locally, and browsing activity is not monitored. Manual checks and administrative actions are stored locally. If you enroll in FireWall Central Administration, the background service sends the PC name, app version, protection status, and policy version to the configured portal; it does not send browsing activity or manual site checks. If you choose to download a public blocklist, your PC connects to that list's provider.

## Customize rules

When running from source, edit `rules.json` while the app is closed. Add websites to `blocked_domains`, or add terms to a category under `categories`:

```json
{
  "blocked_domains": ["example.com"],
  "categories": {
    "my_category": ["keyword-one", "keyword-two"]
  }
}
```

In the app, manage domains under **Blocked domains** and detection terms under **Insights & rules**. Saved local changes take effect on this PC when you select **Apply protection**. On company-managed PCs, the blocked-domain list is visible to Central administrators in the portal; the client app shows connection and policy status without displaying the list.

Existing plain-text Safe Mode passwords are automatically converted to a salted password hash when the app loads the settings. The hash cannot be used to recover the original password.

## FireWall Central Administration on cPanel

The cPanel portal and Windows service target `https://avantispcfeedback.avantis.co.zw/firewall/`. The portal publishes company-wide blocked-domain policies; enrolled Windows services check in periodically and apply them to their PC. Follow [`central/README.md`](./central/README.md) for server deployment, client enrollment, and limitations. A listed domain is blocked on enrolled PCs even if it is a legitimate website. Protect the portal administrator account and hosting environment; centrally delivered policies are validated but not cryptographically signed.
