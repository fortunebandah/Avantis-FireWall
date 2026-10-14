# FireWall Central Administration for cPanel

This is the first central-management server component for the confirmed URL:

- Admin portal: `https://avantispcfeedback.avantis.co.zw/firewall/`
- Device API base: `https://avantispcfeedback.avantis.co.zw/firewall/api/v1/`

The portal/API requires PHP 8.1 or newer, PDO MySQL, JSON, HTTPS, and a MySQL/MariaDB database. It is designed for a cPanel directory deployment. The Windows installer includes the background service that enrolls devices, checks in periodically, and applies the published policy.

## Safety before deployment

1. In cPanel File Manager, open the document-root folder for `avantispcfeedback.avantis.co.zw`.
2. Download backups of the existing `firewall/` test page and any `.htaccess` file in that folder before replacing anything.
3. Keep Avantis files inside that `firewall/` folder. Do not change the subdomain document root or edit the parent website. If the folder already has an `.htaccess`, preserve its existing rules and merge the Avantis rules rather than blindly overwriting them.
4. Confirm `https://avantispcfeedback.avantis.co.zw/firewall/` has a valid certificate before installing the portal.
5. Create a dedicated MySQL database and database user in cPanel. Grant that user access only to this database.

## Upload and configure

1. Upload the contents of this `central/` directory into the existing `firewall/` directory. The Avantis `index.php` replaces the temporary test page, so keep that backup to restore it if needed.
2. In cPanel File Manager, copy `config.example.php` to `config.local.php`.
3. Edit `config.local.php` with the cPanel database name, username, password, host, and a unique random `setup_key` of at least 32 random bytes. Keep this file private; do not put credentials in the desktop application or publish them in a repository.
4. Open phpMyAdmin, select the dedicated Avantis database, and import `schema.sql`.
5. Confirm the host runs PHP 8.1+ and has PDO MySQL enabled. Check cPanel MultiPHP Manager, Select PHP Version, or the host’s PHP information tool.
6. Visit the HTTPS portal path and create the first administrator using the setup key. Use a unique password with at least 14 characters. The portal disables first-admin setup once that account exists.
7. Sign in and publish the company blocked-domain policy. A domain published here will be blocked on every enrolled, online PC after it checks in, including when that domain is a legitimate website.
8. Create a one-time enrollment code for each PC. Codes expire after 24 hours and can be used once. Keep the code private and give it only to the person installing the matching PC.
9. Verify the portal tables and audit events in phpMyAdmin before enrolling company PCs.

Keep cPanel, database, and setup credentials out of screenshots, source control, the desktop app, and support messages. Never change the parent subdomain’s document root to the Avantis folder. If cPanel does not honor the supplied `.htaccess` rules, stop and ask the hosting provider to confirm how to prevent configuration files from being served and how URL rewrites are enabled.

## API contract

All requests use HTTPS and JSON. Unknown devices, expired enrollment codes, and revoked device credentials are rejected.

### Enroll a device once

`POST /firewall/api/v1/enroll`

```json
{
  "code": "one-time-code-from-the-admin-portal",
  "device_name": "Reception-PC-01",
  "app_version": "1.1.3"
}
```

Success returns a unique device ID and a random bearer token. The endpoint service must store that token in a machine-protected location. The server stores only its SHA-256 hash. Never reuse an enrollment code or device token across machines.

### Check in and fetch changed policy

`POST /firewall/api/v1/check-in`

Headers:

```text
Authorization: Bearer DEVICE_TOKEN
Content-Type: application/json
```

Request:

```json
{
  "app_version": "1.1.3",
  "applied_policy_version": 0,
  "protection_status": "unknown"
}
```

`protection_status` is one of `active`, `inactive`, `error`, or `unknown`. The response includes the current policy only when a newer version is available or an administrator queued a check-in. The Windows service validates and applies `blocked_domains` and `subdomain_prefixes`, preserving the desktop app's local detection categories, then reports the applied version on its next check-in. A portal check-in request is queued; it does not wake a powered-off device or a stopped service. The API rejects non-HTTPS requests.

## View and remove blocked domains

In the Central portal, the **Published domains** list shows every domain in the current company policy. Add domains with the add field; this appends them to the existing list rather than replacing it. Remove a domain with its **Remove** button; enrolled agents remove its block at their next check-in. The portal shows sync labels such as **Up to date** and **Waiting for check-in** instead of a growing policy-version fraction. Agents check in about once a minute while connected. The managed desktop app shows connection and policy status but does not display the blocked-domain list; that list is available to administrators in the portal.

The previous portal stored only the latest policy, not a history. If an earlier update replaced the list with an empty or incomplete one, those former domain entries cannot be recovered from the current policy; add them again from an administrator's saved list or backup. New domain additions preserve all entries already published.

## Install and connect a Windows PC

1. On the portal, create a one-time enrollment code for the PC.
2. Run `AvantisFireWall-Setup-1.1.3.exe` on that PC and approve the Windows administrator prompt. The installer asks for a one-time code on a new PC and installs the desktop app and its automatic Windows service into protected Program Files.
3. The installer enrolls the device over HTTPS, stores its credential protected with Windows machine DPAPI, then starts the service. The service checks in about once a minute and automatically applies new policies.
4. Open the desktop app. It displays the Central agent connection status, device name, whether its policy is up to date, and the last successful check-in. The blocked-domain list is shown in the Central admin portal, not in the client app.
5. Confirm the PC appears on the portal's Devices page and reports an active status.

For a client update or reinstall, run the new setup on the enrolled PC; its machine-protected device credential is retained through uninstall and reused, so the existing Central device record stays the same and the enrollment-code page is skipped. Older versions removed this credential during uninstall, so reinstalling those versions could create duplicate rows. If the portal already shows duplicate names, confirm which row is the current PC by checking the last check-in, then revoke the stale row marked **Duplicate device name**. Retire an unused device from the portal before deleting its Windows installation. The background service needs outbound HTTPS access to `avantispcfeedback.avantis.co.zw`. It cannot receive an immediate update while the PC is powered off, disconnected, or the service is stopped; queued check-ins run after the service next connects. A missed check-in is displayed as “No recent check-in,” not proof that the app was removed.

Revoking a device disables its Central credential. After revocation, admins can permanently delete its row from the Devices table; audit events are retained with the device name and ID.

Signed-in administrators can change their own password and create additional administrator accounts from the **Administrator accounts** section. Each new administrator gets a separate email/password sign-in and the same full dashboard access. Passwords must be at least 14 characters; share a newly created account’s initial password securely.

To deploy the admin dashboard, upload `central/index.php` to `firewall/index.php` and `central/assets/avantis-logo-prl.png` to `firewall/assets/avantis-logo-prl.png`. Preserve `config.local.php` and the existing database; do not re-import the schema. The device API has no changes required for these portal improvements.

The Recent activity section initially displays the latest 10 audit events. Select **Read more activity** to keep those visible and load 10 more at a time.

Uninstalling the Windows application stops the service, removes the Avantis hosts-file rules, flushes the PC's DNS cache, and removes the local managed-status markers. The machine-protected device credential is deliberately retained so reinstalling reuses the same enrollment and does not create duplicate device records. It does not remove the device record from the portal; revoke that device in FireWall Central Administration when it is retired. The hosts-file backup remains under `%ProgramData%\Avantis FireWall`.

The API uses HTTPS and bearer credentials, and the client validates policy shape and domains before applying them. Policies are not cryptographically signed: protect the cPanel account, portal administrator accounts, and HTTPS configuration.
