# Workplace deployment

There are three different protection layers. Choosing the right one matters more than adding more browser code.

## 1. Windows hosts protection

The **Apply to Hosts** button writes the configured domains and common subdomains to the Windows hosts file. This layer:

- works in Chrome, Edge, Firefox, and other browsers;
- continues working if Chrome is reinstalled;
- does not require a browser extension after it is applied;
- requires Windows Administrator permission;
- blocks domains, not words inside an HTTPS search query.

The desktop **Check URL** tool also performs local explainable analysis. It can flag raw IP addresses, insecure HTTP, punycode, URL shorteners, unusually long or deeply nested hostnames, suspicious top-level domains, and lookalikes of protected domains. These signals are advisory; they do not change the hosts file until an administrator explicitly applies the rules.

Review the list before applying it on a shared work computer. The rules remain active after Avantis FireWall closes. **Run on Startup** only starts the user interface; it does not silently rewrite the hosts file.

Before the first update, Avantis creates `hosts.avantis.backup` beside the application. It also writes through a temporary file so an interrupted update does not leave a half-written hosts file. Use **Remove Hosts Rules** to remove only the entries managed by Avantis and leave other hosts-file entries alone.

The **Public List** tool can download the URLhaus malware hostfile or StevenBlack community hosts list. It uses HTTPS, an 8 MB size limit, and a 5,000-domain import limit. It only adds domains to the local review list; an administrator must explicitly click **Apply to Hosts**. Review public feeds because they may include false positives or domains unsuitable for a particular workplace.

## 2. Managed DNS filtering

For several laptops, use an organization-controlled DNS filtering service or DNS server. This is the best browser-independent layer for domain categories, malware, adult content, gambling, and SafeSearch enforcement. Configure the approved DNS servers through the router, DHCP, Windows policy, or device management rather than asking each user to change them.

DNS filtering cannot reliably inspect arbitrary search words inside HTTPS. Use its category policies and SafeSearch controls for that part.

## 3. Managed browser policy

If the organization needs exact keyword blocking, use the browser policy supported by the organization through Group Policy, Intune, or another device-management system. A managed policy can enforce approved browsers, SafeSearch, and approved filtering controls across the device.

The Avantis desktop application does not install or require a browser extension. The optional `browser-extension` folder is not a cross-browser enforcement layer; Firefox or another browser would need its own managed policy.

## Recommended setup

1. Use managed DNS for organization-wide category and SafeSearch protection.
2. Use Avantis **Apply to Hosts** for an additional local blocklist layer.
3. Use managed browser/device policy only when exact search-keyword enforcement is required.
4. Keep browser extensions optional and never make them the only control.

Users can bypass local hosts and extension controls with another account, VPN, proxy, or a different device. If enforcement is required, keep administrator control of DNS and device policy.

## Privacy-friendly activity

The desktop Safety Center stores manual checks locally in `activity.json`. Successful browsing is not recorded. It supports 1-hour, 24-hour, and 7-day retention and a clear action. Optional browser-extension activity remains separate and is not required by the main app.