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

Review the list before applying it on a shared work computer. The rules remain active after Avantis FireWall closes.

Before the first update, Avantis creates `hosts.avantis.backup` beside the application. It also writes through a temporary file so an interrupted update does not leave a half-written hosts file. Use **Remove Hosts Rules** to remove only the entries managed by Avantis and leave other hosts-file entries alone.

For enterprise-sized feeds, use **Protect → Export DNS Feed** and load the resulting one-domain-per-line file into managed DNS, a filtering gateway, or device policy. Avantis limits the Windows hosts writer to 1,000 domains because each domain expands into multiple hostnames and sinkhole entries; putting thousands of domains in every laptop hosts file is slower and more likely to be locked by endpoint security.

## 2. Managed DNS filtering

For several laptops, use an organization-controlled DNS filtering service or DNS server. This is the best browser-independent layer for domain categories, malware, adult content, gambling, and SafeSearch enforcement. Configure the approved DNS servers through the router, DHCP, Windows policy, or device management rather than asking each user to change them.

DNS filtering cannot reliably inspect arbitrary search words inside HTTPS. Use its category policies and SafeSearch controls for that part.

## 3. Managed browser policy

If the organization needs exact keyword blocking, use the browser policy supported by the organization through Group Policy, Intune, or another device-management system. A managed policy can enforce approved browsers, SafeSearch, and approved filtering controls across the device.

Avantis does not install or provide a browser extension. Use managed browser or device policy if organization-level browser controls are needed.

## Recommended setup

1. Use managed DNS for organization-wide category and SafeSearch protection.
2. Use Avantis **Apply to Hosts** for an additional local blocklist layer.
3. Use managed browser/device policy only when exact search-keyword enforcement is required.
4. Do not use browser extensions for Avantis; use managed DNS or device policy for additional enforcement.

Users can bypass local hosts controls with another account, VPN, proxy, or a different device. If enforcement is required, keep administrator control of DNS and device policy.

## Privacy-friendly activity

The desktop Safety Center stores manual checks locally in `activity.json`. Successful browsing is not recorded. It supports 1-hour, 24-hour, and 7-day retention and a clear action.