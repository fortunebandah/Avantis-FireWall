# Avantis FireWall Chrome Protection

This extension blocks:

- Search queries containing configured risky words on Google, Bing, DuckDuckGo, and Yahoo
- Direct visits to configured blocked domains and their subdomains

## Install in Chrome

1. Open `chrome://extensions`.
2. Turn on **Developer mode**.
3. Click **Load unpacked**.
4. Select this `browser-extension` folder.
5. Restart the browser tab and test a search such as `betting`.

The extension contains its own `rules.json`. When you change rules in the desktop app, copy the updated categories and blocked domains into `browser-extension/rules.json`, then click **Reload** on the extension page.

Browser Secure DNS settings do not prevent this extension from checking search queries, but hosts-file protection and extension protection are separate layers.
