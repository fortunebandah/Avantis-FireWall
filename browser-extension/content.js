(() => {
  const extensionRulesUrl = chrome.runtime.getURL("rules.json");

  function normalize(value) {
    return value.toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0].split(":")[0];
  }

  function matchesKeyword(value, keyword) {
    const text = value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
    const rule = keyword.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
    return rule && new RegExp(`(^|[^a-z0-9])${rule.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?=$|[^a-z0-9])`).test(text);
  }

  function matchingCategories(value, categories) {
    return Object.entries(categories)
      .filter(([, keywords]) => keywords.some((keyword) => matchesKeyword(value, keyword)))
      .map(([category]) => category);
  }

  function isBlockedHost(hostname, blockedDomains) {
    const host = normalize(hostname);
    return blockedDomains.some((domain) => {
      const blocked = normalize(domain);
      return host === blocked || host.endsWith(`.${blocked}`);
    });
  }

  function getSearchText() {
    const host = location.hostname.toLowerCase();
    if (host.includes("google.")) return new URLSearchParams(location.search).get("q") || "";
    if (host.includes("bing.")) return new URLSearchParams(location.search).get("q") || "";
    if (host.includes("duckduckgo.")) return new URLSearchParams(location.search).get("q") || "";
    if (host.includes("yahoo.")) return new URLSearchParams(location.search).get("p") || "";
    return "";
  }

  function showBlocked(title, detail, categories) {
    document.documentElement.innerHTML = `
      <head><title>Avantis FireWall</title><style>
        :root { color-scheme: light; font-family: Segoe UI, Arial, sans-serif; }
        * { box-sizing: border-box; }
        body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #eaf4f7; color: #16445a; }
        main { width: min(620px, calc(100% - 32px)); background: #fff; border-radius: 14px; overflow: hidden; box-shadow: 0 18px 50px rgba(11, 100, 120, .2); }
        header { background: #0b6478; color: #fff; padding: 28px 32px; }
        .brand { color: #9be3e7; font-size: 13px; font-weight: 700; letter-spacing: 2px; }
        h1 { margin: 8px 0 0; font-size: 28px; }
        section { padding: 30px 32px 34px; }
        p { line-height: 1.6; margin: 0 0 18px; }
        .reason { background: #f0f8fa; border-left: 4px solid #087f92; padding: 14px 16px; margin-bottom: 20px; }
        .tag { display: inline-block; background: #d9f1f3; color: #075d70; padding: 6px 10px; border-radius: 999px; margin: 3px 5px 3px 0; font-size: 13px; }
      </style></head>
      <body><main><header><div class="brand">AVANTIS FIREWALL</div><h1>${title}</h1></header>
      <section><p>${detail}</p><div class="reason">This request matched your configured protection rules.</div>
      <div>${categories.map((category) => `<span class="tag">${category}</span>`).join("")}</div></section></main></body>`;
  }

  fetch(extensionRulesUrl)
    .then((response) => response.json())
    .then((rules) => {
      const categories = matchingCategories(getSearchText(), rules.categories);
      if (categories.length) {
        showBlocked("Search blocked", `This search contains a protected term: <strong>${getSearchText()}</strong>.`, categories);
        return;
      }

      if (isBlockedHost(location.hostname, rules.blocked_domains)) {
        const hostCategories = matchingCategories(location.hostname, rules.categories);
        showBlocked("Site blocked", `Access to <strong>${location.hostname}</strong> is blocked by Avantis FireWall.`, hostCategories);
      }
    })
    .catch(() => {});
})();
