import json
import difflib
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import tkinter as tk
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tkinter import filedialog, ttk
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from PIL import Image, ImageTk
from docx import Document

WINDOWS_HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_BACKUP_PATH = Path(__file__).with_name("hosts.avantis.backup")
RULES_FILE = Path(__file__).with_name("rules.json")
ACTIVITY_FILE = Path(__file__).with_name("activity.json")
LOGO_FILE = Path(__file__).with_name("Images") / "Avantis-logo-prl.png"
DOMAIN_PATTERN = re.compile(r"(?i)(?:https?://)?(?:www\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}")

DEFAULT_CATEGORIES = {
    "adult": [
        "adult", "porn", "porno", "pornhub", "sex", "xxx", "xvideos",
        "nude", "nudity", "strip", "erotic", "playboy", "asian porn",
        "pornography", "explicit", "xxx video", "sex cam", "cam girl",
        "escort", "hookup"
    ],
    "gambling": [
        "casino", "gambling", "betting", "roulette", "poker", "slot",
        "jackpot", "lottery", "sportsbook", "baccarat", "sports betting",
        "live betting", "virtual betting", "betting tips", "casino online",
        "aviator", "crash game", "bet slip", "odds", "bookmaker", "bookie",
        "slot games"
    ],
    "malware": [
        "crack", "keygen", "warez", "nulled", "r57", "download free",
        "torrent", "serial key", "activator", "pirated", "cheat", "mod apk"
    ],
    "scam": [
        "free money", "bitcoin generator", "lottery winner", "fake rewards",
        "clickbank scam", "crypto scam", "giveaway", "claim reward",
        "investment scam", "double your money", "urgent payment", "verify account"
    ],
}

DEFAULT_BLOCKLIST = [
    "pornhub.com",
    "xvideos.com",
    "xnxx.com",
    "bet365.com",
    "casino.com",
    "888casino.com",
    "pokerstars.com",
    "betway.co.zw",
    "hollywoodbets.co.zw",
    "sportingbet.co.zw",
    "zimbet.co.zw",
    "1xbet.co.zw",
    "parimatch.co.zw",
    "stake.com",
    "1xbet.com",
    "betway.com",
    "betano.com",
    "betfair.com",
    "unibet.com",
    "bwin.com",
    "ladbrokes.com",
    "williamhill.com",
    "paddypower.com",
    "betvictor.com",
    "22bet.com",
    "melbet.com",
    "mostbet.com",
    "roobet.com",
    "rollbit.com",
    "duckbet.com",
    "redtube.com",
    "youporn.com",
    "xhamster.com",
    "xnxx.tv",
    "spankbang.com",
    "chaturbate.com",
    "cam4.com",
    "onlyfans.com",
]

DEFAULT_SUBDOMAIN_PREFIXES = [
    "www", "info", "m", "mobile", "login", "account", "sports",
    "casino", "bet", "api", "app", "play",
]

CATEGORY_DESCRIPTIONS = {
    "adult": "Adult or sexually explicit sites and terms.",
    "gambling": "Casino, betting, lottery, and wagering sites and terms.",
    "malware": "Terms commonly associated with pirated or unsafe downloads.",
    "scam": "Fraud, fake rewards, and suspicious money-request terms.",
}

RETENTION_OPTIONS = {
    "1 hour": 1,
    "24 hours": 24,
    "7 days": 24 * 7,
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "cutt.ly",
}
SUSPICIOUS_TLDS = {"click", "download", "gq", "loan", "ml", "tk", "top", "work", "zip"}
PUBLIC_LIST_LIMIT = 5000
PUBLIC_LISTS = {
    "URLhaus malware hostfile": {
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "description": "Abuse.ch hostnames associated with malware distribution.",
    },
    "StevenBlack hosts list": {
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "description": "Community-maintained hosts list containing ads and known harmful domains.",
    },
}


def default_rules():
    return {
        "blocked_domains": DEFAULT_BLOCKLIST[:],
        "categories": {category: keywords[:] for category, keywords in DEFAULT_CATEGORIES.items()},
        "subdomain_prefixes": DEFAULT_SUBDOMAIN_PREFIXES[:],
    }


def load_config():
    if not RULES_FILE.exists():
        return default_rules()

    try:
        with RULES_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)

        # Keep support for the original rules.json format: ["example.com"].
        if isinstance(data, list):
            config = default_rules()
            config["blocked_domains"] = data
            return config

        if isinstance(data, dict):
            config = default_rules()
            if isinstance(data.get("blocked_domains"), list):
                config["blocked_domains"] = data["blocked_domains"]
            if isinstance(data.get("categories"), dict):
                config["categories"] = {
                    str(category): [str(keyword) for keyword in keywords if str(keyword).strip()]
                    for category, keywords in data["categories"].items()
                    if isinstance(keywords, list)
                }
            if isinstance(data.get("subdomain_prefixes"), list):
                config["subdomain_prefixes"] = [
                    normalize_domain(str(prefix)).split(".")[0]
                    for prefix in data["subdomain_prefixes"]
                    if str(prefix).strip()
                ]
            return config
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        pass

    return default_rules()


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    if not value:
        return ""

    parsed = urlparse(value if "://" in value else f"//{value}")
    domain = parsed.netloc or parsed.path.split("/")[0]
    domain = domain.rsplit("@", 1)[-1].split(":", 1)[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.strip(".")


def keyword_matches(domain: str, keyword: str) -> bool:
    searchable = re.sub(r"[^a-z0-9]+", " ", normalize_domain(domain)).strip()
    search_keyword = re.sub(r"[^a-z0-9]+", " ", keyword.lower()).strip()
    if not searchable or not search_keyword:
        return False
    pattern = rf"(?<![a-z0-9]){re.escape(search_keyword)}(?![a-z0-9])"
    return re.search(pattern, searchable) is not None


def detect_categories(domain: str, categories=None):
    text = normalize_domain(domain)
    found = []
    for category, keywords in (categories or DEFAULT_CATEGORIES).items():
        if any(keyword_matches(text, keyword) for keyword in keywords):
            found.append(category)
    return found


def smart_signals(site: str, domain: str, blocklist):
    signals = []
    raw_value = site.strip()
    parsed_value = raw_value if "://" in raw_value else f"//{raw_value}"
    try:
        parsed = urlparse(parsed_value)
        hostname = parsed.hostname or domain
    except ValueError:
        parsed = None
        hostname = domain

    if "xn--" in domain or any(ord(character) > 127 for character in domain):
        signals.append((20, "The domain uses punycode or non-ASCII characters."))

    try:
        ipaddress.ip_address(hostname)
        signals.append((30, "The address uses a raw IP instead of a named domain."))
    except ValueError:
        pass

    if parsed and parsed.username:
        signals.append((25, "The URL contains a username before the host, which can hide the real destination."))

    if parsed and parsed.password:
        signals.append((25, "The URL contains embedded credentials."))

    if parsed and parsed.scheme and parsed.scheme.lower() == "http":
        signals.append((10, "The address does not use encrypted HTTPS."))

    if parsed and parsed.port not in (None, 80, 443):
        signals.append((10, "The URL uses an unusual network port."))

    if domain in SHORTENER_DOMAINS:
        signals.append((15, "This is a URL-shortening service, so the final destination is hidden."))

    labels = domain.split(".")
    if len(labels) >= 5:
        signals.append((10, "The hostname has many subdomain levels."))
    if len(domain) > 45:
        signals.append((10, "The hostname is unusually long."))
    if re.search(r"(?:\d[.-]?){4,}", domain):
        signals.append((10, "The hostname contains an unusual concentration of numbers."))

    if labels and labels[-1] in SUSPICIOUS_TLDS:
        signals.append((10, f"The top-level domain .{labels[-1]} is frequently used in disposable links."))

    for blocked in blocklist:
        blocked_labels = normalize_domain(blocked).split(".")
        if len(blocked_labels) < 2 or len(labels) < 2:
            continue
        candidate = ".".join(labels[-2:])
        target = ".".join(blocked_labels[-2:])
        similarity = difflib.SequenceMatcher(None, candidate, target).ratio()
        if candidate != target and similarity >= 0.86:
            signals.append((25, f"The domain closely resembles the protected domain {target}."))
            break

    return signals


def analyze_site(site: str, blocklist, categories):
    domain = normalize_domain(site)
    matched_keywords = []
    matched_categories = []

    for category, keywords in categories.items():
        category_matches = [keyword for keyword in keywords if keyword_matches(domain, keyword)]
        if category_matches:
            matched_categories.append(category)
            matched_keywords.extend(category_matches)

    is_blocked = any(domain == blocked or domain.endswith(f".{blocked}") for blocked in blocklist)
    signals = smart_signals(site, domain, blocklist) if domain else []
    score = min(100, len(set(matched_keywords)) * 15 + len(matched_categories) * 10 + (70 if is_blocked else 0) + sum(weight for weight, _ in signals))
    if score >= 70:
        level = "High risk"
    elif score >= 35:
        level = "Review"
    else:
        level = "Low risk"

    if is_blocked or level == "High risk":
        recommendation = "Block or avoid this site."
    elif level == "Review":
        recommendation = "Review the destination carefully before continuing."
    else:
        recommendation = "No strong risk signal was found by the local rules."

    return {
        "domain": domain,
        "blocked": is_blocked,
        "categories": matched_categories,
        "keywords": list(dict.fromkeys(matched_keywords)),
        "signals": [message for _, message in signals],
        "score": score,
        "level": level,
        "recommendation": recommendation,
    }


def save_rules(blocklist, categories, subdomain_prefixes=None):
    unique = []
    seen = set()
    for item in blocklist:
        domain = normalize_domain(item)
        if domain and domain not in seen:
            unique.append(domain)
            seen.add(domain)

    with RULES_FILE.open("w", encoding="utf-8") as f:
        json.dump({
            "blocked_domains": unique,
            "categories": categories,
            "subdomain_prefixes": subdomain_prefixes or DEFAULT_SUBDOMAIN_PREFIXES,
        }, f, indent=2)

def load_activity():
    default = {"retention_hours": RETENTION_OPTIONS["24 hours"], "events": []}
    if not ACTIVITY_FILE.exists():
        return default

    try:
        with ACTIVITY_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return default
        retention_hours = int(data.get("retention_hours", default["retention_hours"]))
        if retention_hours not in RETENTION_OPTIONS.values():
            retention_hours = default["retention_hours"]
        events = data.get("events", [])
        if not isinstance(events, list):
            events = []
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return default

    cutoff = datetime.now(timezone.utc) - timedelta(hours=retention_hours)
    active_events = []
    for event in events:
        try:
            timestamp = datetime.fromisoformat(event["timestamp"])
            if timestamp >= cutoff:
                active_events.append(event)
        except (KeyError, TypeError, ValueError):
            continue

    result = {"retention_hours": retention_hours, "events": active_events}
    if len(active_events) != len(events):
        save_activity(active_events, retention_hours)
    return result


def save_activity(events, retention_hours):
    with ACTIVITY_FILE.open("w", encoding="utf-8") as f:
        json.dump({"retention_hours": retention_hours, "events": events[-500:]}, f, indent=2)


def record_activity(event_type, domain, detail):
    activity = load_activity()
    activity["events"].append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "domain": domain or "(unrecognized input)",
        "detail": detail,
    })
    save_activity(activity["events"], activity["retention_hours"])


def write_hosts_file(blocklist, subdomain_prefixes=None):
    if not os.path.exists(WINDOWS_HOSTS_PATH):
        raise FileNotFoundError("Windows hosts file not found.")

    try:
        with open(WINDOWS_HOSTS_PATH, "r", encoding="utf-8") as f:
            content = f.read()
    except PermissionError:
        raise PermissionError("Administrator rights are required to change the hosts file.")

    marker = "# >>> suspicious-site-blocker >>>"
    end_marker = "# <<< suspicious-site-blocker <<<"

    if marker in content and end_marker in content:
        start_index = content.index(marker)
        end_index = content.index(end_marker) + len(end_marker)
        content = content[:start_index] + content[end_index:]

    lines = []
    prefixes = subdomain_prefixes or DEFAULT_SUBDOMAIN_PREFIXES
    for domain in blocklist:
        clean = normalize_domain(domain)
        if clean:
            hostnames = [clean] + [f"{prefix}.{clean}" for prefix in prefixes]
            for hostname in hostnames:
                lines.append(f"127.0.0.1 {hostname}")
                lines.append(f"0.0.0.0 {hostname}")

    block_section = f"\n{marker}\n" + "\n".join(lines) + f"\n{end_marker}\n"
    new_content = content.rstrip() + "\n" + block_section.strip() + "\n"

    try:
        if not HOSTS_BACKUP_PATH.exists():
            shutil.copy2(WINDOWS_HOSTS_PATH, HOSTS_BACKUP_PATH)
        temporary_path = f"{WINDOWS_HOSTS_PATH}.avantis.tmp"
        with open(temporary_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(new_content)
        os.replace(temporary_path, WINDOWS_HOSTS_PATH)
    except PermissionError:
        raise PermissionError("Administrator rights are required to change the hosts file.")
    finally:
        if os.path.exists(f"{WINDOWS_HOSTS_PATH}.avantis.tmp"):
            os.remove(f"{WINDOWS_HOSTS_PATH}.avantis.tmp")


def remove_hosts_rules():
    if not os.path.exists(WINDOWS_HOSTS_PATH):
        raise FileNotFoundError("Windows hosts file not found.")

    marker = "# >>> suspicious-site-blocker >>>"
    end_marker = "# <<< suspicious-site-blocker <<<"
    try:
        with open(WINDOWS_HOSTS_PATH, "r", encoding="utf-8") as f:
            content = f.read()
    except PermissionError:
        raise PermissionError("Administrator rights are required to change the hosts file.")

    if marker not in content or end_marker not in content:
        return False

    start_index = content.index(marker)
    end_index = content.index(end_marker) + len(end_marker)
    new_content = content[:start_index].rstrip() + content[end_index:].lstrip()
    try:
        temporary_path = f"{WINDOWS_HOSTS_PATH}.avantis.tmp"
        with open(temporary_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(new_content)
        os.replace(temporary_path, WINDOWS_HOSTS_PATH)
    except PermissionError:
        raise PermissionError("Administrator rights are required to change the hosts file.")
    finally:
        if os.path.exists(f"{WINDOWS_HOSTS_PATH}.avantis.tmp"):
            os.remove(f"{WINDOWS_HOSTS_PATH}.avantis.tmp")
    return True


def flush_dns_cache():
    subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, check=False)


def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


def relaunch_as_admin():
    if os.name != "nt":
        return False

    import ctypes
    script_path = os.path.abspath(__file__)
    parameters = subprocess.list2cmdline([script_path])
    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        parameters,
        str(Path(__file__).parent),
        1,
    )
    return result > 32


def add_to_startup():
    startup_dir = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    os.makedirs(startup_dir, exist_ok=True)

    shortcut_path = os.path.join(startup_dir, "AvantisFireWall.bat")
    script_path = os.path.abspath(__file__)

    bat_content = (
        "@echo off\n"
        "start /B python \"" + script_path + "\"\n"
    )

    with open(shortcut_path, "w", encoding="utf-8") as f:
        f.write(bat_content)

    return shortcut_path


def show_app_dialog(parent, title, message, kind="info", confirm=False):
    palette = {
        "info": ("#087f92", "Information"),
        "success": ("#16805c", "Success"),
        "warning": ("#b7791f", "Review"),
        "error": ("#c24141", "Action required"),
    }
    accent, label = palette[kind]
    result = {"value": False}
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.configure(bg="#eaf4f7")
    dialog.resizable(False, False)
    dialog.transient(parent)
    if hasattr(parent, "window_icon"):
        dialog.iconphoto(True, parent.window_icon)

    header = tk.Frame(dialog, bg="#0b6478", padx=20, pady=14)
    header.pack(fill="x")
    tk.Label(header, text=label, bg="#0b6478", fg="#ffffff", font=("Segoe UI", 10, "bold")).pack(anchor="w")
    tk.Label(header, text=title, bg="#0b6478", fg="#ffffff", font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(2, 0))

    body = tk.Frame(dialog, bg="#ffffff", padx=20, pady=18)
    body.pack(fill="both", expand=True)
    tk.Label(body, text=message, justify="left", anchor="w", wraplength=460, bg="#ffffff", fg="#16445a", font=("Segoe UI", 10)).pack(fill="x")

    actions = tk.Frame(body, bg="#ffffff")
    actions.pack(fill="x", pady=(18, 0))

    def close(value=False):
        result["value"] = value
        dialog.destroy()

    if confirm:
        tk.Button(actions, text="Cancel", command=lambda: close(False), bg="#ffffff", fg="#16445a", activebackground="#dceff3", relief="solid", borderwidth=1, padx=14, pady=6).pack(side="right", padx=(8, 0))
        tk.Button(actions, text="Continue", command=lambda: close(True), bg=accent, fg="#ffffff", activebackground="#075d70", relief="flat", borderwidth=0, padx=14, pady=7).pack(side="right")
    else:
        tk.Button(actions, text="Close", command=close, bg=accent, fg="#ffffff", activebackground="#075d70", relief="flat", borderwidth=0, padx=18, pady=7).pack(side="right")

    dialog.protocol("WM_DELETE_WINDOW", close)
    dialog.update_idletasks()
    parent.update_idletasks()
    position_x = parent.winfo_rootx() + (parent.winfo_width() - dialog.winfo_width()) // 2
    position_y = parent.winfo_rooty() + (parent.winfo_height() - dialog.winfo_height()) // 2
    dialog.geometry(f"+{max(position_x, 0)}+{max(position_y, 0)}")
    dialog.grab_set()
    dialog.focus_set()
    parent.wait_window(dialog)
    return result["value"]


class BlockerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Avantis FireWall")
        self.geometry("900x680")
        self.minsize(760, 580)
        self.configure(bg="#eaf4f7")

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("App.TFrame", background="#eaf4f7")
        style.configure("App.TLabel", background="#eaf4f7", foreground="#16445a")
        style.configure("Header.TFrame", background="#0b6478")
        style.configure("Header.TLabel", background="#0b6478", foreground="#ffffff")
        style.configure("Panel.TFrame", background="#ffffff")
        style.configure("Panel.TLabel", background="#ffffff", foreground="#12445b")
        style.configure("Muted.TLabel", background="#ffffff", foreground="#527184")
        style.configure("Accent.TButton", background="#087f92", foreground="#ffffff", padding=(12, 7))
        style.map("Accent.TButton", background=[("active", "#075d70")])
        style.configure("Secondary.TButton", background="#dcebee", foreground="#16445a", padding=(12, 8), borderwidth=0, relief="flat")
        style.map("Secondary.TButton", background=[("active", "#c4e1e5"), ("pressed", "#b7d9de")], foreground=[("disabled", "#8aa0a8")])
        style.configure("Accent.TButton", background="#087f92", foreground="#ffffff", padding=(12, 8), borderwidth=0, relief="flat")
        style.map("Accent.TButton", background=[("active", "#075d70"), ("pressed", "#064b5a")], foreground=[("disabled", "#d0e5e8")])
        style.configure("TNotebook", background="#eaf4f7", borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", background="#d4e5e8", foreground="#16445a", padding=(20, 10), borderwidth=0, font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#ffffff"), ("active", "#c4e1e5")], foreground=[("selected", "#075d70")])
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("CardValue.TLabel", background="#ffffff", foreground="#0b6478", font=("Segoe UI", 22, "bold"))
        style.configure("CardTitle.TLabel", background="#ffffff", foreground="#527184", font=("Segoe UI", 9, "bold"))
        style.configure("CardNote.TLabel", background="#ffffff", foreground="#7b93a0", font=("Segoe UI", 9))

        config = load_config()
        self.blocklist = [normalize_domain(item) for item in config["blocked_domains"] if str(item).strip()]
        self.categories = config["categories"]
        self.subdomain_prefixes = config["subdomain_prefixes"]
        self.create_widgets()
        self.refresh_listbox()

    def create_widgets(self):
        header = ttk.Frame(self, style="Header.TFrame", padding=(26, 20))
        header.pack(fill="x")
        brand_row = ttk.Frame(header, style="Header.TFrame")
        brand_row.pack(fill="x")
        logo = tk.Canvas(brand_row, width=270, height=62, bg="#ffffff", highlightthickness=0)
        logo.pack(side="left", padx=(0, 20))
        if LOGO_FILE.exists():
            self.logo_image = tk.PhotoImage(file=str(LOGO_FILE))
            source_logo = Image.open(LOGO_FILE)
            icon_size = min(source_logo.width, source_logo.height)
            self.window_icon = ImageTk.PhotoImage(source_logo.crop((0, 0, icon_size, icon_size)))
            scale = max(1, (self.logo_image.width() + 269) // 270, (self.logo_image.height() + 61) // 62)
            if scale > 1:
                self.logo_image = self.logo_image.subsample(scale, scale)
            logo.create_image(135, 31, image=self.logo_image)
            self.iconphoto(True, self.window_icon)
        title_block = ttk.Frame(brand_row, style="Header.TFrame")
        title_block.pack(side="left", fill="x", expand=True)
        ttk.Label(title_block, text="Avantis FireWall", style="Header.TLabel", font=("Segoe UI", 21, "bold")).pack(anchor="w")
        ttk.Label(title_block, text="Manage safer browsing with simple, editable rules", style="Header.TLabel", font=("Segoe UI", 10)).pack(anchor="w", pady=(4, 0))

        content = ttk.Frame(self, style="App.TFrame", padding=(18, 14))
        content.pack(fill="both", expand=True)

        notebook = ttk.Notebook(content)
        notebook.pack(fill="both", expand=True)

        protect_tab = ttk.Frame(notebook, style="App.TFrame", padding=14)
        import_tab = ttk.Frame(notebook, style="App.TFrame", padding=14)
        domains_tab = ttk.Frame(notebook, style="App.TFrame", padding=14)
        insights_tab = ttk.Frame(notebook, style="App.TFrame", padding=14)
        notebook.add(protect_tab, text="Protect")
        notebook.add(import_tab, text="Import")
        notebook.add(domains_tab, text="Domains")
        notebook.add(insights_tab, text="Insights")

        input_frame = ttk.Frame(protect_tab, style="Panel.TFrame", padding=18)
        input_frame.pack(fill="x", pady=(0, 12))
        input_frame.columnconfigure(0, weight=3)
        input_frame.columnconfigure(1, weight=2)

        analyze_panel = ttk.Frame(input_frame, style="Panel.TFrame", padding=(0, 0, 14, 0))
        analyze_panel.grid(row=0, column=0, sticky="nsew")
        ttk.Label(analyze_panel, text="Analyze a site", style="Panel.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(analyze_panel, text="Check the risk of a URL or domain", style="Muted.TLabel").pack(anchor="w", pady=(2, 6))
        self.check_var = tk.StringVar()
        check_entry = ttk.Entry(analyze_panel, textvariable=self.check_var, font=("Segoe UI", 10))
        check_entry.pack(fill="x", pady=(0, 8))
        ttk.Button(analyze_panel, text="Analyze Risk", command=self.check_url, style="Secondary.TButton").pack(anchor="w")

        add_panel = ttk.Frame(input_frame, style="Panel.TFrame", padding=(14, 0, 0, 0))
        add_panel.grid(row=0, column=1, sticky="nsew")
        ttk.Label(add_panel, text="Add a blocked domain", style="Panel.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(add_panel, text="Add a domain to the local blocklist", style="Muted.TLabel").pack(anchor="w", pady=(2, 6))
        self.add_var = tk.StringVar()
        add_entry = ttk.Entry(add_panel, textvariable=self.add_var, font=("Segoe UI", 10))
        add_entry.pack(fill="x", pady=(0, 8))
        ttk.Button(add_panel, text="Add Domain", command=self.add_url, style="Accent.TButton").pack(anchor="w")

        host_frame = ttk.Frame(protect_tab, style="Panel.TFrame", padding=18)
        host_frame.pack(fill="x")
        ttk.Label(host_frame, text="Protection controls", style="Panel.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(host_frame, text="Apply or remove only Avantis-managed hosts rules. Administrator permission is required.", style="Muted.TLabel").pack(anchor="w", pady=(2, 10))
        host_buttons = ttk.Frame(host_frame, style="Panel.TFrame")
        host_buttons.pack(fill="x")
        ttk.Button(host_buttons, text="Apply to Hosts", command=self.apply_blocking, style="Accent.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(host_buttons, text="Remove Hosts Rules", command=self.remove_blocking, style="Secondary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(host_buttons, text="Run on Startup", command=self.run_on_startup, style="Secondary.TButton").pack(side="left")

        overview = ttk.Frame(protect_tab, style="App.TFrame")
        overview.pack(fill="both", expand=True, pady=(12, 0))
        ttk.Label(overview, text="Protection overview", style="App.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 8))
        ttk.Label(overview, text="A quiet view of what Avantis is ready to protect on this computer.", style="App.TLabel").pack(anchor="w", pady=(0, 10))
        cards = ttk.Frame(overview, style="App.TFrame")
        cards.pack(fill="x")
        for column in range(3):
            cards.columnconfigure(column, weight=1)

        domain_card = ttk.Frame(cards, style="Card.TFrame", padding=16)
        domain_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.domain_stat_label = ttk.Label(domain_card, text="0", style="CardValue.TLabel")
        self.domain_stat_label.pack(anchor="w")
        ttk.Label(domain_card, text="BLOCKED DOMAINS", style="CardTitle.TLabel").pack(anchor="w", pady=(4, 0))
        ttk.Label(domain_card, text="Ready for hosts protection", style="CardNote.TLabel").pack(anchor="w", pady=(2, 0))

        rule_card = ttk.Frame(cards, style="Card.TFrame", padding=16)
        rule_card.grid(row=0, column=1, sticky="nsew", padx=8)
        self.rule_stat_label = ttk.Label(rule_card, text="0", style="CardValue.TLabel")
        self.rule_stat_label.pack(anchor="w")
        ttk.Label(rule_card, text="DETECTION WORDS", style="CardTitle.TLabel").pack(anchor="w", pady=(4, 0))
        ttk.Label(rule_card, text="Local risk dictionary", style="CardNote.TLabel").pack(anchor="w", pady=(2, 0))

        mode_card = ttk.Frame(cards, style="Card.TFrame", padding=16)
        mode_card.grid(row=0, column=2, sticky="nsew", padx=(8, 0))
        ttk.Label(mode_card, text="LOCAL", style="CardValue.TLabel").pack(anchor="w")
        ttk.Label(mode_card, text="PRIVACY MODE", style="CardTitle.TLabel").pack(anchor="w", pady=(4, 0))
        ttk.Label(mode_card, text="No browsing data leaves this app", style="CardNote.TLabel").pack(anchor="w", pady=(2, 0))

        bulk_frame = ttk.Frame(import_tab, style="Panel.TFrame", padding=18)
        bulk_frame.pack(fill="both", expand=True)
        ttk.Label(bulk_frame, text="Bulk import", style="Panel.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(bulk_frame, text="Paste multiple domains separated by new lines, spaces, or commas", style="Muted.TLabel").pack(anchor="w", pady=(2, 6))

        bulk_row = ttk.Frame(bulk_frame, style="Panel.TFrame")
        bulk_row.pack(fill="x")
        self.bulk_text = tk.Text(bulk_row, height=5, wrap="word", font=("Segoe UI", 10), relief="flat", borderwidth=1, highlightthickness=1, highlightbackground="#cbd5e1", highlightcolor="#087f92")
        self.bulk_text.pack(side="left", fill="both", expand=True)
        bulk_actions = ttk.Frame(bulk_row, style="Panel.TFrame")
        bulk_actions.pack(side="left", padx=(12, 0), anchor="n")
        ttk.Button(bulk_actions, text="Add All", command=self.add_multiple, style="Accent.TButton").pack(fill="x")
        ttk.Button(bulk_actions, text="Import File", command=self.import_file, style="Secondary.TButton").pack(fill="x", pady=(8, 0))
        ttk.Button(bulk_actions, text="Public List", command=self.open_public_list, style="Secondary.TButton").pack(fill="x", pady=(8, 0))

        def resize_bulk_input(_event=None):
            if not self.bulk_text.edit_modified():
                return
            line_count = int(self.bulk_text.index("end-1c").split(".")[0])
            self.bulk_text.configure(height=min(12, max(5, line_count)))
            self.bulk_text.edit_modified(False)

        self.bulk_text.bind("<<Modified>>", resize_bulk_input)
        ttk.Label(bulk_frame, text="Public sources are imported for review only. Hosts rules change only after an explicit Apply.", style="Muted.TLabel").pack(anchor="w", pady=(10, 0))

        list_frame = ttk.Frame(domains_tab, style="Panel.TFrame", padding=18)
        list_frame.pack(fill="both", expand=True)
        list_header = ttk.Frame(list_frame, style="Panel.TFrame")
        list_header.pack(fill="x", pady=(0, 8))
        ttk.Label(list_header, text="Blocked domains", style="Panel.TLabel", font=("Segoe UI", 11, "bold")).pack(side="left")
        self.count_label = ttk.Label(list_header, text="", style="Muted.TLabel")
        self.count_label.pack(side="right")

        list_area = ttk.Frame(list_frame, style="Panel.TFrame")
        list_area.pack(fill="both", expand=True)
        scrollbar = ttk.Scrollbar(list_area, orient="vertical")
        scrollbar.pack(side="right", fill="y")
        self.listbox = tk.Listbox(list_area, height=12, activestyle="none", selectmode=tk.EXTENDED, font=("Segoe UI", 10), bg="#f8fafc", fg="#16324f", selectbackground="#087f92", selectforeground="#ffffff", relief="flat", borderwidth=0, yscrollcommand=scrollbar.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.listbox.yview)

        controls = ttk.Frame(list_frame, style="Panel.TFrame")
        controls.pack(fill="x", pady=(10, 0))
        ttk.Button(controls, text="Remove Selected", command=self.remove_selected, style="Secondary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="Clear All", command=self.clear_all, style="Secondary.TButton").pack(side="left")

        insights_panel = ttk.Frame(insights_tab, style="Panel.TFrame", padding=18)
        insights_panel.pack(fill="x")
        ttk.Label(insights_panel, text="Review and tune protection", style="Panel.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(insights_panel, text="Open focused tools only when you need them.", style="Muted.TLabel").pack(anchor="w", pady=(2, 16))
        insight_cards = ttk.Frame(insights_panel, style="Panel.TFrame")
        insight_cards.pack(fill="x")
        for column in range(3):
            insight_cards.columnconfigure(column, weight=1)

        safety_card = ttk.Frame(insight_cards, style="Card.TFrame", padding=16)
        safety_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        ttk.Label(safety_card, text="SAFETY CENTER", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(safety_card, text="Local audit records", style="CardNote.TLabel").pack(anchor="w", pady=(5, 12))
        ttk.Button(safety_card, text="Open", command=self.open_safety_center, style="Secondary.TButton").pack(anchor="w")

        dictionary_card = ttk.Frame(insight_cards, style="Card.TFrame", padding=16)
        dictionary_card.grid(row=0, column=1, sticky="nsew", padx=6)
        ttk.Label(dictionary_card, text="SITE DICTIONARY", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(dictionary_card, text="Search domains and words", style="CardNote.TLabel").pack(anchor="w", pady=(5, 12))
        ttk.Button(dictionary_card, text="Open", command=self.open_site_dictionary, style="Secondary.TButton").pack(anchor="w")

        rules_card = ttk.Frame(insight_cards, style="Card.TFrame", padding=16)
        rules_card.grid(row=0, column=2, sticky="nsew", padx=(6, 0))
        ttk.Label(rules_card, text="RULE LIBRARY", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(rules_card, text="Tune local categories", style="CardNote.TLabel").pack(anchor="w", pady=(5, 12))
        ttk.Button(rules_card, text="Open", command=self.open_rule_manager, style="Secondary.TButton").pack(anchor="w")

    def refresh_listbox(self):
        self.listbox.delete(0, tk.END)
        for item in self.blocklist:
            self.listbox.insert(tk.END, item)
        self.count_label.config(text=f"{len(self.blocklist)} domain{'s' if len(self.blocklist) != 1 else ''}")
        if hasattr(self, "domain_stat_label"):
            self.domain_stat_label.config(text=str(len(self.blocklist)))
        if hasattr(self, "rule_stat_label"):
            self.rule_stat_label.config(text=str(sum(len(words) for words in self.categories.values())))

    def parse_domains(self, value, limit=None):
        domains = []
        seen = set(self.blocklist)
        for item in re.split(r"[\s,;]+", value):
            domain = normalize_domain(item)
            if domain and domain not in seen:
                domains.append(domain)
                seen.add(domain)
                if limit and len(domains) >= limit:
                    break
        return domains

    def extract_domains(self, text, limit=None):
        return self.parse_domains(" ".join(DOMAIN_PATTERN.findall(text)), limit=limit)

    def check_url(self):
        site = self.check_var.get().strip()
        if not site:
            show_app_dialog(self, "Missing website", "Please enter a website or domain.", "warning")
            return

        result = analyze_site(site, self.blocklist, self.categories)
        record_activity(
            "manual_check",
            result["domain"],
            f"{result['level']} ({result['score']}/100); {result['recommendation']}",
        )
        if not result["domain"]:
            show_app_dialog(self, "Invalid website", "Enter a valid website or domain.", "warning")
            return

        reasons = []
        if result["blocked"]:
            reasons.append("already blocked or a subdomain of a blocked site")
        if result["categories"]:
            reasons.append(f"categories: {', '.join(result['categories'])}")
        if result["keywords"]:
            reasons.append(f"matched words: {', '.join(result['keywords'])}")
        if result["signals"]:
            reasons.append("smart signals:\n- " + "\n- ".join(result["signals"]))
        reasons.append(f"recommendation: {result['recommendation']}")

        if reasons:
            show_app_dialog(
                self,
                f"{result['level']} ({result['score']}/100)",
                f"{result['domain']}\n\n" + "\n".join(reasons),
                "warning",
            )
        else:
            show_app_dialog(self, f"{result['level']} ({result['score']}/100)", f"{result['domain']}\n\n{result['recommendation']}", "success")

    def open_safety_center(self):
        dialog = tk.Toplevel(self)
        dialog.title("Safety Center")
        dialog.geometry("780x560")
        dialog.minsize(650, 460)
        dialog.configure(bg="#eaf4f7")
        dialog.transient(self)
        if hasattr(self, "window_icon"):
            dialog.iconphoto(True, self.window_icon)

        header = tk.Frame(dialog, bg="#0b6478", padx=22, pady=16)
        header.pack(fill="x")
        tk.Label(header, text="Safety Center", bg="#0b6478", fg="#ffffff", font=("Segoe UI", 17, "bold")).pack(anchor="w")
        tk.Label(header, text="Local blocked-visit and manual-check activity", bg="#0b6478", fg="#e2f5f7", font=("Segoe UI", 10)).pack(anchor="w", pady=(3, 0))

        body = ttk.Frame(dialog, style="App.TFrame", padding=16)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Only blocked extension events and manual checks are recorded. Successful browsing is not logged.", style="Muted.TLabel", wraplength=700).pack(anchor="w", pady=(0, 12))

        settings = ttk.Frame(body, style="Panel.TFrame", padding=10)
        settings.pack(fill="x", pady=(0, 10))
        ttk.Label(settings, text="Keep records for", style="Panel.TLabel").pack(side="left")
        activity = load_activity()
        selected_retention = next((label for label, hours in RETENTION_OPTIONS.items() if hours == activity["retention_hours"]), "24 hours")
        retention_var = tk.StringVar(value=selected_retention)
        retention_menu = ttk.Combobox(settings, textvariable=retention_var, values=list(RETENTION_OPTIONS), state="readonly", width=14)
        retention_menu.pack(side="left", padx=(8, 0))

        list_frame = ttk.Frame(body, style="Panel.TFrame", padding=10)
        list_frame.pack(fill="both", expand=True)
        activity_scroll = ttk.Scrollbar(list_frame, orient="vertical")
        activity_scroll.pack(side="right", fill="y")
        activity_list = tk.Listbox(list_frame, font=("Consolas", 9), bg="#f8fafc", fg="#16324f", selectbackground="#087f92", selectforeground="#ffffff", relief="flat", borderwidth=0, yscrollcommand=activity_scroll.set)
        activity_list.pack(side="left", fill="both", expand=True)
        activity_scroll.config(command=activity_list.yview)
        count_label = ttk.Label(body, text="", style="Muted.TLabel")
        count_label.pack(anchor="w", pady=(8, 0))

        def refresh_activity(*_):
            current = load_activity()
            activity_list.delete(0, tk.END)
            for event in reversed(current["events"]):
                timestamp = datetime.fromisoformat(event["timestamp"]).astimezone().strftime("%Y-%m-%d %H:%M")
                activity_list.insert(tk.END, f"{timestamp}  |  {event['type']}  |  {event['domain']}  |  {event['detail']}")
            count_label.config(text=f"{len(current['events'])} record{'s' if len(current['events']) != 1 else ''} stored locally")

        def update_retention(_event=None):
            current = load_activity()
            save_activity(current["events"], RETENTION_OPTIONS[retention_var.get()])
            refresh_activity()

        def clear_activity():
            current = load_activity()
            save_activity([], current["retention_hours"])
            refresh_activity()

        retention_menu.bind("<<ComboboxSelected>>", update_retention)
        refresh_activity()
        actions = ttk.Frame(body, style="App.TFrame")
        actions.pack(fill="x", pady=(10, 0))
        ttk.Button(actions, text="Clear Activity", command=clear_activity, style="Secondary.TButton").pack(side="left")
        ttk.Button(actions, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(side="right")

        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.update_idletasks()
        self.update_idletasks()
        position_x = self.winfo_rootx() + (self.winfo_width() - dialog.winfo_width()) // 2
        position_y = self.winfo_rooty() + (self.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(position_x, 0)}+{max(position_y, 0)}")
        dialog.grab_set()
        self.wait_window(dialog)

    def add_url(self):
        site = self.add_var.get().strip()
        if not site:
            show_app_dialog(self, "Missing website", "Type a website first.", "warning")
            return

        domains = self.parse_domains(site)
        if not domains:
            show_app_dialog(self, "Invalid domain", "Enter a valid domain or URL.", "warning")
            return

        self.blocklist.extend(domains)
        save_rules(self.blocklist, self.categories, self.subdomain_prefixes)
        self.refresh_listbox()
        self.add_var.set("")
        show_app_dialog(self, "Domain added", f"{len(domains)} domain{'s' if len(domains) != 1 else ''} added to the block list.", "success")

    def open_site_dictionary(self):
        dialog = tk.Toplevel(self)
        dialog.title("Site and word dictionary")
        dialog.geometry("820x620")
        dialog.minsize(680, 500)
        dialog.configure(bg="#eaf4f7")
        dialog.transient(self)
        if hasattr(self, "window_icon"):
            dialog.iconphoto(True, self.window_icon)

        header = tk.Frame(dialog, bg="#0b6478", padx=22, pady=16)
        header.pack(fill="x")
        tk.Label(header, text="Site and word dictionary", bg="#0b6478", fg="#ffffff", font=("Segoe UI", 17, "bold")).pack(anchor="w")
        tk.Label(header, text="Search blocked domains, detection words, and subdomain prefixes", bg="#0b6478", fg="#e2f5f7", font=("Segoe UI", 10)).pack(anchor="w", pady=(3, 0))

        body = ttk.Frame(dialog, style="App.TFrame", padding=16)
        body.pack(fill="both", expand=True)
        search_var = tk.StringVar()
        ttk.Label(body, text="Search the dictionary", style="Panel.TLabel", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        search_entry = ttk.Entry(body, textvariable=search_var)
        search_entry.pack(fill="x", pady=(4, 10))

        summary = ttk.Label(body, text="", style="Muted.TLabel")
        summary.pack(anchor="w", pady=(0, 8))

        table_frame = ttk.Frame(body, style="Panel.TFrame", padding=8)
        table_frame.pack(fill="both", expand=True)
        table_scroll = ttk.Scrollbar(table_frame, orient="vertical")
        table_scroll.pack(side="right", fill="y")
        columns = ("type", "entry", "category", "meaning")
        table = ttk.Treeview(table_frame, columns=columns, show="headings", yscrollcommand=table_scroll.set)
        table.heading("type", text="Type")
        table.heading("entry", text="Domain or word")
        table.heading("category", text="Category")
        table.heading("meaning", text="Meaning")
        table.column("type", width=105, anchor="w")
        table.column("entry", width=220, anchor="w")
        table.column("category", width=130, anchor="w")
        table.column("meaning", width=310, anchor="w")
        table.pack(side="left", fill="both", expand=True)
        table_scroll.config(command=table.yview)

        entries = []
        for domain in sorted(set(self.blocklist)):
            categories = detect_categories(domain, self.categories)
            category_text = ", ".join(categories) if categories else "custom block"
            meaning = "Blocked domain and its configured subdomains."
            entries.append(("Domain", domain, category_text, meaning))
        for category, keywords in sorted(self.categories.items()):
            meaning = CATEGORY_DESCRIPTIONS.get(category, "Custom detection category.")
            for keyword in sorted(set(keywords)):
                entries.append(("Word", keyword, category, meaning))
        for prefix in sorted(set(self.subdomain_prefixes)):
            entries.append(("Prefix", prefix, "hostname", f"Common subdomain prefix such as {prefix}.example.com."))

        def refresh_dictionary(*_):
            query = search_var.get().strip().lower()
            table.delete(*table.get_children())
            visible = [entry for entry in entries if not query or any(query in str(value).lower() for value in entry)]
            for entry in visible:
                table.insert("", tk.END, values=entry)
            summary.config(text=f"{len(visible)} of {len(entries)} entries")

        search_var.trace_add("write", refresh_dictionary)
        refresh_dictionary()
        ttk.Button(body, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(anchor="e", pady=(10, 0))

        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.update_idletasks()
        self.update_idletasks()
        position_x = self.winfo_rootx() + (self.winfo_width() - dialog.winfo_width()) // 2
        position_y = self.winfo_rooty() + (self.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(position_x, 0)}+{max(position_y, 0)}")
        dialog.grab_set()
        search_entry.focus_set()
        self.wait_window(dialog)

    def open_rule_manager(self):
        dialog = tk.Toplevel(self)
        dialog.title("Manage search rules")
        dialog.geometry("680x560")
        dialog.minsize(580, 460)
        dialog.configure(bg="#eaf4f7")
        dialog.transient(self)
        if hasattr(self, "window_icon"):
            dialog.iconphoto(True, self.window_icon)

        header = tk.Frame(dialog, bg="#0b6478", padx=22, pady=16)
        header.pack(fill="x")
        tk.Label(header, text="Rule library", bg="#0b6478", fg="#ffffff", font=("Segoe UI", 17, "bold")).pack(anchor="w")
        tk.Label(header, text="Search, add, and refine the words Avantis FireWall detects", bg="#0b6478", fg="#e2f5f7", font=("Segoe UI", 10)).pack(anchor="w", pady=(3, 0))

        body = ttk.Frame(dialog, style="App.TFrame", padding=16)
        body.pack(fill="both", expand=True)
        search_var = tk.StringVar()
        ttk.Label(body, text="Search rules", style="Panel.TLabel", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        search_entry = ttk.Entry(body, textvariable=search_var)
        search_entry.pack(fill="x", pady=(4, 12))

        list_frame = ttk.Frame(body, style="Panel.TFrame", padding=10)
        list_frame.pack(fill="both", expand=True)
        rule_scroll = ttk.Scrollbar(list_frame, orient="vertical")
        rule_scroll.pack(side="right", fill="y")
        rule_list = tk.Listbox(list_frame, selectmode=tk.EXTENDED, font=("Segoe UI", 10), bg="#f8fafc", fg="#16445a", selectbackground="#087f92", selectforeground="#ffffff", relief="flat", borderwidth=0, yscrollcommand=rule_scroll.set)
        rule_list.pack(side="left", fill="both", expand=True)
        rule_scroll.config(command=rule_list.yview)
        visible_rules = []

        def refresh_rules(*_):
            query = search_var.get().strip().lower()
            visible_rules.clear()
            rule_list.delete(0, tk.END)
            for category, keywords in sorted(self.categories.items()):
                for keyword in sorted(set(keywords)):
                    if not query or query in category.lower() or query in keyword.lower():
                        visible_rules.append((category, keyword))
                        rule_list.insert(tk.END, f"{category}  /  {keyword}")

        search_var.trace_add("write", refresh_rules)
        refresh_rules()

        editor = ttk.Frame(body, style="Panel.TFrame", padding=(0, 12, 0, 0))
        editor.pack(fill="x")
        category_var = tk.StringVar(value="gambling")
        keyword_var = tk.StringVar()
        ttk.Label(editor, text="Category", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(editor, text="Keyword or phrase", style="Panel.TLabel").grid(row=0, column=1, sticky="w", padx=(12, 0))
        category_entry = ttk.Entry(editor, textvariable=category_var)
        category_entry.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        keyword_entry = ttk.Entry(editor, textvariable=keyword_var)
        keyword_entry.grid(row=1, column=1, sticky="ew", padx=(12, 0), pady=(4, 0))
        editor.columnconfigure(0, weight=1)
        editor.columnconfigure(1, weight=2)

        actions = ttk.Frame(body, style="App.TFrame")
        actions.pack(fill="x", pady=(12, 0))

        def add_rule():
            category = category_var.get().strip().lower()
            keyword = keyword_var.get().strip().lower()
            if not category or not keyword:
                show_app_dialog(dialog, "Incomplete rule", "Enter both a category and a keyword.", "warning")
                return
            self.categories.setdefault(category, [])
            if keyword not in self.categories[category]:
                self.categories[category].append(keyword)
                save_rules(self.blocklist, self.categories, self.subdomain_prefixes)
            keyword_var.set("")
            refresh_rules()

        def remove_rules():
            selected = rule_list.curselection()
            if not selected:
                show_app_dialog(dialog, "No rules selected", "Select one or more rules to remove.", "warning")
                return
            for index in reversed(selected):
                category, keyword = visible_rules[index]
                self.categories[category] = [item for item in self.categories[category] if item != keyword]
                if not self.categories[category]:
                    del self.categories[category]
            save_rules(self.blocklist, self.categories, self.subdomain_prefixes)
            refresh_rules()

        ttk.Button(actions, text="Add Rule", command=add_rule, style="Accent.TButton").pack(side="left")
        ttk.Button(actions, text="Remove Selected", command=remove_rules, style="Secondary.TButton").pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(side="right")

        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.update_idletasks()
        self.update_idletasks()
        position_x = self.winfo_rootx() + (self.winfo_width() - dialog.winfo_width()) // 2
        position_y = self.winfo_rooty() + (self.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(position_x, 0)}+{max(position_y, 0)}")
        dialog.grab_set()
        search_entry.focus_set()
        self.wait_window(dialog)

    def add_multiple(self):
        value = self.bulk_text.get("1.0", tk.END).strip()
        if not value:
            show_app_dialog(self, "Nothing to import", "Paste at least one domain first.", "warning")
            return

        domains = self.parse_domains(value)
        if not domains:
            show_app_dialog(self, "Nothing to import", "No valid new domains were found.", "warning")
            return

        self.blocklist.extend(domains)
        save_rules(self.blocklist, self.categories, self.subdomain_prefixes)
        self.refresh_listbox()
        self.bulk_text.delete("1.0", tk.END)
        show_app_dialog(self, "Bulk import complete", f"{len(domains)} domain{'s' if len(domains) != 1 else ''} added to the block list.", "success")

    def open_public_list(self):
        dialog = tk.Toplevel(self)
        dialog.title("Download a public domain list")
        dialog.geometry("640x360")
        dialog.minsize(560, 320)
        dialog.configure(bg="#eaf4f7")
        dialog.transient(self)
        if hasattr(self, "window_icon"):
            dialog.iconphoto(True, self.window_icon)

        header = tk.Frame(dialog, bg="#0b6478", padx=22, pady=16)
        header.pack(fill="x")
        tk.Label(header, text="Public domain lists", bg="#0b6478", fg="#ffffff", font=("Segoe UI", 17, "bold")).pack(anchor="w")
        tk.Label(header, text="Download known defensive lists for review before blocking", bg="#0b6478", fg="#e2f5f7", font=("Segoe UI", 10)).pack(anchor="w", pady=(3, 0))

        body = ttk.Frame(dialog, style="App.TFrame", padding=16)
        body.pack(fill="both", expand=True)
        list_var = tk.StringVar(value=next(iter(PUBLIC_LISTS)))
        list_menu = ttk.Combobox(body, textvariable=list_var, values=list(PUBLIC_LISTS), state="readonly")
        list_menu.pack(fill="x")
        description = ttk.Label(body, text="", style="Muted.TLabel", wraplength=580)
        description.pack(anchor="w", pady=(8, 0))
        status = ttk.Label(body, text="", style="Muted.TLabel", wraplength=580)
        status.pack(anchor="w", pady=(12, 0))

        def update_description(_event=None):
            description.config(text=PUBLIC_LISTS[list_var.get()]["description"])

        def download_list():
            source = PUBLIC_LISTS[list_var.get()]
            status.config(text="Downloading list...")
            dialog.update_idletasks()
            try:
                request = Request(source["url"], headers={"User-Agent": "Avantis-FireWall/1.0"})
                with urlopen(request, timeout=20) as response:
                    content = response.read(8 * 1024 * 1024 + 1)
                if len(content) > 8 * 1024 * 1024:
                    raise ValueError("The public list is larger than the 8 MB safety limit.")
                domains = self.extract_domains(content.decode("utf-8", errors="ignore"), limit=PUBLIC_LIST_LIMIT)
                if not domains:
                    raise ValueError("No recognizable domains were found in that list.")
                self.blocklist.extend(domains)
                save_rules(self.blocklist, self.categories, self.subdomain_prefixes)
                self.refresh_listbox()
                status.config(text=f"Found {len(domains)} new domains. Review the list, then click Apply to Hosts when ready.")
            except (OSError, ValueError) as error:
                status.config(text=f"Download failed: {error}")

        list_menu.bind("<<ComboboxSelected>>", update_description)
        update_description()
        ttk.Button(body, text="Download and Add", command=download_list, style="Accent.TButton").pack(anchor="w", pady=(18, 0))
        ttk.Button(body, text="Close", command=dialog.destroy, style="Secondary.TButton").pack(anchor="e", pady=(10, 0))
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.grab_set()
        self.wait_window(dialog)

    def import_file(self):
        file_path = filedialog.askopenfilename(
            parent=self,
            title="Import blocked sites",
            filetypes=[
                ("Supported files", "*.txt *.csv *.json *.docx"),
                ("Text files", "*.txt *.csv"),
                ("JSON files", "*.json"),
                ("Word documents", "*.docx"),
                ("All files", "*.*"),
            ],
        )
        if not file_path:
            return

        try:
            path = Path(file_path)
            if path.suffix.lower() == ".docx":
                document = Document(path)
                text_parts = [paragraph.text for paragraph in document.paragraphs]
                text_parts.extend(cell.text for table in document.tables for row in table.rows for cell in row.cells)
                text = "\n".join(text_parts)
            elif path.suffix.lower() == ".json":
                with path.open("r", encoding="utf-8") as file:
                    text = json.dumps(json.load(file))
            else:
                text = path.read_text(encoding="utf-8-sig", errors="ignore")

            domains = self.extract_domains(text)
            if not domains:
                show_app_dialog(self, "No sites found", "The selected file did not contain recognizable domain names.", "warning")
                return

            self.blocklist.extend(domains)
            save_rules(self.blocklist, self.categories, self.subdomain_prefixes)
            self.refresh_listbox()
            show_app_dialog(self, "File import complete", f"{len(domains)} new domain{'s' if len(domains) != 1 else ''} imported from:\n{path.name}", "success")
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            show_app_dialog(self, "Import failed", str(error), "error")

    def remove_selected(self):
        selected = self.listbox.curselection()
        if not selected:
            show_app_dialog(self, "No domains selected", "Select one or more domains first.", "warning")
            return

        removed = [self.blocklist[index] for index in selected]
        for index in reversed(selected):
            self.blocklist.pop(index)
        save_rules(self.blocklist, self.categories, self.subdomain_prefixes)
        self.refresh_listbox()
        show_app_dialog(self, "Domains removed", f"{len(removed)} domain{'s' if len(removed) != 1 else ''} removed.", "success")

    def clear_all(self):
        if show_app_dialog(self, "Clear blocked domains", "Remove all blocked domains?", "warning", confirm=True):
            self.blocklist.clear()
            save_rules(self.blocklist, self.categories, self.subdomain_prefixes)
            self.refresh_listbox()

    def apply_blocking(self):
        if not is_admin():
            if relaunch_as_admin():
                self.destroy()
            else:
                show_app_dialog(self, "Administrator required", "Windows elevation was cancelled. Allow Avantis FireWall through the UAC prompt to update the hosts file.", "error")
            return

        try:
            write_hosts_file(self.blocklist, self.subdomain_prefixes)
            flush_dns_cache()
            show_app_dialog(self, "Protection applied", "The configured domains and common subdomains were added to the Windows hosts file.\n\nIf a browser still opens a site, disable Secure DNS / DNS-over-HTTPS in that browser and restart it.", "success")
        except Exception as e:
            show_app_dialog(self, "Could not apply protection", str(e), "error")

    def remove_blocking(self):
        if not is_admin():
            if relaunch_as_admin():
                self.destroy()
            else:
                show_app_dialog(self, "Administrator required", "Windows elevation was cancelled. Allow Avantis FireWall through the UAC prompt to change the hosts file.", "error")
            return

        if not show_app_dialog(self, "Remove hosts rules", "Remove only the Avantis FireWall rules from the Windows hosts file?", "warning", confirm=True):
            return

        try:
            removed = remove_hosts_rules()
            flush_dns_cache()
            message = "The Avantis FireWall hosts rules were removed." if removed else "No Avantis FireWall hosts rules were found."
            show_app_dialog(self, "Hosts rules removed", message, "success")
        except Exception as e:
            show_app_dialog(self, "Could not remove hosts rules", str(e), "error")

    def run_on_startup(self):
        try:
            shortcut = add_to_startup()
            show_app_dialog(self, "Startup enabled", f"Avantis FireWall was added to Windows startup:\n{shortcut}", "success")
        except Exception as e:
            show_app_dialog(self, "Could not enable startup", str(e), "error")


def main():
    if os.name == "nt" and not is_admin():
        if relaunch_as_admin():
            return
        return

    app = BlockerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
