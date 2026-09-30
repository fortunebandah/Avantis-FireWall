import json
import os
import re
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk
from urllib.parse import urlparse
from PIL import Image, ImageTk
from docx import Document

WINDOWS_HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
RULES_FILE = Path(__file__).with_name("rules.json")
LOGO_FILE = Path(__file__).with_name("Images") / "Avantis-logo-prl.png"
DOMAIN_PATTERN = re.compile(r"(?i)(?:https?://)?(?:www\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}")

DEFAULT_CATEGORIES = {
    "adult": [
        "adult", "porn", "porno", "pornhub", "sex", "xxx", "xvideos",
        "nude", "nudity", "strip", "erotic", "playboy", "asian porn"
    ],
    "gambling": [
        "casino", "gambling", "betting", "roulette", "poker", "slot",
        "jackpot", "lottery", "sportsbook", "baccarat"
    ],
    "malware": [
        "crack", "keygen", "warez", "nulled", "r57", "download free"
    ],
    "scam": [
        "free money", "bitcoin generator", "lottery winner", "fake rewards",
        "clickbank scam", "crypto scam"
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


def detect_categories(domain: str, categories=None):
    text = normalize_domain(domain)
    found = []
    for category, keywords in (categories or DEFAULT_CATEGORIES).items():
        lowered_keywords = [kw.lower() for kw in keywords]
        if any(kw in text for kw in lowered_keywords):
            found.append(category)
    return found


def analyze_site(site: str, blocklist, categories):
    domain = normalize_domain(site)
    matched_keywords = []
    matched_categories = []

    for category, keywords in categories.items():
        category_matches = [keyword for keyword in keywords if keyword.lower() in domain]
        if category_matches:
            matched_categories.append(category)
            matched_keywords.extend(category_matches)

    is_blocked = any(domain == blocked or domain.endswith(f".{blocked}") for blocked in blocklist)
    score = min(100, len(set(matched_keywords)) * 15 + len(matched_categories) * 10 + (70 if is_blocked else 0))
    if score >= 70:
        level = "High risk"
    elif score >= 35:
        level = "Review"
    else:
        level = "Low risk"

    return {
        "domain": domain,
        "blocked": is_blocked,
        "categories": matched_categories,
        "keywords": list(dict.fromkeys(matched_keywords)),
        "score": score,
        "level": level,
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
        with open(WINDOWS_HOSTS_PATH, "w", encoding="utf-8") as f:
            f.write(new_content)
    except PermissionError:
        raise PermissionError("Administrator rights are required to change the hosts file.")


def flush_dns_cache():
    subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, check=False)


def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


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
        style.configure("Header.TFrame", background="#0b6478")
        style.configure("Header.TLabel", background="#0b6478", foreground="#ffffff")
        style.configure("Panel.TFrame", background="#ffffff")
        style.configure("Panel.TLabel", background="#ffffff", foreground="#12445b")
        style.configure("Muted.TLabel", background="#ffffff", foreground="#527184")
        style.configure("Accent.TButton", background="#087f92", foreground="#ffffff", padding=(12, 7))
        style.map("Accent.TButton", background=[("active", "#075d70")])
        style.configure("Secondary.TButton", padding=(10, 7))

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

        input_frame = ttk.Frame(content, style="Panel.TFrame", padding=14)
        input_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(input_frame, text="Quick add", style="Panel.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(input_frame, text="Enter one domain or URL", style="Muted.TLabel").pack(anchor="w", pady=(2, 6))
        self.url_var = tk.StringVar()
        entry = ttk.Entry(input_frame, textvariable=self.url_var, font=("Segoe UI", 10))
        entry.pack(fill="x", pady=(0, 10))

        buttons = ttk.Frame(input_frame, style="Panel.TFrame")
        buttons.pack(fill="x")

        ttk.Button(buttons, text="Check URL", command=self.check_url, style="Secondary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Add Domain", command=self.add_url, style="Accent.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Apply to Hosts", command=self.apply_blocking, style="Secondary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Run on Startup", command=self.run_on_startup, style="Secondary.TButton").pack(side="left")

        bulk_frame = ttk.Frame(content, style="Panel.TFrame", padding=14)
        bulk_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(bulk_frame, text="Bulk import", style="Panel.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(bulk_frame, text="Paste multiple domains separated by new lines, spaces, or commas", style="Muted.TLabel").pack(anchor="w", pady=(2, 6))

        bulk_row = ttk.Frame(bulk_frame, style="Panel.TFrame")
        bulk_row.pack(fill="x")
        self.bulk_text = tk.Text(bulk_row, height=3, wrap="word", font=("Segoe UI", 10), relief="flat", borderwidth=1, highlightthickness=1, highlightbackground="#cbd5e1", highlightcolor="#087f92")
        self.bulk_text.pack(side="left", fill="both", expand=True)
        bulk_actions = ttk.Frame(bulk_row, style="Panel.TFrame")
        bulk_actions.pack(side="left", padx=(12, 0), anchor="n")
        ttk.Button(bulk_actions, text="Add All", command=self.add_multiple, style="Accent.TButton").pack(fill="x")
        ttk.Button(bulk_actions, text="Import File", command=self.import_file, style="Secondary.TButton").pack(fill="x", pady=(8, 0))

        list_frame = ttk.Frame(content, style="Panel.TFrame", padding=14)
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
        self.listbox = tk.Listbox(list_area, height=8, activestyle="none", selectmode=tk.EXTENDED, font=("Segoe UI", 10), bg="#f8fafc", fg="#16324f", selectbackground="#087f92", selectforeground="#ffffff", relief="flat", borderwidth=0, yscrollcommand=scrollbar.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.listbox.yview)

        controls = ttk.Frame(list_frame, style="Panel.TFrame")
        controls.pack(fill="x", pady=(10, 0))
        ttk.Button(controls, text="Remove Selected", command=self.remove_selected, style="Secondary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="Clear All", command=self.clear_all, style="Secondary.TButton").pack(side="left")

    def refresh_listbox(self):
        self.listbox.delete(0, tk.END)
        for item in self.blocklist:
            self.listbox.insert(tk.END, item)
        self.count_label.config(text=f"{len(self.blocklist)} domain{'s' if len(self.blocklist) != 1 else ''}")

    def parse_domains(self, value):
        domains = []
        seen = set(self.blocklist)
        for item in re.split(r"[\s,;]+", value):
            domain = normalize_domain(item)
            if domain and domain not in seen:
                domains.append(domain)
                seen.add(domain)
        return domains

    def extract_domains(self, text):
        return self.parse_domains(" ".join(DOMAIN_PATTERN.findall(text)))

    def check_url(self):
        site = self.url_var.get().strip()
        if not site:
            show_app_dialog(self, "Missing website", "Please enter a website or domain.", "warning")
            return

        result = analyze_site(site, self.blocklist, self.categories)
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

        if reasons:
            show_app_dialog(
                self,
                f"{result['level']} ({result['score']}/100)",
                f"{result['domain']}\n\n" + "\n".join(reasons),
                "warning",
            )
        else:
            show_app_dialog(self, "Low risk (0/100)", f"{result['domain']} did not match any configured rules.", "success")

    def add_url(self):
        site = self.url_var.get().strip()
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
        self.url_var.set("")
        show_app_dialog(self, "Domain added", f"{len(domains)} domain{'s' if len(domains) != 1 else ''} added to the block list.", "success")

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
            show_app_dialog(self, "Administrator required", "Please run this app as Administrator to update the Windows hosts file.", "error")
            return

        try:
            write_hosts_file(self.blocklist, self.subdomain_prefixes)
            flush_dns_cache()
            show_app_dialog(self, "Protection applied", "The configured domains and common subdomains were added to the Windows hosts file.\n\nIf a browser still opens a site, disable Secure DNS / DNS-over-HTTPS in that browser and restart it.", "success")
        except Exception as e:
            show_app_dialog(self, "Could not apply protection", str(e), "error")

    def run_on_startup(self):
        try:
            shortcut = add_to_startup()
            show_app_dialog(self, "Startup enabled", f"Avantis FireWall was added to Windows startup:\n{shortcut}", "success")
        except Exception as e:
            show_app_dialog(self, "Could not enable startup", str(e), "error")


def main():
    app = BlockerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
