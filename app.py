import json
import os
import re
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import ttk, messagebox

WINDOWS_HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
RULES_FILE = Path(__file__).with_name("rules.json")

CATEGORY_KEYWORDS = {
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
]


def normalize_domain(value: str) -> str:
    domain = value.strip().lower()
    domain = domain.replace("http://", "")
    domain = domain.replace("https://", "")
    domain = domain.replace("www.", "")
    domain = domain.split("/")[0]
    domain = domain.split("?")[0]
    domain = domain.split("#")[0]
    domain = domain.strip(".")
    return domain


def detect_categories(domain: str):
    text = normalize_domain(domain)
    found = []
    for category, keywords in CATEGORY_KEYWORDS.items():
        lowered_keywords = [kw.lower() for kw in keywords]
        if any(kw in text for kw in lowered_keywords):
            found.append(category)
    return found


def load_rules():
    if not RULES_FILE.exists():
        return DEFAULT_BLOCKLIST[:]

    try:
        with RULES_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [normalize_domain(item) for item in data if item.strip()]
    except Exception:
        pass

    return DEFAULT_BLOCKLIST[:]


def save_rules(blocklist):
    unique = []
    seen = set()
    for item in blocklist:
        domain = normalize_domain(item)
        if domain and domain not in seen:
            unique.append(domain)
            seen.add(domain)

    with RULES_FILE.open("w", encoding="utf-8") as f:
        json.dump(unique, f, indent=2)


def write_hosts_file(blocklist):
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
    for domain in blocklist:
        clean = normalize_domain(domain)
        if clean:
            lines.append(f"127.0.0.1 {clean}")
            lines.append(f"0.0.0.0 {clean}")

    block_section = f"\n{marker}\n" + "\n".join(lines) + f"\n{end_marker}\n"
    new_content = content.rstrip() + "\n" + block_section.strip() + "\n"

    try:
        with open(WINDOWS_HOSTS_PATH, "w", encoding="utf-8") as f:
            f.write(new_content)
    except PermissionError:
        raise PermissionError("Administrator rights are required to change the hosts file.")


def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


def add_to_startup():
    startup_dir = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    os.makedirs(startup_dir, exist_ok=True)

    shortcut_path = os.path.join(startup_dir, "SuspiciousSiteBlocker.bat")
    script_path = os.path.abspath(__file__)

    bat_content = (
        "@echo off\n"
        "start /B python \"" + script_path + "\"\n"
    )

    with open(shortcut_path, "w", encoding="utf-8") as f:
        f.write(bat_content)

    return shortcut_path


class BlockerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Suspicious Site Blocker")
        self.geometry("650x500")
        self.minsize(600, 430)

        self.blocklist = load_rules()
        self.create_widgets()
        self.refresh_listbox()

    def create_widgets(self):
        title = ttk.Label(self, text="Suspicious Site Blocker", font=("Segoe UI", 18, "bold"))
        title.pack(pady=(12, 8))

        input_frame = ttk.Frame(self)
        input_frame.pack(fill="x", padx=18, pady=(0, 10))

        ttk.Label(input_frame, text="Website or domain:").pack(anchor="w")
        self.url_var = tk.StringVar()
        entry = ttk.Entry(input_frame, textvariable=self.url_var, width=80)
        entry.pack(fill="x", pady=(4, 8))

        buttons = ttk.Frame(self)
        buttons.pack(fill="x", padx=18)

        ttk.Button(buttons, text="Check URL", command=self.check_url).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Add to Block List", command=self.add_url).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Apply to Hosts", command=self.apply_blocking).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Run on Startup", command=self.run_on_startup).pack(side="left", padx=(0, 8))

        ttk.Label(self, text="Blocked domains:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=18, pady=(12, 4))

        self.listbox = tk.Listbox(self, height=15, activestyle="none")
        self.listbox.pack(fill="both", expand=True, padx=18, pady=(0, 10))

        controls = ttk.Frame(self)
        controls.pack(fill="x", padx=18, pady=(0, 14))
        ttk.Button(controls, text="Remove Selected", command=self.remove_selected).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="Clear All", command=self.clear_all).pack(side="left")

    def refresh_listbox(self):
        self.listbox.delete(0, tk.END)
        for item in self.blocklist:
            self.listbox.insert(tk.END, item)

    def check_url(self):
        site = self.url_var.get().strip()
        if not site:
            messagebox.showwarning("Warning", "Please enter a website or domain.")
            return

        domain = normalize_domain(site)
        categories = detect_categories(domain)
        if not categories:
            messagebox.showinfo("Result", f"{domain} is not matching the suspicious keywords in the current detector.")
        else:
            messagebox.showwarning("Suspicious", f"{domain} matches category: {', '.join(categories)}")

    def add_url(self):
        site = self.url_var.get().strip()
        if not site:
            messagebox.showwarning("Warning", "Type a website first.")
            return

        domain = normalize_domain(site)
        if not domain:
            messagebox.showwarning("Warning", "Invalid domain.")
            return

        if domain not in self.blocklist:
            self.blocklist.append(domain)
            save_rules(self.blocklist)
            self.refresh_listbox()
            messagebox.showinfo("Added", f"{domain} was added to the block list.")
        else:
            messagebox.showinfo("Already present", f"{domain} is already blocked.")

    def remove_selected(self):
        selected = self.listbox.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Select an item first.")
            return

        index = selected[0]
        removed = self.blocklist.pop(index)
        save_rules(self.blocklist)
        self.refresh_listbox()
        messagebox.showinfo("Removed", f"{removed} was removed.")

    def clear_all(self):
        if messagebox.askyesno("Confirm", "Remove all blocked domains?"):
            self.blocklist.clear()
            save_rules(self.blocklist)
            self.refresh_listbox()

    def apply_blocking(self):
        if not is_admin():
            messagebox.showerror("Admin required", "Please run this app as Administrator to update the Windows hosts file.")
            return

        try:
            write_hosts_file(self.blocklist)
            messagebox.showinfo("Success", "Suspicious sites were added to the hosts file and blocked.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run_on_startup(self):
        try:
            shortcut = add_to_startup()
            messagebox.showinfo("Startup enabled", f"The app was added to Windows startup: {shortcut}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


def main():
    app = BlockerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
