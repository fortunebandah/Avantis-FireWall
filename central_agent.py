import argparse
import base64
import ctypes
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import win32crypt
import win32event
import win32service
import win32serviceutil
import servicemanager
import pywintypes

import app

APP_VERSION = "1.1.3"
API_BASE_URL = "https://avantispcfeedback.avantis.co.zw/firewall/api/v1"
SERVICE_NAME = "AvantisCentralAgent"
SERVICE_DISPLAY_NAME = "Avantis Central Protection Agent"
CHECK_IN_SECONDS = 60
REQUEST_TIMEOUT_SECONDS = 20
MAX_RESPONSE_BYTES = 131072
MAX_POLICY_DOMAINS = 1000
DPAPI_DESCRIPTION = "Avantis Central device credential"
DPAPI_MACHINE_SCOPE = 0x4
DOMAIN_RE = re.compile(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PREFIX_RE = re.compile(r"^[a-z0-9-]{1,63}$")

PROGRAM_DATA = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
SHARED_DATA_DIR = PROGRAM_DATA / "Avantis FireWall"
SECURE_DATA_DIR = SHARED_DATA_DIR / "agent"
CREDENTIAL_FILE = SECURE_DATA_DIR / "device-credential.dpapi"
STATUS_FILE = SHARED_DATA_DIR / "central-agent-status.json"
MANAGED_MARKER_FILE = SHARED_DATA_DIR / "company-managed.json"
LOG_FILE = SECURE_DATA_DIR / "agent.log"


class AgentError(Exception):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(message: str) -> None:
    SECURE_DATA_DIR.mkdir(parents=True, exist_ok=True)
    line = f"{_utc_now()} {message.replace(chr(10), ' ')[:500]}\n"
    with LOG_FILE.open("a", encoding="utf-8") as log:
        log.write(line)


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_path = tempfile.mkstemp(
        prefix=f"{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(file_descriptor, "wb") as temporary_file:
            temporary_file.write(content)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, path)
    except OSError:
        try:
            os.unlink(temporary_path)
        except OSError:
            pass
        raise


def _write_status(
    device_id: str,
    device_name: str,
    policy_version: int,
    blocked_domains: list[str],
    subdomain_prefixes: list[str],
    protection_status: str,
    last_check_in: str | None,
    error: str = "",
    server_policy_version: int | None = None,
) -> None:
    status = {
        "managed": True,
        "device_id": device_id,
        "device_name": device_name,
        "app_version": APP_VERSION,
        "policy_version": policy_version,
        "server_policy_version": policy_version if server_policy_version is None else server_policy_version,
        "blocked_domains": blocked_domains,
        "subdomain_prefixes": subdomain_prefixes,
        "protection_status": protection_status,
        "last_check_in": last_check_in,
        "last_error": error[:300],
    }
    _atomic_write(
        STATUS_FILE,
        (json.dumps(status, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8"),
    )


def _write_managed_marker(device_id: str, device_name: str) -> None:
    marker = {
        "managed": True,
        "device_id": device_id,
        "device_name": device_name,
        "api_base_url": API_BASE_URL,
    }
    _atomic_write(
        MANAGED_MARKER_FILE,
        (json.dumps(marker, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8"),
    )


def _protect_credentials(credentials: dict) -> bytes:
    plaintext = json.dumps(credentials, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    protected = win32crypt.CryptProtectData(
        plaintext,
        DPAPI_DESCRIPTION,
        None,
        None,
        None,
        DPAPI_MACHINE_SCOPE,
    )
    return bytes(protected)


def _unprotect_credentials(blob: bytes) -> dict:
    plaintext = win32crypt.CryptUnprotectData(blob, None, None, None, 0)[1]
    credentials = json.loads(plaintext.decode("utf-8"))
    if not isinstance(credentials, dict):
        raise AgentError("The saved device credential is invalid.")
    device_id = credentials.get("device_id")
    token = credentials.get("device_token")
    version = credentials.get("policy_version", 0)
    if (
        not isinstance(device_id, str)
        or not re.fullmatch(r"[a-f0-9]{32}", device_id)
        or not isinstance(token, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{40,100}", token)
        or not isinstance(version, int)
        or version < 0
    ):
        raise AgentError("The saved device credential is invalid.")
    return credentials


def _read_credentials() -> dict | None:
    if not CREDENTIAL_FILE.is_file():
        return None
    return _unprotect_credentials(CREDENTIAL_FILE.read_bytes())


def _save_credentials(credentials: dict) -> None:
    _atomic_write(CREDENTIAL_FILE, _protect_credentials(credentials))


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise AgentError("The Avantis Central endpoint returned an unexpected redirect.")


def _api_request(path: str, payload: dict, device_token: str | None = None) -> dict:
    if path not in {"/enroll", "/check-in"}:
        raise AgentError("The Avantis Central API path is not allowed.")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if device_token:
        headers["Authorization"] = f"Bearer {device_token}"
    request = urllib.request.Request(
        f"{API_BASE_URL}{path}",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if response.status < 200 or response.status >= 300:
                raise AgentError(f"Avantis Central returned HTTP {response.status}.")
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        try:
            result = json.loads(error.read(MAX_RESPONSE_BYTES).decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            result = {}
        error_code = result.get("error") if isinstance(result, dict) else None
        if error.code == 429:
            retry = result.get("retry_after_seconds", 60) if isinstance(result, dict) else 60
            raise AgentError(f"Check-in rate limited; retry after {int(retry)} seconds.") from error
        if error.code == 401:
            raise AgentError("This device has been revoked or its credentials are no longer valid.") from error
        if error.code == 409 and error_code == "reported_policy_version_ahead_of_server":
            raise AgentError("The saved device policy version is newer than the server policy.") from error
        raise AgentError(f"Avantis Central returned HTTP {error.code}.") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise AgentError("Avantis Central could not be reached over HTTPS.") from error

    if len(body) > MAX_RESPONSE_BYTES:
        raise AgentError("Avantis Central returned an oversized response.")
    try:
        result = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AgentError("Avantis Central returned invalid JSON.") from error
    if not isinstance(result, dict):
        raise AgentError("Avantis Central returned an invalid response.")
    return result


def enroll_device(enrollment_code: str, device_name: str) -> dict:
    code = enrollment_code.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{30,40}", code):
        raise AgentError("Enter a valid, unused enrollment code from Avantis Central.")
    if not device_name.strip() or len(device_name) > 120:
        raise AgentError("The PC name must be between 1 and 120 characters.")
    response = _api_request(
        "/enroll",
        {
            "code": code,
            "device_name": device_name.strip(),
            "app_version": APP_VERSION,
        },
    )
    device_id = response.get("device_id")
    token = response.get("device_token")
    if (
        not isinstance(device_id, str)
        or not re.fullmatch(r"[a-f0-9]{32}", device_id)
        or not isinstance(token, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{40,100}", token)
    ):
        raise AgentError("Avantis Central returned invalid device credentials.")
    return {
        "device_id": device_id,
        "device_token": token,
        "device_name": device_name.strip(),
        "policy_version": 0,
    }


def validate_policy(document: object) -> tuple[list[str], list[str]]:
    if not isinstance(document, dict):
        raise AgentError("The company policy is not a JSON object.")
    domains = document.get("blocked_domains")
    prefixes = document.get("subdomain_prefixes")
    if not isinstance(domains, list) or not isinstance(prefixes, list):
        raise AgentError("The company policy is missing its domain or subdomain list.")
    if len(domains) > MAX_POLICY_DOMAINS:
        raise AgentError("The company policy exceeds the Windows hosts limit.")

    safe_domains = []
    seen_domains = set()
    for domain in domains:
        if not isinstance(domain, str) or len(domain) > 253 or not DOMAIN_RE.fullmatch(domain):
            raise AgentError("The company policy contains an invalid domain.")
        normalized = domain.lower()
        if app.is_protected_domain(normalized):
            raise AgentError(f"The company policy contains a protected system domain: {normalized}.")
        if normalized not in seen_domains:
            seen_domains.add(normalized)
            safe_domains.append(normalized)

    safe_prefixes = []
    seen_prefixes = set()
    for prefix in prefixes:
        if not isinstance(prefix, str) or not PREFIX_RE.fullmatch(prefix):
            raise AgentError("The company policy contains an invalid subdomain prefix.")
        normalized = prefix.lower()
        if normalized not in seen_prefixes:
            seen_prefixes.add(normalized)
            safe_prefixes.append(normalized)
    return safe_domains, safe_prefixes


def apply_policy(credentials: dict, response: dict) -> dict:
    version = response.get("policy_version")
    if not isinstance(version, int) or version < 0:
        raise AgentError("Avantis Central returned an invalid policy version.")
    policy = response.get("policy")
    if policy is None:
        return credentials
    if version < credentials["policy_version"]:
        raise AgentError("Avantis Central attempted to roll back the company policy version.")
    domains, prefixes = validate_policy(policy)

    app.HOSTS_BACKUP_PATH = SHARED_DATA_DIR / "hosts.avantis.backup"
    try:
        app.write_hosts_file(domains, prefixes)
    except PermissionError as error:
        raise AgentError(
            "Windows denied applying the company policy to the hosts file. "
            "Check Windows permissions or security software, then the agent will retry."
        ) from error
    flushed, flush_error = app.flush_dns_cache()
    if not flushed:
        raise AgentError("The policy was written, but Windows could not refresh its DNS cache.")

    updated = dict(credentials)
    updated["policy_version"] = version
    updated["last_check_in"] = _utc_now()
    updated["blocked_domains"] = domains
    updated["subdomain_prefixes"] = prefixes
    _save_credentials(updated)
    _write_status(
        updated["device_id"],
        updated["device_name"],
        version,
        domains,
        prefixes,
        "active",
        updated["last_check_in"],
        server_policy_version=version,
    )
    _log(f"Applied company policy version {version} ({len(domains)} domains).")
    return updated


def check_in(credentials: dict) -> tuple[dict, dict]:
    status = app.inspect_hosts_rules()
    protection_status = "active" if re.search(r"\d+ Avantis hostnames in \d+ mappings\.", status[0]) else "inactive"
    payload = _api_request(
        "/check-in",
        {
            "app_version": APP_VERSION,
            "applied_policy_version": credentials["policy_version"],
            "protection_status": protection_status,
        },
        credentials["device_token"],
    )
    updated = apply_policy(credentials, payload)
    if payload.get("policy") is None:
        status = app.inspect_hosts_rules()
        protection_status = "active" if re.search(r"\d+ Avantis hostnames in \d+ mappings\.", status[0]) else "inactive"
        last_check_in = _utc_now()
        _write_status(
            updated["device_id"],
            updated["device_name"],
            updated["policy_version"],
            updated.get("blocked_domains", []),
            updated.get("subdomain_prefixes", []),
            protection_status,
            last_check_in,
            server_policy_version=payload.get("policy_version", 0),
        )
        updated["last_check_in"] = last_check_in
        _save_credentials(updated)
        _log(f"Checked in; server policy version {payload.get('policy_version', 0)}.")
    return updated, payload


def _is_administrator() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _set_directory_permissions() -> None:
    SECURE_DATA_DIR.mkdir(parents=True, exist_ok=True)
    commands = [
        (
            "icacls",
            str(SHARED_DATA_DIR),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-32-545:(OI)(CI)(RX)",
        ),
        (
            "icacls",
            str(SECURE_DATA_DIR),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
        ),
    ]
    for command in commands:
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
        except OSError as error:
            raise AgentError(f"Could not set secure Avantis data-folder permissions: {error}") from error
        if result.returncode != 0:
            raise AgentError(f"Windows could not secure the Avantis data folder: {result.stderr.strip()}")


def _service_is_installed() -> bool:
    try:
        win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        return True
    except pywintypes.error:
        return False


def _stop_service_if_running() -> None:
    if not _service_is_installed():
        return
    status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
    if status[1] == win32service.SERVICE_RUNNING:
        win32serviceutil.StopService(SERVICE_NAME)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            current = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
            if current[1] == win32service.SERVICE_STOPPED:
                return
            time.sleep(0.5)
        raise AgentError("The existing Avantis service did not stop in time.")


def install_agent(enrollment_code: str | None) -> None:
    if os.name != "nt" or not _is_administrator():
        raise AgentError("Install Avantis Central from the Windows installer and approve the administrator prompt.")
    _set_directory_permissions()

    credentials = enroll_device(enrollment_code, platform.node()[:120]) if enrollment_code else _read_credentials()
    if credentials is None:
        raise AgentError("Create a one-time enrollment code in Avantis Central, then enter it in the installer.")
    _write_managed_marker(credentials["device_id"], credentials["device_name"])
    _write_status(
        credentials["device_id"],
        credentials["device_name"],
        credentials["policy_version"],
        credentials.get("blocked_domains", []),
        credentials.get("subdomain_prefixes", []),
        "unknown",
        None,
    )
    _save_credentials(credentials)

    _stop_service_if_running()
    if _service_is_installed():
        win32serviceutil.RemoveService(SERVICE_NAME)
    win32serviceutil.InstallService(
        "central_agent.AvantisAgentService",
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        startType=win32service.SERVICE_AUTO_START,
        errorControl=win32service.SERVICE_ERROR_NORMAL,
        exeName=sys.executable,
        exeArgs="--service",
        description="Checks Avantis Central over HTTPS and applies validated company website policies.",
    )
    for recovery_args in (
        [
            "failure",
            SERVICE_NAME,
            "reset=",
            "86400",
            "actions=",
            "restart/60000/restart/60000/restart/60000",
        ],
        ["failureflag", SERVICE_NAME, "flag=", "1"],
    ):
        recovery = subprocess.run(
            ["sc.exe", *recovery_args],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if recovery.returncode != 0:
            detail = (recovery.stderr or recovery.stdout).strip()
            raise AgentError(f"Windows could not configure automatic service recovery: {detail}")
    win32serviceutil.StartService(SERVICE_NAME)


def uninstall_agent() -> None:
    if os.name != "nt" or not _is_administrator():
        raise AgentError("Administrator approval is required to remove the Avantis background service.")
    _stop_service_if_running()
    if _service_is_installed():
        win32serviceutil.RemoveService(SERVICE_NAME)
    app.HOSTS_BACKUP_PATH = SHARED_DATA_DIR / "hosts.avantis.backup"
    app.remove_hosts_rules()
    flushed, flush_error = app.flush_dns_cache()
    if not flushed:
        raise AgentError(f"The service was removed, but Windows could not refresh DNS: {flush_error}")
    for path in (STATUS_FILE, MANAGED_MARKER_FILE):
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            raise AgentError(f"The service was removed, but Avantis could not remove {path.name}: {error}") from error


def stop_agent_service() -> None:
    if os.name != "nt" or not _is_administrator():
        raise AgentError("Administrator approval is required to update the Avantis background service.")
    _stop_service_if_running()


class AvantisAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = "Applies centrally managed Avantis website protection policies."

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        try:
            self._run_agent()
        except BaseException as error:
            _log(f"Service stopped unexpectedly ({type(error).__name__}).")
            raise

    def _run_agent(self):
        credentials = _read_credentials()
        if credentials is None:
            raise AgentError("The device has not been enrolled.")
        _write_managed_marker(credentials["device_id"], credentials["device_name"])
        _log("Avantis Central service started.")
        while True:
            if win32event.WaitForSingleObject(self.stop_event, 0) == win32event.WAIT_OBJECT_0:
                _log("Avantis Central service stopped.")
                return
            try:
                credentials, response = check_in(credentials)
                interval = response.get("check_in_seconds", CHECK_IN_SECONDS)
                if not isinstance(interval, int):
                    interval = CHECK_IN_SECONDS
                wait_seconds = max(30, min(300, interval))
            except (AgentError, OSError) as error:
                _write_status(
                    credentials["device_id"],
                    credentials["device_name"],
                    credentials["policy_version"],
                    credentials.get("blocked_domains", []),
                    credentials.get("subdomain_prefixes", []),
                    "error",
                    credentials.get("last_check_in"),
                    str(error),
                )
                _log(f"Check-in failed ({type(error).__name__}): {error}")
                wait_seconds = CHECK_IN_SECONDS
            if win32event.WaitForSingleObject(self.stop_event, wait_seconds * 1000) == win32event.WAIT_OBJECT_0:
                _log("Avantis Central service stopped.")
                return


def _read_enrollment_file(path: str) -> str:
    enrollment_file = Path(path)
    try:
        code = enrollment_file.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise AgentError("The installer could not read the temporary enrollment code.") from error
    finally:
        try:
            enrollment_file.unlink(missing_ok=True)
        except OSError:
            pass
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Avantis Central Windows service installer.")
    parser.add_argument("--service", action="store_true", help=argparse.SUPPRESS)
    commands = parser.add_mutually_exclusive_group()
    commands.add_argument("--install", action="store_true")
    commands.add_argument("--uninstall", action="store_true")
    commands.add_argument("--stop-service", action="store_true")
    parser.add_argument("--enrollment-code-file")
    args = parser.parse_args(argv)

    if args.service:
        if args.install or args.uninstall or args.stop_service or args.enrollment_code_file:
            parser.error("--service cannot be combined with installer options.")
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(AvantisAgentService)
        servicemanager.StartServiceCtrlDispatcher()
        return 0

    if args.install:
        try:
            enrollment_code = _read_enrollment_file(args.enrollment_code_file) if args.enrollment_code_file else None
            install_agent(enrollment_code)
        except (AgentError, OSError, pywintypes.error) as error:
            print(str(error), file=sys.stderr)
            return 1
        print("Avantis Central service installed and started.")
        return 0
    if args.uninstall:
        try:
            uninstall_agent()
        except (AgentError, OSError, pywintypes.error) as error:
            print(str(error), file=sys.stderr)
            return 1
        print("Avantis Central service removed.")
        return 0
    if args.stop_service:
        try:
            stop_agent_service()
        except (AgentError, OSError, pywintypes.error) as error:
            print(str(error), file=sys.stderr)
            return 1
        print("Avantis Central service stopped.")
        return 0
    parser.error("Choose --install, --uninstall, or the internal --service command.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
