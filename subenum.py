import os
import random
import shutil
import signal
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

import requests

TARGETS = os.getenv("TARGETS")
SCHEDULE = os.getenv("SCHEDULE", "00:00,08:00,16:00")
GITHUB_ACCESS_TOKEN = os.getenv("GITHUB_ACCESS_TOKEN")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
DEAD_DOMAIN_DAYS = int(os.getenv("DEAD_DOMAIN_DAYS", "30"))
CHAOS_API_KEY = os.getenv("CHAOS_API_KEY")

current_log_file = None
banner_printed = False
shutdown_requested = False


def signal_handler(sig, frame):
    global shutdown_requested
    shutdown_requested = True
    log("[warning] Shutdown requested, finishing current operation...")


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def print_banner():
    global banner_printed
    if not banner_printed:
        print(
            r"""
           _
 ___ _   _| |__   ___ _ __  _   _ _ __ ___
/ __| | | | '_ \ / _ \ '_ \| | | | '_ ` _ \
\__ \ |_| | |_) |  __/ | | | |_| | | | | | |
|___/\__,_|_.__/ \___|_| |_|\__,_|_| |_| |_|
"""
        )
        banner_printed = True


def log(message):
    timestamp = f"[{datetime.now():%H:%M:%S}]"
    full_message = f"{timestamp} {message}"
    print(full_message)
    if current_log_file:
        try:
            with open(current_log_file, "a") as f:
                f.write(full_message + "\n")
        except Exception as e:
            print(f"[error] Failed to write log: {e}")


def run_cmd(cmd, timeout=None):
    try:
        return subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
        ).stdout
    except subprocess.CalledProcessError as e:
        raise Exception(f"Command failed with code {e.returncode}")
    except subprocess.TimeoutExpired:
        raise Exception("Command timed out")


def validate_environment():
    required = {
        "TARGETS": TARGETS,
        "DISCORD_WEBHOOK_URL": DISCORD_WEBHOOK_URL,
        "GITHUB_ACCESS_TOKEN": GITHUB_ACCESS_TOKEN,
    }

    missing = [k for k, v in required.items() if not v]
    if missing:
        log(f"[error] Missing required environment variables: {', '.join(missing)}")
        raise SystemExit(1)

    if not CHAOS_API_KEY:
        log("[warning] CHAOS_API_KEY not set, chaos will be skipped")


def fetch_targets():
    try:
        response = requests.get(TARGETS, timeout=30)
        response.raise_for_status()
        targets = [t.strip() for t in response.text.strip().split("\n") if t.strip()]
        log(f"[info] Loaded {len(targets)} target/s")
        return targets
    except Exception as e:
        log(f"[error] Failed to fetch targets: {e}")
        raise


def enumerate_subdomains(targets):
    targets_file = "/tmp/all_targets.txt"
    with open(targets_file, "w") as f:
        f.write("\n".join(targets))

    commands = {
        "subfinder": [
            "subfinder",
            "-silent",
            "-dL",
            targets_file,
            "-sources",
            "virustotal,bevigil,builtwith,certspotter,chaos,cloudflare,digitalyama,dnsdumpster,shodan,netlas,urlscan,github,zoomeyeapi,anubis,commoncrawl,crtsh,digitorus,hackertarget,quake,sitedossier,threatcrowd,waybackarchive,hudsonrock",
            "-pc",
            "provider-config.yaml",
        ],
        "assetfinder": ["assetfinder", "-subs-only"],
        "findomain": ["findomain", "-f", targets_file, "--quiet"],
    }

    if CHAOS_API_KEY:
        commands["chaos"] = [
            "chaos",
            "-silent",
            "-key",
            CHAOS_API_KEY,
            "-dL",
            targets_file,
        ]

    all_domains = set()

    def run_tool(tool, cmd):
        try:
            if tool == "assetfinder":
                with open(targets_file, "r") as f:
                    result = subprocess.run(
                        cmd, stdin=f, capture_output=True, text=True, timeout=3600
                    )
                output = result.stdout
            else:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=3600
                )
                output = result.stdout

            domains = [d.lstrip("*.") for d in output.strip().split("\n") if d]
            return tool, domains
        except FileNotFoundError:
            return tool, f"Tool not found"
        except subprocess.TimeoutExpired:
            return tool, f"Timeout"
        except Exception as e:
            return tool, str(e)

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(run_tool, tool, cmd): tool for tool, cmd in commands.items()
        }

        for future in as_completed(futures):
            tool, result = future.result()
            if isinstance(result, list):
                all_domains.update(result)
                log(f"[{tool.lower()}] Found {len(result)} subdomains")
            else:
                log(f"[{tool.lower()}] {result}")

    os.remove(targets_file)
    log(f"[info] Total subdomains: {len(all_domains)}")
    return all_domains


def dns_filter(domains):
    if not domains:
        return set()
    temp_file = "/tmp/dnsx_input.txt"
    with open(temp_file, "w") as f:
        f.write("\n".join(domains))
    try:
        result = subprocess.run(
            ["dnsx", "-l", temp_file, "-silent", "-retry", "2", "-t", "100"],
            capture_output=True,
            text=True,
            timeout=3600,
        )
        resolved = {line.strip() for line in result.stdout.strip().split("\n") if line}
        os.remove(temp_file)
        return resolved
    except FileNotFoundError:
        log("[dnsx] Tool not found, skipping DNS resolution")
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return domains
    except Exception as e:
        log(f"[dnsx] {str(e)}")
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return domains


def batched_httpx_probe(domains, batch_size=1000, rate_limit=15):
    if not domains:
        return {}
    domain_list = sorted(domains)
    all_resolved = {}
    total_batches = (len(domain_list) + batch_size - 1) // batch_size

    session = requests.Session()

    for i in range(0, len(domain_list), batch_size):
        if shutdown_requested:
            log("[httpx] Stopping due to shutdown request")
            break

        batch = domain_list[i : i + batch_size]
        batch_num = (i // batch_size) + 1
        log(
            f"[httpx] Processing batch {batch_num}/{total_batches} ({len(batch)} hosts)"
        )
        batch_file = f"/tmp/httpx_batch_{batch_num}.txt"
        with open(batch_file, "w") as f:
            f.write("\n".join(batch))
        try:
            result = subprocess.run(
                [
                    "httpx",
                    "-l",
                    batch_file,
                    "-silent",
                    "-nc",
                    "-rate-limit",
                    str(rate_limit),
                    "-timeout",
                    "10",
                    "-retries",
                    "2",
                ],
                capture_output=True,
                text=True,
                timeout=3600,
            )
            for line in result.stdout.strip().split("\n"):
                if line:
                    clean = (
                        line.replace("https://", "")
                        .replace("http://", "")
                        .split("/")[0]
                        .split(":")[0]
                    )
                    all_resolved[clean] = line.strip()
        except Exception as e:
            log(f"[httpx] Batch {batch_num} failed: {str(e)}")
        finally:
            if os.path.exists(batch_file):
                os.remove(batch_file)

    return all_resolved


def probe_domains(domains):
    log(f"[dnsx] Resolving {len(domains)} subdomains...")
    resolved_dns = dns_filter(domains)
    log(f"[dnsx] Found {len(resolved_dns)} hosts resolved!")
    if not resolved_dns:
        return {}
    log(f"[httpx] Probing {len(resolved_dns)} hosts...")
    resolved_http = batched_httpx_probe(resolved_dns)
    log(f"[httpx] Found {len(resolved_http)} responsive hosts!")
    return resolved_http


def load_master_list():
    filepath = "output/subdomains-all.txt"
    if os.path.exists(filepath):
        try:
            with open(filepath) as f:
                return {d.strip() for d in f.read().splitlines() if d.strip()}
        except Exception as e:
            log(f"[error] Failed to load master list: {e}")
            return set()
    return set()


def save_master_list(domains):
    os.makedirs("output", exist_ok=True)
    filepath = "output/subdomains-all.txt"
    temp_filepath = f"{filepath}.tmp"

    try:
        with open(temp_filepath, "w") as f:
            f.write("\n".join(sorted(domains)))
        os.replace(temp_filepath, filepath)

        backup_filepath = "output/subdomains-all.bak"
        if os.path.exists(filepath):
            shutil.copy2(filepath, backup_filepath)
    except Exception as e:
        log(f"[error] Failed to save master list: {e}")
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        raise


def load_dead_domains():
    filepath = "output/subdomains-dead.txt"
    if os.path.exists(filepath):
        try:
            dead_domains = {}
            with open(filepath) as f:
                for line in f:
                    if not line.strip():
                        continue
                    parts = line.strip().split("|")
                    if len(parts) == 2:
                        domain, died_at = parts
                        dead_domains[domain] = datetime.fromisoformat(died_at)
                    else:
                        dead_domains[parts[0]] = datetime.now()
            return dead_domains
        except Exception as e:
            log(f"[error] Failed to load dead subdomains: {e}")
            return {}
    return {}


def save_dead_domains(domains_dict):
    os.makedirs("output", exist_ok=True)
    filepath = "output/subdomains-dead.txt"
    temp_filepath = f"{filepath}.tmp"

    try:
        with open(temp_filepath, "w") as f:
            for domain in sorted(domains_dict.keys()):
                died_at = domains_dict[domain].isoformat()
                f.write(f"{domain}|{died_at}\n")
        os.replace(temp_filepath, filepath)

        backup_filepath = "output/subdomains-dead.bak"
        if os.path.exists(filepath):
            shutil.copy2(filepath, backup_filepath)
    except Exception as e:
        log(f"[error] Failed to save dead subdomains: {e}")
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        raise


def get_domains_to_resurrect(dead_domains):
    now = datetime.now()
    cutoff = now - timedelta(days=DEAD_DOMAIN_DAYS)

    recent_dead = {d: age for d, age in dead_domains.items() if age >= cutoff}
    old_dead = {d: age for d, age in dead_domains.items() if age < cutoff}

    to_check = set(recent_dead.keys())

    if old_dead:
        sample_size = max(1, len(old_dead) // 5)
        sampled_old = random.sample(
            list(old_dead.keys()), k=min(sample_size, len(old_dead))
        )
        to_check.update(sampled_old)
        log(
            f"[info] Checking {len(recent_dead)} recent, {len(sampled_old)} dead subdomains"
        )

    return to_check


def upload_to_gist(content, filename, retries=3, backoff=5):
    if not GITHUB_ACCESS_TOKEN:
        log("[warning] GitHub token not configured, skipping upload")
        return None

    content_size = len(content.encode("utf-8"))

    payload = {
        "files": {filename: {"content": content}},
        "public": False,
        "description": f"Subdomain scan results - {filename}",
    }

    for attempt in range(retries):
        try:
            if attempt > 0:
                log(f"[gist] Retry {attempt}/{retries-1}...")
            else:
                log(f"[gist] Uploading {filename} ({content_size} bytes)...")

            response = requests.post(
                "https://api.github.com/gists",
                headers={
                    "Authorization": f"Bearer {GITHUB_ACCESS_TOKEN}",
                    "Accept": "application/vnd.github.v3+json",
                },
                json=payload,
                timeout=30,
            )

            if response.status_code == 201:
                data = response.json()
                url = data["html_url"]
                log(f"[gist] {url}")
                return url
            else:
                log(f"[gist] Upload failed: status {response.status_code}")

        except Exception as e:
            log(f"[gist] {str(e)}")

        if attempt < retries - 1:
            time.sleep(backoff * (attempt + 1))

    return None


def send_notification(new_domains, resolved_domains, timestamp, domains_file, log_file):
    logs_content = None
    try:
        with open(log_file, "r") as f:
            logs_content = f.read()
    except Exception as e:
        log(f"[warning] Could not read log file: {e}")

    log("[info] Preparing notification...")

    resolved = [resolved_domains[d] for d in new_domains if d in resolved_domains]
    unresolved = [d for d in new_domains if d not in resolved_domains]

    total_resolved = len(resolved)
    total_unresolved = len(unresolved)

    resolved_display = resolved[:15]
    unresolved_display = unresolved[:10]

    display = []
    for url in resolved_display:
        display.append(f"✅ {url}")
    for d in unresolved_display:
        display.append(f"❌ {d}")

    remaining_resolved = total_resolved - len(resolved_display)
    remaining_unresolved = total_unresolved - len(unresolved_display)

    domains_text = "\n".join(display)

    if remaining_resolved > 0 or remaining_unresolved > 0:
        remaining_parts = []
        if remaining_resolved > 0:
            remaining_parts.append(f"{remaining_resolved} more resolved")
        if remaining_unresolved > 0:
            remaining_parts.append(f"{remaining_unresolved} more unresolved")
        domains_text += f"\n\n... and {', '.join(remaining_parts)}"

    if len(domains_text) > 1000:
        domains_text = domains_text[:997] + "..."

    try:
        with open(domains_file) as f:
            gist_url = upload_to_gist(f.read(), os.path.basename(domains_file))
    except Exception as e:
        log(f"[error] Failed to read subdomains file: {e}")
        gist_url = None

    time.sleep(2)
    logs_gist_url = (
        upload_to_gist(logs_content, os.path.basename(log_file))
        if logs_content
        else None
    )

    fields = [
        {"name": "📊 Total", "value": str(len(new_domains)), "inline": True},
        {"name": "✅ Resolved", "value": str(total_resolved), "inline": True},
        {"name": "❌ Unresolved", "value": str(total_unresolved), "inline": True},
        {"name": "📅 Time", "value": timestamp, "inline": True},
    ]
    if gist_url:
        fields.append(
            {"name": "🔎 Results", "value": f"[View]({gist_url})", "inline": True}
        )
    if logs_gist_url:
        fields.append(
            {"name": "📝 Logs", "value": f"[View]({logs_gist_url})", "inline": True}
        )
    fields.append(
        {"name": "🌐 Domains", "value": f"```\n{domains_text}\n```", "inline": False}
    )

    payload = {
        "embeds": [
            {
                "title": "🔍 SUBENUM SCAN RESULTS",
                "color": 5814783,
                "fields": fields,
                "footer": {"text": "⚡ Subenum"},
            }
        ]
    }

    for attempt in range(3):
        try:
            requests.post(
                DISCORD_WEBHOOK_URL, json=payload, timeout=30
            ).raise_for_status()
            log("[discord] Notification sent!")
            return
        except Exception as e:
            log(f"[discord] {str(e)}")
            if attempt < 2:
                time.sleep(5)


def get_next_run():
    times = [t.strip() for t in SCHEDULE.split(",")]
    now = datetime.now()
    today = now.date()
    candidates = []
    for t in times:
        h, m = map(int, t.split(":"))
        dt = datetime(today.year, today.month, today.day, h, m)
        if dt > now:
            candidates.append(dt)
    if not candidates:
        h, m = map(int, times[0].split(":"))
        next_dt = datetime(today.year, today.month, today.day + 1, h, m)
    else:
        next_dt = min(candidates)
    delta = next_dt - now
    hours = int(delta.total_seconds() // 3600)
    minutes = int((delta.total_seconds() % 3600) // 60)
    return next_dt.strftime("%H:%M"), hours, minutes


def print_schedule():
    next_time, h, m = get_next_run()
    log("=" * 60)
    log(f"[info] Scan schedule: {SCHEDULE}")
    log(f"[info] Next scan at {next_time} ({h}h {m}m remaining)")
    log("=" * 60)


def run_full_scan():
    global current_log_file
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    domains_file = f"output/{timestamp}_subdomains.txt"
    current_log_file = f"output/{timestamp}_logs.txt"

    log(f"[info] Starting subdomain enumeration...")

    start = time.time()

    try:
        targets = fetch_targets()
        all_domains = enumerate_subdomains(targets)
    except Exception as e:
        log(f"[error] Enumeration failed: {e}")
        current_log_file = None
        return

    if shutdown_requested:
        log("[info] Scan interrupted")
        current_log_file = None
        return

    master_list = load_master_list()
    new_domains = all_domains - master_list

    if new_domains:
        log(f"[info] Found {len(new_domains)} new subdomains!")

    resolved_domains = {}
    if new_domains:
        resolved_domains = probe_domains(new_domains)

    unresponsive = new_domains - set(resolved_domains.keys())

    dead_list = load_dead_domains()

    revived = set()
    domains_to_resurrect = get_domains_to_resurrect(dead_list)

    if domains_to_resurrect:
        log(f"[info] Checking {len(domains_to_resurrect)} dead subdomains...")
        revived_check = probe_domains(domains_to_resurrect)
        revived = set(revived_check.keys())
        if revived:
            log(f"[info] {len(revived)} subdomains alive!")
            new_domains.update(revived)
            resolved_domains.update({d: revived_check[d] for d in revived})
            for domain in revived:
                del dead_list[domain]

    if unresponsive:
        now = datetime.now()
        for domain in unresponsive:
            dead_list[domain] = now

    try:
        if new_domains or revived or unresponsive:
            master_list.update(new_domains)
            save_master_list(master_list)
            save_dead_domains(dead_list)

        if new_domains:
            with open(domains_file, "w") as f:
                f.write("\n".join(sorted(new_domains)))

            elapsed = (time.time() - start) / 60
            log(f"[info] Scan completed in {elapsed:.2f} minutes")

            time.sleep(30)
            send_notification(
                sorted(new_domains),
                resolved_domains,
                timestamp.replace("_", " "),
                domains_file,
                current_log_file,
            )
        else:
            log("[info] No new subdomains discovered!")
    except Exception as e:
        log(f"[error] Failed to save results: {e}")

    current_log_file = None
    if not shutdown_requested:
        print_schedule()


def main():
    print_banner()

    try:
        validate_environment()
    except SystemExit:
        return

    print_schedule()

    times = [t.strip() for t in SCHEDULE.split(",")]
    while not shutdown_requested:
        now_str = datetime.now().strftime("%H:%M")
        if now_str in times:
            run_full_scan()
            time.sleep(70)
        time.sleep(25)

    log("[info] Shutdown complete")


if __name__ == "__main__":
    main()
