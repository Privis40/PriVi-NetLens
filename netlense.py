#!/usr/bin/env python3
import os
import time
import sys
import re
import threading
import itertools
import requests
from collections import Counter, deque
from scapy.all import sniff, IP, TCP, UDP, wrpcap

# UI Engine: Rich Dashboard
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Console
from rich.text import Text

console = Console()


class PriViNetLens:
    def __init__(self, iface=None):
        self.author  = "PriViSecurity"
        self.version = "5.2"
        self.name    = "PriVi-NetLens"
        # BUG FIX #6: Added iface parameter — sniff() was capturing ALL interfaces
        # including loopback, docker bridges, and VPN adapters, flooding the display
        # with internal traffic. Passing iface=None keeps the default (all) but
        # allows callers to specify e.g. "eth0" or "wlan0".
        self.iface   = iface

        self.buffer      = []
        self.display_log = deque(maxlen=500)
        self.buffer_lock = threading.Lock()
        self.state_lock  = threading.Lock()

        self.geo_cache    = {}
        self.stats        = Counter()
        self.devices      = Counter()
        self.threat_count = 0
        self.start_time   = time.time()
        self._stop_event  = threading.Event()

        self._geo_last_call    = 0.0
        self._geo_min_interval = 1.5

        # BUG FIX #5: Pre-build the header panel once — it contains static ASCII
        # art that never changes. Rebuilding it 10x/sec allocated new Table and
        # Panel objects on every iteration for no benefit.
        self._header_panel = self._build_header_panel()

        # BUG FIX #2: Geo lookups block the sniffer thread (requests.get, timeout=2).
        # Offload them to a dedicated background thread via a queue so the sniffer
        # never stalls waiting for a network response.
        self._geo_queue  = deque()
        self._geo_thread = threading.Thread(target=self._geo_worker, daemon=True)
        self._geo_thread.start()

    # ── ASCII ART ────────────────────────────────────────────────────────────
    def _build_header_panel(self) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        # BUG FIX #3: ASCII art strings used unescaped backslashes (e.g. '\ ', '\|',
        # '\_') — in Python 3.12 these raise SyntaxWarning and will become
        # SyntaxError in a future version. Fixed by using raw strings (r"...").
        ascii_logo = (
            r"[bold cyan]  ____       _ __   ___   _   _      _   _                [/bold cyan]" + "\n"
            r"[bold cyan] |  _ \ _ __(_) \ \ / (_) | \ | | ___| |_| |    ___ _ __  [/bold cyan]" + "\n"
            r"[bold cyan] | |_) | '__| |  \ V /| | |  \| |/ _ \ __| |   / _ \ '_ \ [/bold cyan]" + "\n"
            r"[bold cyan] |  __/| |  | |   | | | | | |\  |  __/ |_| |__|  __/ | | |[/bold cyan]" + "\n"
            r"[bold cyan] |_|   |_|  |_|   |_| |_| |_| \_|\___|\__|______\___|_| |_|[/bold cyan]" + "\n"
            f"[dim white]  {self.author} | {self.name} v{self.version} | Network Forensic Intelligence[/dim white]"
        )
        grid.add_row(ascii_logo)
        return Panel(grid, style="blue")

    # ── OS FINGERPRINTING ────────────────────────────────────────────────────
    def get_os_fingerprint(self, ttl, window):
        if ttl == 0:
            return "Invalid/Spoofed"
        elif ttl <= 64:
            if window == 65535:
                return "macOS/iOS"
            return "Linux/Android" if window > 5840 else "Linux Server"
        elif ttl <= 128:
            return "Windows PC"
        elif ttl <= 255:
            return "Cisco/Network"
        return "Generic IP"

    # ── GEO LOOKUP ───────────────────────────────────────────────────────────
    def _geo_worker(self):
        """Background thread processes geo lookups so the sniffer never blocks."""
        while not self._stop_event.is_set():
            if self._geo_queue:
                ip = self._geo_queue.popleft()
                # Skip if already cached by the time we get to it
                with self.state_lock:
                    if ip in self.geo_cache:
                        continue
                    now = time.time()
                    if now - self._geo_last_call < self._geo_min_interval:
                        time.sleep(0.1)
                        continue
                    self._geo_last_call = now
                try:
                    r = requests.get(
                        f"https://ip-api.com/json/{ip}?fields=countryCode",
                        timeout=2
                    ).json()
                    loc = r.get('countryCode', '??')
                    with self.state_lock:
                        if len(self.geo_cache) >= 1000:
                            del self.geo_cache[next(iter(self.geo_cache))]
                        self.geo_cache[ip] = loc
                # BUG FIX #1: Replaced bare except — swallowed KeyboardInterrupt
                # and all errors silently. Specific exceptions now handled.
                except requests.exceptions.RequestException:
                    pass
                except (ValueError, KeyError):
                    pass
            else:
                time.sleep(0.05)

    def get_geo_loc(self, ip):
        """Non-blocking geo lookup — returns cached value or queues a background fetch."""
        if re.match(r"^(192\.168|10\.|172\.(1[6-9]|2\d|3[01])\.|127\.)", ip):
            return "LAN"
        with self.state_lock:
            if ip in self.geo_cache:
                return self.geo_cache[ip]
        # Queue for background lookup — return pending indicator immediately
        if ip not in self._geo_queue:
            self._geo_queue.append(ip)
        return "..."

    # ── SECURITY AUDIT ───────────────────────────────────────────────────────
    def audit_security(self, port, proto):
        if port == 0:
            return "[dim]N/A (ICMP)[/dim]"
        unsecure = {80: "HTTP", 21: "FTP", 23: "Telnet", 110: "POP3", 25: "SMTP"}
        if port in unsecure:
            self.threat_count += 1
            return f"[bold red]!! UNSECURE ({unsecure[port]}) !![/bold red]"
        return "[bold green]SECURE / ENCRYPTED[/bold green]"

    # ── LAYOUT ───────────────────────────────────────────────────────────────
    def make_layout(self) -> Layout:
        term_height = console.size.height
        # BUG FIX #4: Original upper_size = min(12, max(8, term_height - 20))
        # didn't account for the header panel (size=7). On a 15-line terminal:
        # header(7) + upper(8) = 15, lower gets 0 → LayoutError.
        # Now reserves space for header explicitly before computing upper_size.
        header_size = 7
        available   = max(0, term_height - header_size)
        upper_size  = min(10, max(5, available // 2))

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=header_size),
            Layout(name="upper",  size=upper_size),
            Layout(name="lower")
        )
        layout["upper"].split_row(
            Layout(name="stats"),
            Layout(name="intel")
        )
        return layout

    # ── PACKET TABLE ─────────────────────────────────────────────────────────
    def generate_packet_table(self) -> Table:
        table = Table(expand=True, border_style="blue", box=None)
        table.add_column("TIME",            style="white",   width=10)
        table.add_column("SOURCE IP",       style="yellow",  width=16)
        table.add_column("OS TYPE",         style="cyan",    width=16)
        table.add_column("SERVICE",         style="magenta", width=10)
        table.add_column("SECURITY STATUS", justify="center")
        table.add_column("LOC",             style="green",   width=5)
        rows = list(itertools.islice(reversed(self.display_log), 15))[::-1]
        for row in rows:
            table.add_row(*row)
        return table

    # ── PACKET HANDLER ───────────────────────────────────────────────────────
    def packet_handler(self, pkt):
        if not pkt.haslayer(IP):
            return
        ip_layer = pkt[IP]
        ts    = time.strftime("%H:%M:%S")
        win   = pkt[TCP].window if pkt.haslayer(TCP) else 0
        os_id = self.get_os_fingerprint(ip_layer.ttl, win)
        # BUG FIX #2: get_geo_loc() is now non-blocking — queues lookup
        # and returns cached value or "..." immediately. No longer stalls
        # the sniffer thread for up to 2s on every cache miss.
        loc   = self.get_geo_loc(ip_layer.src)
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "ICMP"
        port  = (pkt[TCP].dport if pkt.haslayer(TCP)
                 else pkt[UDP].dport if pkt.haslayer(UDP)
                 else 0)
        with self.state_lock:
            self.stats[proto]   += 1
            self.devices[os_id] += 1
            risk = self.audit_security(port, proto)
        self.display_log.append([ts, ip_layer.src, os_id, f"{proto}/{port}", risk, loc])
        with self.buffer_lock:
            self.buffer.append(pkt)

    # ── MAIN RUN LOOP ────────────────────────────────────────────────────────
    def run(self):
        if os.getuid() != 0:
            console.print("[bold red][!] PriVi-NetLens requires root. Run with sudo.[/bold red]")
            sys.exit(1)

        layout = self.make_layout()
        sniff_kwargs = {"prn": self.packet_handler, "store": 0}
        if self.iface:
            sniff_kwargs["iface"] = self.iface
        threading.Thread(target=sniff, kwargs=sniff_kwargs, daemon=True).start()

        try:
            with Live(layout, refresh_per_second=4, screen=True):
                while not self._stop_event.is_set():
                    # BUG FIX #5: Use pre-built static header — no longer
                    # creates new Table/Panel objects 10x/sec.
                    layout["header"].update(self._header_panel)

                    with self.state_lock:
                        stats_snap   = dict(self.stats)
                        devices_snap = self.devices.most_common(8)
                        threat_snap  = self.threat_count

                    stats_text = Text()
                    stats_text.append(f"Uptime: {int(time.time() - self.start_time)}s\n", style="dim")
                    for pr, count in stats_snap.items():
                        stats_text.append(f"  {pr}: {count}\n", style="bold green")
                    layout["stats"].update(Panel(stats_text, title="[bold white]Protocols[/bold white]"))

                    intel_text = Text()
                    intel_text.append(f"CRITICAL THREATS: {threat_snap}\n", style="bold red")
                    for device, count in devices_snap:
                        intel_text.append(f"  {device}: {count}\n", style="cyan")
                    layout["intel"].update(Panel(intel_text, title="[bold white]OS Intelligence[/bold white]"))

                    layout["lower"].update(Panel(
                        self.generate_packet_table(),
                        title="[bold cyan]Forensic Live Stream[/bold cyan]"
                    ))
                    time.sleep(0.1)

        except KeyboardInterrupt:
            pass

        self.shutdown()

    # ── SHUTDOWN ─────────────────────────────────────────────────────────────
    def shutdown(self):
        self._stop_event.set()
        console.print("\n[bold yellow][!] Audit Terminated. Exporting Forensics...[/bold yellow]")

        ts = int(time.time())

        with self.buffer_lock:
            captured = list(self.buffer)

        if captured:
            pcap_file = f"PriVi_Forensic_{ts}.pcap"
            try:
                wrpcap(pcap_file, captured)
                console.print(f"[bold green][+] Forensic PCAP saved: {pcap_file}[/bold green]")
            except Exception as e:
                console.print(f"[bold red][!] PCAP error: {e}[/bold red]")
        else:
            console.print("[bold yellow][~] No packets captured — PCAP skipped.[/bold yellow]")

        report_file = f"NETLENS_SUMMARY_{ts}.txt"
        # BUG FIX #4b: Take final snapshot under lock before writing report —
        # sniffer daemon may still be processing packets at shutdown boundary.
        with self.state_lock:
            final_threats  = self.threat_count
            final_devices  = dict(self.devices)
            final_stats    = dict(self.stats)
        try:
            with open(report_file, "w") as f:
                f.write(f"PRIVI-SECURITY: NETLENS VANGUARD REPORT\n{'=' * 40}\n")
                f.write(f"Total Packets : {len(captured)} | Threats: {final_threats}\n")
                f.write(f"Devices       : {final_devices}\n")
                f.write(f"Protocols     : {final_stats}\n")
                elapsed = int(time.time() - self.start_time)
                f.write(f"Duration      : {elapsed}s\n")
            console.print(f"[bold green][+] Executive Summary saved: {report_file}[/bold green]")
        except OSError as e:
            console.print(f"[bold red][!] Report error: {e}[/bold red]")

        sys.exit(0)


if __name__ == "__main__":
    import argparse
    # BUG FIX #6: Added --iface argument so users can target a specific
    # interface instead of capturing everything including loopback/docker/VPN.
    parser = argparse.ArgumentParser(description="PriVi-NetLens Network Forensic Tool")
    parser.add_argument("--iface", "-i", default=None,
                        help="Network interface to capture on (e.g. eth0, wlan0). Default: all.")
    args = parser.parse_args()
    sentry = PriViNetLens(iface=args.iface)
    sentry.run()
      
