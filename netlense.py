#!/usr/bin/env python3
"""
🛡️ PriVi-NetLens v5.3 — Network Forensic Intelligence Dashboard
Developed by Prince Ubebe | PriViSecurity
"""

import os
import sys
import re
import time
import json
import threading
import itertools
import argparse
import requests
from collections import Counter, deque, defaultdict, OrderedDict

from scapy.all import sniff, IP, TCP, UDP, ARP, DNS, DNSQR, wrpcap

from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Console
from rich.text import Text

console = Console()


# ── CONSTANTS ─────────────────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD   = 10          # distinct ports within window → port scan
PORT_SCAN_WINDOW      = 30          # seconds
STANDARD_DNS_PORT     = 53
NON_STANDARD_DNS_WARN = True        # flag DNS on ports other than 53
GEO_CACHE_MAX         = 1000
GEO_RATE_LIMIT        = 1.5        # seconds between ip-api calls
UNSECURE_PORTS        = {80: "HTTP", 21: "FTP", 23: "Telnet", 110: "POP3", 25: "SMTP"}


class PriViNetLens:
    def __init__(self, iface=None, bpf_filter=None, no_geo=False):
        self.author     = "PriViSecurity"
        self.version    = "5.3"
        self.name       = "PriVi-NetLens"
        self.iface      = iface
        self.bpf_filter = bpf_filter
        self.no_geo     = no_geo

        # ── Locks ────────────────────────────────────────────────────────────
        self.buffer_lock = threading.Lock()
        self.state_lock  = threading.Lock()

        # ── Packet buffer & display ──────────────────────────────────────────
        self.buffer       = []          # all captured packets
        self.threat_pkts  = []          # threat-only packets for second PCAP
        self.display_log  = deque(maxlen=500)
        self.threat_feed  = deque(maxlen=100)

        # ── Stats ────────────────────────────────────────────────────────────
        self.stats        = Counter()
        self.devices      = Counter()
        self.threat_count = 0
        self.start_time   = time.time()
        self._stop_event  = threading.Event()

        # ── Packet rate (rolling 5s window) ──────────────────────────────────
        self._pkt_times   = deque()     # timestamps of recent packets
        self._pkt_rate    = 0.0

        # ── Port scan tracker ────────────────────────────────────────────────
        # { src_ip: deque of (timestamp, dst_port) }
        self._scan_tracker   = defaultdict(deque)
        self._scan_alerted   = set()    # IPs already flagged to avoid spam

        # ── ARP spoof tracker ────────────────────────────────────────────────
        # { ip: set of MACs seen }
        self._arp_map        = defaultdict(set)
        self._arp_alerted    = set()

        # ── Geo lookup ───────────────────────────────────────────────────────
        self.geo_cache       = OrderedDict()   # FIX: true LRU via OrderedDict
        self._geo_queue      = deque()
        self._geo_pending    = set()           # FIX: O(1) membership check
        self._geo_last_call  = 0.0
        self._geo_thread     = threading.Thread(target=self._geo_worker, daemon=True)
        if not self.no_geo:
            self._geo_thread.start()

        # ── Pre-built static header ──────────────────────────────────────────
        self._header_panel = self._build_header_panel()

        # ── Pre-build layout once ────────────────────────────────────────────
        self._layout = self._make_layout()

    # ── ASCII HEADER ──────────────────────────────────────────────────────────
    def _build_header_panel(self) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
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

    # ── OS FINGERPRINT ────────────────────────────────────────────────────────
    def get_os_fingerprint(self, ttl, window):
        if ttl == 0:
            return "Invalid/Spoofed"
        elif ttl <= 64:
            return "macOS/iOS" if window == 65535 else ("Linux/Android" if window > 5840 else "Linux Server")
        elif ttl <= 128:
            return "Windows PC"
        elif ttl <= 255:
            return "Cisco/Network"
        return "Generic IP"

    # ── GEO LOOKUP ───────────────────────────────────────────────────────────
    def _geo_worker(self):
        """Background thread — processes geo lookups so sniffer never blocks."""
        while not self._stop_event.is_set():
            if self._geo_queue:
                # FIX: guard popleft with try/except to handle race condition
                try:
                    ip = self._geo_queue.popleft()
                except IndexError:
                    time.sleep(0.05)
                    continue

                with self.state_lock:
                    if ip in self.geo_cache:
                        self._geo_pending.discard(ip)
                        continue
                    now = time.time()
                    if now - self._geo_last_call < GEO_RATE_LIMIT:
                        # put it back and wait
                        self._geo_queue.appendleft(ip)
                        time.sleep(0.1)
                        continue
                    self._geo_last_call = now

                try:
                    r = requests.get(
                        f"https://ip-api.com/json/{ip}?fields=countryCode",
                        timeout=2
                    ).json()
                    loc = r.get("countryCode", "??")
                    with self.state_lock:
                        if len(self.geo_cache) >= GEO_CACHE_MAX:
                            self.geo_cache.popitem(last=False)   # LRU evict oldest
                        self.geo_cache[ip] = loc
                        self._geo_pending.discard(ip)
                except requests.exceptions.RequestException:
                    with self.state_lock:
                        self._geo_pending.discard(ip)
                except (ValueError, KeyError):
                    with self.state_lock:
                        self._geo_pending.discard(ip)
            else:
                time.sleep(0.05)

    def get_geo_loc(self, ip):
        """Non-blocking — returns cached value or queues background fetch."""
        if self.no_geo:
            return "OFF"
        if re.match(r"^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|127\.)", ip):
            return "LAN"
        with self.state_lock:
            if ip in self.geo_cache:
                # FIX: move to end for LRU freshness
                self.geo_cache.move_to_end(ip)
                return self.geo_cache[ip]
            # FIX: O(1) check via set instead of O(n) deque scan
            if ip not in self._geo_pending:
                self._geo_pending.add(ip)
                self._geo_queue.append(ip)
        return "..."

    # ── PORT SCAN DETECTION ───────────────────────────────────────────────────
    def check_port_scan(self, src_ip, dst_port, pkt):
        """Track distinct ports per source IP within a rolling window."""
        now = time.time()
        with self.state_lock:
            tracker = self._scan_tracker[src_ip]
            # Purge entries outside the rolling window
            while tracker and now - tracker[0][0] > PORT_SCAN_WINDOW:
                tracker.popleft()
            tracker.append((now, dst_port))
            # Count distinct ports in window
            distinct_ports = len({entry[1] for entry in tracker})
            if distinct_ports >= PORT_SCAN_THRESHOLD and src_ip not in self._scan_alerted:
                self._scan_alerted.add(src_ip)
                self.threat_count += 1
                msg = f"[bold red]!! PORT SCAN: {src_ip} — {distinct_ports} ports/{PORT_SCAN_WINDOW}s !![/bold red]"
                self.threat_feed.append((time.strftime("%H:%M:%S"), msg))
                with self.buffer_lock:
                    self.threat_pkts.append(pkt)

    # ── ARP SPOOF DETECTION ───────────────────────────────────────────────────
    def check_arp_spoof(self, pkt):
        """Flag IPs that appear with multiple MAC addresses."""
        if not pkt.haslayer(ARP):
            return
        arp = pkt[ARP]
        ip  = arp.psrc
        mac = arp.hwsrc
        if not ip or ip == "0.0.0.0":
            return
        with self.state_lock:
            self._arp_map[ip].add(mac)
            if len(self._arp_map[ip]) > 1 and ip not in self._arp_alerted:
                self._arp_alerted.add(ip)
                self.threat_count += 1
                macs = ", ".join(self._arp_map[ip])
                msg = f"[bold red]!! ARP SPOOF: {ip} → MACs: {macs} !![/bold red]"
                self.threat_feed.append((time.strftime("%H:%M:%S"), msg))
                with self.buffer_lock:
                    self.threat_pkts.append(pkt)

    # ── DNS ANOMALY DETECTION ─────────────────────────────────────────────────
    def check_dns_anomaly(self, pkt, port, proto):
        """Flag DNS traffic on non-standard ports."""
        if not NON_STANDARD_DNS_WARN:
            return
        if not pkt.haslayer(DNS):
            return
        if port != STANDARD_DNS_PORT and port != 0:
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            with self.state_lock:
                self.threat_count += 1
            msg = f"[bold yellow]!! DNS on non-std port {port} from {src} !![/bold yellow]"
            self.threat_feed.append((time.strftime("%H:%M:%S"), msg))
            with self.buffer_lock:
                self.threat_pkts.append(pkt)

    # ── SECURITY AUDIT ────────────────────────────────────────────────────────
    def audit_security(self, port, proto):
        """Returns a Rich-markup security status string."""
        if port == 0:
            return "[dim]N/A (ICMP)[/dim]"
        if port in UNSECURE_PORTS:
            # FIX: threat_count increment moved here under state_lock in packet_handler
            return f"[bold red]!! UNSECURE ({UNSECURE_PORTS[port]}) !![/bold red]"
        return "[bold green]SECURE / ENCRYPTED[/bold green]"

    # ── PACKET RATE ───────────────────────────────────────────────────────────
    def _update_pkt_rate(self):
        """Maintain a rolling 5-second packet rate counter."""
        now = time.time()
        self._pkt_times.append(now)
        cutoff = now - 5.0
        while self._pkt_times and self._pkt_times[0] < cutoff:
            self._pkt_times.popleft()
        self._pkt_rate = len(self._pkt_times) / 5.0

    # ── LAYOUT ────────────────────────────────────────────────────────────────
    def _make_layout(self) -> Layout:
        """Build layout once; only .update() inside the run loop."""
        term_height = console.size.height
        header_size = 7
        available   = max(0, term_height - header_size)
        upper_size  = min(10, max(5, available // 3))

        layout = Layout()
        layout.split_column(
            Layout(name="header",  size=header_size),
            Layout(name="upper",   size=upper_size),
            Layout(name="middle",  size=upper_size),
            Layout(name="lower"),
        )
        layout["upper"].split_row(
            Layout(name="stats"),
            Layout(name="intel"),
        )
        return layout

    # ── PACKET TABLE ──────────────────────────────────────────────────────────
    def _generate_packet_table(self) -> Table:
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

    # ── THREAT FEED TABLE ─────────────────────────────────────────────────────
    def _generate_threat_table(self) -> Table:
        table = Table(expand=True, border_style="red", box=None)
        table.add_column("TIME",  style="white", width=10)
        table.add_column("THREAT EVENT")
        rows = list(itertools.islice(reversed(self.threat_feed), 8))[::-1]
        for ts, msg in rows:
            table.add_row(ts, msg)
        return table

    # ── PACKET HANDLER ────────────────────────────────────────────────────────
    def packet_handler(self, pkt):
        # ARP spoof check (doesn't need IP layer)
        self.check_arp_spoof(pkt)

        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        ts    = time.strftime("%H:%M:%S")
        win   = pkt[TCP].window if pkt.haslayer(TCP) else 0
        os_id = self.get_os_fingerprint(ip_layer.ttl, win)
        loc   = self.get_geo_loc(ip_layer.src)
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "ICMP"
        port  = (pkt[TCP].dport if pkt.haslayer(TCP)
                 else pkt[UDP].dport if pkt.haslayer(UDP)
                 else 0)

        # Update stats and run audit under single lock acquisition
        with self.state_lock:
            self.stats[proto]   += 1
            self.devices[os_id] += 1
            risk = self.audit_security(port, proto)
            # FIX: threat_count for unsecure ports now incremented here, under lock
            if port in UNSECURE_PORTS:
                self.threat_count += 1

        # Packet rate
        self._update_pkt_rate()

        # Detection checks
        if proto in ("TCP", "UDP") and port != 0:
            self.check_port_scan(ip_layer.src, port, pkt)
        self.check_dns_anomaly(pkt, port, proto)

        # Log entry
        self.display_log.append([ts, ip_layer.src, os_id, f"{proto}/{port}", risk, loc])

        # Buffer packet
        with self.buffer_lock:
            self.buffer.append(pkt)
            if port in UNSECURE_PORTS:
                self.threat_pkts.append(pkt)

    # ── MAIN RUN LOOP ─────────────────────────────────────────────────────────
    def run(self):
        # FIX: cross-platform root check
        if hasattr(os, "getuid"):
            if os.getuid() != 0:
                console.print("[bold red][!] PriVi-NetLens requires root. Run with sudo.[/bold red]")
                sys.exit(1)
        else:
            # Windows — check via ctypes
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    console.print("[bold red][!] PriVi-NetLens requires Administrator privileges.[/bold red]")
                    sys.exit(1)
            except Exception:
                console.print("[bold yellow][~] Could not verify privileges. Proceeding anyway.[/bold yellow]")

        layout = self._layout
        sniff_kwargs = {"prn": self.packet_handler, "store": 0}
        if self.iface:
            sniff_kwargs["iface"] = self.iface
        if self.bpf_filter:
            sniff_kwargs["filter"] = self.bpf_filter
        threading.Thread(target=sniff, kwargs=sniff_kwargs, daemon=True).start()

        try:
            with Live(layout, refresh_per_second=4, screen=True):
                while not self._stop_event.is_set():
                    layout["header"].update(self._header_panel)

                    with self.state_lock:
                        stats_snap   = dict(self.stats)
                        devices_snap = self.devices.most_common(6)
                        threat_snap  = self.threat_count
                        rate_snap    = self._pkt_rate

                    stats_text = Text()
                    stats_text.append(f"Uptime : {int(time.time() - self.start_time)}s\n", style="dim")
                    stats_text.append(f"Rate   : {rate_snap:.1f} pkt/s\n", style="bold yellow")
                    for pr, count in stats_snap.items():
                        stats_text.append(f"  {pr}: {count}\n", style="bold green")
                    layout["stats"].update(Panel(stats_text, title="[bold white]Protocols[/bold white]"))

                    intel_text = Text()
                    intel_text.append(f"THREATS : {threat_snap}\n", style="bold red")
                    for device, count in devices_snap:
                        intel_text.append(f"  {device}: {count}\n", style="cyan")
                    layout["intel"].update(Panel(intel_text, title="[bold white]OS Intelligence[/bold white]"))

                    layout["middle"].update(Panel(
                        self._generate_threat_table(),
                        title="[bold red]Threat Feed[/bold red]",
                        border_style="red"
                    ))

                    layout["lower"].update(Panel(
                        self._generate_packet_table(),
                        title="[bold cyan]Forensic Live Stream[/bold cyan]"
                    ))

                    time.sleep(0.1)

        except KeyboardInterrupt:
            pass

        self.shutdown()

    # ── SHUTDOWN ──────────────────────────────────────────────────────────────
    def shutdown(self):
        self._stop_event.set()
        console.print("\n[bold yellow][!] Audit Terminated. Exporting Forensics...[/bold yellow]")

        # FIX: single timestamp for all exports
        ts = int(time.time())

        with self.buffer_lock:
            captured      = list(self.buffer)
            threat_pkts   = list(self.threat_pkts)

        # Full PCAP
        if captured:
            pcap_file = f"PriVi_Forensic_{ts}.pcap"
            try:
                wrpcap(pcap_file, captured)
                console.print(f"[bold green][+] Forensic PCAP saved: {pcap_file}[/bold green]")
            except Exception as e:
                console.print(f"[bold red][!] PCAP error: {e}[/bold red]")
        else:
            console.print("[bold yellow][~] No packets captured — PCAP skipped.[/bold yellow]")

        # Threat-only PCAP
        if threat_pkts:
            threat_pcap = f"PriVi_Threats_{ts}.pcap"
            try:
                wrpcap(threat_pcap, threat_pkts)
                console.print(f"[bold green][+] Threat PCAP saved: {threat_pcap}[/bold green]")
            except Exception as e:
                console.print(f"[bold red][!] Threat PCAP error: {e}[/bold red]")

        # Take final snapshots under lock
        with self.state_lock:
            final_threats   = self.threat_count
            final_devices   = dict(self.devices)
            final_stats     = dict(self.stats)
            final_arp       = {ip: list(macs) for ip, macs in self._arp_map.items() if len(macs) > 1}
            final_scanned   = list(self._scan_alerted)
            elapsed         = int(time.time() - self.start_time)

        # Text report
        report_file = f"NETLENS_SUMMARY_{ts}.txt"
        try:
            with open(report_file, "w") as f:
                f.write(f"PRIVI-SECURITY: NETLENS V5.3 REPORT\n{'=' * 40}\n")
                f.write(f"Total Packets  : {len(captured)} | Threats: {final_threats}\n")
                f.write(f"Devices        : {final_devices}\n")
                f.write(f"Protocols      : {final_stats}\n")
                f.write(f"Duration       : {elapsed}s\n")
                f.write(f"Port Scan IPs  : {final_scanned}\n")
                f.write(f"ARP Spoof IPs  : {final_arp}\n")
            console.print(f"[bold green][+] Summary saved: {report_file}[/bold green]")
        except OSError as e:
            console.print(f"[bold red][!] Report error: {e}[/bold red]")

        # JSON report
        json_file = f"NETLENS_SUMMARY_{ts}.json"
        try:
            report_data = {
                "tool":         f"{self.name} v{self.version}",
                "author":       self.author,
                "timestamp":    ts,
                "duration_sec": elapsed,
                "total_packets": len(captured),
                "threat_count": final_threats,
                "protocols":    final_stats,
                "devices":      final_devices,
                "port_scan_ips": final_scanned,
                "arp_spoof_ips": final_arp,
                "threat_feed":  [{"time": t, "event": e} for t, e in self.threat_feed],
            }
            with open(json_file, "w") as f:
                json.dump(report_data, f, indent=2)
            console.print(f"[bold green][+] JSON report saved: {json_file}[/bold green]")
        except OSError as e:
            console.print(f"[bold red][!] JSON error: {e}[/bold red]")

        # FIX: no sys.exit() here — return cleanly to run(), let the caller exit
        return


# ── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PriVi-NetLens v5.3 — Network Forensic Intelligence")
    parser.add_argument("--iface",    "-i", default=None,
                        help="Network interface (e.g. eth0, wlan0). Default: all.")
    parser.add_argument("--filter",   "-f", default=None,
                        help='BPF filter string (e.g. "tcp port 80 or tcp port 443").')
    parser.add_argument("--no-geo",         action="store_true",
                        help="Disable geo lookups (useful on air-gapped networks).")
    args = parser.parse_args()

    sentry = PriViNetLens(
        iface      = args.iface,
        bpf_filter = args.filter,
        no_geo     = args.no_geo,
    )
    sentry.run()
    sys.exit(0)
