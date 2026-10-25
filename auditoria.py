#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditoria Mista - Múltiplas técnicas de detecção
- Funciona como standalone CLI e como Módulo/Motor para scanners contínuos
- ARP + Nmap agressivo + Masscan (fallback) + p0f (passive)
- Múltiplas tentativas de OS detection
- Detecção híbrida de portas (masscan + nmap)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import socket
import subprocess
import threading
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from shutil import which
from typing import Any, Dict, List, Optional, Tuple, Union

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
LOCK = threading.Lock()
DEBUG_MODE = False


# ---------------- Helpers ----------------
def set_debug_mode(mode: bool) -> None:
    global DEBUG_MODE
    DEBUG_MODE = mode


def debug_print(msg: str) -> None:
    if DEBUG_MODE:
        print(f"[DEBUG] {msg}")


def run_cmd(cmd: List[str], timeout: Optional[int] = None) -> Tuple[str, str, int]:
    try:
        debug_print(f"Running command: {' '.join(cmd)}")
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout or "", p.stderr or "", p.returncode
    except FileNotFoundError as e:
        return "", str(e), 127
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 124
    except Exception as e:
        return "", str(e), 1


def bin_ok(name: str) -> bool:
    return which(name) is not None


def ensure_outdir(path: str) -> None:
    p = Path(path)
    if not p.exists():
        p.mkdir(parents=True, exist_ok=True)


def is_root() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False


def save_debug_file(filename: str, content: str, outdir: str) -> None:
    if DEBUG_MODE and outdir and outdir != "None":
        debug_path = Path(outdir) / "debug"
        debug_path.mkdir(exist_ok=True)
        (debug_path / filename).write_text(content)
        debug_print(f"Saved debug file: {filename}")


# ---------------- ARP discovery ----------------
def run_arp_scan(network: str, iface: Optional[str] = None) -> List[Dict[str, str]]:
    devices: List[Dict[str, str]] = []
    arp_scan_bin = which("arp-scan")
    if arp_scan_bin:
        cmd = (
            [arp_scan_bin, network] if "/" in network else [arp_scan_bin, "--localnet"]
        )
        if iface:
            cmd += ["-I", iface]
        stdout, stderr, rc = run_cmd(cmd, timeout=60)
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if IP_RE.match(parts[0]):
                ip = parts[0]
                mac = parts[1] if len(parts) > 1 else ""
                vendor = " ".join(parts[2:]) if len(parts) > 2 else ""
                devices.append({"ip": ip, "mac": mac, "vendor": vendor})
    else:
        try:
            with open("/proc/net/arp", "r") as f:
                next(f)
                for line in f:
                    cols = line.split()
                    if len(cols) >= 4 and IP_RE.match(cols[0]):
                        devices.append({"ip": cols[0], "mac": cols[3], "vendor": ""})
        except Exception as e:
            print(f"[!] Falha /proc/net/arp: {e}")

    uniq = {}
    for d in devices:
        uniq[d["ip"]] = d
    return list(uniq.values())


# ---------------- Masscan ----------------
def masscan_ports(ip: str, port_range: str = "1-65535", rate: int = 1000) -> List[int]:
    if not bin_ok("masscan") or not is_root():
        return []

    cmd = ["masscan", ip, "-p", port_range, "--rate", str(rate), "-oL", "-"]
    stdout, stderr, rc = run_cmd(cmd, timeout=120)

    ports = []
    for line in stdout.splitlines():
        if line.startswith("open"):
            parts = line.split()
            if len(parts) >= 4:
                try:
                    port = int(parts[2])
                    ports.append(port)
                except ValueError:
                    continue
    return sorted(ports)


# ---------------- Nmap scanning & parsing ----------------
def parse_nmap_xml(xml_text: str, ip: str, outdir: str = "None") -> Dict[str, Any]:
    data: Dict[str, Any] = {"status": None, "hostname": "", "os": [], "ports": []}
    if not xml_text.strip():
        return data

    if outdir and outdir != "None":
        save_debug_file(f"nmap_{ip.replace('.', '_')}.xml", xml_text, outdir)

    try:
        root = ET.fromstring(xml_text)
    except Exception as e:
        data["error"] = f"xml parse error: {e}"
        return data

    host_elem = root.find("host")
    if host_elem is None:
        host_elem = root.find(".//host")

    if host_elem is None:
        return data

    st = host_elem.find("status")
    if st is not None:
        data["status"] = st.get("state")

    hn = host_elem.find("hostnames/hostname")
    if hn is not None:
        data["hostname"] = hn.get("name") or ""

    os_elem = host_elem.find("os")
    if os_elem is not None:
        for osm in os_elem.findall("osmatch"):
            os_name = osm.get("name", "")
            os_accuracy = osm.get("accuracy", "0")
            if os_name:
                data["os"].append({"name": os_name, "accuracy": os_accuracy})

        if not data["os"]:
            for osc in os_elem.findall("osclass"):
                os_type = osc.get("type", "")
                os_vendor = osc.get("vendor", "")
                os_family = osc.get("osfamily", "")
                os_gen = osc.get("osgen", "")
                os_accuracy = osc.get("accuracy", "0")

                os_parts = [p for p in [os_vendor, os_family, os_gen] if p]
                if os_parts:
                    os_name = " ".join(os_parts) + (f" ({os_type})" if os_type else "")
                    data["os"].append({"name": os_name, "accuracy": os_accuracy})

        if not data["os"] and os_elem.find("osfingerprint") is not None:
            data["os_note"] = (
                "OS fingerprint detectado mas sem match na base de dados do Nmap"
            )

    ports_parent = host_elem.find("ports")
    if ports_parent is not None:
        for p in ports_parent.findall("port"):
            portid = p.get("portid")
            proto = p.get("protocol")

            state_elem = p.find("state")
            state = state_elem.get("state") if state_elem is not None else None

            service = p.find("service")
            service_name = service.get("name") if service is not None else None
            product = service.get("product") if service is not None else None
            version = service.get("version") if service is not None else None
            extrainfo = service.get("extrainfo") if service is not None else None
            devicetype = service.get("devicetype") if service is not None else None
            ostype = service.get("ostype") if service is not None else None

            service_desc_parts = [p for p in [product, version, extrainfo] if p]
            service_description = (
                " ".join(service_desc_parts) if service_desc_parts else None
            )

            data["ports"].append(
                {
                    "port": portid,
                    "proto": proto,
                    "state": state,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "devicetype": devicetype,
                    "ostype": ostype,
                    "description": service_description,
                }
            )

    return data


def nmap_scan_host(
    ip: str,
    extra_opts: Optional[Union[List[str], str]] = None,
    timeout: int = 300,
    port_range: Optional[str] = None,
    aggressive: bool = True,
    outdir: str = "None",
) -> Dict[str, Any]:
    nmap = which("nmap")
    if not nmap:
        return {"ip": ip, "error": "nmap not installed"}

    base_opts = ["-Pn", "-oX", "-"]

    if aggressive:
        base_opts.extend(["-A", "-T4", "--min-rate", "1000"])
    else:
        base_opts.extend(["-sV", "--version-intensity", "7", "-T4"])

    if is_root():
        if not aggressive:
            base_opts.extend(["-sS", "-O", "--osscan-guess", "--osscan-limit"])
        else:
            base_opts.insert(0, "-sS")
    else:
        base_opts.insert(0, "-sT")

    if port_range:
        if port_range == "-":
            base_opts.extend(["-p-"])
        else:
            base_opts.extend(["-p", port_range])
    else:
        base_opts.extend(["--top-ports", "1000"])

    if extra_opts:
        if isinstance(extra_opts, str):
            extra_opts = shlex.split(extra_opts)
        base_opts = extra_opts + base_opts

    cmd = [nmap] + base_opts + [ip]

    print(f"[*] Scanning {ip}... (timeout: {timeout}s)")
    debug_print(f"Command: {' '.join(cmd)}")

    stdout, stderr, rc = run_cmd(cmd, timeout=timeout)

    xml_text = stdout.strip()
    if not xml_text:
        combined = stdout + "\n" + stderr
        idx = combined.find("<nmaprun")
        if idx != -1:
            xml_text = combined[idx:].strip()

    if not xml_text:
        error_msg = stderr.strip() or "no nmap output"
        return {"ip": ip, "error": error_msg}

    parsed = parse_nmap_xml(xml_text, ip, outdir)
    parsed["ip"] = ip
    parsed["scan_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not parsed.get("os") and is_root():
        if "os_note" not in parsed:
            parsed["os_note"] = (
                "Nmap não conseguiu determinar o SO (host pode bloquear OS fingerprinting)"
            )
    elif not is_root():
        parsed["os_note"] = "Detecção de SO requer privilégios root"

    return parsed


def nmap_scan_specific_ports(
    ip: str,
    ports: List[int],
    timeout: int = 300,
    outdir: str = "None",
    extra_opts: Optional[Union[List[str], str]] = None,
) -> Dict[str, Any]:
    if not ports:
        return {"ip": ip, "ports": []}
    port_list = ",".join(str(p) for p in ports)
    return nmap_scan_host(
        ip,
        extra_opts=extra_opts,
        port_range=port_list,
        timeout=timeout,
        aggressive=True,
        outdir=outdir,
    )


def nmap_threaded(
    ips: List[str],
    threads: int = 10,
    extra_opts: Optional[Union[List[str], str]] = None,
    port_range: Optional[str] = None,
    aggressive: bool = True,
    use_masscan: bool = True,
    outdir: str = "None",
) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}

    if use_masscan and bin_ok("masscan") and is_root():
        print("[*] Usando masscan para descoberta rápida de portas...")
        masscan_results = {}
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {
                ex.submit(masscan_ports, ip, port_range or "1-65535"): ip for ip in ips
            }
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    masscan_results[ip] = fut.result()
                except Exception:
                    masscan_results[ip] = []

        print("[*] Fazendo scan detalhado com nmap nas portas descobertas...")
        with ThreadPoolExecutor(max_workers=threads) as ex:
            future_to_ip = {}
            for ip in ips:
                ports = masscan_results.get(ip, [])
                if ports:
                    fut = ex.submit(
                        nmap_scan_specific_ports, ip, ports, 300, outdir, extra_opts
                    )
                    future_to_ip[fut] = ip
                else:
                    fut = ex.submit(
                        nmap_scan_host,
                        ip,
                        extra_opts,
                        300,
                        port_range,
                        aggressive,
                        outdir,
                    )
                    future_to_ip[fut] = ip

            for fut in as_completed(future_to_ip):
                ip = future_to_ip[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"ip": ip, "error": str(e)}
                with LOCK:
                    results[ip] = res
    else:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            future_to_ip = {
                ex.submit(
                    nmap_scan_host, ip, extra_opts, 300, port_range, aggressive, outdir
                ): ip
                for ip in ips
            }
            for fut in as_completed(future_to_ip):
                ip = future_to_ip[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"ip": ip, "error": str(e)}
                with LOCK:
                    results[ip] = res

    return results


# ---------------- Hostname helpers ----------------
def reverse_dns(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name or ""
    except Exception:
        return ""


def mdns_lookup(ip: str) -> str:
    if not bin_ok("avahi-resolve"):
        return ""
    out, _, _ = run_cmd(["avahi-resolve", "-a", ip], timeout=5)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == ip:
            return parts[1]
    return ""


def netbios_lookup(ip: str) -> str:
    if not bin_ok("nmblookup"):
        return ""
    out, _, _ = run_cmd(["nmblookup", "-A", ip], timeout=6)
    for line in out.splitlines():
        if "<00>" in line or "<20>" in line:
            return line.strip().split()[0]
    return ""


def resolve_hostnames(ips: List[str], threads: int = 10) -> Dict[str, Dict[str, str]]:
    """Resolve DNS, mDNS e NetBIOS para uma lista de IPs."""
    host_extra: Dict[str, Dict[str, str]] = {}

    def host_lookup(ip):
        res = {}
        rd = reverse_dns(ip)
        if rd:
            res["reverse_dns"] = rd
        md = mdns_lookup(ip)
        if md:
            res["mdns"] = md
        nb = netbios_lookup(ip)
        if nb:
            res["netbios"] = nb
        return ip, res

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(host_lookup, ip): ip for ip in ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                _, val = fut.result()
            except Exception:
                val = {}
            host_extra[ip] = val

    return host_extra


# ---------------- SNMP Helpers ----------------
def snmp_collect(
    ip: str, community: str = "public", version: str = "2c"
) -> Dict[str, str]:
    if not bin_ok("snmpwalk"):
        return {"error": "snmpwalk not installed"}
    out: Dict[str, str] = {}
    oids = {
        "sysDescr": "1.3.6.1.2.1.1.1.0",
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysUpTime": "1.3.6.1.2.1.1.3.0",
    }
    for k, oid in oids.items():
        if version in ("1", "2c"):
            cmd = ["snmpwalk", "-v2c", "-c", community, ip, oid]
        else:
            cmd = ["snmpwalk", "-v3", "-u", community, ip, oid]
        stdout, stderr, _ = run_cmd(cmd, timeout=20)
        out[k] = (stdout or stderr).strip()
    if version in ("1", "2c"):
        stdout, stderr, _ = run_cmd(
            ["snmpwalk", "-v2c", "-c", community, ip, "1.3.6.1.2.1.2.2"], timeout=20
        )
        out["interfaces"] = (stdout or stderr).strip()
    return out


def run_snmp_collection(
    ips: List[str], community: str, version: str = "2c", threads: int = 10
) -> Dict[str, Dict[str, str]]:
    """Tenta obter informações via SNMP para uma lista de IPs."""
    snmp_map = {}
    if not community or not bin_ok("snmpwalk"):
        return snmp_map

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(snmp_collect, ip, community, version): ip for ip in ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                snmp_map[ip] = fut.result()
            except Exception as e:
                snmp_map[ip] = {"error": str(e)}
    return snmp_map


# ---------------- Core Pipeline / Orquestrador ----------------
def run_audit_pipeline(
    arp_list: List[Dict[str, str]],
    threads: int = 5,
    extra_opts: Optional[Union[List[str], str]] = None,
    port_range: Optional[str] = None,
    aggressive: bool = True,
    use_masscan: bool = True,
    snmp_community: Optional[str] = None,
    snmp_version: str = "2c",
    outdir: str = "None",
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Função principal que o scanner.py vai importar e executar.
    Recebe uma lista de dispositivos (com IP e MAC) e devolve a análise completa.
    """
    ips = [d["ip"] for d in arp_list]
    if not ips:
        return [], {}

    # 1. Nmap Scanning
    nmap_map = nmap_threaded(
        ips,
        threads=threads,
        extra_opts=extra_opts,
        port_range=port_range,
        aggressive=aggressive,
        use_masscan=use_masscan,
        outdir=outdir,
    )

    # 2. Hostname Discovery
    host_extra = resolve_hostnames(ips, threads=min(10, len(ips) or 1))

    # 3. SNMP Collection
    snmp_map = {}
    if snmp_community:
        snmp_map = run_snmp_collection(
            ips, snmp_community, snmp_version, threads=min(10, len(ips) or 1)
        )

    # 4. Análise e Merge
    suspects = detect_arp_spoofing(arp_list)
    merged = merge_results(
        arp_list, nmap_map, snmp_map if snmp_map else None, host_extra
    )

    return merged, suspects


# ---------------- Merge & export ----------------
def detect_arp_spoofing(devs: List[Dict[str, str]]) -> Dict[str, Any]:
    mac2ips = defaultdict(set)
    ip2macs = defaultdict(set)
    for d in devs:
        ip = d.get("ip")
        mac = (d.get("mac") or "").lower()
        if mac:
            mac2ips[mac].add(ip)
        if ip:
            ip2macs[ip].add(mac)
    return {
        "mac_with_multiple_ips": {
            m: list(ips) for m, ips in mac2ips.items() if len(ips) > 1
        },
        "ip_with_multiple_macs": {
            ip: list(macs) for ip, macs in ip2macs.items() if len(macs) > 1
        },
    }


def merge_results(
    arp_list: List[Dict[str, str]],
    nmap_map: Dict[str, Dict[str, Any]],
    snmp_map: Optional[Dict[str, Dict[str, str]]] = None,
    host_extra: Optional[Dict[str, Dict[str, str]]] = None,
) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []

    for d in arp_list:
        ip = d["ip"]
        nm = nmap_map.get(ip, {})
        sn = snmp_map.get(ip) if snmp_map else None
        extra = host_extra.get(ip) if host_extra else None

        os_list = nm.get("os", [])
        if os_list:
            os_list_sorted = sorted(
                os_list, key=lambda x: int(x.get("accuracy", "0")), reverse=True
            )
            best_os = os_list_sorted[0]
            os_guess = (
                f"{best_os.get('name', '')} ({best_os.get('accuracy', '0')}% confiança)"
            )
        else:
            os_guess = nm.get("os_note", "Desconhecido")

        if os_guess == "Desconhecido" and sn and sn.get("sysDescr"):
            snmp_desc = sn.get("sysDescr", "")
            if snmp_desc and "error" not in snmp_desc.lower():
                os_guess = f"Via SNMP: {snmp_desc[:100]}"

        ports = nm.get("ports", [])
        open_ports = [p for p in ports if p.get("state") == "open"]

        port_strings = []
        port_details = []
        for p in open_ports:
            port_num = p.get("port")
            proto_val = p.get("proto", "tcp")
            svc = p.get("service") or "desconhecido"

            desc = p.get("description")
            if desc:
                port_strings.append(f"{port_num}/{proto_val} ({svc}: {desc})")
            else:
                prod = p.get("product")
                if prod:
                    port_strings.append(f"{port_num}/{proto_val} ({svc} - {prod})")
                else:
                    port_strings.append(f"{port_num}/{proto_val} ({svc})")

            port_details.append(
                {
                    "port": port_num,
                    "protocol": proto_val,
                    "service": svc,
                    "product": p.get("product"),
                    "version": p.get("version"),
                    "extrainfo": p.get("extrainfo"),
                }
            )

        port_summary = (
            "; ".join(port_strings)
            if port_strings
            else "Nenhuma porta aberta detectada"
        )

        hostname = (
            nm.get("hostname")
            or (extra.get("reverse_dns") if extra else "")
            or (sn.get("sysName") if sn else "")
            or ""
        )

        entry = {
            "ip": ip,
            "scan_timestamp": nm.get("scan_timestamp", ""),
            "mac": d.get("mac", ""),
            "vendor": d.get("vendor", ""),
            "hostname": hostname,
            "os": os_guess,
            "os_details": os_list,
            "ports": port_summary,
            "ports_details": port_details,
            "nmap_raw": nm,
            "snmp_raw": sn,
            "extra": extra,
        }
        merged.append(entry)
    return merged


def write_json(path: str, data: Any) -> None:
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2))


def write_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            ["IP", "Data/Hora", "MAC", "Vendor", "Hostname", "OS", "Portas/Funções"]
        )
        for r in rows:
            w.writerow(
                [
                    r.get("ip", ""),
                    r.get("scan_timestamp", ""),
                    r.get("mac", ""),
                    r.get("vendor", ""),
                    r.get("hostname", ""),
                    r.get("os", ""),
                    r.get("ports", ""),
                ]
            )


def write_html(path: str, rows: List[Dict[str, Any]], suspects: Dict[str, Any]) -> None:
    rows_json = json.dumps(rows, ensure_ascii=False)
    suspects_json = json.dumps(suspects, ensure_ascii=False)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!doctype html>
<html lang="pt">
<head>
<meta charset="utf-8">
<title>Auditoria - Dashboard</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.1/css/jquery.dataTables.min.css">
<style>
    body{{font-family:Arial;margin:16px;background-color:#f9f9f9;color:#333;}}
    table{{border-collapse:collapse;width:100%;}}
    th,td{{padding:8px;border:1px solid #ddd;text-align:left;}}
    th{{background-color:#4CAF50;color:white;}}
    #sus{{background-color:#fff3cd;padding:15px;border-radius:5px;border-left:4px solid #ffc107;margin:20px 0;}}
    .stats{{display:flex;gap:20px;margin:20px 0;}}
    .stat-box{{background:#fff;padding:15px;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,0.1);flex:1;}}
    .stat-box h3{{margin:0 0 10px 0;color:#4CAF50;}}
    .stat-box p{{margin:5px 0;font-size:24px;font-weight:bold;}}
</style>
<script src="https://code.jquery.com/jquery-3.5.1.js"></script>
<script src="https://cdn.datatables.net/1.13.1/js/jquery.dataTables.min.js"></script>
</head>
<body>
<h1>Auditoria de Rede</h1>
<p><strong>Gerado em:</strong> {now}</p>

<div class="stats">
    <div class="stat-box"><h3>Total de Hosts</h3><p id="total-hosts">0</p></div>
    <div class="stat-box"><h3>Hosts com SO Detectado</h3><p id="hosts-with-os">0</p></div>
    <div class="stat-box"><h3>Total de Portas Abertas</h3><p id="total-ports">0</p></div>
</div>

<div id="sus"><h3>⚠️ Anomalias Detectadas</h3><pre id="sus-content"></pre></div>

<h2>Dispositivos Detectados</h2>
<table id="tbl" class="display">
<thead><tr>
    <th>IP</th><th>Data/Hora</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th>Sistema Operativo</th><th>Portas e Funções</th>
</tr></thead>
<tbody id="rows"></tbody>
</table>

<script>
const data = {rows_json};
const suspects = {suspects_json};

function renderRows() {{
    const tbody = document.getElementById('rows');
    let hostsWithOS = 0; let totalPorts = 0;

    data.forEach(r => {{
        if (r.os && r.os !== 'Desconhecido' && !r.os.includes('não conseguiu') && !r.os.includes('requer privilégios')) {{
            hostsWithOS++;
        }}
        if (r.ports_details) {{ totalPorts += r.ports_details.length; }}

        const tr = `<tr>
            <td>${{r.ip || ''}}</td><td>${{r.scan_timestamp || ''}}</td>
            <td>${{r.mac || ''}}</td><td>${{r.vendor || ''}}</td>
            <td>${{r.hostname || ''}}</td><td>${{r.os || 'Desconhecido'}}</td>
            <td>${{r.ports || 'N/A'}}</td>
        </tr>`;
        tbody.insertAdjacentHTML('beforeend', tr);
    }});

    document.getElementById('total-hosts').textContent = data.length;
    document.getElementById('hosts-with-os').textContent = hostsWithOS;
    document.getElementById('total-ports').textContent = totalPorts;
}}

$(document).ready(function() {{
    renderRows();
    $('#tbl').DataTable({{"pageLength": 25, "order": [[0, "asc"]]}});

    const susContent = document.getElementById('sus-content');
    if (Object.keys(suspects.mac_with_multiple_ips).length === 0 && Object.keys(suspects.ip_with_multiple_macs).length === 0) {{
        susContent.textContent = 'Nenhuma anomalia detectada.';
    }} else {{
        susContent.textContent = JSON.stringify(suspects, null, 2);
    }}
}});
</script>
</body>
</html>"""
    Path(path).write_text(html)


# ---------------- Main (Modo CLI) ----------------
def main():
    parser = argparse.ArgumentParser(
        description="Auditoria Mista - Versão Avançada (Standalone)"
    )
    parser.add_argument("network", help="Rede (ex: 192.168.1.0/24) ou IP")
    parser.add_argument("outdir", help="Pasta de output")
    parser.add_argument(
        "--threads", type=int, default=5, help="threads para nmap (padrão: 5)"
    )
    parser.add_argument("--iface", help="Interface para arp-scan")
    parser.add_argument("--snmp", help="SNMP community")
    parser.add_argument(
        "--snmp-version", default="2c", choices=["1", "2c", "3"], help="SNMP version"
    )
    parser.add_argument(
        "--extra-nmap-opts", help='Extras para nmap (use aspas. Ex: "--script vuln")'
    )
    parser.add_argument("--port-range", help="Range de portas. Padrão: top 1000")
    parser.add_argument(
        "--no-aggressive",
        action="store_true",
        help="Desativar modo agressivo do nmap (-A)",
    )
    parser.add_argument("--no-masscan", action="store_true", help="Não usar masscan")
    parser.add_argument("--debug", action="store_true", help="Ativar modo debug")
    args = parser.parse_args()

    set_debug_mode(args.debug)
    ensure_outdir(args.outdir)

    out_json = os.path.join(args.outdir, "results.json")
    out_csv = os.path.join(args.outdir, "results.csv")
    out_html = os.path.join(args.outdir, "dashboard.html")

    print("=" * 70)
    print("AUDITORIA DE REDE - Standalone Mode")
    print("=" * 70)

    if not is_root():
        print("\nATENÇÃO: A correr SEM privilégios root. Resultados limitados.\n")

    print("[1/3] ARP Discovery")
    arp_list = run_arp_scan(args.network, iface=args.iface)
    if not arp_list:
        print("[!] Nenhum host via ARP. Usando fallback...")
        arp_list = [{"ip": args.network, "mac": "", "vendor": ""}]
    print(f"    ✓ {len(arp_list)} hosts detectados\n")

    print(f"[2/3] A Executar Pipeline de Auditoria em {len(arp_list)} alvos...")

    # Chama a nossa nova função unificada
    merged, suspects = run_audit_pipeline(
        arp_list=arp_list,
        threads=args.threads,
        extra_opts=args.extra_nmap_opts,
        port_range=args.port_range,
        aggressive=not args.no_aggressive,
        use_masscan=not args.no_masscan,
        snmp_community=args.snmp,
        snmp_version=args.snmp_version,
        outdir=args.outdir if DEBUG_MODE else "None",
    )
    print("    ✓ Pipeline concluído\n")

    print("[3/3] Exportação de Resultados")
    write_json(
        out_json,
        {
            "generated": datetime.now().isoformat() + "Z",
            "results": merged,
            "suspects": suspects,
        },
    )
    write_csv(out_csv, merged)
    write_html(out_html, merged, suspects)

    print("=" * 70)
    print(f"✅ Ficheiros gerados na pasta: {args.outdir}")


if __name__ == "__main__":
    main()
