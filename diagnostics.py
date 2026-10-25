#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de Diagnóstico do Toolkit de Auditoria e Vigilância
- Verifica permissões, ficheiros essenciais, dependências externas e pacotes Python.
- Suporta comandos de instalação para Debian/Ubuntu, Fedora e Arch Linux.
"""

import os
import sys
from pathlib import Path
from shutil import which


def print_header(text):
    print("\n" + "=" * 75)
    print(f"  {text}")
    print("=" * 75)


def print_section(text):
    print(f"\n[•] {text}")
    print("-" * 75)


def is_root():
    """Verifica se o script corre com privilégios de super-utilizador."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def check_tool(name):
    """Valida se uma ferramenta binária existe no PATH do sistema."""
    path = which(name)
    if path:
        print(f"  ✅ {name:15} - Instalado em: {path}")
        return True
    else:
        print(f"  ❌ {name:15} - NÃO ENCONTRADO")
        return False


def check_python_file(filename):
    """Verifica a presença dos ficheiros do toolkit na diretoria atual."""
    if Path(filename).exists():
        print(f"  ✅ {filename:22} - Presente")
        return True
    else:
        print(f"  ❌ {filename:22} - EM FALTA")
        return False


def check_python_module(module_name, display_name):
    """Verifica se um pacote Python (PIP) está instalado."""
    try:
        __import__(module_name)
        print(f"  ✅ {display_name:15} - Instalado")
        return True
    except ImportError:
        print(f"  ❌ {display_name:15} - NÃO ENCONTRADO")
        return False


def main():
    print_header("DIAGNÓSTICO DO TOOLKIT DE AUDITORIA, VIGILÂNCIA E DASHBOARD")

    issues = []
    recommendations = []

    # 1. Verificação de Privilégios
    print_section("1. Permissões de Sistema")
    if is_root():
        print("  ✅ Utilizador: ROOT (Sudo detetado)")
        print("     - Deteção de SO e Scans ARP estão totalmente disponíveis.")
    else:
        print("  ⚠️  Utilizador: COMUM (Sem Sudo)")
        issues.append("O script não está a correr como root.")
        recommendations.append(
            "Executa o toolkit com 'sudo' (auditoria/scanner) para garantir a precisão dos resultados."
        )

    # 2. Verificação de Ficheiros
    print_section("2. Integridade do Projeto (Ficheiros Python)")
    core_ok = check_python_file("auditoria.py")
    scanner_ok = check_python_file("scanner.py")
    dash_ok = check_python_file("dashboard.py")

    if not core_ok:
        issues.append("Motor de auditoria (auditoria.py) não encontrado.")
    if not scanner_ok:
        issues.append("O ficheiro 'scanner.py' não está nesta pasta.")
    if not dash_ok:
        issues.append("O ficheiro 'dashboard.py' não está nesta pasta.")

    # 3. Verificação de Dependências (Binários do SO)
    print_section("3. Ferramentas de Rede Externas (SO)")

    # Ferramentas usadas pelo auditoria.py e scanner.py
    tools = [
        "nmap",
        "arp-scan",
        "masscan",
        "snmpwalk",
        "avahi-resolve",
        "nmblookup",
        "rsync",
    ]
    missing_tools = []

    for tool in tools:
        if not check_tool(tool):
            missing_tools.append(tool)
            issues.append(f"Falta a ferramenta de sistema: {tool}")

    # 4. Verificação de Dependências Python (PIP)
    print_section("4. Bibliotecas Python (PIP)")

    pip_modules = [
        ("streamlit", "Streamlit"),
        ("pandas", "Pandas"),
        ("plotly", "Plotly"),
    ]
    missing_pip = []

    for mod, disp in pip_modules:
        if not check_python_module(mod, disp):
            missing_pip.append(disp)
            issues.append(f"Falta a biblioteca Python: {disp}")

    # 6. Resumo e Plano de Ação
    print_header("RESUMO DO DIAGNÓSTICO")

    if not issues:
        print("\n✅ EXCELENTE! O teu ambiente está perfeitamente configurado.")
        print("\nComandos prontos a usar:")
        print("  • Snapshot:  sudo python3 auditoria.py 192.168.1.0/24 ./output")
        print(
            "  • Vigilante: sudo python3 scanner.py 192.168.1.0/24 ./output --interval 30"
        )
        print("  • Dashboard: streamlit run dashboard.py")
    else:
        print(f"\n⚠️  Atenção: Foram detetados {len(issues)} problemas.")

        print("\n💡 COMO RESOLVER:")
        step = 1

        if missing_tools:
            print(f"  {step}. Instala as dependências de sistema em falta:")
            print(
                "     [Debian/Ubuntu/Kali] sudo apt update && sudo apt install -y nmap arp-scan masscan snmp avahi-utils samba-common-bin rsync"
            )
            print(
                "     [Fedora]             sudo dnf install -y nmap arp-scan masscan net-snmp-utils avahi-tools samba-client rsync"
            )
            print(
                "     [Arch Linux]         sudo pacman -S nmap arp-scan masscan net-snmp avahi smbclient rsync"
            )
            step += 1

        if missing_pip:
            print(
                f"  {step}. Instala as bibliotecas Python necessárias para o Dashboard:"
            )
            print("     pip install streamlit pandas plotly")
            step += 1

        for rec in recommendations:
            print(f"  {step}. {rec}")
            step += 1

    print("\n" + "=" * 75)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Diagnóstico cancelado pelo utilizador.")
        sys.exit(0)
