#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scanner de Rede Contínuo (IDS Lite)
- Requer o módulo auditoria.py na mesma pasta
- Faz scans diferenciais e adiciona novos dispositivos à base de dados
- Aguarda o comando "fim" para processar o output final
- Suporta envio de dados para servidor central via rsync
"""

import argparse
import json
import os
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path

# Importar o nosso motor de auditoria
try:
    import auditoria as audit
except ImportError:
    print("[!] ERRO: O ficheiro 'auditoria.py' não foi encontrado na mesma pasta.")
    print("Por favor, certifica-te de que está na mesma diretoria que este script.")
    sys.exit(1)


def carregar_base_dados(caminho: str) -> dict:
    """Carrega o database.json se existir, senão devolve uma estrutura limpa."""
    if Path(caminho).exists():
        try:
            with open(caminho, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Erro ao ler {caminho}: {e}")

    # Estrutura padrão se estiver vazio ou não existir
    return {"generated": "", "results": [], "suspects": {}}


def guardar_base_dados(caminho: str, db: dict) -> None:
    """Guarda a informação no ficheiro JSON de forma segura."""
    db["generated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)


def enviar_para_central(ficheiro_local: str, node_id: str, destino: str) -> None:
    """Envia o ficheiro local para o servidor central com o nome do nodo."""
    if not destino:
        return

    # Garantir que o destino acaba com uma barra (/) para apontar para uma pasta
    if not destino.endswith("/"):
        destino += "/"

    caminho_destino = f"{destino}{node_id}.json"

    # Comando rsync: -a (archive), -z (comprime), -q (quiet)
    comando = ["rsync", "-azq", ficheiro_local, caminho_destino]

    try:
        subprocess.run(comando, check=True)
        print(f"[➔] Dados sincronizados com o Central como '{node_id}.json'")
    except Exception as e:
        print(f"[!] Erro na sincronização com o servidor central: {e}")


def logic_scanner_loop(
    network: str,
    outdir: str,
    interval: int,
    pipeline_args: dict,
    stop_event: threading.Event,
    node_id: str,
    sync_dest: str,
):
    """
    Função principal da Thread de Scanning.
    Gere o ciclo infinito, o scan inicial e os scans diferenciais.
    """
    db_path = os.path.join(outdir, "database.json")
    db = carregar_base_dados(db_path)

    # 1. SCAN INICIAL (Se a base de dados estiver vazia)
    if not db["results"]:
        print(
            f"\n[SCANNER] Base de dados vazia. A iniciar SCAN TOTAL à rede {network}..."
        )

        arp_list = audit.run_arp_scan(network, iface=pipeline_args.get("iface"))

        # Fallback se o ARP não detetar nada
        if not arp_list:
            print("[!] Nenhum host detetado via ARP. A usar fallback de IPs...")
            if "/" in network:
                prefix = ".".join(network.split("/")[0].split(".")[:3])
                arp_list = [
                    {"ip": f"{prefix}.{i}", "mac": "", "vendor": ""}
                    for i in range(1, 255)
                ]
            else:
                arp_list = [{"ip": network, "mac": "", "vendor": ""}]

        merged, suspects = audit.run_audit_pipeline(arp_list, **pipeline_args)

        db["results"] = merged
        db["suspects"] = suspects
        guardar_base_dados(db_path, db)

        print(f"[SCANNER] Scan Total concluído. {len(merged)} dispositivos guardados.")

        # Sincronizar após o scan inicial
        if sync_dest:
            enviar_para_central(db_path, node_id, sync_dest)

    else:
        print(
            f"\n[SCANNER] Base de dados encontrada. {len(db['results'])} dispositivos já conhecidos."
        )

    # 2. CICLO INFINITO DE MONITORIZAÇÃO
    while not stop_event.is_set():
        # Entra no estado de espera. O wait() devolve True se for interrompido pelo stop_event.set()
        print(
            f"\n[SCANNER] A aguardar {interval // 60} minutos até à próxima verificação..."
        )
        interrupted = stop_event.wait(interval)

        if interrupted:
            # Recebeu ordem de paragem (escrevemos "fim")
            break

        print(
            f"\n[{datetime.now().strftime('%H:%M:%S')}] A iniciar verificação de rotina (ARP Scan)..."
        )
        current_arp = audit.run_arp_scan(network, iface=pipeline_args.get("iface"))

        # Identificar dispositivos conhecidos (usar MAC primariamente, e IP como fallback)
        known_macs = {
            str(r.get("mac") or "").lower() for r in db["results"] if r.get("mac")
        }
        known_ips_no_mac = {r.get("ip") for r in db["results"] if not r.get("mac")}

        novos_dispositivos = []
        for d in current_arp:
            mac = str(d.get("mac") or "").lower()
            ip = d.get("ip")

            if mac:
                if mac not in known_macs:
                    novos_dispositivos.append(d)
            else:
                if ip not in known_ips_no_mac:
                    novos_dispositivos.append(d)

        if novos_dispositivos:
            print(f"[!] DETETADOS {len(novos_dispositivos)} NOVOS DISPOSITIVOS!")
            for nd in novos_dispositivos:
                print(f"    -> IP: {nd.get('ip')} | MAC: {nd.get('mac')}")

            print("[SCANNER] A iniciar Auditoria Profunda apenas nestes novos alvos...")
            novos_merged, novos_suspects = audit.run_audit_pipeline(
                novos_dispositivos, **pipeline_args
            )

            # Adicionar aos resultados existentes
            db["results"].extend(novos_merged)

            # Atualizar os suspects (juntar dicionários de anomalias, se existirem)
            db["suspects"].update(novos_suspects)

            guardar_base_dados(db_path, db)
            print(
                f"[SCANNER] Base de dados atualizada. Total de dispositivos agora: {len(db['results'])}"
            )

            # Sincronizar após encontrar e analisar os novos dispositivos
            if sync_dest:
                enviar_para_central(db_path, node_id, sync_dest)
        else:
            print("[SCANNER] Nenhum dispositivo novo detetado. Rede sem alterações.")


def main():
    parser = argparse.ArgumentParser(
        description="Scanner de Rede Contínuo (Orquestrador)"
    )
    parser.add_argument("network", help="Rede (ex: 192.168.1.0/24) ou IP a monitorizar")
    parser.add_argument("outdir", help="Pasta de output onde fica o database.json")

    # Argumentos exclusivos do Scanner e Sincronização
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Intervalo de verificação em MINUTOS (padrão: 30)",
    )
    parser.add_argument(
        "--node-id",
        type=str,
        default="Sensor_Local",
        help="Identificador deste Raspberry (ex: Sala, Garagem)",
    )
    parser.add_argument(
        "--sync-dest",
        type=str,
        help="Destino rsync no servidor central (ex: utilizador@100.x.x.x:/pasta/central/)",
    )

    # Argumentos repassados para o motor (auditoria.py)
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
    parser.add_argument(
        "--debug", action="store_true", help="Ativar modo debug no motor"
    )

    args = parser.parse_args()

    # Prepara a pasta e os argumentos
    audit.ensure_outdir(args.outdir)
    audit.set_debug_mode(args.debug)

    intervalo_segundos = args.interval * 60

    # Dicionário com os argumentos que o pipeline de auditoria precisa
    pipeline_args = {
        "threads": args.threads,
        "extra_opts": args.extra_nmap_opts,
        "port_range": args.port_range,
        "aggressive": not args.no_aggressive,
        "use_masscan": not args.no_masscan,
        "snmp_community": args.snmp,
        "snmp_version": args.snmp_version,
        "outdir": args.outdir if args.debug else "None",
    }

    print("=" * 70)
    print("🚀 SCANNER CONTÍNUO INICIADO")
    print("=" * 70)
    if not audit.is_root():
        print("⚠️  ATENÇÃO: A correr SEM privilégios root. Os scans serão limitados.")
    print(f"📡 Node ID: {args.node_id}")
    if args.sync_dest:
        print(f"🔄 Destino de Sincronização: {args.sync_dest}")
    print(
        "💡 Escreve 'fim' e pressiona ENTER a qualquer momento para parar e gerar o relatório.\n"
    )

    # Criar o Evento de Paragem e iniciar a Thread Trabalhadora
    stop_event = threading.Event()
    scanner_thread = threading.Thread(
        target=logic_scanner_loop,
        args=(
            args.network,
            args.outdir,
            intervalo_segundos,
            pipeline_args,
            stop_event,
            args.node_id,
            args.sync_dest,
        ),
        daemon=True,
    )
    scanner_thread.start()

    # 3. INTERRUPÇÃO: Ciclo de Escuta da Consola (Thread Principal)
    try:
        while True:
            comando = input().strip().lower()
            if comando == "fim":
                print("\n[!] Comando 'fim' recebido. A preparar para parar...")
                stop_event.set()  # Acorda a thread se ela estiver a dormir

                print(
                    "[!] A aguardar finalização segura da thread (se estiver a meio de um scan, pode demorar)..."
                )
                scanner_thread.join()
                break
    except KeyboardInterrupt:
        # Se carregares em Ctrl+C, também deve parar limpo
        print("\n[!] Cancelado pelo utilizador (Ctrl+C). A parar...")
        stop_event.set()
        scanner_thread.join()

    # 4. FINALIZAÇÃO E PROCESSAMENTO DE DADOS
    print("\n[PROCESSAMENTO FINAL] A gerar relatórios (CSV e Dashboard HTML)...")
    db_path = os.path.join(args.outdir, "database.json")
    out_csv = os.path.join(args.outdir, "results.csv")
    out_html = os.path.join(args.outdir, "dashboard.html")

    db_final = carregar_base_dados(db_path)

    if db_final["results"]:
        audit.write_csv(out_csv, db_final["results"])
        audit.write_html(out_html, db_final["results"], db_final.get("suspects", {}))

        print("=" * 70)
        print("✅ SCANNER DESLIGADO COM SUCESSO")
        print("=" * 70)
        print("📊 Ficheiros finais gerados:")
        print(f"   • Base de Dados: {db_path}")
        print(f"   • Folha de Cálculo: {out_csv}")
        print(f"   • Dashboard Web: {out_html}")
    else:
        print("[!] Não há dados recolhidos para gerar os relatórios.")


if __name__ == "__main__":
    main()
