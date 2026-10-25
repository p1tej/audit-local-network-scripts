#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dashboard Central - Network Guardian
Lê múltiplos ficheiros JSON gerados pelos sensores e exibe num painel interativo.
Inclui gráficos Plotly, Inspetor de Portas, Exportações e Upload de Históricos.
"""

import glob
import json
import os
from datetime import datetime
from typing import Dict, List, Tuple

import pandas as pd
import plotly.express as px
import streamlit as st

# Configuração inicial da página (deve ser a primeira chamada do Streamlit)
st.set_page_config(page_title="Network Guardian Global", page_icon="🛡️", layout="wide")

# Constantes
PASTA_DADOS = "./central_data"


def processar_ficheiro_json(
    conteudo: dict,
    nome_sensor: str,
    ultima_att: str,
    lista_dispositivos: List[Dict],
    resultados_brutos: List[Dict],
    suspeitos_combinados: Dict,
):
    """Lógica partilhada para extrair dados do JSON (local ou upload)"""
    # Guardar bruto para exportação Mestra JSON
    resultados_brutos.extend(conteudo.get("results", []))

    # Unir suspeitos
    s = conteudo.get("suspects", {})
    if "mac_with_multiple_ips" in s:
        suspeitos_combinados["mac_with_multiple_ips"].update(s["mac_with_multiple_ips"])
    if "ip_with_multiple_macs" in s:
        suspeitos_combinados["ip_with_multiple_macs"].update(s["ip_with_multiple_macs"])

    # Processar para a Tabela do Dashboard
    for disp in conteudo.get("results", []):
        ip = str(disp.get("ip", ""))
        mac = str(disp.get("mac", ""))
        hostname = str(disp.get("hostname", ""))

        # Limpar strings vazias para melhor visualização
        hostname = hostname if hostname else "N/A"

        is_suspect = (
            ip in suspeitos_combinados["ip_with_multiple_macs"]
            or mac in suspeitos_combinados["mac_with_multiple_ips"]
        )

        portas_raw = disp.get("ports_details", [])
        scan_time = disp.get("scan_timestamp", ultima_att)

        lista_dispositivos.append(
            {
                "Localização": nome_sensor,
                "IP": ip,
                "MAC": mac,
                "Hostname": hostname,
                "Fabricante": disp.get("vendor", "Desconhecido") or "Desconhecido",
                "Sistema Operativo": disp.get("os", "Desconhecido") or "Desconhecido",
                "Total Portas": len(portas_raw),
                "Estado": "⚠️ Suspeito" if is_suspect else "✅ Seguro",
                "Último Scan": scan_time,
                "Detalhes_Portas": portas_raw,
            }
        )


def carregar_dados(
    uploaded_files,
) -> Tuple[List[Dict], Dict[str, str], List[Dict], Dict]:
    """
    Lê os ficheiros JSON locais e os ficheiros enviados pelo utilizador (upload).
    Devolve: (Tabela Formatada, Info Sensores, Resultados Brutos para Export, Suspeitos Combinados)
    """
    if not os.path.exists(PASTA_DADOS):
        os.makedirs(PASTA_DADOS)

    ficheiros_locais = glob.glob(os.path.join(PASTA_DADOS, "*.json"))

    lista_dispositivos: List[Dict] = []
    info_sensores: Dict[str, str] = {}
    resultados_brutos: List[Dict] = []
    suspeitos_combinados: Dict = {
        "mac_with_multiple_ips": {},
        "ip_with_multiple_macs": {},
    }

    # 1. Processar Ficheiros da Diretoria Local (rsync)
    for f in ficheiros_locais:
        try:
            with open(f, "r", encoding="utf-8") as file:
                conteudo = json.load(file)
                nome_sensor = os.path.basename(f).replace(".json", "")
                ultima_att = conteudo.get("generated", "Desconhecido")
                info_sensores[nome_sensor] = ultima_att

                processar_ficheiro_json(
                    conteudo,
                    nome_sensor,
                    ultima_att,
                    lista_dispositivos,
                    resultados_brutos,
                    suspeitos_combinados,
                )
        except Exception as e:
            st.sidebar.error(f"Erro ao processar o ficheiro {f}: {e}")

    # 2. Processar Ficheiros Uploaded (Drag & Drop)
    if uploaded_files:
        for uf in uploaded_files:
            try:
                conteudo = json.load(uf)
                nome_sensor = uf.name.replace(".json", "") + " (Upload)"
                ultima_att = conteudo.get("generated", "Desconhecido")
                info_sensores[nome_sensor] = ultima_att

                processar_ficheiro_json(
                    conteudo,
                    nome_sensor,
                    ultima_att,
                    lista_dispositivos,
                    resultados_brutos,
                    suspeitos_combinados,
                )
            except Exception as e:
                st.sidebar.error(f"Erro ao processar o upload de {uf.name}: {e}")

    return lista_dispositivos, info_sensores, resultados_brutos, suspeitos_combinados


def processar_datas(df: pd.DataFrame) -> pd.DataFrame:
    """Converte as strings de timestamp para objetos DateTime e extrai Dia e Hora."""
    if df.empty:
        return df

    df["Último Scan DT"] = pd.to_datetime(df["Último Scan"], errors="coerce")
    df["Dia"] = df["Último Scan DT"].dt.date.astype(str)
    df["Hora"] = df["Último Scan DT"].dt.hour

    # Limpar texto do SO para os gráficos ficarem bonitos
    df["SO Curto"] = (
        df["Sistema Operativo"]
        .astype(str)
        .apply(
            lambda x: x.split("(")[0].strip() if x and x != "nan" else "Desconhecido"
        )
    )

    return df


def main():
    st.title("🛡️ Network Guardian - Consola Central")

    # 1. Reservar o espaço no topo da barra lateral para os filtros
    espaco_filtros = st.sidebar.container()

    # 2. Definir o Upload no FIM da barra lateral (no código aparece aqui para ser processado)
    st.sidebar.markdown("---")
    st.sidebar.header("📁 Fontes de Dados Extra")
    uploaded_files = st.sidebar.file_uploader(
        "Adicionar ficheiros JSON históricos", accept_multiple_files=True, type=["json"]
    )

    # 3. Carregar e Processar Dados
    dados_formatados, sensores, raw_results, suspects = carregar_dados(uploaded_files)

    if not dados_formatados:
        st.warning("A aguardar dados...")
        return

    df = pd.DataFrame(dados_formatados)
    df = processar_datas(df)

    # 4. Preencher o espaço do topo (os filtros aparecem em primeiro no ecrã)
    with espaco_filtros:
        st.header("Filtros de Visão")

        # Pesquisa
        pesquisa = st.text_input("🔍 Pesquisar (IP, MAC, Nome, Fabricante, SO):")

        # Localização
        opcoes_locais = sorted(df["Localização"].unique().tolist())
        locais = st.multiselect(
            "📍 Sensor / Localização:", options=opcoes_locais, default=opcoes_locais
        )

        # Dia
        opcoes_dias = sorted([d for d in df["Dia"].unique().tolist() if d != "NaT"])
        dias_selecionados = st.multiselect(
            "📅 Dia de Análise:", options=opcoes_dias, default=opcoes_dias
        )

        # Estado
        opcoes_estados = df["Estado"].unique().tolist()
        estados = st.multiselect(
            "🛡️ Estado de Segurança:", options=opcoes_estados, default=opcoes_estados
        )

    # ==========================================
    # APLICAR FILTROS
    # ==========================================
    df_filtrado = df[
        df["Localização"].isin(locais)
        & df["Estado"].isin(estados)
        & df["Dia"].isin(dias_selecionados)
    ]

    # Aplicar Pesquisa Ampla (IP, MAC, Hostname, Fabricante, SO)
    if pesquisa:
        ser_ip: pd.Series = pd.Series(df_filtrado["IP"]).astype(str)
        ser_mac: pd.Series = pd.Series(df_filtrado["MAC"]).astype(str)
        ser_host: pd.Series = pd.Series(df_filtrado["Hostname"]).astype(str)
        ser_vendor: pd.Series = pd.Series(df_filtrado["Fabricante"]).astype(str)
        ser_os: pd.Series = pd.Series(df_filtrado["Sistema Operativo"]).astype(str)

        mask_ip = ser_ip.str.contains(pesquisa, case=False, na=False)
        mask_mac = ser_mac.str.contains(pesquisa, case=False, na=False)
        mask_host = ser_host.str.contains(pesquisa, case=False, na=False)
        mask_vendor = ser_vendor.str.contains(pesquisa, case=False, na=False)
        mask_os = ser_os.str.contains(pesquisa, case=False, na=False)

        df_filtrado = df_filtrado[
            mask_ip | mask_mac | mask_host | mask_vendor | mask_os
        ]

    if df_filtrado.empty:  # type: ignore
        st.warning("Nenhum dispositivo encontrado com estes filtros.")
        return

    # ==========================================
    # PAINEL PRINCIPAL (Métricas)
    # ==========================================
    st.markdown("### 📊 Visão Global da Rede")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Sensores Filtrados", len(df_filtrado["Localização"].unique()))  # type: ignore
    c2.metric("Total de Dispositivos", int(df_filtrado.shape[0]))

    suspeitos_df = df_filtrado[df_filtrado["Estado"] == "⚠️ Suspeito"]
    c3.metric(
        "Dispositivos Suspeitos", int(suspeitos_df.shape[0]), delta_color="inverse"
    )

    ser_os_metric: pd.Series = pd.Series(df_filtrado["SO Curto"])
    c4.metric("Sistemas Operativos", int(ser_os_metric.nunique()))

    # ==========================================
    # GRÁFICOS TEMPORAIS (Plotly)
    # ==========================================
    st.markdown("---")
    st.markdown("### 📈 Análise Temporal")
    col_temp1, col_temp2 = st.columns(2)

    with col_temp1:
        st.markdown("**Crescimento e Deteções por Dia**")
        df_daily = df_filtrado.groupby("Dia")["IP"].nunique().reset_index()  # type: ignore
        df_daily.columns = ["Dia", "Dispositivos"]  # type: ignore
        fig_timeline = px.line(
            df_daily,
            x="Dia",
            y="Dispositivos",
            markers=True,
            color_discrete_sequence=["#1f77b4"],
        )
        fig_timeline.update_layout(margin=dict(l=0, r=0, t=30, b=0))
        st.plotly_chart(fig_timeline, width="stretch")

    with col_temp2:
        st.markdown("**Volume de Atividade por Hora do Dia**")
        df_horas = df_filtrado.dropna(subset=["Hora"])  # type: ignore
        fig_hours = px.histogram(
            df_horas,
            x="Hora",
            nbins=24,
            labels={"Hora": "Hora do Dia (0-23)"},
            color_discrete_sequence=["#ff7f0e"],
        )
        fig_hours.update_layout(bargap=0.1, margin=dict(l=0, r=0, t=30, b=0))
        st.plotly_chart(fig_hours, width="stretch")

    # ==========================================
    # GRÁFICOS DE DISTRIBUIÇÃO (Plotly Donuts)
    # ==========================================
    st.markdown("---")
    st.markdown("### 🎯 Perfil e Distribuição da Rede")

    grafico_opcao = st.radio(
        "Ver distribuição detalhada por coluna:",
        ["Fabricante", "SO Curto", "Localização", "Estado"],
        horizontal=True,
    )

    col_dist1, col_dist2 = st.columns([1, 1])

    with col_dist1:
        st.markdown(f"**Distribuição por {grafico_opcao}**")
        fig_donut = px.pie(
            df_filtrado,
            names=grafico_opcao,
            hole=0.4,
            color_discrete_sequence=px.colors.qualitative.Pastel,
        )
        fig_donut.update_traces(textposition="inside", textinfo="percent+label")
        fig_donut.update_layout(showlegend=False, margin=dict(l=0, r=0, t=30, b=0))
        st.plotly_chart(fig_donut, width="stretch")

    with col_dist2:
        st.markdown("**Nível de Exposição (Portas)**")
        df_filtrado_copy = df_filtrado.copy()
        df_filtrado_copy["Status Portas"] = df_filtrado_copy["Total Portas"].apply(  # type: ignore
            lambda x: "Portas Abertas" if x > 0 else "Seguro (Sem Portas)"
        )
        fig_ports = px.pie(
            df_filtrado_copy,
            names="Status Portas",
            hole=0.4,
            color="Status Portas",
            color_discrete_map={
                "Portas Abertas": "#EF553B",
                "Seguro (Sem Portas)": "#00CC96",
            },
        )
        fig_ports.update_traces(textposition="inside", textinfo="percent+label")
        fig_ports.update_layout(showlegend=True, margin=dict(l=0, r=0, t=30, b=0))
        st.plotly_chart(fig_ports, width="stretch")

    # ==========================================
    # TABELA DE DADOS & EXPORTAÇÕES
    # ==========================================
    st.markdown("---")
    st.markdown("### 📋 Inventário Consolidado")

    col_titulo_tabela, col_export_csv, col_export_json = st.columns([2, 1, 1])

    # Prepara a tabela removendo colunas temporárias e dados brutos
    colunas_remover = ["Detalhes_Portas", "Último Scan DT", "Dia", "Hora", "SO Curto"]
    df_exibicao = df_filtrado.drop(  # type: ignore
        columns=[c for c in colunas_remover if c in df_filtrado.columns]  # type: ignore
    )

    # Reordenar colunas para que o Hostname apareça num sítio lógico (depois de MAC)
    colunas_ordem = [
        "Localização",
        "IP",
        "MAC",
        "Hostname",
        "Fabricante",
        "Sistema Operativo",
        "Total Portas",
        "Estado",
        "Último Scan",
    ]
    # Garantir que usamos apenas as colunas que realmente existem
    colunas_ordem = [c for c in colunas_ordem if c in df_exibicao.columns]
    df_exibicao = df_exibicao[colunas_ordem]

    st.dataframe(df_exibicao, width="stretch", hide_index=True)

    with col_export_csv:
        csv_data = df_exibicao.to_csv(index=False).encode("utf-8")  # type: ignore
        st.download_button(
            label="📊 Exportar Vista (CSV)",
            data=csv_data,
            file_name=f"rede_filtrada_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv",
            width="stretch",
            help="Exporta apenas o que estás a ver na tabela atual (com filtros aplicados).",
        )

    with col_export_json:
        db_unificada = {
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "results": raw_results,
            "suspects": suspects,
        }
        json_data = json.dumps(db_unificada, ensure_ascii=False, indent=2).encode(
            "utf-8"
        )
        st.download_button(
            label="📦 Exportar Master (JSON)",
            data=json_data,
            file_name=f"master_database_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
            mime="application/json",
            width="stretch",
            help="Gera um ficheiro JSON único com todos os dados brutos de todos os sensores sincronizados.",
        )

    # ==========================================
    # ANÁLISE DETALHADA DE PORTAS (INSPETOR)
    # ==========================================
    st.markdown("---")
    st.markdown("### 🔍 Inspetor de Dispositivos (Portas e Funções)")

    ips_disponiveis = sorted(df_filtrado["IP"].unique())  # type: ignore
    ip_selecionado = st.selectbox(
        "Selecione o IP a inspecionar:",
        options=["-- Escolha um IP --"] + ips_disponiveis,
    )

    if ip_selecionado and ip_selecionado != "-- Escolha um IP --":
        linha_dispositivo = df_filtrado[df_filtrado["IP"] == ip_selecionado].iloc[0]  # type: ignore
        portas_detalhadas = linha_dispositivo["Detalhes_Portas"]
        hostname_display = linha_dispositivo["Hostname"]
        hostname_str = f" - {hostname_display}" if hostname_display != "N/A" else ""

        st.write(
            f"**Dispositivo:** {ip_selecionado}{hostname_str} ({linha_dispositivo['Fabricante']}) | **Sensor:** {linha_dispositivo['Localização']}"
        )

        if portas_detalhadas and len(portas_detalhadas) > 0:
            tabela_portas = []
            for p in portas_detalhadas:
                porta_num = p.get("port", "N/A")
                protocolo = p.get("proto", "tcp").upper()
                servico = p.get("service", "Desconhecido")
                descricao = p.get("description", "")

                tabela_portas.append(
                    {
                        "Porta": f"{porta_num} / {protocolo}",
                        "Serviço": servico.upper(),
                        "Função / Detalhe": descricao if descricao else "Indisponível",
                    }
                )
            st.table(pd.DataFrame(tabela_portas))
        else:
            st.success("Nenhuma porta aberta ou vulnerável detetada neste dispositivo.")

    # ==========================================
    # ESTADO DOS SENSORES (RODAPÉ)
    # ==========================================
    st.markdown("---")
    col_titulo, col_botao = st.columns([4, 1])
    with col_titulo:
        st.markdown("#### 📡 Último Check-in dos Sensores")
    with col_botao:
        if st.button("🔄 Atualizar Dashboard"):
            st.rerun()

    cols = st.columns(min(len(sensores), 4) if sensores else 1)
    for i, (sensor, data_hora) in enumerate(sensores.items()):
        cols[i % 4].info(f"**{sensor}**\n\n⏳ {data_hora}")


if __name__ == "__main__":
    main()
