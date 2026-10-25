# 🛡️ Toolkit de Auditoria e Vigilância de Rede (Network Guardian)

Este conjunto de ferramentas foi desenvolvido para mapear exaustivamente uma rede local, monitorizar continuamente a entrada de novos dispositivos (IDS Lite) e centralizar toda a informação num Dashboard interativo e moderno.

## ⚙️ Estrutura do Projeto

O toolkit é composto por três componentes principais que trabalham em simbiose:

1. **`auditoria.py` (O Motor):** O núcleo técnico. Responsável por realizar o "trabalho pesado" de varrimento (scan), identificação de Sistemas Operativos (SO), deteção de portas abertas, serviços e resolução de hostnames.
    
2. **`scanner.py` (O Vigilante / Sensor):** O orquestrador de monitorização. Utiliza o motor para vigiar a rede em intervalos definidos, mantendo uma base de dados local e enviando os dados (via `rsync`) para o servidor central.
    
3. **`dashboard.py` (A Consola Central):** Uma aplicação web interativa (construída em Streamlit) que agrega os dados de vários sensores, permitindo filtrar, pesquisar, gerar gráficos e exportar relatórios.

---

## 🛠️ Requisitos do Sistema

Para garantir que todas as ferramentas funcionam corretamente, deves instalar as dependências de sistema operativo e as bibliotecas Python:

### 1. Ferramentas Base do Sistema (Linux)
O motor de rede precisa destas ferramentas para extrair o máximo de informação:
- `nmap`, `arp-scan`, `masscan`, `snmpwalk`, `avahi-resolve` (mdns), `nmblookup` (netbios), `rsync` (sincronização).
*Exemplo Kali/Ubuntu:* `sudo apt install nmap arp-scan masscan snmp avahi-utils samba-common-bin rsync`

### 2. Bibliotecas Python (Dashboard)
Para correr a consola central:
- `pip install streamlit pandas plotly`

### 3. Privilégios
A execução do `auditoria.py` e `scanner.py` com `sudo` é **altamente recomendada** para permitir que o Nmap utilize pacotes RAW para *fingerprinting* de SO e scans stealth. O `dashboard.py` não necessita de `sudo`.

---

## 🩺 1. diagnostics.py (O Assistente de Saúde)

Antes de iniciares qualquer processo, deves executar o diagnóstico para garantir que o teu ambiente está "pronto".

**Comando:**
```bash
python3 diagnostics.py
```

**O que o Assistente faz:**
- Verifica permissões de root.
- Confirma a presença de todos os scripts Python.
- Valida se os binários de rede e pacotes do PIP estão instalados (fornecendo os comandos de instalação caso faltem).

---

## 🔍 2. auditoria.py (Modo Snapshot)

Utiliza este script quando precisares de um relatório imediato, profundo e detalhado sobre o estado atual da rede ou de um alvo específico.

### Comandos Comuns

| Objetivo | Comando |
| :--- | :--- |
| **Varrimento total da rede** | `sudo python3 auditoria.py 192.168.1.0/24 ./relatorio` |
| **Analisar apenas um IP** | `sudo python3 auditoria.py 192.168.1.50 ./alvo_unico` |
| **Scan de todas as portas** | `sudo python3 auditoria.py [IP] [PASTA] --port-range -` |
| **Recolha via SNMP** | `sudo python3 auditoria.py [IP] [PASTA] --snmp public` |

---

## 📡 3. scanner.py (Modo Vigilante / Sensor)

Utiliza este script em máquinas distribuídas (ex: Raspberry Pis) para manter uma vigilância ativa. Ele não repete o scan pesado em dispositivos conhecidos, atacando apenas endereços MAC novos.

### Comandos Comuns

| Objetivo | Comando |
| :--- | :--- |
| **Vigilância standard (30 min)** | `sudo python3 scanner.py 192.168.1.0/24 ./output` |
| **Vigilância apertada (5 min)** | `sudo python3 scanner.py 192.168.1.0/24 ./output --interval 5` |
| **Enviar para Central (Rsync)**| `sudo python3 scanner.py 192.168.1.0/24 ./output --node-id "Sensor_RH" --sync-dest "user@ip:/caminho/central_data"` |

### Fluxo Lógico do Scanner
1. Verifica a base de dados local (`database.json`). Se vazia, faz scan total.
2. Fica a aguardar o tempo do `--interval`.
3. Executa um scan ARP rápido. Se detetar MACs novos, faz auditoria profunda **apenas** a esses IPs.
4. Se o argumento `--sync-dest` estiver definido, envia automaticamente o JSON atualizado para a consola central via `rsync`.
5. Ao escreveres `fim` no terminal, gera relatórios finais HTML e CSV.

---

## 📊 4. dashboard.py (Consola Central)

A consola central é a interface gráfica onde toda a informação recolhida se junta. Pode ler dados recebidos via rsync (pasta `./central_data`) ou via upload manual (Drag & Drop).

**Comando para iniciar:**
```bash
streamlit run dashboard.py
```

### Funcionalidades do Dashboard:
- **Visão Global:** Métricas de hosts totais, hosts suspeitos e sistemas operativos.
- **Inspetor de Portas:** Permite detalhar as portas abertas e vulnerabilidades de um IP específico.
- **Gráficos Interativos (Plotly):** Distribuição por fabricantes, estados de segurança e linhas temporais.
- **Exportação Master:** Cria um ficheiro JSON ou CSV agregando dados de *todos* os sensores da rede num só documento.
