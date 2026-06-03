# WG Tunnel

**Gerenciador de túnel WireGuard com painel web** — exponha serviços do seu homelab no IP público de uma VPS, incluindo o IP de saída de processos específicos (resolve CGNAT e anúncio de IP para servidores de jogo).

---

## Como funciona

```
Internet → VPS (IP público) → WireGuard → Homelab
               ↑
         DNAT automático por porta
         Controle de expose por processo
         Painel web para gerenciar tudo
```

O homelab conecta à VPS via WireGuard. A partir do painel web na VPS você:

- **Cria peers** e baixa os `.conf` gerados
- **Redireciona portas** — o tráfego que chega na VPS é enviado automaticamente ao peer via DNAT
- **Expõe processos** — força o tráfego de saída de um processo específico pelo túnel, fazendo ele anunciar o IP da VPS (útil para servidores de jogo atrás de CGNAT)

O agente no homelab aplica as configurações de expose automaticamente, sem intervenção manual.

---

## Componentes

| Componente | Onde roda | Descrição |
|---|---|---|
| `server/` | VPS | Painel web + API REST + gerenciamento WireGuard/iptables |
| `agent/` | Homelab | Daemon que sincroniza com o server e aplica policy routing |

---

## Setup — VPS

### Pré-requisitos

```bash
apt install wireguard-tools docker.io docker-compose-plugin
```

### 1. Configurar

```bash
git clone https://github.com/seu-usuario/wg-tunnel
cd wg-tunnel/server

cp .env.example .env
nano .env
```

Descubra sua interface de rede pública:

```bash
ip route get 8.8.8.8 | awk '{print $5; exit}'
```

### 2. Subir

```bash
docker compose up -d
docker compose logs -f
```

O token de acesso aparece nos logs:

```
🔑 Token de acesso: abc123def456...
```

Acesse o painel em `http://<IP_DA_VPS>:8080`.

> **Recomendado:** coloque o painel atrás de um reverse proxy com HTTPS (Caddy, nginx, Traefik).

---

## Setup — Homelab

### 1. No painel web

1. Clique em **Novo peer**
2. Dê um nome (ex: `homelab`) e marque **Gateway**
3. Clique em **↓ .conf** para baixar a configuração

### 2. No homelab

```bash
apt install wireguard-tools golang

# Cole o conteúdo do .conf baixado:
nano /etc/wireguard/wg0.conf

# Compile e instale o agente:
cd wg-tunnel/agent
bash install.sh
```

### 3. Configure o agente

Abra o modal **⇡ Expor** no painel web e copie o token do peer. Edite o serviço:

```bash
nano /etc/systemd/system/wgtunnel-agent.service
# Preencha SERVER_URL e AGENT_TOKEN

systemctl daemon-reload
systemctl enable --now wgtunnel-agent
```

Pronto. A partir daqui, tudo é pelo painel.

---

## Expor portas

No painel, aba **Portas** → **+ Adicionar porta**.

Exemplo para um servidor DayZ:

| Proto | Porta VPS | Peer | Porta destino |
|---|---|---|---|
| UDP | 27015 | homelab | 27015 |

O DNAT é aplicado na VPS imediatamente.

---

## Expor processos (forçar IP de saída)

Útil quando o serviço anuncia seu próprio IP (servidores de jogo, torrents, etc.) e você precisa que ele anuncie o IP da VPS.

No painel, clique em **⇡ Expor** no peer gateway → adicione o nome do processo (ex: `DayZServer`) → **Salvar**.

O agente detecta a mudança em até 10 segundos, localiza o processo por nome e move seu tráfego de saída pelo túnel via cgroup + policy routing. Se o processo reiniciar, o agente reconfigura automaticamente no próximo ciclo.

---

## Variáveis do servidor

| Variável | Padrão | Descrição |
|---|---|---|
| `VPS_PUBLIC_IP` | — | IP público da VPS **(obrigatório)** |
| `NET_IFACE` | `eth0` | Interface de rede pública |
| `WG_PORT` | `51820` | Porta WireGuard |
| `WG_IFACE` | `wg0` | Nome da interface WireGuard |

## Variáveis do agente

| Variável | Padrão | Descrição |
|---|---|---|
| `SERVER_URL` | — | URL do servidor **(obrigatório)** |
| `AGENT_TOKEN` | — | Token do peer gerado no painel **(obrigatório)** |
| `WG_IFACE` | `wg0` | Interface WireGuard |
| `VPS_WG_IP` | `10.10.0.1` | IP da VPS no túnel |
| `RT_TABLE` | `200` | Tabela de roteamento para policy routing |
| `FWMARK` | `0x64` | Fwmark para marcação de pacotes |
| `POLL_INTERVAL` | `10` | Segundos entre sincronizações com o servidor |

---

## Segurança

- O token de acesso fica em `/data/token.txt` — guarde-o em local seguro
- Chaves privadas WireGuard nunca são expostas pela API (somente via download do `.conf`)
- `network_mode: host` é necessário para o iptables funcionar corretamente
- Recomendado: coloque o painel atrás de HTTPS antes de expor na internet

---

---

# WG Tunnel

**WireGuard tunnel manager with a web panel** — expose your homelab services on a VPS public IP, including the outbound IP of specific processes (solves CGNAT and IP announcement issues for game servers).

---

## How it works

```
Internet → VPS (public IP) → WireGuard → Homelab
                ↑
          Automatic DNAT per port
          Per-process expose control
          Web panel to manage everything
```

The homelab connects to the VPS over WireGuard. From the web panel on the VPS you can:

- **Create peers** and download generated `.conf` files
- **Forward ports** — inbound traffic on the VPS is automatically forwarded to the peer via DNAT
- **Expose processes** — forces a specific process's outbound traffic through the tunnel, making it announce the VPS IP (useful for game servers behind CGNAT)

The agent on the homelab applies expose configuration automatically, with no manual intervention required.

---

## Components

| Component | Runs on | Description |
|---|---|---|
| `server/` | VPS | Web panel + REST API + WireGuard/iptables management |
| `agent/` | Homelab | Daemon that syncs with the server and applies policy routing |

---

## Setup — VPS

### Prerequisites

```bash
apt install wireguard-tools docker.io docker-compose-plugin
```

### 1. Configure

```bash
git clone https://github.com/your-user/wg-tunnel
cd wg-tunnel/server

cp .env.example .env
nano .env
```

Find your public network interface:

```bash
ip route get 8.8.8.8 | awk '{print $5; exit}'
```

### 2. Start

```bash
docker compose up -d
docker compose logs -f
```

The access token appears in the logs:

```
🔑 Token de acesso: abc123def456...
```

Access the panel at `http://<VPS_IP>:8080`.

> **Recommended:** put the panel behind a reverse proxy with HTTPS (Caddy, nginx, Traefik).

---

## Setup — Homelab

### 1. In the web panel

1. Click **Novo peer**
2. Give it a name (e.g. `homelab`) and check **Gateway**
3. Click **↓ .conf** to download the configuration

### 2. On the homelab

```bash
apt install wireguard-tools golang

# Paste the contents of the downloaded .conf:
nano /etc/wireguard/wg0.conf

# Build and install the agent:
cd wg-tunnel/agent
bash install.sh
```

### 3. Configure the agent

Open the **⇡ Expor** modal in the web panel and copy the peer token. Edit the service file:

```bash
nano /etc/systemd/system/wgtunnel-agent.service
# Fill in SERVER_URL and AGENT_TOKEN

systemctl daemon-reload
systemctl enable --now wgtunnel-agent
```

Done. Everything from here on is managed through the panel.

---

## Port forwarding

In the panel, go to the **Portas** tab → **+ Adicionar porta**.

Example for a DayZ server:

| Proto | VPS Port | Peer | Destination Port |
|---|---|---|---|
| UDP | 27015 | homelab | 27015 |

The DNAT rule is applied on the VPS immediately.

---

## Process expose (force outbound IP)

Useful when a service announces its own IP (game servers, torrents, etc.) and you need it to announce the VPS IP instead.

In the panel, click **⇡ Expor** on the gateway peer → add the process name (e.g. `DayZServer`) → **Salvar**.

The agent detects the change within 10 seconds, finds the process by name, and routes its outbound traffic through the tunnel via cgroup + policy routing. If the process restarts, the agent reconfigures automatically on the next poll cycle.

---

## Server environment variables

| Variable | Default | Description |
|---|---|---|
| `VPS_PUBLIC_IP` | — | VPS public IP **(required)** |
| `NET_IFACE` | `eth0` | Public network interface |
| `WG_PORT` | `51820` | WireGuard listen port |
| `WG_IFACE` | `wg0` | WireGuard interface name |

## Agent environment variables

| Variable | Default | Description |
|---|---|---|
| `SERVER_URL` | — | Server URL **(required)** |
| `AGENT_TOKEN` | — | Peer token generated in the panel **(required)** |
| `WG_IFACE` | `wg0` | WireGuard interface |
| `VPS_WG_IP` | `10.10.0.1` | VPS IP inside the tunnel |
| `RT_TABLE` | `200` | Routing table ID for policy routing |
| `FWMARK` | `0x64` | Packet mark for routing |
| `POLL_INTERVAL` | `10` | Seconds between server syncs |

---

## Security

- The access token is stored at `/data/token.txt` — keep it safe
- WireGuard private keys are never exposed through the API (only via `.conf` download)
- `network_mode: host` is required for iptables to work correctly
- Recommended: put the panel behind HTTPS before exposing it to the internet
