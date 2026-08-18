# VulnVerse AI Security Academy

A structured, hands-on AI security learning platform — Prompt Injection, RAG Security,
AI Agent Security, MCP Security, AI Evasion, and 14 modules from beginner to advanced.

The platform combines:
 
- **14 structured theory modules** (Beginner → Advanced) covering everything from AI/ML fundamentals to Multi-Agent Security, MCP Security, Embeddings & Vector DB attacks, and AI Infrastructure.
- **Interactive quizzes** to reinforce concepts after every module.
- **Realistic vulnerable labs** — full product-style UIs (an IDE, a package registry, a shopping assistant, a sprint manager, and more) each hiding a real, chainable vulnerability class: Prompt Injection, IDOR/BOLA, SMTP injection, MCP tool abuse, agent memory poisoning, and supply chain attacks.
- A consistent **Learn → Understand → Analyze → Exploit → Detect → Mitigate → Practice** flow, so every topic goes from concept to hands-on exploitation to defensive understanding.

## Demo

https://github.com/user-attachments/assets/d45cdfe9-569e-4779-8d7d-0d758a7ce0f5


## Requirements

- Docker Must Be Installed
- https://ollama.com if using local models, OR an API key from a cloud LLM provider
- A few GB of free disk space minimum 45-50GB

## Quick Start

```bash
# First Install Docker
sudo apt-get update
sudo apt-get install docker.io
sudo apt-get install docker-compose

# Then Download and run setup.sh 
git clone https://github.com/sahil0921/VulnVerse-AI-Security-Academy.git
cd VulnVerse-AI-Security-Academy
./setup.sh

## Running individual labs
 
# If you have a low-end system or limited disk space, you don't need to build everything at once — build and run only the labs you actually need, one at a time.
 
# Same two-command pattern works for everything, including the hub:

docker compose build <name>
docker compose up -d <name>

 
# Example — run only theory + frontend (lab-hub):**

docker compose build lab-hub
docker compose up -d lab-hub

 
# Example — run a specific lab (e.g. RAG lab):**

docker compose build rag-lab
docker compose up -d rag-lab
```
 
> Start `lab-hub` first — it's needed regardless of which other labs you run.


### Available labs
 
| Category | Lab folders |
|---|---|
| Main Web App | `nimbletech-web` |
| Prompt Injection Labs | `support-chatbot`, `email-assistant`, `url-summarizer`, `order-bot`, `jailbreak-lab` |
| Agent Labs | `agent-helpdesk`, `agent-docprocessor`, `agent-browser`, `agent-codereview`, `agent-memory`, `supply-chain-lab`, `idor` |
| Multi-Agent (A2A) | `multiagent` |
| Recon Target | `recon-target` |
| RAG Pipeline Lab | `rag-lab` |
| LLM Output Attacks | `output-xss-reflected`, `output-xss-stored`, `output-sqli`, `output-codeinj`, `output-funccall`, `output-exfil` |
| AI Data Attacks Lab | `data-attacks-lab`, `llm-hallucination`, `llm-abuse`, `llm-safeguards` |
| MCP Attacks | `mcp-recon`, `mcp-poisoning`, `mcp-apps-ui`, `mcp-permissions`, `mcp-chaining` |
| AI Evasion Attacks Labs | `evasion-spam-wb`, `evasion-spam-bb`, `evasion-sentiment` |
| Embedding Attack Labs | `embedding-recon`, `embedding-export`, `embedding-invert-zeroshot`, `embedding-invert-beam`, `embedding-invert-algen`, `embedding-invert-vec2text`, `embedding-membership` |
| AI Infrastructure | `cloud-ssrf-lab` |
| Threat Modeling | `threat-modeling` |
| Final Assessment | `capstone-chatbot`, `capstone-rag-agent` |
| Hub Dashboard | `lab-hub` |

`setup.sh` will interactively ask for your Ollama host / LLM provider / API key / model,
then build and start everything. Once done, open: **http://localhost:8080**

## Scripts

### Linux (bash)

| Script | What it does |
|---|---|
| `./setup.sh` | Run once — interactive wizard (Ollama/API config) + builds images + starts containers |
| `./resume.sh` | Everyday on/off — starts existing containers back up (no rebuild) |
| `./stop.sh` | Stop the lab (data stays safe) |
| `./clean.sh` | **Permanent** — deletes everything (containers+volumes+images), frees disk space. Asks for confirmation |
| `./change.sh` | Change Ollama host / LLM provider / model / API key later, without redoing full setup |
| `./status.sh` | Shows running containers + disk usage |


### Windows (PowerShell)

Same scripts, `.ps1` versions, same behavior. Requires Docker Desktop with the WSL2
or Hyper-V backend

| Script | What it does |
|---|---|
| `.\setup.ps1` | Run once — interactive wizard + builds images + starts containers |
| `.\resume.ps1` | Everyday on/off — starts existing containers back up (no rebuild) |
| `.\stop.ps1` | Stop the lab (data stays safe) |
| `.\clean.ps1` | **Permanent** — deletes everything, frees disk space. Asks for confirmation |
| `.\change.ps1` | Change Ollama host / LLM provider / model / API key later |
| `.\status.ps1` | Shows running containers + disk usage |

If Windows blocks the scripts from running, open PowerShell as Administrator once and run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

Then run scripts normally, e.g. `.\setup.ps1`.

### Typical flow

```bash
./setup.sh      # once - interactive wizard
./stop.sh       # done for the day, stop the lab
./resume.sh     # next day, back up
./change.sh     # switch model, update API key, etc.
./resume.sh     # apply the change (recreates containers)
./clean.sh      # when you want to remove it for good

# Note - same goes for Windows .ps1 versions
```

## Configuration

All settings live in `.env`, generated by `setup.sh or setup.ps1`:

```
OLLAMA_HOST=http://<ip>:<port>
LLM_PROVIDER=ollama | api
LLM_MODEL=<model name>
API_PROVIDER=claude | openai | gemini | nvidia | openrouter   # only if LLM_PROVIDER=api
API_KEY=<your key>                                              # only if LLM_PROVIDER=api
```

Use `./change.sh` (or `.\change.ps1`) any time to update these without re-running the
full wizard.

## Why VulnVerse?

Most AI security resources are either purely theoretical (research papers, blog posts) or too narrow (a single CTF-style challenge). VulnVerse bridges that gap with a full academy structure — designed for security professionals, bug bounty hunters, and AppSec engineers who want to extend their existing pentesting skillset into AI/LLM systems.

Built and maintained as an independent project — feedback, issues, and contributions welcome.


## License

MIT License — Copyright (c) 2026 Sahil
