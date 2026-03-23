# Starter Packs

Ready-made Heddle configs for common services. Copy one to `agents/`, update the URL, and run it.

## Available Packs

| Pack | Tools | Trust | What It Does |
|------|-------|-------|-------------|
| [prometheus.yaml](prometheus.yaml) | 5 | T1 (read-only) | PromQL queries, target health, alerts, metric discovery |
| [grafana.yaml](grafana.yaml) | 5 | T1 (read-only) | Dashboards, datasources, alert rules, health |
| [git-forge.yaml](git-forge.yaml) | 3 | T1 (read-only) | Repos, issues, repo details (Gitea/GitHub/Forgejo) |
| [ollama.yaml](ollama.yaml) | 4 | T2 (worker) | Model listing, VRAM status, text generation, model info |
| [sonarr.yaml](sonarr.yaml) | 6 | T1 (read-only) | TV library, download queue, search, calendar, history |
| [radarr.yaml](radarr.yaml) | 6 | T1 (read-only) | Movie library, download queue, search, calendar, history |

## Usage

```bash
# 1. Copy a pack
cp packs/prometheus.yaml agents/

# 2. Edit the base URL if needed (default: localhost)
vim agents/prometheus.yaml

# 3. Validate
heddle validate agents/prometheus.yaml

# 4. Run
heddle run agents/prometheus.yaml --port 8200
```

## Credentials

Some packs require authentication. Heddle keeps secrets out of config files:

```bash
# Store a secret
heddle secrets set grafana-auth "Bearer glsa_xxxx"

# Grant access to a specific config
heddle secrets grant grafana grafana-auth

# Verify policy
heddle secrets policy
```

Configs reference secrets with `{{secret:key}}` — resolved at runtime, never written to disk.

## Customizing

Every pack is a standard Heddle YAML config. You can:

- Add tools by adding entries to `exposes` and `http_bridge`
- Change the trust tier in `runtime.trust_tier`
- Add `access: write` to tools that modify state
- Add credential headers with `{{secret:key}}` templates
- Combine multiple packs into a single mesh with `heddle mesh agents/`

## Creating Your Own

```bash
# Generate a config from natural language (requires Ollama)
heddle generate "agent that wraps the PagerDuty API" --model qwen3:14b

# Or start from a pack and modify it
cp packs/prometheus.yaml agents/my-custom-monitor.yaml
```
