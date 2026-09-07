---
title: "Official Model Context Protocol (MCP) Server"
summary: "Setup guide and configurations for connecting Cursor, VS Code, Claude Desktop, Windsurf, Zed, and Antigravity to the official EAF MCP server."
public_url: "https://docs.echteralsfake.me/#mcp"
aliases:
  - "EAF MCP Server"
  - "Official MCP Server"
keywords:
  - "MCP"
  - "Model Context Protocol"
  - "Cursor"
  - "Claude Desktop"
  - "VS Code"
  - "Copilot"
  - "Windsurf"
  - "Zed"
  - "Antigravity"
---

# Official Model Context Protocol (MCP) Server

Connect your AI coding assistant directly to the official, hosted Model Context Protocol (MCP) server for the EchterAlsFake Python API ecosystem.

## Server Endpoint
`https://mcp.echteralsfake.me/mcp`

## Why Use the MCP Server?

Using the MCP server with an AI coding assistant in your development workflow will **greatly improve how you can work with the APIs and is absolutely the recommended way to work on the projects**.

Scraper APIs and asynchronous media engines have nuanced interfaces, dynamic source-loading mechanisms (e.g. `load_sources("html")`), typed result unwrap contracts, and strict error handling hierarchies. Standard AI models without MCP frequently hallucinate removed v3 patterns (e.g. `fetch()`, `result.video`, `proxies` dictionaries).

When connected to this MCP server, your AI assistant receives:
- **Up-to-date, live API documentation and tool definitions**
- **Complete coverage across all 16 packages** (`eaf_base_api` + all 15 scrapers)
- **Accurate method signatures, arguments, and return types**
- **Idiomatic async code patterns and error handling guidance**

## Key Features

- **No authentication required** — Free, open access with no tokens, signups, or API keys needed.
- **No strict rate limits** — Smooth, uninterrupted pair-programming experience.
- **Always up to date** — Automatically tracks upstream codebase changes and new releases.
- **Completely anonymous** — Zero IP logs, zero query retention, zero profiling. Complete privacy.

---

## Editor Configuration & Setup Guides

### 1. Cursor

Add to `.cursor/mcp.json` in your project root, or configure via **Cursor Settings > Features > MCP**:

```json
{
  "mcpServers": {
    "eaf-apis": {
      "url": "https://mcp.echteralsfake.me/mcp"
    }
  }
}
```

### 2. VS Code (GitHub Copilot / Cline / Roo Code / Continue)

Add to `.vscode/mcp.json` in your workspace or configure in your extension settings:

```json
{
  "servers": {
    "eaf-apis": {
      "url": "https://mcp.echteralsfake.me/mcp",
      "type": "sse"
    }
  }
}
```

Alternatively, if your client uses `mcp-remote` over stdio:

```json
{
  "servers": {
    "eaf-apis": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://mcp.echteralsfake.me/mcp"]
    }
  }
}
```

### 3. Claude Desktop

Add to `claude_desktop_config.json`:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "eaf-apis": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://mcp.echteralsfake.me/mcp"]
    }
  }
}
```

### 4. Windsurf (Codeium)

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "eaf-apis": {
      "serverUrl": "https://mcp.echteralsfake.me/mcp"
    }
  }
}
```

### 5. Zed

Add to `~/.config/zed/settings.json`:

```json
{
  "context_servers": {
    "eaf-apis": {
      "url": "https://mcp.echteralsfake.me/mcp"
    }
  }
}
```

### 6. Antigravity / Gemini CLI

Add via the CLI tool:

```bash
agy mcp add eaf-apis --url https://mcp.echteralsfake.me/mcp
```

Or add directly to your workspace configuration:

```json
{
  "mcp_servers": {
    "eaf-apis": {
      "url": "https://mcp.echteralsfake.me/mcp"
    }
  }
}
```

---

## Related MCP documents

- [EAF Python API documentation overview](overview.md)
- [Overview — eaf_base_api](eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/#mcp](https://docs.echteralsfake.me/#mcp)
