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
  - "Claude Code"
  - "VS Code"
  - "Copilot"
  - "Cline"
  - "Roo Code"
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

Add to `.cursor/mcp.json` in your project root, or globally in `~/.cursor/mcp.json` (or configure via **Cursor Settings > Features > MCP**):

```json
{
  "mcpServers": {
    "eaf-apis": {
      "url": "https://mcp.echteralsfake.me/mcp"
    }
  }
}
```

If your Cursor client requires bridging over stdio, use `mcp-remote`:

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

### 2. VS Code (GitHub Copilot / Native MCP)

Add to `.vscode/mcp.json` in your workspace, or user-level configuration via the Command Palette (**MCP: Open User Configuration**):

```json
{
  "servers": {
    "eaf-apis": {
      "type": "http",
      "url": "https://mcp.echteralsfake.me/mcp"
    }
  }
}
```

Alternatively, if running through the `mcp-remote` stdio bridge:

```json
{
  "servers": {
    "eaf-apis": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://mcp.echteralsfake.me/mcp"]
    }
  }
}
```

### 3. VS Code Extensions (Cline & Roo Code)

Extensions such as **Cline** and **Roo Code** use the `mcpServers` object format (not `servers`).

Configure in Cline (`cline_mcp_settings.json` via Cline MCP panel) or Roo Code (`.roo/mcp.json` or `mcp_settings.json`):

```json
{
  "mcpServers": {
    "eaf-apis": {
      "url": "https://mcp.echteralsfake.me/mcp"
    }
  }
}
```

Or via stdio bridge:

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

### 4. Claude Desktop & Claude Code

#### Claude Desktop
Claude Desktop connects to remote servers via a local `stdio` bridge. Add to `claude_desktop_config.json`:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

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

#### Claude Code (CLI)
Add via the Claude Code CLI tool:

```bash
claude mcp add --transport http eaf-apis https://mcp.echteralsfake.me/mcp
```

### 5. Windsurf (Codeium)

Add to `~/.codeium/windsurf/mcp_config.json` (macOS/Linux) or `%USERPROFILE%\.codeium\windsurf\mcp_config.json` (Windows):

```json
{
  "mcpServers": {
    "eaf-apis": {
      "serverUrl": "https://mcp.echteralsfake.me/mcp"
    }
  }
}
```

Or via stdio bridge (`mcp-remote`):

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

### 6. Zed

Add to `~/.config/zed/settings.json` (or configure via **Settings > AI > Context Servers / MCP Servers**):

```json
{
  "context_servers": {
    "eaf-apis": {
      "url": "https://mcp.echteralsfake.me/mcp"
    }
  }
}
```

### 7. Antigravity / Gemini CLI

Add via the CLI tool:

```bash
agy mcp add eaf-apis https://mcp.echteralsfake.me/mcp
```

> **Note:** Flags must precede `<name>`, and URLs are detected automatically—do **not** pass a `--url` flag (e.g. `agy mcp add eaf-apis --url ...` is rejected as an invalid command).

Or add directly to your global configuration (`~/.gemini/config/mcp_config.json`):

```json
{
  "mcpServers": {
    "eaf-apis": {
      "serverUrl": "https://mcp.echteralsfake.me/mcp"
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
