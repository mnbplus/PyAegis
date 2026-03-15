# PyAegis MCP Integration

PyAegis exposes its security-scanning engine as an [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server, allowing AI agents such as **Claude Desktop** and **Cursor** to call PyAegis tools directly during code generation or review.

---

## Available Tools

| Tool | Description |
|---|---|
| `scan_code` | Scan a Python code string for security vulnerabilities |
| `scan_file` | Scan a Python file on disk |
| `explain_finding` | Explain a rule ID and provide remediation advice |
| `list_rules` | List all built-in detection rules |

---

## Installation

Install PyAegis with the MCP extra:

```bash
pip install pyaegis[mcp]
# or with uv
uv add "pyaegis[mcp]"
```

---

## Configuring Claude Desktop

### 1. Find the config file

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

Create the file if it does not exist.

### 2. Add the PyAegis MCP server

```json
{
  "mcpServers": {
    "pyaegis": {
      "command": "python",
      "args": ["-m", "pyaegis.mcp_server"],
      "env": {}
    }
  }
}
```

If you use `uv`:

```json
{
  "mcpServers": {
    "pyaegis": {
      "command": "uv",
      "args": ["run", "--with", "pyaegis[mcp]", "python", "-m", "pyaegis.mcp_server"]
    }
  }
}
```

### 3. Restart Claude Desktop

After saving the config, restart Claude Desktop. You should see a hammer icon (🔨) in the chat interface indicating MCP tools are available.

---

## Configuring Cursor

Cursor supports MCP servers via its settings.

### Option A — `~/.cursor/mcp.json` (user-level, all projects)

Create or edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "pyaegis": {
      "command": "python",
      "args": ["-m", "pyaegis.mcp_server"]
    }
  }
}
```

### Option B — `.cursor/mcp.json` (project-level)

Add the same JSON inside a `.cursor/mcp.json` file at the root of your project. This scopes the server to that project only.

### Enabling in Cursor settings

1. Open **Cursor Settings** → **Features** → **MCP**.
2. Verify that `pyaegis` appears in the server list and shows a green status indicator.
3. In Agent mode, Cursor will automatically call PyAegis tools when relevant.

---

## Example: Asking Claude to Scan Generated Code

After configuring Claude Desktop, you can ask Claude to scan code it has just written:

### Prompt example

```
You just generated a Flask API endpoint for me. Before I use it,
please run scan_code on it and fix any security issues PyAegis finds.
```

### What happens

1. Claude calls `scan_code` with the generated Python code.
2. PyAegis runs taint-analysis and returns findings as JSON, for example:

```json
{
  "status": "issues_found",
  "count": 1,
  "findings": [
    {
      "filename": "<string>",
      "line": 8,
      "severity": "CRITICAL",
      "rule_id": "PYA-002",
      "sink_name": "cursor.execute",
      "source_var": "user_id",
      "message": "SQL injection via tainted data",
      "sink_context": "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)"
    }
  ]
}
```

3. Claude calls `explain_finding` with `rule_id: "PYA-002"` to understand the issue.
4. Claude fixes the code and explains the change to you.

### Another useful prompt

```
List all PyAegis rules (list_rules), then scan this file: /path/to/app.py
For every HIGH or CRITICAL finding, call explain_finding and suggest a fix.
```

---

## Running the Server Manually (for testing)

```bash
# stdio mode (used by Claude Desktop and Cursor)
python -m pyaegis.mcp_server

# Test with the MCP Inspector
npx -y @modelcontextprotocol/inspector python -m pyaegis.mcp_server
```

The inspector opens a web UI at `http://localhost:5173` where you can call tools interactively.

---

## Severity Levels

| Level | Meaning |
|---|---|
| `CRITICAL` | Immediate exploitation risk (SQLi, CMDi, RCE) |
| `HIGH` | Serious risk, should be fixed before shipping |
| `MEDIUM` | Notable weakness, fix when possible |
| `LOW` | Minor issue or best-practice deviation |

Pass `severity_filter: ["HIGH", "CRITICAL"]` to `scan_code` / `scan_file` to focus on the most important issues.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Server not appearing in Claude Desktop | Check JSON syntax in `claude_desktop_config.json`; restart Claude |
| `ImportError: mcp` | Run `pip install pyaegis[mcp]` |
| `ImportError: pyaegis` | Run `pip install pyaegis` |
| No findings returned | Try without `severity_filter`; ensure the file contains Python code |
| stdio corruption / blank responses | Never `print()` inside `mcp_server.py`; use `logging` to stderr only |
