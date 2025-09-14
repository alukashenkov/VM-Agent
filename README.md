# VM-Agent

A mockup vulnerability analysis tool that uses AI agents to research and analyze security vulnerabilities using the Vulners database and internet intelligence.

![License](https://img.shields.io/badge/License-AGPL--3.0-blue)

![Orchestration](https://img.shields.io/badge/Orchestration-CrewAI-673ab7)
![Model](https://img.shields.io/badge/Model-gpt--4o-00bcd4)
![Agents](https://img.shields.io/badge/Agents-7-9c27b0)
![Tasks](https://img.shields.io/badge/Tasks-7-3f51b5)
![Tools](https://img.shields.io/badge/Tools-3-009688)
![MCP](https://img.shields.io/badge/MCP-Vulners-795548)
![Web UI](https://img.shields.io/badge/Web%20UI-Auto%20opens%20browser-4caf50)
![Framework](https://img.shields.io/badge/Framework-Flask-000?logo=flask)
![Logs](https://img.shields.io/badge/Logs-SSE%20live%20streaming-ff9800)

![VM-Agent Web UI](images/VM-Agent%20WebUI.png)

> Tested with OpenAI model gpt-4o.

## Features

- **Multi-Agent Analysis**: Uses specialized AI agents for different aspects of vulnerability research
- **Vulners Database Integration**: Direct access to comprehensive vulnerability data via MCP
- **Internet Intelligence**: Augments database findings with real-time threat intelligence
- **Web Interface**: Simple web UI for easy interaction
- **Local Development**: Can be run directly as a Python script
- **Real-Time Logs**: Live console logs streamed to the web UI via SSE
- **Resizable Split UI**: Adjustable split view with live logs on the right

## Quick Start

### Local Development

1. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

2. **Set up environment variables**:

   ```bash
   cp env.example .env
   # Edit .env file with your API keys
   ```

3. **Run with the local runner (Recommended)**:

   ```bash
   # Launch web UI
   python run_local.py
   ```

4. **Alternative: Run components directly**:

   ```bash
   # Run the script directly
   python agent.py
   
   # Or run the web interface locally
   python web_app.py
   ```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | Your OpenAI API key | Required |
| `OPENAI_MODEL` | OpenAI model to use | `gpt-4o` |
| `SERPER_API_KEY` | Your Serper Search API key | Optional (enables web search) |
| `DEBUG` | Enable detailed logging | `False` |
| `HOST` | Web server host | `localhost` |
| `PORT` | Web server port | `8080` |
| `VULNERS_MCP_HOST` | MCP server host | `localhost` |
| `VULNERS_MCP_PORT` | MCP server port | `8000` |

### Example Prompts

- Analyze CVE-2025-7775
- Analyze CTX694938 and its security implications
- Analyze the latest exploited vulnerability in Citrix products

## Architecture

### AI Agents

1. **Research Strategy Planner**: Analyzes requests and plans optimal research workflow and tool sequence.
2. **Senior Vulnerability Researcher**: Primary Vulners MCP data collection and targeted web discovery.
3. **Exploit Intelligence Analyst**: Assesses exploitation status, EPSS, and evidence strength from shared data.
4. **Technical Exploitation Analyst**: Retrieves and summarizes detailed exploitation methodologies and PoCs when warranted.
5. **Cyber Threat Intelligence Researcher**: Augments with adversary/campaign TTPs from authoritative sources.
6. **Vulnerability Risk Scoring Analyst**: Produces quantitative risk score and uncertainty using evidence-based algorithm.
7. **Principal Security Analyst**: Synthesizes a concise narrative report with remediation guidance.

### Components

- **agents_definitions.py**: All agent, task, tool definitions and Crew setup
- **agent.py**: Core execution wrapper, logging, and configuration capture
- **web_app.py**: Flask web interface with SSE log streaming endpoints
- **run_local.py**: Local runner that sets up env and launches the web UI
- **templates/**: Frontend templates (primary page at `templates/index.html`)
- **requirements.txt**: Python dependencies (unpinned)
- **env.example**: Example environment variables file

## API Endpoints

### Web Interface

- `GET /`: Main web interface
- `POST /api/start_run`: Initialize a streaming session. Returns `{ "session_id": "..." }`.
- `GET /api/logs/stream?session_id=...`: Server-Sent Events (SSE) stream of live logs for the given session.
- `POST /api/analyze`: Submit analysis request. Accepts `prompt` and optional `session_id` (to stream logs).
- `GET /api/health`: Health check

### Request Format

```json
{
  "prompt": "Analyze CVE-2025-7775",
  "session_id": "optional-session-id-from-/api/start_run"
}
```

### Response Format

```json
{
  "success": true,
  "result": "Analysis result text...",
  "result_html": "HTML formatted analysis result...",
  "log_file": "/path/to/log/file.txt"
}
```

Flow for live logs:

1. `POST /api/start_run` → read `session_id`
2. Open `GET /api/logs/stream?session_id=...` (SSE)
3. `POST /api/analyze` with the same `session_id`

## Development

### Local Testing

```bash
# Run with local runner (recommended)
python run_local.py              # Web UI mode

# Run components directly
python agent.py                   # Script mode, update natural_prompt accordingly
DEBUG=True python agent.py        # Debug mode
```

## Troubleshooting

### Common Issues

1. **MCP Server**:
   - If using MCP-backed features, ensure your MCP server is reachable at `VULNERS_MCP_HOST:VULNERS_MCP_PORT`

2. **API Keys**:
   - Verify `OPENAI_API_KEY` is set correctly
   - Optionally set `SERPER_API_KEY` to enable web search

3. **Logging**:
   - Set `DEBUG=True` for detailed output
   - Log files are named `vm_agent_log_at_YYYY-MM-DDTHH-MM-SS.txt`
   - Check log files in mounted volume

### Health Checks

```bash
# Check web interface
curl http://localhost:8080/api/health

# Check MCP server
curl http://localhost:8000/health
```

## Security Notes

- API keys are stored as environment variables
- Web interface runs on internal network by default
- Consider reverse proxy for production deployment
- Log files may contain sensitive information

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

See the LICENSE file for the full text of the license.
