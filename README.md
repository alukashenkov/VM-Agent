# VM-Agent

An advanced multi-agent vulnerability analysis system that leverages AI agents to research and analyze security vulnerabilities using the Vulners database and internet intelligence. Built with the latest CrewAI capabilities and FastMCP 2.0 Framework support.

![License](https://img.shields.io/badge/License-AGPL--3.0-blue)

![Orchestration](https://img.shields.io/badge/Orchestration-CrewAI%20Latest-673ab7)
![MCP Framework](https://img.shields.io/badge/MCP-FastMCP%202.0-ff6f00)
![Model](https://img.shields.io/badge/Model-gpt--4o-00bcd4)
![LLM Engine](https://img.shields.io/badge/LLM-LiteLLM-9c27b0)
![Agents](https://img.shields.io/badge/Agents-7-9c27b0)
![Tasks](https://img.shields.io/badge/Tasks-7-3f51b5)
![Tools](https://img.shields.io/badge/Tools-Dynamic%20Discovery-009688)
![MCP](https://img.shields.io/badge/MCP-Vulners-795548)
![Web UI](https://img.shields.io/badge/Web%20UI-Auto%20opens%20browser-4caf50)
![Framework](https://img.shields.io/badge/Framework-Flask-000?logo=flask)
![Logs](https://img.shields.io/badge/Logs-SSE%20live%20streaming-ff9800)

![VM-Agent Web UI](images/VM-Agent%20WebUI.png)

> Built with the latest CrewAI framework capabilities and FastMCP 2.0 for advanced MCP server integration.
> Tested with OpenAI model gpt-4o and LiteLLM engine.

## Features

### Core Capabilities

- **Multi-Agent Analysis**: 7 specialized AI agents for comprehensive vulnerability research with sequential orchestration
- **Latest CrewAI Framework**: Built on CrewAI's latest capabilities including:
  - Native MCPServerAdapter for seamless MCP integration
  - Agent caching and delegation for efficient collaboration
  - LiteLLM integration for flexible model selection
  - Advanced task orchestration with sequential processing
  
### FastMCP 2.0 Framework Support

- **Dynamic MCP Tool Discovery**: Automatically discovers and loads tools from MCP servers using JSON-RPC protocol
- **Streamable HTTP Transport**: Native support for FastMCP 2.0's streamable-http transport protocol
- **Server-Provided Descriptions**: Tool schemas and descriptions come directly from the MCP server
- **Dual Endpoint Support**: Works with both `/mcp` (standard) and `/sse` (FastMCP 2.0) endpoints
- **Easy Server Switching**: Change MCP servers by updating one environment variable
- **Connection Pooling**: Maintains persistent MCP server connections for optimal performance

### Intelligence Gathering

- **Vulners Database Integration**: Direct access to comprehensive vulnerability data via MCP protocol
- **Internet Intelligence**: Augments database findings with real-time threat intelligence using SerperDevTool
- **Strategic Research Planning**: AI-driven research strategy optimization based on request analysis
- **Comprehensive CVE Analysis**: Full vulnerability profiles with CVSS, EPSS, exploitation evidence, and remediation
- **Threat Actor Attribution**: Validated threat intelligence with TTP analysis and MITRE ATT&CK mappings
- **Quantitative Risk Scoring**: Evidence-based risk scoring with uncertainty metrics

### User Interface

- **Modern Web Interface**: Clean, responsive web UI built with Flask
- **Real-Time Log Streaming**: Live console logs streamed to the web UI via Server-Sent Events (SSE)
- **Resizable Split View**: Adjustable split interface with analysis results and live execution logs
- **Auto Browser Launch**: Automatically opens browser on startup for immediate access
- **Markdown Rendering**: Beautiful rendering of analysis reports with syntax highlighting
- **Local Development**: Can be run directly as a Python script or via web interface

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
| `VULNERS_MCP_URL` | Full MCP server endpoint URL | `http://localhost:8000/mcp` |

**MCP Server Configuration (FastMCP 2.0):**

Set `VULNERS_MCP_URL` to your MCP server's full endpoint URL (include the endpoint path):

```bash
# LA-Vulners-MCP (FastMCP 2.0 with streamable-http transport)
# Standard endpoint:
VULNERS_MCP_URL=http://localhost:8000/mcp

# FastMCP 2.0 SSE endpoint (recommended):
VULNERS_MCP_URL=http://localhost:8000/sse

# Remote MCP server
VULNERS_MCP_URL=http://your-server.com:8000/mcp
```

**Switching Between MCP Servers:**

VM-Agent uses CrewAI's native `MCPServerAdapter` with **FastMCP 2.0 Framework** support for seamless server switching:

1. Update the `VULNERS_MCP_URL` in your `.env` file
2. Restart VM-Agent
3. Agents will **automatically discover** all tools from the new MCP server
4. No code changes required - tools use schemas provided by the MCP server

**FastMCP 2.0 Framework Features:**

- **Streamable HTTP Transport**: Native support for `streamable-http` protocol
- **Persistent Connections**: Connection pooling via global MCP adapter for optimal performance
- **Dynamic Tool Loading**: Tools are cached after first discovery for fast subsequent access
- **Flexible Endpoints**: Supports both `/mcp` (JSON-RPC) and `/sse` (Server-Sent Events) endpoints
- **Server-Driven Schema**: Tool descriptions, parameters, and validation come directly from the MCP server

**How Tool Discovery Works:**

1. VM-Agent creates `MCPServerAdapter` with your MCP server URL at startup
2. Adapter connects using `streamable-http` transport protocol
3. Queries the MCP server using JSON-RPC `tools/list` method
4. Creates dynamic tool wrappers with server-provided descriptions and schemas
5. Agents call tools via JSON-RPC `tools/call` method through the adapter
6. Connection remains open for the lifetime of the application
7. **No hardcoded tool definitions needed!**

**Supported MCP Servers:**

- LA-Vulners-MCP (FastMCP 2.0-based)
- Any MCP server implementing streamable-http transport
- Standard HTTP-based MCP servers with JSON-RPC support

### Example Prompts

- Analyze CVE-2025-7775
- Analyze CTX694938 and its security implications
- Analyze the latest exploited vulnerability in Citrix products

## Architecture

### AI Agents (Sequential Orchestration)

VM-Agent employs a sophisticated multi-agent architecture with **7 specialized agents** working in sequence, powered by the latest CrewAI framework capabilities:

1. **Research Strategy Planner** (`temperature: 0.1`)
   - Analyzes vulnerability research requests and creates optimized investigation strategies
   - Prioritizes Vulners database queries when identifiers are present
   - Plans internet discovery workflows for "latest/recent" vulnerability research
   - Ensures efficient resource allocation and systematic research methodology
   - **Tools**: None (strategic planning only)
   - **Delegation**: Disabled (pure planning role)

2. **Senior Vulnerability Researcher** (`temperature: 0.2`)
   - Executes research plans with comprehensive vulnerability intelligence gathering
   - Primary Vulners database interrogation using dynamically discovered MCP tools
   - Targeted internet research for identifier discovery and context enrichment
   - Processes related CVEs, vendor advisories, and security bulletins
   - **Tools**: All MCP tools (dynamic discovery) + SerperDevTool (web search)
   - **Delegation**: Enabled (collaborative research)
   - **Caching**: Enabled for performance optimization

3. **Exploit Intelligence Analyst** (`temperature: 0.15`)
   - Analyzes exploitation patterns, EPSS scores, and exploit document evidence
   - Processes shared Vulners data without redundant API calls (memory-efficient)
   - Assesses exploitation timelines using ShadowServer and telemetry data
   - Evaluates risk predictions and exploit availability with recency analysis
   - **Tools**: MCP tools + SerperDevTool (for additional context)
   - **Delegation**: Enabled
   - **Caching**: Enabled

4. **Technical Exploitation Analyst** (`temperature: 0.2`)
   - Retrieves detailed technical exploitation information when exploitation evidence is strong
   - Analyzes proof-of-concept code, exploitation methodologies, and attack vectors
   - Extracts technical requirements, constraints, and mitigation bypass techniques
   - Prioritizes authoritative sources (GitHub, ExploitDB, security research)
   - **Tools**: MCP tools + SerperDevTool
   - **Delegation**: Enabled
   - **Caching**: Enabled
   - **Activation**: Conditional (based on exploitation evidence strength)

5. **Cyber Threat Intelligence Researcher** (`temperature: 0.25`)
   - Augments technical findings with verified threat intelligence
   - Researches threat actor attribution and attack campaigns
   - Analyzes comprehensive TTPs with MITRE ATT&CK framework mappings
   - Documents exploitation methodologies, lateral movement, and detection evasion
   - Validates intelligence against authoritative sources (CISA, security firms)
   - **Tools**: SerperDevTool (web search for threat intelligence)
   - **Delegation**: Enabled
   - **Caching**: Enabled

6. **Vulnerability Risk Scoring Analyst** (`temperature: 0.1`)
   - Generates quantitative risk scores using evidence-based algorithms
   - Processes aggregated RISK_INPUTS from all previous agents
   - Calculates Evidence (E), Popularity (P), Technical Exploitability (T), and EPSS (R) factors
   - Produces uncertainty metrics based on evidence quality and diversity
   - Applies recency weighting and patch availability adjustments
   - **Tools**: None (uses only shared data from previous tasks)
   - **Delegation**: Disabled (pure analytical role)
   - **Caching**: Enabled
   - **Output**: `{"value": X.X, "uncertainty": Y.Y}`

7. **Principal Security Analyst** (`temperature: 0.3`)
   - Synthesizes all research findings into comprehensive narrative reports
   - Integrates technical metrics, exploitation analysis, and threat intelligence
   - Features quantitative risk scores with detailed justification
   - Provides actionable remediation guidance prioritized by risk level
   - Writes in professional, flowing narrative paragraphs (not bullet points)
   - **Tools**: None (synthesis only)
   - **Delegation**: Enabled (can query other agents)
   - **Caching**: Enabled

### Agent Collaboration Features

- **Agent Delegation**: Agents can delegate questions to coworkers for collaborative research
- **Data Sharing**: Efficient sharing of tool outputs to avoid redundant API calls
- **RISK_INPUTS Protocol**: Each agent contributes structured risk data for scoring algorithm
- **Sequential Processing**: Tasks execute in order with full context from previous agents
- **Caching**: LLM response caching for improved performance and reduced costs

### Components

- **agents_definitions.py** (1,177 lines)
  - All 7 agent definitions with prompts and LLM configurations
  - 7 task definitions with detailed instructions
  - MCP tool discovery and initialization using `MCPServerAdapter`
  - SerperDevTool integration for web search
  - LiteLLM wrapper for CrewAI compatibility
  - Global MCP adapter for persistent connections
  - Crew setup with sequential processing

- **agent.py** (367 lines)
  - Core execution wrapper and orchestration
  - Comprehensive logging system (console + file)
  - Configuration capture and serialization
  - Crew configuration logging with LLM details
  - TeeStream implementation for simultaneous console/file output
  - ANSI escape sequence cleaning for log files
  - Execution context handling (console vs. web)

- **web_app.py** (257 lines)
  - Flask web interface with lazy agent loading
  - Server-Sent Events (SSE) log streaming
  - Session management with UUID tracking
  - Markdown rendering with syntax highlighting
  - Real-time log capture and streaming to browser
  - Health check endpoint
  - API endpoints for analysis requests

- **run_local.py** (144 lines)
  - Local development runner with auto browser launch
  - Environment setup and validation
  - Web server initialization and monitoring
  - Automatic browser opening on startup

- **templates/index.html**
  - Modern, responsive web UI
  - Resizable split view (results + logs)
  - Real-time SSE log streaming
  - Markdown rendering with code syntax highlighting
  - Loading states and error handling

- **requirements.txt**
  - `crewai` - Latest CrewAI framework
  - `crewai-tools[mcp]` - MCP integration for CrewAI
  - `litellm` - LLM abstraction layer
  - `python-dotenv` - Environment variable management
  - `flask` - Web framework
  - `markdown` - Markdown rendering
  - `Pygments` - Syntax highlighting

- **env.example**: Example environment configuration with MCP server URLs

### Technical Stack

- **Orchestration**: CrewAI (latest version) with sequential processing
- **MCP Integration**: FastMCP 2.0 Framework via `crewai-tools[mcp]` MCPServerAdapter
- **LLM Engine**: LiteLLM for flexible model support (OpenAI, Anthropic, etc.)
- **Web Framework**: Flask with Server-Sent Events (SSE) for real-time streaming
- **Transport Protocol**: Streamable HTTP for MCP server communication
- **Web Search**: SerperDevTool (CrewAI native implementation)
- **Logging**: Dual-stream logging (console + file) with ANSI escape cleaning
- **Frontend**: Vanilla JavaScript with SSE, Markdown rendering, and syntax highlighting

## MCP Integration Details

### FastMCP 2.0 Framework Architecture

VM-Agent leverages **CrewAI's native MCPServerAdapter** with full FastMCP 2.0 Framework support:

```python
# From agents_definitions.py (lines 79-132)
from crewai_tools import MCPServerAdapter

# Global MCP adapter for persistent connections
_mcp_adapter = None
_mcp_tools_cache = []

def get_mcp_tools():
    """Get tools from MCP server using CrewAI's built-in MCPServerAdapter."""
    global _mcp_adapter, _mcp_tools_cache
    
    # Configure MCP server with streamable-http transport
    server_params = {
        "url": mcp_endpoint,  # e.g., http://localhost:8000/mcp
        "transport": "streamable-http"
    }
    
    # Create persistent MCP adapter
    _mcp_adapter = MCPServerAdapter(server_params, connect_timeout=30)
    mcp_tools = _mcp_adapter.__enter__()  # Keep connection alive
    
    # Cache tools for performance
    _mcp_tools_cache = list(mcp_tools)
    return _mcp_tools_cache
```

### MCP Tool Discovery Flow

1. **Initialization** (Module Load Time)
   - `get_mcp_tools()` called when `agents_definitions.py` is imported
   - Creates `MCPServerAdapter` with server URL from `VULNERS_MCP_URL`
   - Configures `streamable-http` transport protocol
   - Sets 30-second connection timeout

2. **Connection Establishment**
   - Adapter connects to MCP server endpoint
   - Sends JSON-RPC `tools/list` request
   - Receives tool schemas with names, descriptions, and parameter definitions

3. **Tool Wrapper Creation**
   - Creates dynamic tool wrappers for each discovered tool
   - Preserves server-provided descriptions and parameter schemas
   - Tools are ready for immediate use by agents

4. **Tool Execution**
   - Agents call tools by name through the adapter
   - Adapter sends JSON-RPC `tools/call` requests
   - Parameters validated against server-provided schemas
   - Results returned directly to agents

5. **Connection Management**
   - Connection remains open for application lifetime
   - Tools cached after first discovery for performance
   - No reconnection overhead on subsequent requests

### Supported Tool Types

All tools discovered from the MCP server are automatically available to agents:

- CVE/vulnerability query tools (e.g., `bulletin_by_id`, `search_lucene`)
- Software audit tools (e.g., `audit_software`, `audit_linux_packages`)
- CPE search tools (e.g., `search_cpe`)
- Autocomplete/suggestion tools (e.g., `query_autocomplete`)
- Any custom tools exposed by your MCP server

## API Endpoints

### Web Interface

- **`GET /`** - Main web interface
  - Returns HTML page with resizable split view (results + live logs)
  - Auto-connects to SSE stream for real-time updates
  
- **`POST /api/start_run`** - Initialize a streaming session
  - Returns: `{ "session_id": "..." }`
  - Creates queue for SSE log streaming
  - Session expires after 10 minutes (configurable)
  
- **`GET /api/logs/stream?session_id=...`** - Server-Sent Events (SSE) stream
  - Returns: text/event-stream with live log updates
  - Events: `init` (connection established), `data` (log lines), `done` (analysis complete)
  - Includes heartbeat comments to keep connection alive
  
- **`POST /api/analyze`** - Submit analysis request
  - Body: `{ "prompt": "...", "session_id": "..." }` (session_id optional)
  - Returns: Analysis results with HTML rendering
  - Streams logs to SSE if session_id provided
  
- **`GET /api/health`** - Health check endpoint
  - Returns: `{ "status": "healthy", "service": "vulners-agent" }`

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
  "result": "Analysis result text (markdown)...",
  "result_html": "HTML formatted analysis result with syntax highlighting...",
  "log_file": "/absolute/path/to/logs/vm_agent_log_at_YYYY-MM-DDTHH-MM-SS.txt"
}
```

### Live Log Streaming Flow

1. **Client**: `POST /api/start_run` → receives `session_id`
2. **Client**: Opens `GET /api/logs/stream?session_id=...` (SSE connection)
3. **Client**: Receives `event: init` confirmation
4. **Client**: `POST /api/analyze` with the same `session_id`
5. **Server**: Streams log lines as `data:` events in real-time
6. **Server**: Sends `event: done` when analysis completes
7. **Client**: Closes SSE connection and displays final results

## Development

### Local Testing

```bash
# Run with local runner (recommended)
python run_local.py              # Web UI mode

# Run components directly
python agent.py                   # Script mode, update natural_prompt accordingly
DEBUG=True python agent.py        # Debug mode
```

## Logging System

VM-Agent implements a sophisticated dual-stream logging system for comprehensive execution tracking:

### Log Files

- **Location**: `logs/vm_agent_log_at_YYYY-MM-DDTHH-MM-SS.txt` (in VM-Agent directory)
- **Format**: Clean text with ANSI escape sequences removed
- **Content**: Configuration section + full execution logs + final output
- **Encoding**: UTF-8

### Log Sections

1. **Configuration Section** (JSON)
   - Prompt and crew setup
   - All agent definitions with roles, goals, and backstories
   - All task definitions with descriptions and expected outputs
   - LLM configurations for each agent (model, temperature, tokens)
   - Tool assignments per agent

2. **Execution Logs** (Real-time)
   - Agent thinking process and tool calls
   - MCP tool discovery and connection status
   - Tool execution results and responses
   - Agent delegation and collaboration
   - Error messages and warnings

3. **Final Output** (Markdown)
   - Complete vulnerability analysis report
   - Risk scores and assessments
   - Remediation guidance

### Console Output

- **Colored Output**: Uses ANSI codes for better readability in terminal
- **Real-time Streaming**: See agent execution as it happens
- **Progress Indicators**: Visual feedback for long-running operations
- **Debug Mode**: Set `DEBUG=True` for verbose output from all agents

### Web Interface Logs

- **Live Streaming**: SSE-based real-time log delivery to browser
- **Clean Format**: ANSI codes stripped for clean browser display
- **Line-by-line**: Individual log lines sent as separate events
- **Automatic Scrolling**: Logs auto-scroll to show latest output

## Troubleshooting

### Common Issues

1. **MCP Server Connection**:

   ```bash
   # Check if MCP server is running
   curl http://localhost:8000/health  # or your MCP server URL

   # Test MCP endpoint
   curl -X POST http://localhost:8000/mcp \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
   ```

   **Expected**: JSON response with list of available tools

   **If connection fails**:
   - Verify `VULNERS_MCP_URL` in `.env` file
   - Ensure MCP server is running (`http://localhost:8000/mcp`)
   - Check firewall settings
   - For FastMCP 2.0: Try `/sse` endpoint if `/mcp` fails
   - Review MCP adapter initialization in console output

2. **API Keys**:
   - **OpenAI**: Verify `OPENAI_API_KEY` is set correctly
   - **Serper**: Optionally set `SERPER_API_KEY` to enable web search
   - Check `.env` file format (no quotes around values)
   - Ensure no extra whitespace in API keys

3. **Logging Issues**:
   - Set `DEBUG=True` in `.env` for detailed output
   - Log files created in `logs/` subdirectory
   - Check write permissions for log directory
   - Log file naming: `vm_agent_log_at_YYYY-MM-DDTHH-MM-SS.txt`
   - Review both console output and log file for complete picture

4. **CrewAI & MCP Integration**:

   ```bash
   # Verify installations
   pip list | grep -E "crewai|litellm"

   # Expected:
   # crewai              <version>
   # crewai-tools        <version>
   # litellm             <version>
   ```

   **If tools not discovered**:
   - Check console output during startup for tool discovery messages
   - Verify MCP server exposes tools via `tools/list` JSON-RPC method
   - Ensure `transport: "streamable-http"` is supported by your MCP server
   - Try setting longer `connect_timeout` in `agents_definitions.py`

5. **FastMCP 2.0 Specific**:
   - **Transport Protocol**: Ensure MCP server supports `streamable-http`
   - **Endpoint Selection**: Try both `/mcp` and `/sse` endpoints
   - **Connection Pooling**: Check if `_mcp_adapter` is initialized (shown in startup logs)
   - **Tool Caching**: First request discovers tools, subsequent requests use cache

6. **Web Interface Issues**:
   - **Port already in use**: Change `PORT` in `.env` (default: 8080)
   - **No browser opens**: Run `python run_local.py` or open `http://localhost:8080` manually
   - **SSE not streaming**: Check browser console for connection errors
   - **Logs not appearing**: Verify session_id matches between `/api/start_run` and `/api/logs/stream`

### Health Checks

```bash
# Check VM-Agent web interface
curl http://localhost:8080/api/health
# Expected: {"status":"healthy","service":"vulners-agent"}

# Check MCP server (LA-Vulners-MCP)
curl http://localhost:8000/health
# Expected: {"status":"healthy"}

# Test MCP tool discovery
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
# Expected: JSON with tools array

# Check if agents loaded successfully (from logs)
grep "MCP tools initialized" logs/vm_agent_log_at_*.txt
# Expected: "✅ MCP tools initialized: X tools available"
```

### Debug Mode

Enable comprehensive debugging by setting environment variable:

```bash
DEBUG=True python agent.py
# or
DEBUG=True python run_local.py
```

**Debug output includes**:

- Detailed agent thinking and reasoning
- Full tool call parameters and responses
- LLM API request/response cycles
- MCP adapter connection details
- Exception stack traces
- CrewAI internal operations

## Performance & Optimization

### Agent Optimization

- **LLM Caching**: All agents have caching enabled for faster repeated queries
- **Temperature Tuning**: Each agent optimized for its specific role:
  - Planning & Scoring: 0.1 (very deterministic)
  - Research & Analysis: 0.15-0.2 (balanced)
  - Synthesis: 0.25-0.3 (creative but grounded)
- **Token Limits**: 10,000 max completion tokens per agent (5,000 for scoring)
- **Request Timeout**: 90 seconds per LLM call with 3 retries

### MCP Integration Performance

- **Connection Pooling**: Single persistent MCP adapter for all agents
- **Tool Caching**: Tools discovered once at startup, cached for subsequent use
- **Streamable HTTP**: Efficient transport protocol for large responses
- **Lazy Loading**: Web interface loads CrewAI only on first request (fast startup)
- **No Reconnection Overhead**: MCP connection remains open for application lifetime

### Data Sharing Efficiency

- **Avoid Redundant API Calls**: Agents share tool outputs instead of re-querying
- **RISK_INPUTS Protocol**: Structured data passing between agents for risk scoring
- **Sequential Processing**: Each agent builds on previous agent's work
- **Delegation**: Agents can query coworkers without duplicate research

### Web Interface Performance

- **SSE Streaming**: Real-time log delivery with minimal overhead
- **Line-by-line Buffering**: Logs sent as individual events to prevent large payloads
- **Heartbeat Comments**: Keep-alive mechanism for proxy compatibility
- **Session Cleanup**: Automatic queue cleanup after 10 minutes
- **Lazy Agent Loading**: CrewAI modules loaded only when needed

## Key Implementation Details

### Anti-Hallucination Controls

- **CVE Conflation Prevention**: Explicit warnings in all agent prompts to never conflate different CVE IDs
- **Critical Protection**: NEVER confuse CVE-2025-44228 with CVE-2021-44228 (Log4Shell)
- **Reserved CVE Handling**: Agents explicitly report "reserved candidate" status without inventing details
- **Evidence-Only Rules**: Strict requirements to stick to tool outputs without speculation
- **No Assumption Policy**: Agents prohibited from inferring missing vulnerability details

### Intelligent CVE Filtering

- **Statistical Analysis**: Tracks CVE mention frequency and document type diversity
- **Evidence Quality Assessment**: Calculates composite scores for CVE relevance
- **Dynamic Thresholds**: Adapts filtering based on evidence distribution
- **Safety Nets**: Prevents over-filtering when evidence is minimal
- **Fat Finger Prevention**: Filters out low-confidence CVE mentions

### Risk Scoring Algorithm

- **Evidence Factor (E)**: Wild exploitation, ShadowServer data, exploit docs, scanner coverage
- **Popularity Factor (P)**: Affected software categorization (internet-critical to niche)
- **Technical Exploitability (T)**: CVSS vector constraints (AV, AC, PR, UI)
- **EPSS Integration (R)**: Latest exploit prediction scores
- **Recency Weighting**: Newer documents weighted higher, outdated info reduced
- **Uncertainty Calculation**: Based on evidence diversity, volume, and quality
- **Output**: `{"value": 0.0-10.0, "uncertainty": 0.0-10.0}`

### Report Generation

- **Narrative Style**: Concise, flowing paragraphs (not bullet points)
- **Professional Tone**: Technical precision with accessible communication
- **Flexible Structure**: All relevant information without enforced rigid sections
- **Evidence Traceability**: Every claim linked to tool outputs
- **Risk Score Integration**: Quantitative scores featured prominently with justification
- **Related CVEs**: Up to 6 related CVEs with linkage reasons when applicable

## Security Notes

- **API Keys**: Stored as environment variables (`.env` file)
- **Network**: Web interface runs on localhost by default
- **Production**: Consider reverse proxy (nginx, Caddy) for external access
- **Logs**: May contain sensitive vulnerability information - secure log directory
- **MCP Server**: Ensure MCP server endpoint is trusted and secured
- **Rate Limiting**: Consider implementing rate limits for production deployments

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

See the LICENSE file for the full text of the license.
