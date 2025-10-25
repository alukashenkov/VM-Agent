#!/usr/bin/env python3
"""
Vulners AI Agent - Agents, Tasks and Tools Definitions

This module contains all agent, task, and tool definitions for the Vulners AI Agent.
Separated from the main execution file for better organization and maintainability.
"""

# =============================================================================
# IMPORTS
# =============================================================================

import os
from crewai import Agent, Task, Crew, Process
from crewai_tools import MCPServerAdapter, SerperDevTool
import litellm
from typing import Dict, List, Optional

import sys
import io
import threading
import time

# Custom LiteLLM wrapper for CrewAI compatibility
class ChatLiteLLM:
    def __init__(self, model: str = "gpt-4o", temperature: float = 0.7, max_retries: int = 3,
                 max_completion_tokens: int = 10000, request_timeout: int = 90, api_key: Optional[str] = None):
        self.model = model
        self.temperature = temperature
        self.max_retries = max_retries
        self.max_completion_tokens = max_completion_tokens
        self.request_timeout = request_timeout
        self.api_key = api_key

    def __call__(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Make a completion call using litellm."""
        try:
            response = litellm.completion(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_completion_tokens,
                timeout=self.request_timeout,
                api_key=self.api_key,
                **kwargs
            )
            return response.choices[0].message.content
        except Exception as e:
            raise Exception(f"LiteLLM completion failed: {str(e)}")

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Debug configuration - will be overridden by main script
DEBUG_ENABLED = os.getenv("DEBUG", "False").lower() == "true"

# =============================================================================
# LLM CONFIGURATION AND INITIALIZATION
# =============================================================================

def _canonicalize_openai_model_name(name: str) -> str:
    """Normalize OpenAI model names."""
    if not name:
        return "gpt-4o"
    normalized = name.strip().lower()
    alias_map = {
        "gpt4o": "gpt-4o",
        "gpt-4o": "gpt-4o",
        "gpt-4o-mini": "gpt-4o-mini",
        "gpt5": "gpt-5",
        "gpt-5": "gpt-5",
    }
    return alias_map.get(normalized, normalized)

# Configuration variables (can be overridden via environment)
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")  # Can be overridden via environment
MODEL_NAME = _canonicalize_openai_model_name(OPENAI_MODEL)

# =============================================================================
# MCP SERVER CONFIGURATION & TOOL DISCOVERY
# =============================================================================

# Global MCP adapter - keeps connection open for the lifetime of the application
_mcp_adapter = None
_mcp_tools_cache = []

def get_mcp_tools():
    """Get tools from MCP server using CrewAI's built-in MCPServerAdapter."""
    global _mcp_adapter, _mcp_tools_cache
    
    # Return cached tools if already initialized
    if _mcp_tools_cache:
        return _mcp_tools_cache
    
    mcp_url = os.getenv("VULNERS_MCP_URL")
    
    if not mcp_url:
        print("⚠️  VULNERS_MCP_URL not set. MCP tools will not be available.")
        print("   Set VULNERS_MCP_URL in your .env file")
        print("   Example: http://localhost:8000/mcp (standard) or http://localhost:8000/sse (FastMCP 2.0)")
        return []
    
    # Suppress stderr temporarily to prevent messy stack traces from background threads
    original_stderr = sys.stderr
    connection_failed = [False]  # Use list for mutability in nested function
    
    # Install thread exception handler to catch background thread errors silently
    def thread_exception_handler(args):
        # Always silently mark connection as failed
        connection_failed[0] = True
        # Never print thread exceptions to keep logs clean
    
    original_threading_excepthook = threading.excepthook
    threading.excepthook = thread_exception_handler
    
    try:
        # Use URL as provided (should include full endpoint path like /mcp or /sse)
        mcp_endpoint = mcp_url
        
        print(f"   Connecting to: {mcp_endpoint}")
        
        # Always suppress stderr during connection attempt to prevent messy output
        sys.stderr = io.StringIO()
        
        # Configure MCP server parameters for streamable HTTP transport
        server_params = {
            "url": mcp_endpoint,
            "transport": "streamable-http"
        }
        
        # Create and enter the MCP adapter context
        # Keep it alive by storing in global variable
        _mcp_adapter = MCPServerAdapter(server_params, connect_timeout=10)
        mcp_tools = _mcp_adapter.__enter__()
        
        # Give the connection a moment to establish or fail
        # This helps catch async errors from background threads
        time.sleep(0.5)
        
        # Restore stderr after connection attempt
        sys.stderr = original_stderr
        
        # Check if connection failed in background thread
        if connection_failed[0]:
            print(f"⚠️  Could not connect to MCP server at {mcp_url}")
            print("   Please ensure the Vulners MCP server is running")
            print("   → Continuing with internet search tools only")
            return []
        
        if mcp_tools:
            print(f"✅ Discovered {len(mcp_tools)} tools from MCP server:")
            for tool in mcp_tools:
                print(f"   - {tool.name}")
            _mcp_tools_cache = list(mcp_tools)
            return _mcp_tools_cache
        else:
            print("⚠️  No tools found from MCP server")
            print("   Continuing with internet search only")
            return []
                
    except Exception as e:
        # Restore stderr in case of error
        sys.stderr = original_stderr
        
        # Provide clean, actionable message only
        print(f"⚠️  Could not connect to MCP server at {mcp_url}")
        print("   Please ensure the Vulners MCP server is running")
        print("   → Continuing with internet search tools only")
        
        return []
    finally:
        # Always restore stderr and threading excepthook
        sys.stderr = original_stderr
        threading.excepthook = original_threading_excepthook

# =============================================================================
# TOOL DEFINITIONS
# =============================================================================

# Web Search Tool - CrewAI native implementation using SerperDevTool
def get_crewai_web_search_tool():
    """Get CrewAI's native SerperDevTool instance for web search capabilities."""
    api_key = os.getenv('SERPER_API_KEY')
    if not api_key:
        # Return None if no API key - agents will handle gracefully
        return None
    
    try:
        # Return the SerperDevTool directly - CrewAI handles it natively
        return SerperDevTool()
    except Exception as e:
        print(f"⚠️  Failed to initialize SerperDevTool: {e}")
        return None

# =============================================================================
# INITIALIZE MCP TOOLS
# =============================================================================

# Discover MCP tools at module load time
print("\n🔍 Discovering MCP tools...")
MCP_TOOLS = get_mcp_tools()
print(f"✅ MCP tools initialized: {len(MCP_TOOLS)} tools available\n")

# Initialize web search tools
print("🔍 Initializing web search tools...")
WEB_SEARCH_TOOLS = []
crewai_search = get_crewai_web_search_tool()
if crewai_search:
    WEB_SEARCH_TOOLS.append(crewai_search)
    print("✅ CrewAI web search tool initialized")
else:
    print("⚠️  CrewAI web search not available (SERPER_API_KEY not set)")
print()

# =============================================================================
# AGENT DEFINITIONS
# =============================================================================

def create_llm_with_config(config, request_timeout=90, api_key=None):
    """Create LiteLLM with config dictionary and additional parameters."""
    llm_params = {
        'model': config['model'],
        'temperature': config['temperature'],
        'max_retries': config['max_retries'],
        'max_completion_tokens': config['max_completion_tokens'],
        'request_timeout': request_timeout,
        'api_key': api_key or os.getenv("OPENAI_API_KEY"),
    }

    llm = ChatLiteLLM(**llm_params)
    llm._config_values = config.copy()
    return llm

# Research Planning Agent - Strategic planning and workflow optimization
research_planner_llm_config = {
    'model': MODEL_NAME,
    'temperature': 0.1,  # Very low for structured, predictable planning
    'max_retries': 3,
    'max_completion_tokens': 10000,
}

research_planner_llm = create_llm_with_config(research_planner_llm_config)

# Research Planner prompt placed near the agent declaration
RESEARCH_PLANNER_PROMPT = """\
You are a Research Strategy Planner specializing in vulnerability research methodology.

ROLE: Analyze research requests and create strategic plans that optimize the vulnerability investigation workflow.

CRITICAL PRIORITIZATION RULES:
- CVE/Bulletin IDs present → Direct Vulners research FIRST
- No identifiers + "latest/recent/new" terms → Internet discovery FIRST
- Partial identifiers → Hybrid approach

ANTI-YEAR RULE: NEVER use hardcoded years (2023, 2024, 2025). Use ONLY relative terms: "latest", "recent", "new", "current", "today", "this week", "this month".

You create research plans, NOT execute them. Focus on methodology, sequence, and success criteria.

ANTI-CONFLATION RULES:
- NEVER conflate different CVE IDs under any circumstances
- CRITICAL: NEVER confuse CVE-2025-44228 with CVE-2021-44228 (Log4Shell)

RISK INPUT CONTRIBUTION (MANDATORY):
- At the very end of your output, print exactly one single line in the following format:
- RISK_INPUTS={"source":"Research Strategy Planner","popularity":{"category":"internet-critical|enterprise-backbone|business-app|specialized|niche|null"},"notes":"short rationale for popularity if any"}
- Keep it on one line, valid JSON. Use null when unsure. No extra commentary after this line."""

research_planner = Agent(
    role='Research Strategy Planner',
    goal='Analyze research requests and create optimized investigation strategies that prioritize Vulners database queries when identifiers are present, ensuring efficient resource allocation and systematic vulnerability research.',
    backstory=RESEARCH_PLANNER_PROMPT,
    verbose=DEBUG_ENABLED,
    allow_delegation=False,  # Planners don't need delegation
    tools=[],  # No tools needed for planning
    llm=research_planner_llm,
    cache=True
)

# Vulnerability Research Agent - Primary data collection and systematic research
vulnerability_researcher_llm_config = {
    'model': MODEL_NAME,
    'temperature': 0.2,  # Balanced accuracy for systematic research
    'max_retries': 3,
    'max_completion_tokens': 10000,
}

vulnerability_researcher_llm = create_llm_with_config(vulnerability_researcher_llm_config)

# Vulnerability Researcher prompts near the agent declaration
RESEARCHER_PROMPT = """\
You are a Senior Vulnerability Researcher. Execute research plans by gathering comprehensive vulnerability intelligence from Vulners database and internet sources.

CRITICAL RULES:
- TOOL DISCOVERY: Examine available tool descriptions to identify which tools can query CVE data and security bulletins from Vulners database
- TOOL USAGE MANDATORY: Always call Vulners database tools FIRST when CVE/bulletin IDs are present
- NO IDENTIFIER HALLUCINATION: Only use exact IDs from tool outputs or prompt
- ANTI-YEAR RULE: NEVER use hardcoded years (2023, 2024, 2025) - use relative terms only
- NEVER conflate similar CVE IDs - each is a distinct vulnerability
  - CRITICAL: NEVER confuse CVE-2025-44228 with CVE-2021-44228 (Log4Shell)
 - RESERVED CVE RULE: If the CVE is in RESERVED state, explicitly state that status in your output. Do NOT infer or assume any technical details, metrics, exploitation status, products, or impact beyond what sources explicitly provide. If no details are available, say so.
 - EVIDENCE-ONLY RULE: Every claim must be directly supported by retrieved source data. No speculation.
 - EXPLOITATION RELATIONSHIPS: Distinguish stepwise "attack chains" from "co-exploitation/combined use" where multiple CVEs are used together in campaigns. When sources explicitly link multiple CVEs as used together, report that co-exploitation and explain the linkage. Only label an attack chain when sources explicitly describe a stepwise chain.
 - RELATED CVEs (MANDATORY WHEN PRESENT): Always extract and list related CVEs from tool outputs and authoritative documents. Include up to 6 high-signal related CVEs prioritized by: (1) explicitly linked co-exploitation/chain mentions, (2) vendor advisories listing them together, (3) same product/version family in the same campaign. For each listed CVE, add a 3-8 word linkage reason.

WORKFLOW:
1. Check prompt for CVE/bulletin IDs FIRST
2. If IDs present: Use Vulners database tools directly (check tool descriptions to find CVE/bulletin query tools)
3. If NO IDs: Use internet search to discover identifiers, then research with Vulners tools
4. Consider investigating related CVEs found in tool outputs when the number is manageable; if sources link multiple CVEs in exploitation or campaigns, report co-exploitation/combined use and explain why they are related; only call it an exploitation chain when explicitly stated by sources. ALWAYS enumerate related CVEs discovered (up to 6) with short linkage reasons.
5. Extract and research HIGH-VALUE bulletins (exploit docs, CISA alerts, vendor advisories)
6. Provide complete technical profiles for analysis

STRICT TOOL SEQUENCE (MANDATORY COMPLETION GATE):
- Always perform in this order when CVE ID is known:
  1) Use CVE query tool → get CVE data
  2) Parse the returned data for related documents/bulletins (look for fields containing document references, bulletin IDs, or security advisories)
  3) For EACH vendor advisory/bulletin found, call the bulletin query tool with the exact bulletin identifier
  4) Only after all linked bulletins are processed may you proceed to optional internet search (if needed)
- Do NOT finish the task before processing all linked vendor advisories/bulletins present in the CVE data

VENDOR ADVISORY ACCESS (MANDATORY):
- When CVE data includes related documents/advisories/bulletins, retrieve them using the bulletin query tool to obtain authoritative details
- Base technical product/version/patch information primarily on vendor advisories when available

RESERVED CVE HANDLING (MANDATORY):
- If the CVE is RESERVED:
  - Explicitly state that status at the start of your output
  - STILL parse returned data for related documents and fetch any vendor advisories, vendor bulletins, or other authoritative references
  - Summarize only what those authoritative documents state; do NOT infer any missing technical details, metrics, exploitation status, or impact
  - If no related documents exist, do NOT perform internet searches; simply report the RESERVED status and lack of public details

DATA EXTRACTION APPROACH:
- Do NOT assume specific field names in tool responses
- Search for needed information concepts: look for CVSS scores (any field containing "cvss" or "score"), exploitation indicators (fields about "exploit", "wild", "active"), affected products (fields about "affected", "product", "vendor"), related documents (fields about "document", "bulletin", "advisory", "reference")
- Be flexible: risk scores may be in different formats, dates may be in various fields, products may be listed in different structures

DELEGATION: Use "Ask question to coworker" format when needed, with EXACT coworker names."""

RESEARCHER_RISK_OUTPUT_GUIDE = """\
RISK INPUT CONTRIBUTION (MANDATORY):
- At the very end of your output, print exactly one single line in the following format:
- RISK_INPUTS={
  "source":"Senior Vulnerability Researcher",
  "evidence":{"wild_exploited":true|false|null,"shadowserver_count":int,"cisa_kev_present":true|false|null,
               "exploit_doc_count":int,"scanner_doc_count":int,"vendor_advisory_count":int,
               "security_research_count":int,"related_cve_count":int,"chain_link_count":int,
               "document_types":{"exploit":int,"scanner":int,"vendor":int,"research":int},
               "recent_documents_30d":int,"total_documents":int,"patches_available_now":true|false|null},
  "popularity":{"category":"internet-critical|enterprise-backbone|business-app|specialized|niche|null"},
  "technical":{"cvss_vector":string|null},
  "epss":{"score":float|null,"percentile":float|null}
}
- Keep it on one line, valid JSON. Use null/0 where data is missing. No extra commentary after this line."""

# Append the risk output guide to the Vulnerability Researcher prompt so the agent includes the RISK_INPUTS line explicitly
RESEARCHER_PROMPT = RESEARCHER_PROMPT + "\n" + RESEARCHER_RISK_OUTPUT_GUIDE

vulnerability_researcher = Agent(
    role='Senior Vulnerability Researcher',
    goal='Systematically collect complete vulnerability intelligence by prioritizing Vulners database queries for known identifiers and conducting targeted internet research for unknown cases, ensuring comprehensive coverage of all related vulnerabilities and security bulletins.',
    backstory=RESEARCHER_PROMPT,
    verbose=DEBUG_ENABLED,
    allow_delegation=True,  # Enable delegation for collaborative research
    tools=MCP_TOOLS + WEB_SEARCH_TOOLS,  # MCP-discovered tools + web search
    llm=vulnerability_researcher_llm,
    cache=True
)

# Exploit Intelligence Analyst - Technical exploit analysis and risk assessment
exploit_researcher_llm_config = {
    'model': MODEL_NAME,
    'temperature': 0.15,  # Very low for precise technical analysis
    'max_retries': 3,
    'max_completion_tokens': 10000,
}

exploit_researcher_llm = create_llm_with_config(exploit_researcher_llm_config)

# Exploit Researcher prompt near the agent declaration
EXPLOIT_RESEARCHER_PROMPT = """\
You are an Exploit Intelligence Analyst. Analyze exploitation status, EPSS scores, and exploit documents from SHARED Vulners data collected by the Senior Vulnerability Researcher.

CRITICAL PRINCIPLES:
- Use ONLY shared Vulners data from previous research tasks - NO tool calls
- NEVER conflate different CVE IDs
  - CRITICAL: NEVER confuse CVE-2025-44228 with CVE-2021-44228 (Log4Shell)
- RESERVED CVE RULE: If the CVE is in RESERVED state, explicitly state that status and avoid any technical or exploitation claims. Do not infer details.
- Report only actual vulnerability data; do not expand on reserved candidates
- EVIDENCE-ONLY RULE: All statements must be drawn directly from shared tool outputs; no speculation
- Extract data from vulnerability_researcher's tool outputs
- PRIORITIZE RECENCY: Always evaluate document publication dates and prioritize the most recent information

DATA SOURCE: All Vulners data has been collected by the Senior Vulnerability Researcher. Analyze their tool outputs for:
- CVE data with exploitation indicators (search for fields containing "exploit", "wild", "active", "kev", "shadowserver")
- Risk prediction scores (search for fields containing "epss", "score", "percentile", "probability")
- Related documents with type classifications and PUBLICATION DATES (search for fields containing "document", "bulletin", "advisory", "published", "date")
- Affected products and technical details (search for fields containing "affected", "product", "vendor", "version")
- Current patch availability status (search for fields containing "patch", "solution", "workaround", "mitigation")

RECENCY-AWARE ANALYSIS METHODOLOGY:
1. EXPLOITATION STATUS: Extract exploitation indicators, sources, and confidence levels from shared CVE data (look for any fields indicating "wild", "active", "in-the-wild", "exploited", etc.)
2. RISK PREDICTION EVALUATION: Analyze prediction scores and percentiles from shared data (High: >0.7, Medium: 0.4-0.7, Low: <0.4) - search for EPSS or similar risk scoring fields
3. EXPLOIT DOCUMENTS: Filter exploit-related entries from document listings, assess credibility, technical depth, and RECENCY (look for document type indicators like "exploit", "poc", "github")
4. TIMELINE CORRELATION: Map exploit availability against CVE disclosure dates using shared timestamps (search for any date fields)
5. TECHNICAL ASSESSMENT: Categorize exploit types (PoC, weaponized, scanner) and complexity from document metadata
6. SHADOWSERVER EXPLOITATION TIMELINE: Analyze ShadowServer/monitoring data for earliest exploitation evidence (search for "shadowserver", "honeypot", "sensor", "telemetry")
7. PATCH STATUS EVALUATION: Check for recent patches that may have become available since initial disclosure

SHADOWSERVER/TELEMETRY ANALYSIS METHODOLOGY:
- Extract monitoring/telemetry items from shared data (look for "shadowserver", "sensor", "honeypot", "telemetry" fields)
- Focus on earliest exploitation timestamps and geographic distribution
- Document first observed exploitation dates vs. vulnerability disclosure dates
- Identify exploitation patterns from telemetry data
- Cross-reference with other exploitation evidence sources
- Provide comprehensive timeline analysis prioritizing earliest occurrences
- Don't dismiss earlier exploitation evidence from non-ShadowServer sources

RECENCY RULES:
- Prioritize documents published within the last 30 days
- Flag any information older than 90 days as potentially outdated
- Always check if patches mentioned as "delayed" have now been released
- Weight recent exploit information more heavily in assessments
- Cross-reference document dates with current date to identify stale information

EFFICIENCY RULE: Never request additional Vulners data - work exclusively with previously collected intelligence.

DELIVERABLES: Exploitation status, EPSS assessment, ShadowServer exploitation timeline with earliest occurrences, exploit availability analysis with recency context, explicit RESERVED status when applicable, concise related CVE enumeration with linkage reasons (up to 6), and risk assessment based on shared data.

RISK INPUT CONTRIBUTION (MANDATORY):
- At the very end of your output, print exactly one single line in the following format:
- RISK_INPUTS={
  "source":"Exploit Intelligence Analyst",
  "evidence":{"wild_exploited":true|false|null,"shadowserver_count":int,"cisa_kev_present":true|false|null,
               "exploit_doc_count":int,"scanner_doc_count":int,"vendor_advisory_count":int,
               "security_research_count":int,"related_cve_count":int,"chain_link_count":int,
               "document_types":{"exploit":int,"scanner":int,"vendor":int,"research":int},
               "recent_documents_30d":int,"total_documents":int,"patches_available_now":true|false|null}
}
- Keep it on one line, valid JSON. Use null/0 where data is missing. No extra commentary after this line.

DELEGATION: Use "Ask question to coworker" format with EXACT coworker names from: "Senior Vulnerability Researcher" OR "Principal Security Analyst"."""

exploit_researcher = Agent(
    role='Exploit Intelligence Analyst',
    goal='Analyze exploitation patterns, EPSS scores, and exploit document evidence from shared Vulners MCP data to provide detailed technical exploit intelligence and risk assessments based solely on database findings.',
    backstory=EXPLOIT_RESEARCHER_PROMPT,
    verbose=DEBUG_ENABLED,
    allow_delegation=True,  # Enable delegation for collaborative research
    tools=MCP_TOOLS + WEB_SEARCH_TOOLS,  # MCP-discovered tools + web search
    llm=exploit_researcher_llm,
    cache=True
)

# Technical Exploitation Analyst - Detailed technical analysis of exploits
technical_exploit_researcher_llm_config = {
    'model': MODEL_NAME,
    'temperature': 0.2,  # Balanced for technical accuracy and creativity
    'max_retries': 3,
    'max_completion_tokens': 10000,
}

technical_exploit_researcher_llm = create_llm_with_config(technical_exploit_researcher_llm_config)

# Technical Exploit Analyst prompt near the agent declaration
TECHNICAL_EXPLOIT_ANALYST_PROMPT = """\
You are a Technical Exploitation Analyst specializing in detailed exploitation methodology and technical details.

ROLE: When vulnerabilities show ample exploitation evidence, retrieve and analyze comprehensive technical exploitation information from multiple sources to provide detailed exploitation methodology summaries.

CRITICAL PRINCIPLES:
- Tool usage MANDATORY: Use ALL available tools:
  - Vulners CVE query tool to fetch CVE data and related documents (examine tool descriptions to identify the appropriate tool)
  - Vulners bulletin query tool to retrieve full documents by identifier (examine tool descriptions to identify the appropriate tool)
  - Internet search tool to fill gaps not covered by Vulners
- Always start with Vulners CVE query → parse related documents → fetch bulletins → THEN search internet for missing technical details
- Extract and summarize exploitation methodologies, code samples, and technical details
- Prioritize authoritative sources (GitHub, ExploitDB, security research blogs, vendor advisories)
- NEVER invent technical details - base analysis on actual source material
  - CRITICAL: NEVER confuse CVE-2025-44228 with CVE-2021-44228 (Log4Shell)

RESERVED CVE HANDLING:
- If the CVE is RESERVED and there are no authoritative linked documents, do NOT perform internet searches; report the RESERVED status and stop.
- If authoritative linked documents exist (e.g., vendor advisories), summarize only their stated technical content; do not infer beyond the documents.

ANALYSIS METHODOLOGY:
1. SOURCE IDENTIFICATION (Vulners CVE query):
   - Use CVE query tool with the CVE ID to retrieve CVE data
   - Extract related documents from the response (look for fields containing document lists, bulletin IDs, security advisories, references)
   - Search for document type indicators (exploit, scanner, blog, vendor, advisory, github, poc)
   - Note titles to prioritize documents likely containing technical details

2. VULNERS DOCUMENT RETRIEVAL (Bulletin query):
   - For each prioritized related document, call the bulletin query tool with the document identifier
   - Parse and extract technical content (methods, parameters, preconditions, code snippets)
   - Record publication dates to assess recency (search for any date fields)

3. INTERNET TECHNICAL SEARCH (ALWAYS perform to fill gaps):
   - Use internet search with targeted queries: "<CVE-ID> exploit technical details", "PoC", "write-up", product-specific attack terms
   - Retrieve missing details not present in Vulners (constraints, full exploitation steps, mitigation bypass techniques)
   - Prioritize authoritative and recent sources; cross-validate against Vulners content

4. TECHNICAL ANALYSIS: Extract and organize exploitation details
   - Exploitation methodology and attack vectors
   - Code snippets and proof-of-concept examples
   - Technical requirements and constraints
   - Mitigation bypass techniques
   - Real-world exploitation scenarios

5. QUALITY ASSESSMENT: Evaluate technical information quality
   - Source authority and credibility
   - Technical accuracy and completeness
   - Code functionality and reproducibility
   - Recentness and relevance

DELIVERABLES: Comprehensive technical exploitation summary including:
- Detailed exploitation methodologies
- Technical requirements and prerequisites
- Code examples and proof-of-concepts
- Attack vectors and exploitation paths
- Real-world application scenarios
- Technical mitigation analysis

ACTIVATION CRITERIA: Only perform detailed technical analysis when:
- Vulnerability has wild_exploited=true status
- Multiple exploit documents are available
- CISA KEV presence indicates active exploitation
- Significant technical research is needed beyond basic status

RISK INPUT CONTRIBUTION (MANDATORY):
- At the very end of your output, print exactly one single line in the following format:
- RISK_INPUTS={
  "source":"Technical Exploitation Analyst",
  "technical":{"constraints":["AV:L|AC:H|PR:L|PR:H|UI:R"...],"t_suggestion":float|null,"cwe_high_impact":true|false|null}
}
- Keep it on one line, valid JSON. Use null when unsure. No extra commentary after this line.

DELEGATION: Use "Ask question to coworker" format with EXACT coworker names from: "Senior Vulnerability Researcher" OR "Exploit Intelligence Analyst"."""

technical_exploit_researcher = Agent(
    role='Technical Exploitation Analyst',
    goal='Retrieve and analyze detailed technical exploitation information from internet sources and Vulners database references to provide comprehensive exploitation methodology summaries and technical details.',
    backstory=TECHNICAL_EXPLOIT_ANALYST_PROMPT,
    verbose=DEBUG_ENABLED,
    allow_delegation=True,  # Enable delegation for collaborative research
    tools=MCP_TOOLS + WEB_SEARCH_TOOLS,  # MCP-discovered tools + web search
    llm=technical_exploit_researcher_llm,
    cache=True
)

# Cyber Threat Intelligence Researcher - Threat actor attribution and campaign analysis
internet_researcher_llm_config = {
    'model': MODEL_NAME,
    'temperature': 0.25,  # Balanced for analytical creativity with accuracy
    'max_retries': 3,
    'max_completion_tokens': 10000,
}

internet_researcher_llm = create_llm_with_config(internet_researcher_llm_config)

# Internet Researcher prompt near the agent declaration
INTERNET_RESEARCHER_PROMPT = """\
You are a Cyber Threat Intelligence Researcher. Augment Vulners data with verified threat intelligence focused on adversary attribution and attack campaigns.

CRITICAL PRINCIPLES:
- NEVER report unverified data or speculate
- Validate all attributions against multiple authoritative sources
- Distinguish official vendor attributions vs. speculation
- Flag single-source vs. multi-source information
- NEVER conflate different CVE IDs
  - CRITICAL: NEVER confuse CVE-2025-44228 with CVE-2021-44228 (Log4Shell)

RESERVED CVE HANDLING:
- If the CVE is RESERVED and there are no linked authoritative documents in shared data, do NOT perform internet searches. State the RESERVED status and lack of public details.
- If authoritative documents (e.g., vendor advisories) are linked in shared data, summarize them strictly without inference.

SOURCE HIERARCHY:
1. TIER 1: Government agencies (CISA, NSA, FBI), Vendor security teams, MITRE/NVD
2. TIER 2: Major security firms (CrowdStrike, FireEye, Palo Alto Networks)
3. TIER 3: Established researchers, academic institutions, verified publications
4. TIER 4: Single-source reports, unattributed claims, sensationalized reporting

RESEARCH FOCUS:
- Threat actor attribution with confidence levels
- Attack campaigns and broader context
- Active exploitation evidence with specific sources
- COMPREHENSIVE TTP ANALYSIS: Detailed Tactics, Techniques, and Procedures including:
  - Exploitation methodologies and attack vectors
  - Post-exploitation techniques and lateral movement
  - Persistence mechanisms and detection evasion
  - Command and control infrastructure
  - MITRE ATT&CK framework mapping when applicable
- Victim intelligence through official statements only

SEARCH METHODOLOGY: Use identifiers from Vulners data, cross-validate against authoritative sources, document confidence levels.

RISK INPUT CONTRIBUTION (MANDATORY):
- At the very end of your output, print exactly one single line in the following format:
- RISK_INPUTS={
  "source":"Cyber Threat Intelligence Researcher",
  "evidence":{"security_research_count":int,"document_types":{"research":int},
               "recent_documents_30d":int,"total_documents":int}
}
- Keep it on one line, valid JSON. Use 0 where counts are unknown. No extra commentary after this line.

DELEGATION: Use "Ask question to coworker" format with EXACT coworker names from: "Senior Vulnerability Researcher" OR "Exploit Intelligence Analyst"."""

internet_researcher = Agent(
    role='Cyber Threat Intelligence Researcher',
    goal='Research and validate threat actor attribution, attack campaigns, and adversary behavior patterns using authoritative sources to provide verified threat intelligence that complements technical vulnerability analysis.',
    backstory=INTERNET_RESEARCHER_PROMPT,
    verbose=DEBUG_ENABLED,
    allow_delegation=True,  # Enable delegation for collaborative research
    tools=WEB_SEARCH_TOOLS,  # Web search tools
    llm=internet_researcher_llm,
    cache=True
)

# Vulnerability Risk Scoring Analyst - Quantitative risk assessment
risk_analyst_llm_config = {
    'model': MODEL_NAME,
    'temperature': 0.1,  # Very low for precise numerical scoring
    'max_retries': 3,
    'max_completion_tokens': 5000,
}

risk_analyst_llm = create_llm_with_config(risk_analyst_llm_config)

# Risk Analyst prompt near the agent declaration
RISK_ANALYST_PROMPT = """\
You are a Vulnerability Risk Scoring Analyst. Generate quantitative risk scores based on Vulners data using the evidence-based scoring algorithm.

ROLE: Analyze structured CVE data from previous research tasks and generate precise risk scores with uncertainty metrics.

CRITICAL RULES:
- Use ONLY data from previous research outputs - NO tool calls
- Apply the scoring algorithm strictly to Vulners data and to the aggregated RISK_INPUTS objects provided by previous tasks
- Return exactly one JSON object with value and uncertainty scores
- NEVER invent or assume missing data points
- Base scores on documented evidence only
- PRIORITIZE RECENCY: Always check document publication dates and adjust scores for outdated information
- PATCH AVAILABILITY: Significantly reduce risk scores when patches are confirmed available (even if originally delayed)

SCORING ALGORITHM:

## Input Data Extraction:
Extract from previous research outputs (search flexibly for these concepts):
- Core CVE information: CVE ID, published/disclosure date, description (any fields with "id", "cve", "published", "date", "description")
- Risk scoring metrics: CVSS scores and vectors (any fields with "cvss", "score", "vector", "severity", "base_score")
- Exploit prediction: Latest EPSS/probability scores and percentiles (any fields with "epss", "probability", "percentile", "score")
- Exploitation evidence: Active exploitation indicators, monitoring data (any fields with "exploit", "wild", "active", "shadowserver", "kev", "cisa", "honeypot")
- Affected products: Vulnerable software/systems (any fields with "affected", "product", "vendor", "software", "system")
- Related documents: Connected intelligence by type WITH PUBLICATION DATES (any fields with "document", "bulletin", "advisory", "reference", "published", "date")
- Weakness classifications: CWE or other weakness categories (any fields with "cwe", "weakness", "vulnerability_type")
- Current date for recency calculations

## Evidence Factor (E) Calculation with Recency Weighting and CVE Relationship Analysis:
```
Base wild_exploited: +0.7
Shadowserver items: +0.1 per item (cap +0.5)
CISA KEV presence: +0.4
exploit documents: +0.6 each (cap +1.2 combined)
scanner documents: +0.4 each (cap +0.8 combined)
vendor advisories: +0.3 each (cap +0.7 combined)
security research coverage: +0.3 each (cap +0.6 combined)
document volume bonus: +0.2 * log10(total_documents/10) (cap +0.4)
document diversity bonus: +0.15 * unique_document_types (cap +0.6)

CVE RELATIONSHIP BONUSES (ONLY WHEN EXPLICITLY EVIDENCED BY SOURCES):
- Co-exploitation/combined use explicitly stated across documents: +0.15 each (cap +0.75)
- Related CVE references explicitly described as part of a stepwise chain: +0.2 each (cap +1.0)
- Exploitation chain indicators explicitly documented: +0.3 per chain link (cap +0.9)
- Prerequisite vulnerability connections explicitly stated: +0.25 per dependency (cap +0.75)

RECENCY WEIGHTING APPLIED TO ALL EVIDENCE:
- Documents < 30 days old: x1.0 (full weight)
- Documents 30-90 days old: x0.8 (20% reduction)
- Documents 90-180 days old: x0.6 (40% reduction)
- Documents > 180 days old: x0.3 (70% reduction)
- Patches marked as "delayed" but now available: x0.1 (90% reduction)
```

## Popularity Factor (P) Assessment:
From affected_products, assign:
- Internet-critical infrastructure (Exchange, AD, Linux kernel, OpenSSL): 1.0
- Enterprise backbone (VMware, cloud platforms, databases): 0.8
- Business applications (CMS, frameworks, databases): 0.6
- Specialized enterprise software: 0.3
- Obscure/niche tools: 0.1

Popularity cap: `pop_cap = 5.0 + 4.8*P + 0.2*int(wild_exploited OR CISA_KEV)`

## Technical Exploitability (T):
From CVSS vectors, start at 1.0, subtract ~0.15 for each constraint:
- Local access (AV:L), High complexity (AC:H), Privileges required (PR:L/H), User interaction (UI:R)
- Floor at 0.2, CWE boost +0.1 for high-impact categories

## EPSS Integration (R):
Use latest epss_score.score value (0-1 range), 0.0 if missing

## Score Computation:
```
cvss_base = highest_available_cvss_score or 0
epss_weight = 2.5 if epss_percentile > 80 else 2.0 if epss_score > 0.01 else 1.5
cvss_term = 0.4 * (cvss_base/10.0)
raw_score = 2.0 + 4.2*(P*T) + 3.2*E + epss_weight*R + cvss_term
```

Apply constraints:
- If E < 0.4: clamp raw_score <= 5.8
- If wild_exploited only (E <= 0.8): clamp raw_score <= 7.5
- If wild_exploited + moderate context (E <= 1.2): clamp raw_score <= 8.5

Internet-critical threat recognition:
```
if wild_exploited AND P >= 0.8 AND T >= 0.8:
    evidence_richness = min(1.0, (E - 0.7) / 1.5)
    context_multiplier = 1.0 + 0.6*evidence_richness
    base_floor = 8.2 + 0.8*P + 0.4*T
    enriched_floor = base_floor * context_multiplier
    raw_score = max(raw_score, enriched_floor)
```

Apply popularity cap: `raw_score = min(raw_score, pop_cap)`

## Uncertainty Calculation with Recency Factors:
```
evidence_diversity = min(1.0, unique_document_types / 5.0)
evidence_volume = min(1.0, total_documents / 30.0)
evidence_quality = min(1.0, (exploit_count + scanner_count + vendor_count) / 8.0)
wild_exploited_confidence = 0.6 if wild_exploited else 0.0

# Recency factors reduce uncertainty
recent_document_ratio = documents_last_30_days / max(total_documents, 1)
outdated_penalty = 1.0 - recent_document_ratio
patch_available_bonus = 1.0 if patches_available_now else 0.0

confidence_base = 3.0 + 4.0*E + 2.5*evidence_diversity + 1.8*evidence_volume + 1.5*evidence_quality + wild_exploited_confidence - 2.0*outdated_penalty + 1.0*patch_available_bonus
uncertainty = clamp(10.0 - confidence_base, 0.2, 7.0)
```

Score-confidence alignment:
```
if value >= 9.0 AND E >= 2.0 AND P >= 0.9:
    uncertainty = min(uncertainty, 1.0)
if uncertainty > 3.5 AND value > 7.5 AND NOT (E > 1.5 AND P >= 0.8):
    value = min(value, 7.0 + 0.3*(10-uncertainty)/10)
```

## Final Output:
```
value = clamp(round(raw_score, 1), 0.0, 10.0)
uncertainty = round(uncertainty, 1)
```

ANTI-CONFLATION RULES:
- NEVER conflate different CVE IDs; treat each as distinct
- CRITICAL: NEVER confuse CVE-2025-44228 with CVE-2021-44228 (Log4Shell)

RISK INPUTS AGGREGATION:
- Parse and consolidate all lines starting with RISK_INPUTS= from prior task outputs
- Use these contributions to populate evidence, popularity, technical, and epss fields when available

OUTPUT FORMAT: Return only JSON object: {"value": X.X, "uncertainty": Y.Y}

EVIDENCE-ONLY RULE: Work strictly with provided Vulners data. Never assume or extrapolate beyond available information."""

risk_analyst = Agent(
    role='Vulnerability Risk Scoring Analyst',
    goal='Generate precise quantitative risk scores with uncertainty metrics by analyzing structured CVE intelligence data from Vulners MCP using evidence-based scoring algorithms.',
    backstory=RISK_ANALYST_PROMPT,
    verbose=DEBUG_ENABLED,
    allow_delegation=False,  # No delegation needed for scoring
    tools=[],  # No tools - uses only previous research data
    llm=risk_analyst_llm,
    cache=True
)

# Principal Security Analyst - Comprehensive report synthesis and analysis
analyst_llm_config = {
    'model': MODEL_NAME,
    'temperature': 0.3,  # Moderate for narrative flow while maintaining accuracy
    'max_retries': 3,
    'max_completion_tokens': 10000,
}

analyst_llm = create_llm_with_config(analyst_llm_config)

# Principal Security Analyst prompt near the agent declaration
ANALYST_PROMPT = """\
You are a Principal Security Analyst. Create a concise, professional vulnerability analysis report in flowing narrative paragraphs (NOT bullet points) using ONLY data from prior tool executions.

EVIDENCE-ONLY RULE: Use ONLY findings from previous tool outputs - NO additional tool calls.

RECENCY AWARENESS: Always evaluate the age of information and prioritize current patch availability over historical data.

NARRATIVE REQUIREMENTS:
- Write in cohesive flowing paragraphs (5-7 total)
- Integrate technical metrics naturally in prose
- Balance technical precision with accessible communication
- Use natural transitions between concepts
- NEVER speculate or conflate CVE IDs
- State "No evidence found" for missing data
- RESERVED CVE RULE: If the CVE is in RESERVED state, explicitly state that status and avoid any technical or exploitation claims. Do not infer details.
- Report only actual vulnerability data (no reserved candidates)
- MANDATORY: Include the generated risk score prominently in the analysis
  - Explicitly explain how the score (value and uncertainty) was derived, citing the key drivers from evidence, popularity, technical exploitability, and EPSS

REPORT STRUCTURE:
- Opening: Vulnerability overview with key metrics (CVSS, CWE, EPSS), products, exploitation status
- Exploitation Analysis: Real-world evidence, threat actors, methodology with confidence levels
- Vulnerability Context: Related CVEs (MANDATORY when present), co-exploitation/combined use when sources link CVEs as used together, attack chains only when explicitly evidenced, vulnerability families. Enumerate up to 6 related CVEs with short linkage reasons.
- Remediation Guidance: Patches, configurations, detection strategies with priorities
- Assessment Summary: Final section integrating the computed risk score with contextual explanation, risk evaluation with score justification, and actionable next steps

QUALITY STANDARDS: Every claim traceable to tool output, professional tone, actionable intelligence, risk score integration.

MANDATORY TECHNICAL INTEGRATION: When available, integrate detailed technical exploitation analysis produced by the Technical Exploitation Analyst, including exploitation methodologies, code examples, technical requirements/constraints, and mitigation bypass notes.

DELEGATION: Use "Ask question to coworker" format with EXACT coworker names from: "Senior Vulnerability Researcher" OR "Exploit Intelligence Analyst" OR "Cyber Threat Intelligence Researcher" OR "Technical Exploitation Analyst" OR "Vulnerability Risk Scoring Analyst"."""

analyst = Agent(
    role='Principal Security Analyst',
    goal='Synthesize all research findings into a cohesive, evidence-based vulnerability analysis report that provides clear risk assessments, specific remediation guidance, and actionable defensive recommendations for security teams.',
    backstory=ANALYST_PROMPT,
    verbose=DEBUG_ENABLED,
    allow_delegation=True,  # Enable delegation for comprehensive analysis
    llm=analyst_llm,
    cache=True
)

# =============================================================================
# TASK DEFINITIONS
# =============================================================================

research_planning_task = Task(
    description="""Analyze the research request '{prompt}' and create a strategic research plan to determine the best approach for vulnerability investigation.

RESEARCH PLANNING OBJECTIVES:
1. PROMPT ANALYSIS: Parse the request to identify research objectives, scope, and any provided identifiers
2. RESEARCH STRATEGY: Determine whether internet research is needed to discover identifiers or if direct Vulners database queries are sufficient
3. IDENTIFIER DISCOVERY PLAN: If no specific identifiers provided, plan internet research strategy to find relevant CVE IDs, bulletin IDs, or security advisories
4. RESEARCH PRIORITIZATION: Establish research priorities and sequence based on the request type and available information

PRIORITY RULES:
- ALWAYS prioritize direct Vulners research when ANY identifiers are present
- Internet research is SECONDARY and only for discovery when no identifiers provided
- Focus on efficiency: use available identifiers first, discover missing ones second

ANTI-YEAR-HALLUCINATION RULES - CRITICAL
- NEVER add hardcoded years like "2023", "2024", "2025" to research strategies
- NEVER add hardcoded years like "2023", "2024", "2025" to search methodologies
- NEVER add hardcoded years like "2023", "2024", "2025" to execution plans
- ONLY use relative time terms: "latest", "recent", "new", "current", "today", "this week", "this month"
- If you see ANY year in your thoughts, STOP and remove it immediately
- This is a CRITICAL rule - violating it will cause research failure

PLANNING METHODOLOGY:

1. PROMPT ANALYSIS:
   - Identify if specific CVE IDs, bulletin IDs, or any security identifiers are provided
   - RECOGNIZE SECURITY IDENTIFIER PATTERNS: CVE-XXXX-XXXXX format, vendor security bulletins, advisory numbers, patch references
   - Determine research scope (vendor, product, vulnerability type, timeframe)
   - Assess whether the request requires discovery of recent/current vulnerabilities
   - Identify any special research requirements (exploited, zero-day, critical severity)

2. RESEARCH STRATEGY DETERMINATION:
   - DIRECT QUERY (HIGHEST PRIORITY): If ANY identifiers provided (CVE IDs, bulletin IDs, advisory IDs), plan direct Vulners database research FIRST
   - DISCOVERY RESEARCH (SECONDARY): If NO identifiers provided AND request asks for "latest", "recent", "new", or "current" vulnerabilities, plan internet research first
   - HYBRID APPROACH: If partial identifiers provided, plan combination of direct research (for known IDs) + targeted discovery (for missing context)

3. INTERNET RESEARCH PLANNING (WHEN NEEDED):
   - Identify search terms and strategies for finding recent security identifiers
   - CRITICAL: NEVER include hardcoded years in search strategies - use only relative time terms like "latest", "recent", "new", "current"
   - Plan focus areas (vendor, product, vulnerability type, severity)
   - Establish criteria for prioritizing discovered identifiers
   - Plan search sequence and fallback strategies

4. RESEARCH EXECUTION PLAN:
   - Sequence research steps (internet discovery -> identifier research -> related document analysis)
   - Identify priority research areas and resource allocation
   - Plan for comprehensive coverage vs. focused analysis
   - Establish success criteria and completion conditions

OUTPUT PROTOCOL:
- Append exactly one single line at the very end: RISK_INPUTS={...} as specified in your prompt.
""",
    expected_output="Clear research strategy document including: (1) Research objectives and scope analysis, (2) Required research approach (direct query vs. discovery research), (3) Specific search strategies and identifier discovery plans when needed, (4) Research sequence and priority order, (5) Success criteria and expected outcomes. The last line must be a single-line RISK_INPUTS JSON object.",
    agent=research_planner
)

vulnerability_research_task = Task(
    description="""Execute the research plan: Gather comprehensive vulnerability intelligence from Vulners database and internet sources.

CRITICAL WORKFLOW:
1. Check prompt for CVE/bulletin IDs FIRST
2. If IDs present: Use Vulners database tools directly (examine available tool descriptions to identify CVE and bulletin query tools)
3. If NO IDs: Use internet search to discover identifiers, then research with Vulners tools
4. Investigate a manageable subset of related CVEs when useful; do not assume they form a chain unless explicitly stated by sources. ALWAYS enumerate related CVEs discovered (up to 6) with short linkage reasons.
5. Extract and research HIGH-VALUE bulletins (exploit docs, CISA alerts, vendor advisories)
6. Provide complete technical profiles for analysis

RESERVED CVE WORKFLOW (MANDATORY):
- If CVE is RESERVED:
  - Explicitly report RESERVED status
  - Parse returned data for related documents; for any vendor advisories/bulletins present, fetch them using bulletin query tool and summarize only their contents
  - Do NOT perform internet searches unless authoritative documents are linked in the data and need cross-checking
  - If no linked documents, end with RESERVED status and no further details

CVE RELATIONSHIP ANALYSIS (CONDITIONAL):
- If sources link multiple CVEs as being used together in exploitation or campaigns, report co-exploitation/combined use and explain the linkage (shared vector, prerequisite environment, same actor/toolkit, or coordinated campaign).
- Only mention or analyze stepwise exploitation chains when sources explicitly describe chain order or dependency.
- Map attack chains and vulnerability dependencies only if supported by cited sources.
- Do not infer chains from mere co-mentions of CVEs; prefer describing observed co-exploitation where applicable.
- Investigate a manageable subset of related CVEs when useful, without assuming they form a chain.
- Assess relationship impact on risk only when explicitly evidenced (co-exploitation or chain).

TOOL USAGE RULES:
- Tool calls MANDATORY - use only tool outputs
- NEVER use hardcoded years - use relative terms only
- NEVER conflate similar CVE IDs
- RESERVED CVE RULE: If the CVE is RESERVED, explicitly report that status and refrain from technical details unless present in sources
- Research related documents and CVE relationships only when evidenced in Vulners data; avoid assumptions

TOOL SEQUENCE: Vulners database tools FIRST when identifiers present, internet search FIRST when no identifiers.

OUTPUT PROTOCOL:
- Append exactly one single line at the very end: RISK_INPUTS={...} as specified in your prompt (see RESEARCHER_RISK_OUTPUT_GUIDE).
""",
expected_output='Complete vulnerability intelligence including: CVE data with metrics (CVSS, CWE, EPSS), bulletin analysis with patches, exploitation evidence, related documents, affected versions, CVE relationship analysis (co-exploitation/combined use and, when explicitly evidenced, exploitation chains) with relationships and exploitation pathways, and remediation guidance from all sources. The last line must be a single-line RISK_INPUTS JSON object.',
    agent=vulnerability_researcher
)

exploit_analysis_task = Task(
    description="""Analyze exploitation data from SHARED Vulners data collected by the Senior Vulnerability Researcher. NO additional tool calls required.

DATA SOURCE: Use ONLY the Vulners tool outputs from the vulnerability research task. All necessary data has been collected.

ANALYSIS FOCUS:
1. EXPLOITATION STATUS: Extract exploitation indicators, sources, and confidence levels from shared CVE data (search for fields indicating active exploitation)
2. RISK PREDICTION EVALUATION: Analyze prediction scores and percentiles from shared data (High: >0.7, Medium: 0.4-0.7, Low: <0.4) - look for EPSS or similar scoring
3. EXPLOIT DOCUMENTS: Filter exploit-related entries from shared document listings, assess credibility and technical depth
4. TIMELINE CORRELATION: Map exploit availability against CVE disclosure dates using shared timestamps
5. TECHNICAL ASSESSMENT: Categorize exploit types (PoC, weaponized, scanner) and complexity from shared document metadata
6. MONITORING TELEMETRY ANALYSIS: Analyze monitoring/telemetry data for earliest exploitation evidence (search for ShadowServer, honeypot, sensor data)
7. CVE RELATIONSHIP ANALYSIS: Analyze related CVE relationships, including co-exploitation/combined use and, when explicitly evidenced, stepwise exploitation chains, from shared data. ALWAYS enumerate related CVEs when present (up to 6) with 3-8 word linkage reasons.

RESERVED CVE GATING (MANDATORY):
- If the shared CVE is RESERVED and the researcher provided no linked authoritative documents (vendor advisories/bulletins), immediately state RESERVED status and conclude; do not proceed with exploitation analysis.
- If authoritative documents are linked and summarized by the researcher, limit analysis strictly to what those documents state; avoid inference.

MONITORING TELEMETRY ANALYSIS REQUIREMENTS:
- Extract and summarize monitoring/telemetry items from shared Vulners data (look for ShadowServer, honeypot, sensor, telemetry fields)
- Focus on exploitation timeline and earliest occurrences observed
- Document the first detection timestamps and geographic distribution
- Correlate telemetry data with vulnerability disclosure dates
- Identify exploitation patterns and attack signatures from telemetry
- Cross-reference with other sources - don't dismiss earlier exploitation evidence from different sources
- Provide timeline analysis showing progression from disclosure to active exploitation

CVE RELATIONSHIP ANALYSIS (CONDITIONAL):
- If sources in the shared data link multiple CVEs as used together, report co-exploitation/combined use and describe the relationship.
- Analyze stepwise exploitation chains only when explicitly indicated by sources in the shared data; identify chain links and prerequisite vulnerabilities.
- Map connections enabling complex attacks only with cited evidence.
- Avoid assuming chains from related CVE lists alone; prefer co-exploitation language where appropriate.
- Assess exploitation feasibility impact only when relationship evidence exists (co-exploitation or chain).

EFFICIENCY RULE: Work exclusively with previously collected intelligence - no additional Vulners queries needed if this ID has already been researched.
TOOL USAGE: Use Vulners database tools FIRST for referenced documents if IDs are present in the context, then internet search for additional technical details.

OUTPUT PROTOCOL:
- Append exactly one single line at the very end: RISK_INPUTS={...} as specified in your prompt.

DELIVERABLES: Exploitation status, risk prediction assessment, exploit availability analysis with recency context, concise related CVE enumeration with linkage reasons (up to 6), and (when explicitly evidenced) CVE chain relationships, plus risk assessment based on shared data.""",
    expected_output='Exploit intelligence summary with exploitation status, risk prediction evaluation, exploit documents analysis, monitoring/telemetry timeline with earliest occurrences, conditional CVE chain analysis only when explicitly evidenced, and risk assessment based on shared Vulners data. The last line must be a single-line RISK_INPUTS JSON object.',
    agent=exploit_researcher
)

threat_intelligence_task = Task(
    description="""Augment vulnerability intelligence with verified threat intelligence focused on adversary attribution and attack campaigns.

SEARCH OBJECTIVES:
1. THREAT ACTOR ATTRIBUTION: Validate claims against multiple authoritative sources
2. ATTACK CAMPAIGNS: Research broader campaign context and victim intelligence
3. COMPREHENSIVE TTPs ANALYSIS: Detailed analysis of Tactics, Techniques, and Procedures used in exploitation
   - IDENTIFY SPECIFIC TTPs: Map exploitation to MITRE ATT&CK framework when possible
   - ATTACK VECTORS: Document how the vulnerability is being exploited in the wild
   - EXPLOITATION METHODOLOGY: Detail step-by-step attack procedures observed
   - POST-EXPLOITATION: Analyze follow-on actions and lateral movement techniques
   - DETECTION EVASION: Identify techniques used to avoid security controls
4. VICTIM INTELLIGENCE: Verify claims about affected organizations
5. TIMELINE CORRELATION: Map attack timelines against disclosure dates

TTP COLLECTION FOCUS:
- Search for specific exploitation techniques observed in the wild
- Document weaponized exploit usage and deployment methods
- Analyze command and control infrastructure associated with exploitation
- Identify persistence mechanisms and lateral movement techniques
- Map to MITRE ATT&CK framework for standardized TTP classification

SOURCE HIERARCHY: Government agencies (CISA, NSA), threat intel firms (CrowdStrike, Mandiant, ShadowServer), security news (THN, BleepingComputer).

VERIFICATION: Cross-reference attributions, distinguish confirmed vs. suspected, focus on actionable intelligence.

OUTPUT PROTOCOL:
- Append exactly one single line at the very end: RISK_INPUTS={...} as specified in your prompt.
""",
    expected_output='Comprehensive threat intelligence summary with detailed TTP analysis including specific exploitation techniques, MITRE ATT&CK mappings, attack methodologies, attribution confidence, campaign context, victim intelligence, and actionable defensive recommendations based on observed TTP patterns. The last line must be a single-line RISK_INPUTS JSON object.',
    agent=internet_researcher
)

technical_exploitation_task = Task(
    description="""Retrieve and analyze detailed technical exploitation information for vulnerabilities with ample exploitation evidence using ALL available tools (Vulners CVE query, Vulners bulletin query, and Internet Search).

ACTIVATION CRITERIA: Only execute when vulnerability shows strong exploitation evidence:
- Active exploitation indicators from Vulners data
- Multiple exploit documents available
- CISA KEV or similar catalog presence indicating active exploitation
- Significant technical research needed beyond basic status

TECHNICAL ANALYSIS OBJECTIVES:
1. VULNERS REFERENCE EXTRACTION (MANDATORY): Extract exploitation document references from Vulners data using CVE query tool
   - Related documents with exploit-related types (search for document type indicators)
   - Bulletin/advisory IDs from document listings
   - Technical references in CVE descriptions
   - Security advisory references

2. DOCUMENT RETRIEVAL (MANDATORY): Use Vulners bulletin query tool to retrieve referenced documents by ID
   - Extract exact bulletin/document IDs from CVE query results
   - Use bulletin query tool to get detailed technical information
   - Parse technical details, code samples, and methodologies from retrieved documents

3. INTERNET TECHNICAL SEARCH (MANDATORY): Search for additional detailed exploitation information not present in Vulners
   - Use specific search terms: "[CVE-ID] exploit technical details methodology"
   - Look for proof-of-concept code, exploitation walkthroughs, technical write-ups
   - Prioritize authoritative sources (GitHub, ExploitDB, security research blogs)
   - Focus on recent publications with technical depth

4. TECHNICAL SYNTHESIS: Extract and organize exploitation details
   - Exploitation methodology and attack vectors
   - Code snippets and proof-of-concept examples
   - Technical requirements and prerequisites
   - Mitigation bypass techniques
   - Real-world exploitation scenarios
   - Attack chain analysis

5. QUALITY VALIDATION: Assess technical information credibility
   - Source authority and expertise
   - Technical accuracy and completeness
   - Code functionality and reproducibility
   - Recentness and current relevance

DELIVERABLES: Comprehensive technical exploitation summary including:
- Detailed exploitation methodologies with step-by-step analysis
- Technical requirements, prerequisites, and constraints
- Code examples and functional proof-of-concept references
- Attack vectors and exploitation paths with technical details
- Real-world application scenarios and impact analysis
- Technical mitigation analysis and bypass techniques

EFFICIENCY RULE: Use Vulners database tools FIRST when identifiers are present; ALWAYS follow with internet search to fill missing technical details.
TOOL USAGE: CVE query tool → parse document listings and titles → bulletin query tool by document identifier → internet search for gaps.

OUTPUT PROTOCOL:
- Append exactly one single line at the very end: RISK_INPUTS={...} as specified in your prompt.

OUTPUT FORMAT: Structured technical summary with clear sections for methodology, code examples, and technical analysis.""",
    expected_output='Comprehensive technical exploitation summary including detailed methodologies, code examples, attack vectors, technical requirements, and exploitation analysis for vulnerabilities with ample exploitation evidence. The last line must be a single-line RISK_INPUTS JSON object.',
    agent=technical_exploit_researcher
)

risk_scoring_task = Task(
    description="""Generate quantitative risk scores using SHARED Vulners data collected by the Senior Vulnerability Researcher and aggregated RISK_INPUTS lines from all prior tasks. NO additional tool calls required.

DATA SOURCE: Use ONLY the Vulners tool outputs from the vulnerability research task and the RISK_INPUTS single-line JSON contributions from all prior tasks. All necessary data has been collected.

RISK SCORING OBJECTIVES:
1. DATA EXTRACTION: Extract key metrics from SHARED research outputs (search flexibly for these data points):
   - Core CVE information: ID, published date, description (any fields with "id", "cve", "published", "date", "description")
   - Risk scoring metrics: CVSS scores and vectors (any fields with "cvss", "score", "vector", "severity", "base_score")
   - Exploit prediction: EPSS/probability scores and percentiles (any fields with "epss", "probability", "percentile", "score")
   - Exploitation evidence: Active exploitation indicators, monitoring data (any fields with "exploit", "wild", "active", "shadowserver", "kev", "cisa", "honeypot", "telemetry")
   - Affected products/systems (any fields with "affected", "product", "vendor", "software", "system")
   - Related documents by type and metadata WITH PUBLICATION DATES (any fields with "document", "bulletin", "advisory", "reference", "published", "date")
   - Weakness classifications: CWE and attack patterns (any fields with "cwe", "weakness", "vulnerability_type", "capec", "attack_pattern")
   - Current date for recency calculations

2. RECENCY EVALUATION: Assess information freshness and current status:
   - Calculate age of all documents in days from current date
   - Identify documents older than 90 days as potentially outdated
   - Check for patches previously marked as "delayed" but now available
   - Flag any stale exploitation information or outdated vendor guidance
   - Determine current patch availability status for risk adjustment

3. EVIDENCE ANALYSIS: Assess exploitation evidence strength from shared data with recency weighting:
   - Active exploitation confirmation and sources (search for exploitation indicator fields)
   - Known Exploited Vulnerabilities catalog presence (search for KEV, CISA, catalog fields)
   - Exploit document availability from document listings (search for GitHub, ExploitDB, PoC, exploit-type documents)
   - Scanner coverage with view counts (search for Nessus, OpenVAS, Nuclei, scanner documents)
   - Vendor advisories and emergency patches (search for vendor, advisory, patch, solution fields)
   - Security research coverage and authority from shared intelligence
   - Apply recency weighting to all evidence types

3. POPULARITY ASSESSMENT: Evaluate affected system popularity from shared product data:
   - Internet-critical infrastructure (Exchange, AD, Linux kernel, OpenSSL): 1.0
   - Enterprise backbone (VMware, cloud platforms, databases): 0.8
   - Business applications (CMS, frameworks, databases): 0.6
   - Specialized enterprise software: 0.3
   - Obscure/niche tools: 0.1

4. TECHNICAL EXPLOITABILITY: Analyze from shared scoring metrics and weakness data:
   - Network accessibility (search for AV:N vs AV:L or similar indicators in CVSS vectors)
   - Attack complexity (search for AC:L vs AC:H or similar indicators)
   - Privileges required (search for PR:N vs PR:L/H or similar indicators)
   - User interaction requirements (search for UI:N vs UI:R or similar indicators)
   - Weakness boost for high-impact categories (search for critical CWE types or attack pattern severity)

5. SCORE COMPUTATION: Apply evidence-based algorithm to shared data:
   - Aggregate exploitation evidence factor (E)
   - Calculate popularity factor (P) with hard caps
   - Determine technical exploitability (T)
   - Integrate EPSS scores (R) with appropriate weighting
   - Apply adaptive scoring formula with context constraints
   - Calculate uncertainty metric based on evidence quality

EFFICIENCY RULE: Work exclusively with previously collected Vulners intelligence and RISK_INPUTS contributions - no additional queries needed.

CRITICAL REQUIREMENTS:
- Use ONLY data from previous research task outputs
- NEVER invent or assume missing data points
- Apply scoring algorithm precisely as specified
- Return exactly one JSON object: {"value": X.X, "uncertainty": Y.Y}
- Ensure value is 0.0-10.0 (1 decimal) and uncertainty is 0.0-10.0 (1 decimal)
- Lower uncertainty = higher confidence in the score""",
    expected_output='JSON object with quantitative risk assessment: {"value": X.X, "uncertainty": Y.Y} where value is the 0.0-10.0 risk score and uncertainty is the 0.0-10.0 confidence metric (lower = more confident).',
    agent=risk_analyst
)

analysis_task = Task(
    description="""Create a comprehensive vulnerability analysis report using ONLY SHARED data from previous research tasks. NO additional tool calls required.

DATA SOURCE: Use ONLY the outputs from: vulnerability_researcher (Vulners data), exploit_researcher (exploitation analysis), technical_exploit_researcher (technical exploitation details), internet_researcher (threat intelligence), and risk_analyst (quantitative scoring).

SYNTHESIS REQUIREMENTS:
1. Integrate exact technical metrics from shared Vulners data (search for CVSS scores, CWE classifications, EPSS predictions with precise values - be flexible about field names)
2. Compile exploitation evidence from shared exploit analysis including monitoring/telemetry timeline and earliest occurrences
3. Include CVE relationship analysis from shared intelligence:
   - Document related CVE relationships and connections when sources link them (co-exploitation/combined use) or explicitly describe chains
   - Explain how CVEs are used together in campaigns or toolkits when sources state it; only explain stepwise chains when documented
   - Identify prerequisite vulnerabilities that enable attacks only with explicit citations
   - Map attack pathways leveraging multiple vulnerabilities only when supported by evidence
   - Assess the impact of co-exploitation or chains on overall risk assessment only when relationship evidence exists
4. Document remediation steps with exact versions and configurations from shared sources
5. Provide detection mechanisms and monitoring guidance from shared research
6. MANDATORY: Integrate the generated risk score prominently in the analysis
7. CRITICAL: Evaluate information recency and current patch availability status
8. CONDITIONAL: Include detailed technical exploitation analysis when available from the Technical Exploitation Analyst
9. MANDATORY: Include comprehensive TTP analysis with MITRE ATT&CK mappings and exploitation methodologies from threat intelligence research

RECENCY EVALUATION:
- Assess publication dates of all documents and intelligence
- Flag any information older than 90 days as potentially outdated
- Explicitly check if patches mentioned as "delayed" are now available
- Cross-reference document dates with current date to identify stale information
- Prioritize recent patches, advisories, and security updates in recommendations

REPORT FORMAT: Flowing narrative paragraphs (NOT bullet points), 6-8 paragraphs total.
- Opening: Vulnerability overview with key metrics and exploitation status from shared data (flexibly extract CVSS, severity, and exploitation indicators)
- Risk Assessment: Prominently feature the computed risk score (value and uncertainty) with contextual explanation of the scoring methodology and factors
- Current Status Evaluation: Explicit assessment of patch availability and information recency
- Exploitation Analysis: Risk prediction assessment, monitoring/telemetry timeline with earliest occurrences, exploit availability, and technical details from shared analysis
- Technical Exploitation Details: When available, detailed exploitation methodologies, code examples, and technical analysis from the Technical Exploitation Analyst
- Threat Intelligence & TTPs: Detailed analysis of threat actor attribution, attack campaigns, adversary TTPs with MITRE ATT&CK mappings, exploitation methodologies, and observed attack patterns from shared research
- CVE Relationship Analysis: Detailed analysis of related CVE relationships, including co-exploitation/combined use, and stepwise exploitation chains ONLY when explicitly evidenced in shared intelligence; otherwise, focus on individual CVEs without assuming chains
- Remediation Guidance: Specific patches and mitigation strategies prioritized by risk score from shared sources, emphasizing current availability
- Closing Assessment: Risk evaluation with score justification and priority recommendations

RISK SCORE INTEGRATION:
- Extract the JSON risk score from the shared risk scoring task output
- Interpret the risk value (0.0-10.0) and uncertainty (0.0-10.0) in context
- Explain how the score was derived from available shared evidence
- Use the score to prioritize remediation recommendations
- Contextualize the uncertainty level and its implications

EFFICIENCY RULE: Work exclusively with previously collected intelligence - no additional queries needed.

QUALITY: Every claim traceable to shared task outputs, no speculation, focus on actionable intelligence, risk score prominently featured.""",
    expected_output='Comprehensive vulnerability analysis report in flowing narrative paragraphs, integrating all shared research findings including detailed CVE relationship analysis (co-exploitation/combined use and explicitly evidenced chains), monitoring/telemetry timeline with earliest occurrences, comprehensive TTP analysis with MITRE ATT&CK mappings, and threat intelligence, with evidence-based assessments, prominently featuring the quantitative risk score, and providing actionable recommendations prioritized by risk level.',
    agent=analyst
)

# =============================================================================
# CREW SETUP AND ORCHESTRATION
# =============================================================================

# Create the base crew with explicit agents
base_crew = Crew(
    name="VM-Agent",
    agents=[
        research_planner,
        vulnerability_researcher,
        exploit_researcher,
        internet_researcher,
        technical_exploit_researcher,
        risk_analyst,
        analyst
    ],
    tasks=[
        research_planning_task,
        vulnerability_research_task,
        exploit_analysis_task,
        threat_intelligence_task,
        technical_exploitation_task,
        risk_scoring_task,
        analysis_task
    ],
    process=Process.sequential,
    verbose=DEBUG_ENABLED
)
