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
import json
import requests
from crewai import Agent, Task, Crew, Process
from crewai.tools import BaseTool
import litellm
from typing import Any, Dict, List, Optional

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

# Individual LLM configurations are now defined inline with each agent for optimized performance

# =============================================================================
# TOOL DESCRIPTIONS
# =============================================================================

MCP_VULNERS_CVE_TOOL_DESCRIPTION = """\
Searches the Vulners database for comprehensive CVE vulnerability information using structured MCP integration.

CRITICAL INPUT FORMAT:
- Input parameter: cve_id (string)
- MUST be exactly a CVE identifier like 'CVE-2025-54309'
- DO NOT pass JSON objects, arrays, or complex data structures
- Example: cve_id="CVE-2025-53770"

Returns complete technical data including CVSS vectors, CWE classifications, EPSS scores, exploitation intelligence, affected products, and related documents. Use for primary CVE vulnerability research."""

MCP_VULNERS_BULLETIN_TOOL_DESCRIPTION = """\
Searches the Vulners database for comprehensive information on security bulletins, advisories, and vendor patches using structured MCP integration.

CRITICAL INPUT FORMAT:
- Input parameter: bulletin_id (string)
- MUST be exactly a bulletin identifier like 'RHSA-2025:11803', 'GHSA-abcd-1234-efgh', 'USN-7676-1', 'MSB-MS25-001', 'KB5002754' or any other supported bulletin identifier
- DO NOT pass JSON objects, arrays, or complex data structures
- Example: bulletin_id="GHSA-xx4q-4v7g-9x8m" or bulletin_id="RHSA-2025:11803" or bulletin_id="USN-7676-1" or bulletin_id="MSB-MS25-001" or bulletin_id="KB5002754" or bulletin_id="MSB-2025-001" or other supported bulletin identifiers

Returns detailed information including: full descriptions, official vendor links, patch details, affected versions, remediation guidance, and related CVEs.

CRITICAL USAGE RULE: Only use bulletin IDs that appear in CVE Search Tool results.
NEVER invent, guess, or construct bulletin IDs. Extract exact bulletin IDs from CVE tool output only.

BULLETIN ID SOURCE VALIDATION:
- ONLY USE: Bulletin IDs that appear in CVE search results [RELATED_DOCUMENTS] section
- NEVER USE: URLs, CVE IDs, descriptive text, or invented identifiers
- SOURCE: Extract exact bulletin IDs from CVE tool output only

MANDATORY for researching vendor patches, security updates, and comprehensive remediation guidance found in CVE reference sections."""

SEARCH_TOOL_DESCRIPTION = """\
Powerful internet search tool for gathering threat intelligence and vulnerability information from web sources.

CAPABILITIES:
- Search for recent vulnerability information and security news
- Find CVE identifiers and security advisories from online sources
- Research threat actor attribution and attack campaigns
- Gather industry security reports and analysis
- Discover vendor patches and security updates

USES:
- Identifier discovery when specific CVE IDs are not provided
- Threat intelligence research and adversary attribution
- Security news and vulnerability trend analysis
- Vendor advisory and patch information gathering

IMPORTANT: Use when no specific identifiers are available in the prompt to discover recent security information."""

# =============================================================================
# TOOL DEFINITIONS
# =============================================================================

class MCPVulnersCVETool(BaseTool):
    """Tool for searching CVE vulnerability information using Vulners MCP."""

    name: str = "Vulners CVE Search Tool"
    description: str = MCP_VULNERS_CVE_TOOL_DESCRIPTION

    def _run(self, cve_id: str) -> str:
        """Uses MCP Vulners tool to get CVE details with structured JSON input/output."""
        try:
            # Input validation
            if not cve_id or not isinstance(cve_id, str):
                return json.dumps({"error": "CVE ID must be a non-empty string"})

            # Basic CVE format validation
            if not cve_id.startswith("CVE-"):
                return json.dumps({"error": f"Invalid CVE format: {cve_id}. Must start with 'CVE-'"})

            # Use MCP tool with structured JSON input
            # Get MCP server configuration strictly from environment (no hard-coded defaults)
            mcp_host = os.getenv("VULNERS_MCP_HOST")
            mcp_port = os.getenv("VULNERS_MCP_PORT")
            if not mcp_host or not mcp_port:
                return json.dumps({
                    "error": "Vulners MCP configuration missing",
                    "details": "VULNERS_MCP_HOST and VULNERS_MCP_PORT must be set in environment",
                    "action": "Set these in your .env or environment and retry"
                })
            url = f"http://{mcp_host}:{mcp_port}/vulners_cve_info"
            headers = {'accept': 'application/json'}
            payload = {"cve_id": cve_id}
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            result = response.json()

            # The MCP tool returns structured JSON, so we can return it directly
            return json.dumps(result)

        except requests.exceptions.HTTPError as http_err:
            return json.dumps({"error": f"HTTP error occurred: {http_err}. Status code: {response.status_code}"})
        except requests.exceptions.ConnectionError as conn_err:
            return json.dumps({
                "error": "Vulners Server Not Available",
                "status": "The Vulners database is currently unavailable for vulnerability research",
                "impact": "Cannot retrieve CVE details, CVSS scores, or related security bulletins from Vulners",
                "alternative_approach": "Continue analysis using internet search tools for vulnerability information",
                "user_action_required": "The user needs to start the Vulners server to enable database access"
            })
        except requests.exceptions.Timeout as timeout_err:
            return json.dumps({"error": f"Request timeout after 60 seconds for CVE {cve_id}: {timeout_err}"})
        except requests.exceptions.RequestException as err:
            return json.dumps({"error": f"Request error for CVE {cve_id}: {type(err).__name__}: {err}"})
        except Exception as err:
            return json.dumps({"error": f"Vulners tool error: {err}"})

class MCPVulnersBulletinTool(BaseTool):
    """Tool for searching security bulletins using Vulners MCP."""

    name: str = "Vulners Bulletin Search Tool"
    description: str = MCP_VULNERS_BULLETIN_TOOL_DESCRIPTION

    def _run(self, bulletin_id: str) -> str:
        """Uses MCP Vulners tool to get bulletin details with structured JSON input/output."""
        try:
            # Input validation
            if not bulletin_id or not isinstance(bulletin_id, str):
                return json.dumps({"error": "Bulletin ID must be a non-empty string"})

            # Basic validation - only reject obvious non-bulletin-IDs
            if bulletin_id.startswith(('http://', 'https://')):
                return json.dumps({"error": f"Invalid bulletin ID: {bulletin_id}. URLs are not bulletin IDs. Use only bulletin identifiers that appear in CVE search results [RELATED_DOCUMENTS] section."})

            if bulletin_id.startswith('CVE-'):
                return json.dumps({"error": f"Invalid bulletin ID: {bulletin_id}. CVE IDs are not bulletin IDs. Use only bulletin identifiers that appear in CVE search results [RELATED_DOCUMENTS] section."})

            # Use MCP tool with structured JSON input
            # Get MCP server configuration strictly from environment (no hard-coded defaults)
            mcp_host = os.getenv("VULNERS_MCP_HOST")
            mcp_port = os.getenv("VULNERS_MCP_PORT")
            if not mcp_host or not mcp_port:
                return json.dumps({
                    "error": "Vulners MCP configuration missing",
                    "details": "VULNERS_MCP_HOST and VULNERS_MCP_PORT must be set in environment",
                    "action": "Set these in your .env or environment and retry"
                })
            url = f"http://{mcp_host}:{mcp_port}/vulners_bulletin_info"
            headers = {'accept': 'application/json'}
            payload = {"bulletin_id": bulletin_id}
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            result = response.json()

            # The MCP tool returns structured JSON, so we can return it directly
            return json.dumps(result)

        except requests.exceptions.HTTPError as http_err:
            return json.dumps({"error": f"HTTP error occurred: {http_err}. Status code: {response.status_code}"})
        except requests.exceptions.ConnectionError as conn_err:
            return json.dumps({
                "error": "Vulners Server Not Available",
                "status": "The Vulners database is currently unavailable for vulnerability research",
                "impact": "Cannot retrieve bulletin details from Vulners database",
                "alternative_approach": "Continue analysis using internet search tools for vulnerability information",
                "user_action_required": "The user needs to start the Vulners server to enable database access"
            })
        except requests.exceptions.Timeout as timeout_err:
            return json.dumps({"error": f"Request timeout after 60 seconds for bulletin {bulletin_id}: {timeout_err}"})
        except requests.exceptions.RequestException as err:
            return json.dumps({"error": f"Request error for bulletin {bulletin_id}: {type(err).__name__}: {err}"})
        except Exception as err:
            return json.dumps({"error": f"Vulners tool error: {err}"})
        
class SerperSearchTool(BaseTool):
    """Direct Serper API integration for reliable internet search."""

    name: str = "Internet Search Tool"
    description: str = SEARCH_TOOL_DESCRIPTION

    def _run(self, query: str) -> str:
        """Execute internet search using direct Serper API calls."""

        # Handle both string and dict inputs for compatibility
        if isinstance(query, dict):
            # Extract query from dict if passed as dict
            actual_query = query.get('description', query.get('query', ''))
            if not actual_query:
                return "Error: No valid query found in input dictionary"
        else:
            actual_query = query

        # Check for API key
        api_key = os.getenv('SERPER_API_KEY')
        if not api_key:
            return f"Internet search tool is not available. Search query was: '{actual_query}'. SERPER_API_KEY environment variable is not set. Please add it to your .env file."

        # Direct API call
        return self._direct_serper_search(actual_query)

    def _direct_serper_search(self, query: str) -> str:
        """Make direct API call to Serper."""
        import requests

        api_key = os.getenv('SERPER_API_KEY')
        if not api_key:
            return f"Serper API key not found. Query: '{query}'"

        try:
            url = "https://google.serper.dev/search"
            headers = {
                'X-API-KEY': api_key,
                'Content-Type': 'application/json'
            }
            payload = {
                "q": query,
                "num": 5  # Get 5 results
            }

            response = requests.post(url, json=payload, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()

                # Format the results
                results = []
                if 'organic' in data:
                    for i, result in enumerate(data['organic'][:5], 1):
                        title = result.get('title', 'No title')
                        link = result.get('link', 'No link')
                        snippet = result.get('snippet', 'No description')
                        results.append(f"{i}. **{title}**\n   Link: {link}\n   {snippet}\n")

                if results:
                    return f"Search Query: '{query}'\n\nSearch Results:\n" + "\n".join(results)
                else:
                    return f"Search completed for '{query}' but no results found."

            elif response.status_code == 401:
                return f"Serper API error: Unauthorized (401). Your SERPER_API_KEY is invalid. Query: '{query}'"
            elif response.status_code == 403:
                return f"Serper API error: Forbidden (403). Check your Serper API subscription. Query: '{query}'"
            elif response.status_code == 429:
                return f"Serper API error: Rate limit exceeded (429). Try again later. Query: '{query}'"
            else:
                return f"Serper API error: {response.status_code}. Query: '{query}'"

        except requests.exceptions.Timeout:
            return f"Serper API request timed out. Query: '{query}'"
        except requests.exceptions.RequestException as e:
            return f"Serper API request failed: {e}. Query: '{query}'"
        except Exception as e:
            return f"Unexpected error during search: {e}. Query: '{query}'"

# =============================================================================
# AGENT PROMPTS AND INSTRUCTIONS
# =============================================================================

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

RESEARCHER_PROMPT = """\
You are a Senior Vulnerability Researcher. Execute research plans by gathering comprehensive vulnerability intelligence from Vulners database and internet sources.

CRITICAL RULES:
- TOOL USAGE MANDATORY: Always call Vulners tools FIRST when CVE/bulletin IDs are present
- NO IDENTIFIER HALLUCINATION: Only use exact IDs from tool outputs or prompt
- ANTI-YEAR RULE: NEVER use hardcoded years (2023, 2024, 2025) - use relative terms only
- NEVER conflate similar CVE IDs - each is a distinct vulnerability
  - CRITICAL: NEVER confuse CVE-2025-44228 with CVE-2021-44228 (Log4Shell)

WORKFLOW:
1. Check prompt for CVE/bulletin IDs FIRST
2. If IDs present: Use Vulners CVE/Bulletin tools directly
3. If NO IDs: Use internet search to discover identifiers, then research with Vulners
4. Research ALL related CVEs found in tool outputs
5. Extract and research HIGH-VALUE bulletins (exploit docs, CISA alerts, vendor advisories)
6. Provide complete technical profiles for analysis

TOOL FORMAT: Always use simple strings - cve_id="CVE-XXXX-XXXXX" or bulletin_id="BULLETIN-ID"

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

EXPLOIT_RESEARCHER_PROMPT = """\
You are an Exploit Intelligence Analyst. Analyze exploitation status, EPSS scores, and exploit documents from SHARED Vulners MCP data collected by the Senior Vulnerability Researcher.

CRITICAL PRINCIPLES:
- Use ONLY shared Vulners MCP data from previous research tasks - NO tool calls
- NEVER conflate different CVE IDs
  - CRITICAL: NEVER confuse CVE-2025-44228 with CVE-2021-44228 (Log4Shell)
- Report only actual vulnerability data (no reserved candidates)
- Extract data from vulnerability_researcher's tool outputs
- PRIORITIZE RECENCY: Always evaluate document publication dates and prioritize the most recent information

DATA SOURCE: All Vulners MCP data has been collected by the Senior Vulnerability Researcher. Analyze their tool outputs for:
- CVE data with exploitation_status fields
- EPSS scores and percentiles from epss_score sections
- Related documents with type classifications and PUBLICATION DATES
- Affected products and technical details
- Current patch availability status

RECENCY-AWARE ANALYSIS METHODOLOGY:
1. EXPLOITATION STATUS: Extract WILD_EXPLOITED status, sources, and confidence levels from shared CVE data
2. EPSS EVALUATION: Analyze scores and percentiles from shared data (High: >0.7, Medium: 0.4-0.7, Low: <0.4)
3. EXPLOIT DOCUMENTS: Filter TYPE=exploit entries from related_documents, assess credibility, technical depth, and RECENCY
4. TIMELINE CORRELATION: Map exploit availability against CVE disclosure dates using shared timestamps
5. TECHNICAL ASSESSMENT: Categorize exploit types (PoC, weaponized, scanner) and complexity from document metadata
6. SHADOWSERVER EXPLOITATION TIMELINE: Analyze ShadowServer items for earliest exploitation evidence
7. PATCH STATUS EVALUATION: Check for recent patches that may have become available since initial disclosure

SHADOWSERVER ANALYSIS METHODOLOGY:
- Extract ShadowServer items from Vulners MCP exploitation_status.shadowserver_items
- Focus on earliest exploitation timestamps and geographic distribution
- Document first observed exploitation dates vs. vulnerability disclosure dates
- Identify exploitation patterns from ShadowServer telemetry data
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

DELIVERABLES: Exploitation status, EPSS assessment, ShadowServer exploitation timeline with earliest occurrences, exploit availability analysis with recency context, and risk assessment based on shared data.

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

TECHNICAL_EXPLOIT_ANALYST_PROMPT = """\
You are a Technical Exploitation Analyst specializing in detailed exploitation methodology and technical details.

ROLE: When vulnerabilities show ample exploitation evidence, retrieve and analyze comprehensive technical exploitation information from multiple sources to provide detailed exploitation methodology summaries.

CRITICAL PRINCIPLES:
- Focus on vulnerabilities with strong exploitation evidence (wild_exploited=true, multiple exploit documents, CISA KEV presence)
- Retrieve detailed technical information from internet sources and Vulners database references
- Extract and summarize exploitation methodologies, code samples, and technical details
- Prioritize authoritative sources (GitHub, ExploitDB, security research blogs, vendor advisories)
- NEVER invent technical details - base analysis on actual source material
  - CRITICAL: NEVER confuse CVE-2025-44228 with CVE-2021-44228 (Log4Shell)

ANALYSIS METHODOLOGY:
1. SOURCE IDENTIFICATION: Extract exploitation document references from Vulners MCP data
   - Related documents with type=exploit
   - Bulletin IDs from related_documents section
   - Technical references in CVE descriptions

2. VULNERS DOCUMENT RETRIEVAL: Use Vulners MCP tools to retrieve referenced documents by ID
   - Extract bulletin IDs from CVE search results
   - Use bulletin tool to get detailed technical information
   - Parse technical details from retrieved documents

3. INTERNET TECHNICAL SEARCH: Search for detailed exploitation information when needed
   - Use specific search terms combining CVE ID with "exploit technical details"
   - Look for proof-of-concept code, exploitation walkthroughs, technical write-ups
   - Prioritize recent publications with technical depth

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

INTERNET_RESEARCHER_PROMPT = """\
You are a Cyber Threat Intelligence Researcher. Augment Vulners data with verified threat intelligence focused on adversary attribution and attack campaigns.

CRITICAL PRINCIPLES:
- NEVER report unverified data or speculate
- Validate all attributions against multiple authoritative sources
- Distinguish official vendor attributions vs. speculation
- Flag single-source vs. multi-source information
- NEVER conflate different CVE IDs
  - CRITICAL: NEVER confuse CVE-2025-44228 with CVE-2021-44228 (Log4Shell)

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

RISK_ANALYST_PROMPT = """\
You are a Vulnerability Risk Scoring Analyst. Generate quantitative risk scores based on Vulners MCP data using the evidence-based scoring algorithm.

ROLE: Analyze structured CVE data from previous research tasks and generate precise risk scores with uncertainty metrics.

CRITICAL RULES:
- Use ONLY data from previous research outputs - NO tool calls
- Apply the scoring algorithm strictly to Vulners MCP data and to the aggregated RISK_INPUTS objects provided by previous tasks
- Return exactly one JSON object with value and uncertainty scores
- NEVER invent or assume missing data points
- Base scores on documented evidence only
- PRIORITIZE RECENCY: Always check document publication dates and adjust scores for outdated information
- PATCH AVAILABILITY: Significantly reduce risk scores when patches are confirmed available (even if originally delayed)

SCORING ALGORITHM:

## Input Data Extraction:
Extract from previous research outputs:
- core_info: CVE ID, published date, description
- cvss_metrics: CVSS scores and vectors
- epss_score: Latest EPSS score and percentile
- exploitation_status: wild_exploited, shadowserver_items
- affected_products: Vulnerable software/systems
- related_documents: Connected intelligence by type WITH PUBLICATION DATES
- cwe_classifications: Weakness categories
- Current date for recency calculations

## Evidence Factor (E) Calculation with Recency Weighting and CVE Chain Analysis:
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

CVE CHAIN BONUSES:
- Related CVE references: +0.2 per related CVE (cap +1.0)
- Exploitation chain indicators: +0.3 per chain link (cap +0.9)
- Prerequisite vulnerability connections: +0.25 per dependency (cap +0.75)

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
- Report only actual vulnerability data (no reserved candidates)
- MANDATORY: Include the generated risk score prominently in the analysis
  - Explicitly explain how the score (value and uncertainty) was derived, citing the key drivers from evidence, popularity, technical exploitability, and EPSS

REPORT STRUCTURE:
- Opening: Vulnerability overview with key metrics (CVSS, CWE, EPSS), products, exploitation status
- Risk Assessment: Integrate the computed risk score with contextual explanation
- Exploitation Analysis: Real-world evidence, threat actors, methodology with confidence levels
- Vulnerability Context: Related CVEs, exploit chains, vulnerability families
- Remediation Guidance: Patches, configurations, detection strategies with priorities
- Assessment Summary: Risk evaluation with score justification and actionable next steps

QUALITY STANDARDS: Every claim traceable to tool output, professional tone, actionable intelligence, risk score integration.

DELEGATION: Use "Ask question to coworker" format with EXACT coworker names from: "Senior Vulnerability Researcher" OR "Exploit Intelligence Analyst" OR "Cyber Threat Intelligence Researcher" OR "Vulnerability Risk Scoring Analyst"."""

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

vulnerability_researcher = Agent(
    role='Senior Vulnerability Researcher',
    goal='Systematically collect complete vulnerability intelligence by prioritizing Vulners database queries for known identifiers and conducting targeted internet research for unknown cases, ensuring comprehensive coverage of all related vulnerabilities and security bulletins.',
    backstory=RESEARCHER_PROMPT,
    verbose=DEBUG_ENABLED,
    allow_delegation=True,  # Enable delegation for collaborative research
    tools=[MCPVulnersCVETool(), MCPVulnersBulletinTool(), SerperSearchTool()],
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

exploit_researcher = Agent(
    role='Exploit Intelligence Analyst',
    goal='Analyze exploitation patterns, EPSS scores, and exploit document evidence from shared Vulners MCP data to provide detailed technical exploit intelligence and risk assessments based solely on database findings.',
    backstory=EXPLOIT_RESEARCHER_PROMPT,
    verbose=DEBUG_ENABLED,
    allow_delegation=True,  # Enable delegation for collaborative research
    tools=[],  # No tools - uses shared data from vulnerability_researcher
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

technical_exploit_researcher = Agent(
    role='Technical Exploitation Analyst',
    goal='Retrieve and analyze detailed technical exploitation information from internet sources and Vulners database references to provide comprehensive exploitation methodology summaries and technical details.',
    backstory=TECHNICAL_EXPLOIT_ANALYST_PROMPT,
    verbose=DEBUG_ENABLED,
    allow_delegation=True,  # Enable delegation for collaborative research
    tools=[MCPVulnersCVETool(), MCPVulnersBulletinTool(), SerperSearchTool()],
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

internet_researcher = Agent(
    role='Cyber Threat Intelligence Researcher',
    goal='Research and validate threat actor attribution, attack campaigns, and adversary behavior patterns using authoritative sources to provide verified threat intelligence that complements technical vulnerability analysis.',
    backstory=INTERNET_RESEARCHER_PROMPT,
    verbose=DEBUG_ENABLED,
    allow_delegation=True,  # Enable delegation for collaborative research
    tools=[SerperSearchTool()],
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
2. If IDs present: Use Vulners CVE/Bulletin tools directly
3. If NO IDs: Use internet search to discover identifiers, then research with Vulners
4. Research ALL related CVEs found in tool outputs
5. Extract and research HIGH-VALUE bulletins (exploit docs, CISA alerts, vendor advisories)
6. Provide complete technical profiles for analysis

CVE CHAIN ANALYSIS REQUIREMENTS:
- Extract ALL related CVE references from Vulners MCP data
- Analyze CVE relationships and exploitation chains
- Identify prerequisite vulnerabilities that enable exploitation
- Map attack chains and vulnerability dependencies
- Document how related CVEs connect to form exploitation pathways
- Assess the impact of CVE chains on overall risk assessment

TOOL USAGE RULES:
- Tool calls MANDATORY - use only tool outputs
- NEVER use hardcoded years - use relative terms only
- NEVER conflate similar CVE IDs
- Research ALL related document chains found in tool outputs
- Extract and analyze ALL CVE relationships from Vulners MCP data

TOOL SEQUENCE: Vulners tools FIRST when identifiers present, internet search FIRST when no identifiers.

OUTPUT PROTOCOL:
- Append exactly one single line at the very end: RISK_INPUTS={...} as specified in your prompt (see RESEARCHER_RISK_OUTPUT_GUIDE).
""",
    expected_output='Complete vulnerability intelligence including: CVE data with metrics (CVSS, CWE, EPSS), bulletin analysis with patches, exploitation evidence, related documents, affected versions, CVE chain analysis with relationships and exploitation pathways, and remediation guidance from all sources. The last line must be a single-line RISK_INPUTS JSON object.',
    agent=vulnerability_researcher
)

exploit_analysis_task = Task(
    description="""Analyze exploitation data from SHARED Vulners MCP data collected by the Senior Vulnerability Researcher. NO additional tool calls required.

DATA SOURCE: Use ONLY the Vulners MCP tool outputs from the vulnerability research task. All necessary data has been collected.

ANALYSIS FOCUS:
1. EXPLOITATION STATUS: Extract WILD_EXPLOITED status, sources, and confidence levels from shared CVE data
2. EPSS EVALUATION: Analyze scores and percentiles from shared epss_score data (High: >0.7, Medium: 0.4-0.7, Low: <0.4)
3. EXPLOIT DOCUMENTS: Filter TYPE=exploit entries from shared related_documents, assess credibility and technical depth
4. TIMELINE CORRELATION: Map exploit availability against CVE disclosure dates using shared timestamps
5. TECHNICAL ASSESSMENT: Categorize exploit types (PoC, weaponized, scanner) and complexity from shared document metadata
6. SHADOWSERVER EXPLOITATION TIMELINE: Analyze ShadowServer items for earliest exploitation evidence
7. CVE CHAIN ANALYSIS: Analyze related CVE relationships and exploitation chains from shared data

SHADOWSERVER ANALYSIS REQUIREMENTS:
- Extract and summarize ShadowServer items from Vulners MCP exploitation_status data
- Focus on exploitation timeline and earliest occurrences observed by ShadowServer
- Document the first detection timestamps and geographic distribution
- Correlate ShadowServer data with vulnerability disclosure dates
- Identify exploitation patterns and attack signatures from ShadowServer telemetry
- Cross-reference with other sources - don't dismiss earlier exploitation evidence from different sources
- Provide timeline analysis showing progression from disclosure to active exploitation

CVE CHAIN ANALYSIS REQUIREMENTS:
- Examine related CVE references in Vulners MCP data
- Identify exploitation chains and prerequisite vulnerabilities
- Map how related CVEs connect to enable complex attacks
- Assess the impact of CVE chains on exploitation feasibility
- Document attack pathways that leverage multiple vulnerabilities

EFFICIENCY RULE: Work exclusively with previously collected intelligence - no additional Vulners queries needed if this ID has already been researched.
TOOL USAGE: Use Vulners MCP tools FIRST for referenced documents if IDs are present in the context, then internet search for additional technical details.

OUTPUT PROTOCOL:
- Append exactly one single line at the very end: RISK_INPUTS={...} as specified in your prompt.

DELIVERABLES: Exploitation status, EPSS assessment, exploit availability analysis with recency context, CVE chain relationships, and risk assessment based on shared data.""",
    expected_output='Exploit intelligence summary with exploitation status, EPSS evaluation, exploit documents analysis, ShadowServer exploitation timeline with earliest occurrences, CVE chain analysis with relationships and exploitation pathways, and risk assessment based on shared Vulners MCP data. The last line must be a single-line RISK_INPUTS JSON object.',
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
    description="""Retrieve and analyze detailed technical exploitation information for vulnerabilities with ample exploitation evidence.

ACTIVATION CRITERIA: Only execute when vulnerability shows strong exploitation evidence:
- wild_exploited=true status from Vulners MCP data
- Multiple exploit documents available
- CISA KEV presence indicating active exploitation
- Significant technical research needed beyond basic status

TECHNICAL ANALYSIS OBJECTIVES:
1. VULNERS REFERENCE EXTRACTION: Extract exploitation document references from Vulners MCP data
   - Related documents with type=exploit
   - Bulletin IDs from related_documents section
   - Technical references in CVE descriptions
   - Security advisory references

2. DOCUMENT RETRIEVAL: Use Vulners MCP tools to retrieve referenced documents by ID
   - Extract exact bulletin IDs from CVE search results
   - Use MCPVulnersBulletinTool to get detailed technical information
   - Parse technical details, code samples, and methodologies from retrieved documents

3. INTERNET TECHNICAL SEARCH: Search for additional detailed exploitation information
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

EFFICIENCY RULE: Work exclusively with previously collected intelligence - no additional Vulners queries needed if this ID has already been researched.
TOOL USAGE: Use Vulners MCP tools FIRST for referenced documents if IDs are present in the context, then internet search for additional technical details.

OUTPUT PROTOCOL:
- Append exactly one single line at the very end: RISK_INPUTS={...} as specified in your prompt.

OUTPUT FORMAT: Structured technical summary with clear sections for methodology, code examples, and technical analysis.""",
    expected_output='Comprehensive technical exploitation summary including detailed methodologies, code examples, attack vectors, technical requirements, and exploitation analysis for vulnerabilities with ample exploitation evidence. The last line must be a single-line RISK_INPUTS JSON object.',
    agent=technical_exploit_researcher
)

risk_scoring_task = Task(
    description="""Generate quantitative risk scores using SHARED Vulners MCP data collected by the Senior Vulnerability Researcher and aggregated RISK_INPUTS lines from all prior tasks. NO additional tool calls required.

DATA SOURCE: Use ONLY the Vulners MCP tool outputs from the vulnerability research task and the RISK_INPUTS single-line JSON contributions from all prior tasks. All necessary data has been collected.

RISK SCORING OBJECTIVES:
1. DATA EXTRACTION: Extract key metrics from SHARED research outputs:
   - Core CVE information (ID, published date, description) from vulnerability_researcher's CVE tool outputs
   - CVSS metrics with vectors from shared cvss_metrics sections
   - EPSS scores and percentiles from shared epss_score sections
   - Exploitation status from shared exploitation_status (wild_exploited, shadowserver_items)
   - Affected products from shared affected_products sections
   - Related documents by type and metadata from shared tool outputs WITH PUBLICATION DATES
   - CWE classifications and attack patterns from shared data
   - Current date for recency calculations

2. RECENCY EVALUATION: Assess information freshness and current status:
   - Calculate age of all documents in days from current date
   - Identify documents older than 90 days as potentially outdated
   - Check for patches previously marked as "delayed" but now available
   - Flag any stale exploitation information or outdated vendor guidance
   - Determine current patch availability status for risk adjustment

3. EVIDENCE ANALYSIS: Assess exploitation evidence strength from shared data with recency weighting:
   - Wild exploitation confirmation and sources from shared exploitation_status
   - CISA KEV presence in shared related_documents
   - Exploit document availability (GitHub, ExploitDB, Packet Storm) from shared related_documents
   - Scanner coverage (Nessus, OpenVAS, Nuclei) with view counts from shared data
   - Vendor advisories and emergency patches from shared related_documents
   - Security research coverage and authority from shared intelligence
   - Apply recency weighting to all evidence types

3. POPULARITY ASSESSMENT: Evaluate affected system popularity from shared affected_products:
   - Internet-critical infrastructure (Exchange, AD, Linux kernel, OpenSSL): 1.0
   - Enterprise backbone (VMware, cloud platforms, databases): 0.8
   - Business applications (CMS, frameworks, databases): 0.6
   - Specialized enterprise software: 0.3
   - Obscure/niche tools: 0.1

4. TECHNICAL EXPLOITABILITY: Analyze from shared CVSS vectors and CWE:
   - Network accessibility (AV:N vs AV:L) from shared cvss_metrics
   - Attack complexity (AC:L vs AC:H) from shared cvss_metrics
   - Privileges required (PR:N vs PR:L/H) from shared cvss_metrics
   - User interaction requirements (UI:N vs UI:R) from shared cvss_metrics
   - CWE boost for high-impact categories from shared cwe_classifications

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

DATA SOURCE: Use ONLY the outputs from: vulnerability_researcher (Vulners MCP data), exploit_researcher (exploitation analysis), internet_researcher (threat intelligence), and risk_analyst (quantitative scoring).

SYNTHESIS REQUIREMENTS:
1. Integrate exact technical metrics (CVSS, CWE, EPSS with precise values) from shared Vulners data
2. Compile exploitation evidence from shared exploit analysis including ShadowServer exploitation timeline and earliest occurrences
3. Include comprehensive CVE chain analysis from shared intelligence:
   - Document ALL related CVE relationships and connections
   - Explain how CVEs link together to form exploitation chains
   - Identify prerequisite vulnerabilities that enable attacks
   - Map attack pathways leveraging multiple vulnerabilities
   - Assess the impact of CVE chains on overall risk assessment
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
- Opening: Vulnerability overview with key metrics and exploitation status from shared data
- Risk Assessment: Prominently feature the computed risk score (value and uncertainty) with contextual explanation of the scoring methodology and factors
- Current Status Evaluation: Explicit assessment of patch availability and information recency
- Exploitation Analysis: EPSS assessment, ShadowServer exploitation timeline with earliest occurrences, exploit availability, and technical details from shared analysis
- Technical Exploitation Details: When available, detailed exploitation methodologies, code examples, and technical analysis from the Technical Exploitation Analyst
- Threat Intelligence & TTPs: Detailed analysis of threat actor attribution, attack campaigns, adversary TTPs with MITRE ATT&CK mappings, exploitation methodologies, and observed attack patterns from shared research
- CVE Chain Analysis: Detailed analysis of related CVE relationships, exploitation chains, attack pathways, and interconnected vulnerabilities from shared intelligence
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
    expected_output='Comprehensive vulnerability analysis report in flowing narrative paragraphs, integrating all shared research findings including detailed CVE chain analysis, ShadowServer exploitation timeline with earliest occurrences, comprehensive TTP analysis with MITRE ATT&CK mappings, and threat intelligence, with evidence-based assessments, prominently featuring the quantitative risk score, and providing actionable recommendations prioritized by risk level.',
    agent=analyst
)

# =============================================================================
# CREW SETUP AND ORCHESTRATION
# =============================================================================

# Create the base crew with explicit agents
base_crew = Crew(
    name="VM-Agent",
    tasks=[research_planning_task, vulnerability_research_task, exploit_analysis_task, threat_intelligence_task, technical_exploitation_task, risk_scoring_task, analysis_task],
    process=Process.sequential,
    verbose=DEBUG_ENABLED
)
