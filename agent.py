#!/usr/bin/env python3
"""
Vulners AI Agent - Main Execution File

This script provides automated vulnerability intelligence gathering and analysis 
using the Vulners database and internet research capabilities.

Agents, tools, and tasks have been moved to agents_definitions.py for better organization.
"""

# =============================================================================
# IMPORTS AND ENVIRONMENT SETUP
# =============================================================================

import os
import logging
import json
import sys
from datetime import datetime
from dotenv import load_dotenv
from crewai import Crew
from contextlib import contextmanager

# Disable CrewAI telemetry to prevent connection timeout errors - MUST be set before any CrewAI imports
os.environ["CREWAI_TELEMETRY_OPT_OUT"] = "true"
os.environ["OTEL_SDK_DISABLED"] = "true"  # Additional telemetry disable for OpenTelemetry

# Import agent definitions, tools, and tasks from separate module
from agents_definitions import create_crew

# Load environment variables from .env file
load_dotenv()
# Configuration for timing display - respect DEBUG setting
DEBUG_ENABLED = os.getenv("DEBUG", "False").lower() == "true"

# Setup logging
def setup_logging():
    """Setup logging configuration for both console and file output."""
    # Create log file in the same directory as this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    logs_dir = os.path.join(script_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    log_filename = os.path.join(logs_dir, f"vm_agent_log_at_{datetime.now().strftime('%Y-%m-%dT%H-%M-%S')}.txt")

    # Configure root logger to only show warnings/errors from other libraries
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.WARNING)
    # Remove any existing root handlers to prevent interference
    root_logger.handlers = []

    # Add a handler for warnings/errors from other libraries
    if DEBUG_ENABLED:
        warning_handler = logging.StreamHandler()
        warning_handler.setLevel(logging.WARNING)
        warning_handler.setFormatter(logging.Formatter('⚠️  %(name)s: %(message)s'))
        root_logger.addHandler(warning_handler)

    # Create console logger (for regular execution messages)
    console_logger = logging.getLogger('vm_agent_console')
    console_logger.setLevel(logging.DEBUG if DEBUG_ENABLED else logging.INFO)
    console_logger.handlers = []  # Clear any existing handlers

    # Create file logger (for detailed configuration and all messages)
    file_logger = logging.getLogger('vm_agent_file')
    file_logger.setLevel(logging.DEBUG)
    file_logger.handlers = []  # Clear any existing handlers

    # Create formatters - console with colors, file clean text
    console_formatter = logging.Formatter('%(message)s')

    # For file output, we'll strip ANSI codes
    class CleanFormatter(logging.Formatter):
        def format(self, record):
            message = super().format(record)
            # Remove ANSI escape sequences for clean text file
            import re
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            return ansi_escape.sub('', message)

    clean_file_formatter = CleanFormatter('%(message)s')

    # File handler (shared for both loggers) - clean output, append mode for tee stream
    file_handler = logging.FileHandler(log_filename, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(clean_file_formatter)

    # Console handler (only for console logger)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if DEBUG_ENABLED else logging.INFO)
    console_handler.setFormatter(console_formatter)

    # Add handlers to loggers
    console_logger.addHandler(console_handler)
    console_logger.addHandler(file_handler)  # Console logger also writes to file
    file_logger.addHandler(file_handler)

    return console_logger, file_logger, log_filename

# Initialize logging
console_logger, file_logger, log_filename = setup_logging()

@contextmanager
def capture_stdout_to_log(log_filename):
    """Context manager to capture stdout and also write to log file."""
    class TeeStream:
        def __init__(self, original_stream, log_file):
            self.original_stream = original_stream
            self.log_file = log_file

        def write(self, data):
            if data.strip():  # Only write non-empty lines
                try:
                    # Clean ANSI codes from the data before writing to log
                    import re
                    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                    clean_data = ansi_escape.sub('', data)

                    with open(self.log_file, 'a', encoding='utf-8') as f:
                        f.write(clean_data)
                        f.flush()
                except:
                    pass  # Don't fail if log write fails
            self.original_stream.write(data)
            self.original_stream.flush()

        def flush(self):
            self.original_stream.flush()

    original_stdout = sys.stdout
    original_stderr = sys.stderr

    try:
        sys.stdout = TeeStream(original_stdout, log_filename)
        sys.stderr = TeeStream(original_stderr, log_filename)
        yield
    finally:
        sys.stdout = original_stdout
        sys.stderr = original_stderr

def get_crew_configuration(crew: Crew, prompt: str) -> dict:
    """Gathers the configuration of the crew, agents, tasks, and all LLM configurations."""

    def mask_api_key(api_key: str) -> str:
        """Masks the API key for security."""
        return f"{api_key[:4]}...{api_key[-4:]}" if api_key and len(api_key) > 8 else "Not set or too short"

    config = {
        "prompt": prompt,
        "crew": {
            "process": str(crew.process),
            "verbose": crew.verbose,
            "agent_count": len(crew.tasks),
        },
        "agents": [],
        "tasks": [],
    }

    # Extract agents from task assignments (hierarchical mode doesn't use explicit agents list)
    agents_dict = {}

    # Function to get LLM configuration for an agent
    def get_agent_llm_config(agent):
        if hasattr(agent, 'llm') and agent.llm:
            llm = agent.llm

            # Try to get stored configuration first, then fall back to direct access
            if hasattr(llm, '_config_values'):
                config = llm._config_values.copy()
            else:
                # Fallback to direct attribute access
                config = {
                    "model": getattr(llm, 'model', 'gpt-4o'),
                    "temperature": getattr(llm, 'temperature', 0.1),
                    "max_retries": 3,
                    "max_completion_tokens": 10000,
                }

            return config
        return None

    # Extract agents from tasks (primary method, works for both hierarchical and sequential)
    for task in crew.tasks:
        if task.agent:
            agent = task.agent
            agent_key = f"{agent.role}_{agent.goal[:20]}..."  # Create unique key for deduplication
            if agent_key not in agents_dict:
                agent_data = {
                    "role": agent.role,
                    "goal": agent.goal,
                    "backstory": agent.backstory,
                    "tools": [{"name": tool.name, "description": tool.description} for tool in agent.tools] if hasattr(agent, 'tools') and agent.tools else [],
                    "allow_delegation": agent.allow_delegation,
                    "verbose": agent.verbose,
                }
                llm_config = get_agent_llm_config(agent)
                if llm_config:
                    agent_data["llm_configuration"] = llm_config
                agents_dict[agent_key] = agent_data

    # Add agents to config
    config["agents"] = list(agents_dict.values())

    for task in crew.tasks:
        config["tasks"].append({
            "description": task.description,
            "expected_output": task.expected_output,
            "agent": task.agent.role,
        })
        
    return config

def log_configuration_section(log_filename, crew, prompt):
    """Log the crew configuration section to file directly."""
    # Ensure the file is fresh for configuration
    with open(log_filename, 'w', encoding='utf-8') as f:
        f.write("########################################\n")
        f.write("## Crew Configuration\n")
        f.write("########################################\n\n")

        config = get_crew_configuration(crew, prompt)
        f.write(json.dumps(config, indent=2))
        f.write("\n\n")

    # Force flush to ensure it's written
    with open(log_filename, 'a', encoding='utf-8') as f:
        f.flush()

# Removed log_crew_execution_section function as logging is now handled within captured output

def run_crew_execution_with_logging(natural_prompt: str, console_logger, file_logger, execution_context="console"):
    """Run the crew and return results with comprehensive logging."""
    console_logger.info(f"🚀 Starting VM-Agent Execution")
    console_logger.info(f"Prompt: {natural_prompt}")
    console_logger.info("")

    inputs = {'prompt': natural_prompt}
    result = None  # Initialize result to avoid UnboundLocalError

    try:
        # Create a fresh crew for this request to avoid state accumulation issues
        base_crew = create_crew()
        
        # Log crew configuration (file only)
        log_configuration_section(log_filename, base_crew, natural_prompt)

        if execution_context == "console":
            # Console execution with tee stream for simultaneous console + file output
            console_logger.info("⏳ Starting crew execution...")

            class TeeStream:
                def __init__(self, original_stream, log_file):
                    self.original_stream = original_stream
                    self.log_file = log_file

                def write(self, data):
                    if data.strip():  # Only write non-empty content
                        # Write to original stream (console)
                        self.original_stream.write(data)
                        self.original_stream.flush()

                        # Write to log file (clean version)
                        try:
                            # Remove ANSI codes for clean log file
                            import re
                            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                            clean_data = ansi_escape.sub('', data)

                            with open(self.log_file, 'a', encoding='utf-8') as f:
                                f.write(clean_data)
                                f.flush()
                        except:
                            pass  # Don't fail if log write fails

                def flush(self):
                    self.original_stream.flush()

            # Temporarily replace stdout and stderr with tee streams
            original_stdout = sys.stdout
            original_stderr = sys.stderr

            try:
                sys.stdout = TeeStream(original_stdout, log_filename)
                sys.stderr = TeeStream(original_stderr, log_filename)

                # Execute crew - output goes to both console and file in real-time
                try:
                    result = base_crew.kickoff(inputs=inputs)
                except Exception as crew_error:
                    # Handle CrewAI execution failures gracefully
                    error_msg = f"❌ Crew execution failed: {str(crew_error)}"
                    console_logger.error(error_msg)
                    file_logger.error(f"Crew execution error: {str(crew_error)}")

                    # Check if it's a planning-related error
                    if "PlannerTaskPydanticOutput" in str(crew_error) or "planning" in str(crew_error).lower():
                        console_logger.warning("⚠️  Planning system failed - falling back to direct execution")
                        file_logger.warning("Planning system failed - falling back to direct execution")

                        # Try to disable planning and retry
                        try:
                            console_logger.info("🔄 Retrying with planning disabled...")
                            base_crew.planning = False
                            result = base_crew.kickoff(inputs=inputs)
                            console_logger.info("✅ Retry successful")
                        except Exception as retry_error:
                            error_msg = f"❌ Retry also failed: {str(retry_error)}"
                            console_logger.error(error_msg)
                            file_logger.error(f"Retry failed: {str(retry_error)}")
                            raise crew_error  # Raise original error
                    else:
                        raise crew_error  # Re-raise non-planning errors

            finally:
                # Restore original streams
                sys.stdout = original_stdout
                sys.stderr = original_stderr

            # Log completion
            console_logger.info("✅ Crew execution completed")

        else:
            # Web execution (or any other context) - simple approach
            console_logger.info("⏳ Starting crew execution...")

            # Execute crew - let CrewAI output naturally, use logging for tracking
            try:
                result = base_crew.kickoff(inputs=inputs)
            except Exception as crew_error:
                # Handle CrewAI execution failures gracefully
                error_msg = f"❌ Crew execution failed: {str(crew_error)}"
                console_logger.error(error_msg)
                file_logger.error(f"Crew execution error: {str(crew_error)}")

                # Check if it's a planning-related error
                if "PlannerTaskPydanticOutput" in str(crew_error) or "planning" in str(crew_error).lower():
                    console_logger.warning("⚠️  Planning system failed - falling back to direct execution")
                    file_logger.warning("Planning system failed - falling back to direct execution")

                    # Try to disable planning and retry
                    try:
                        console_logger.info("🔄 Retrying with planning disabled...")
                        base_crew.planning = False
                        result = base_crew.kickoff(inputs=inputs)
                        console_logger.info("✅ Retry successful")
                    except Exception as retry_error:
                        error_msg = f"❌ Retry also failed: {str(retry_error)}"
                        console_logger.error(error_msg)
                        file_logger.error(f"Retry failed: {str(retry_error)}")
                        raise crew_error  # Raise original error
                else:
                    raise crew_error  # Re-raise non-planning errors

            # Log completion
            console_logger.info("✅ Crew execution completed")

        console_logger.info("")
        console_logger.info("########################################")
        console_logger.info("## Execution Summary")
        console_logger.info("########################################")
        console_logger.info(f"Analysis completed at: {datetime.now().isoformat()}")
        console_logger.info(f"Debug mode: {'Enabled' if DEBUG_ENABLED else 'Disabled'}")

        return result

    except Exception as e:
        console_logger.error(f"❌ Execution failed: {e}")
        file_logger.error(f"❌ Execution failed: {e}")
        import traceback
        file_logger.error("Full traceback:")
        file_logger.error(traceback.format_exc())
        return None

if __name__ == '__main__':
    
    # Flexible prompt examples - modify as needed:
    # Single CVE with smart bulletin research: "Analyze CVE-2025-53770 with critical patches and advisories"
    # Comparison: "Compare CVE-2025-53770 and CVE-2024-12345 for severity and impact"  
    # Bulletin focus: "Analyze RHSA-2025:11803 and its security implications"
    # Research question: "What are the exploitation trends for WordPress plugin vulnerabilities in 2025?"
    # Threat landscape: "Assess the current threat landscape for SharePoint vulnerabilities"
    # Comprehensive analysis: "Provide complete vulnerability analysis for CVE-2025-53770 including all vendor patches and remediation guidance"
    
    natural_prompt = "Analyze CVE-2025-53770"

    console_logger.info("=" * 80)
    console_logger.info("VM-Agent Starting")
    console_logger.info(f"Timestamp: {datetime.now().isoformat()}")
    console_logger.info(f"Debug Mode: {'Enabled' if DEBUG_ENABLED else 'Disabled'}")
    console_logger.info("=" * 80)
    console_logger.info("")

    try:
        result = run_crew_execution_with_logging(natural_prompt, console_logger, file_logger)

    except Exception as e:
        console_logger.error(f"❌ Fatal error in main execution: {e}")
        file_logger.error(f"❌ Fatal error in main execution: {e}")
        import traceback
        file_logger.error("Full traceback:")
        file_logger.error(traceback.format_exc())
        print(f"\n❌ Fatal error: {e}")
        print("Check log file for complete details")