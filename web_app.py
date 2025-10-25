#!/usr/bin/env python3
"""
Vulners AI Agent Web Interface

A simple Flask web application that provides a web interface for the Vulners AI Agent.
"""

import os
import markdown
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import time
import uuid
import re
from queue import Queue, Empty

# Load environment variables first (same as agent.py)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # Fallback if python-dotenv is not available
    pass

# DON'T import agent functions at module level - this loads all CrewAI dependencies
# Instead, import them inside the route handler when actually needed
# This makes the web server start much faster

app = Flask(__name__)

# Lazy import helper for agent functions
_agent_module = None

def _get_agent_functions():
    """Lazy-load agent module only when needed."""
    global _agent_module
    if _agent_module is None:
        print("  📦 Loading CrewAI agents (first request only)...")
        import time
        start = time.time()
        
        # Import agent module (tiktoken issue is fixed in agents_definitions.py)
        from agent import run_crew_execution_with_logging, setup_logging
        
        print(f"  ✓ Agents loaded in {time.time() - start:.2f}s")
        _agent_module = {
            'run_crew_execution_with_logging': run_crew_execution_with_logging,
            'setup_logging': setup_logging
        }
    return _agent_module

# Real-time update function removed to prevent duplicate page opening

SESSION_QUEUES = {}
SESSION_TIMEOUT_SECONDS = 60 * 10  # Best-effort cleanup window

# ANSI escape sequence remover (same pattern used in file logger)
ANSI_ESCAPE_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def _enqueue(session_id, message: str):
    try:
        q = SESSION_QUEUES.get(session_id)
        if q is not None and message is not None:
            # Normalize and strip ANSI escapes for tidy browser output
            cleaned = ANSI_ESCAPE_RE.sub('', message)
            cleaned = cleaned.replace('\r', '\n')
            # Split into lines to avoid gigantic SSE frames
            for line in cleaned.splitlines():
                q.put(line.rstrip())
    except Exception:
        # Swallow enqueue errors to avoid interrupting main flow
        pass

def _mark_session_done(session_id):
    try:
        q = SESSION_QUEUES.get(session_id)
        if q is not None:
            q.put(None)  # Sentinel to end SSE
    except Exception:
        pass

@app.route('/api/start_run', methods=['POST'])
def start_run():
    """Initialize a new streaming session and return its ID."""
    session_id = uuid.uuid4().hex
    SESSION_QUEUES[session_id] = Queue()
    return jsonify({"session_id": session_id})

@app.route('/api/logs/stream')
def logs_stream():
    """Server-Sent Events endpoint that streams logs for a given session."""
    session_id = request.args.get('session_id')
    if not session_id or session_id not in SESSION_QUEUES:
        return jsonify({'error': 'Invalid or missing session_id'}), 400

    q = SESSION_QUEUES[session_id]

    def generate():
        last_heartbeat = time.time()
        # Initial event to confirm connection
        yield 'event: init\ndata: {}\n\n'
        while True:
            try:
                item = q.get(timeout=1.0)
                if item is None:
                    yield 'event: done\ndata: end\n\n'
                    break
                # Ensure each line is sent as a separate SSE message
                yield f"data: {item}\n\n"
            except Empty:
                # Heartbeat comment to keep connection alive behind proxies
                if time.time() - last_heartbeat > 15:
                    yield ': heartbeat\n\n'
                    last_heartbeat = time.time()

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/')
def index():
    """Render the main page."""
    print(f"📄 Page request received from {request.remote_addr}")
    return render_template('index.html')

# SocketIO event handlers removed to prevent duplicate page opening

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """API endpoint to run vulnerability analysis."""
    try:
        data = request.get_json()
        if not data or 'prompt' not in data:
            return jsonify({'error': 'Missing prompt parameter'}), 400
        
        prompt = data['prompt'].strip()
        if not prompt:
            return jsonify({'error': 'Prompt cannot be empty'}), 400

        session_id = data.get('session_id')
        
        print(f"🔍 Starting analysis for prompt: {prompt}")

        # Lazy-load agent functions only when needed (first request)
        agent_funcs = _get_agent_functions()
        setup_logging = agent_funcs['setup_logging']
        run_crew_execution_with_logging = agent_funcs['run_crew_execution_with_logging']

        # Setup logging for the analysis
        console_logger, file_logger, log_filename = setup_logging()

        # Run the analysis using the direct agent function with web context
        if session_id and session_id in SESSION_QUEUES:
            # Per-request Tee for stdout/stderr to also push to SSE queue
            class TeeStream:
                def __init__(self, original_stream, sid):
                    self.original_stream = original_stream
                    self.sid = sid
                    self._buffer = ''

                def write(self, data):
                    # Always forward to original stream
                    self.original_stream.write(data)
                    self.original_stream.flush()

                    if not data:
                        return
                    # Buffer until newline to send complete lines
                    self._buffer += data
                    while '\n' in self._buffer:
                        line, self._buffer = self._buffer.split('\n', 1)
                        _enqueue(self.sid, line)

                def flush(self):
                    self.original_stream.flush()
                    if self._buffer:
                        _enqueue(self.sid, self._buffer)
                        self._buffer = ''

            import sys as _sys
            original_stdout = _sys.stdout
            original_stderr = _sys.stderr
            try:
                _sys.stdout = TeeStream(original_stdout, session_id)
                _sys.stderr = TeeStream(original_stderr, session_id)
                result = run_crew_execution_with_logging(prompt, console_logger, file_logger, execution_context="web")
            finally:
                try:
                    _sys.stdout.flush()
                    _sys.stderr.flush()
                except Exception:
                    pass
                _sys.stdout = original_stdout
                _sys.stderr = original_stderr
                _mark_session_done(session_id)
        else:
            result = run_crew_execution_with_logging(prompt, console_logger, file_logger, execution_context="web")

        # Convert CrewOutput to string for JSON serialization
        result_str = str(result) if result else "No result generated"
        

        
        # Convert markdown to HTML for proper rendering
        try:
            # Configure markdown with extensions for better formatting
            md = markdown.Markdown(extensions=[
                'markdown.extensions.fenced_code',
                'markdown.extensions.tables',
                'markdown.extensions.codehilite',
                'markdown.extensions.nl2br'
            ])
            result_html = md.convert(result_str)
        except Exception as e:
            print(f"⚠️  Markdown conversion failed: {e}")
            # Fallback to plain text if markdown conversion fails
            result_html = result_str.replace('\n', '<br>')
        
        # Prepare response
        response = {
            'success': True,
            'result': result_str,  # Keep original markdown for debugging
            'result_html': result_html,  # Add HTML version for rendering
            'log_file': log_filename
        }
        
        print(f"✅ Analysis completed successfully")
        return jsonify(response)
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        
        # Error handling without real-time updates
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'service': 'vulners-agent'})

if __name__ == '__main__':
    # Force debug mode to False to prevent duplicate page opening
    debug_mode = False
    # Read host/port from environment for consistency with run_local
    host = os.getenv('HOST', 'localhost')
    try:
        port = int(os.getenv('PORT', '8080'))
    except ValueError:
        port = 8080

    print(f"Starting Vulners AI Agent Web Interface on {host}:{port}")
    print(f"Debug mode: {debug_mode} (forced to False to prevent duplicate tabs)")

    # Use regular Flask development server with debug disabled to prevent duplicate page opening
    app.run(host=host, port=port, debug=False, use_reloader=False)
