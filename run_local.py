#!/usr/bin/env python3
"""
Local development runner for Vulners AI Agent

This script helps run the application locally with proper environment setup.
Always launches the web UI for easy interaction.
"""

import os
import sys
import webbrowser
import time
from pathlib import Path

def setup_environment():
    """Setup environment variables for local development."""
    # Use load_dotenv for proper .env file parsing (same as agent.py)
    try:
        from dotenv import load_dotenv
        # Load from .env file if it exists
        env_file = Path('.env')
        if env_file.exists():
            print("Loading environment from .env file...")
            load_dotenv(env_file)
        else:
            print("⚠️  No .env file found. Using system environment variables.")
    except ImportError:
        print("⚠️  python-dotenv not available. Using system environment variables.")
        # Fallback to manual parsing if dotenv is not available
        env_file = Path('.env')
        if env_file.exists():
            print("Loading environment from .env file (manual parsing)...")
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key] = value

def check_requirements():
    """Check if required environment variables are set."""
    required_vars = ['OPENAI_API_KEY']
    missing_vars = []
    
    for var in required_vars:
        value = os.getenv(var)
        if not value:
            missing_vars.append(var)
        else:
            # Show first few characters of API key for debugging
            masked_value = value[:10] + "..." + value[-4:] if len(value) > 14 else "***"
            print(f"✅ {var}: {masked_value}")
    
    if missing_vars:
        print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
        print("Please set them in your .env file or environment.")
        return False
    
    return True

def run_web():
    """Run the web interface."""
    print("🌐 Starting Vulners AI Agent web interface...")
    
    # Import here to ensure environment is loaded first
    from web_app import app
    import threading
    
    debug_mode = os.getenv('DEBUG', 'False').lower() == 'true'
    # Read host/port from environment with sensible defaults
    host = os.getenv('HOST', 'localhost')
    try:
        port = int(os.getenv('PORT', '8080'))
    except ValueError:
        port = 8080
    
    print(f"Web interface will be available at: http://{host}:{port}")
    print(f"Debug mode: {debug_mode}")
    
    # Start the Flask server in a background thread
    def start_server():
        # Force debug=False to prevent duplicate tabs
        app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)
    
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # Give the server a moment to start
    print("⏳ Waiting for server to start...")
    time.sleep(2)
    
    # Open browser automatically after server is ready (single tab)
    try:
        # Always open localhost for convenience even if host is 0.0.0.0
        webbrowser.open(f'http://localhost:{port}')
        print("🌐 Browser opened automatically")
    except Exception as e:
        print(f"⚠️  Could not open browser automatically: {e}")
        print(f"Please manually open: http://localhost:{port}")
    
    # Keep the main thread alive
    try:
        server_thread.join()
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")

def main():
    print("🚀 Vulners AI Agent - Local Development Runner")
    print("=" * 50)
    
    # Setup environment FIRST - before any imports
    setup_environment()
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Always run web interface
    run_web()

if __name__ == '__main__':
    main()
