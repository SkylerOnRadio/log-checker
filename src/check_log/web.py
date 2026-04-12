import os
import sys
import subprocess
import signal
from typing import Optional
from .config import C

def launch_full_app(logfile: Optional[str], app_dir: str):

    is_unix = os.name != 'nt'

    '''launches flask backend and frontend simultaneously from a specified directory'''
    # Resolve absolute path of the provided directory
    base_dir = os.path.abspath(app_dir)
    backend_path = os.path.join(base_dir, "backend.py")
    frontend_dir = os.path.join(base_dir, "frontend") 

    print(f"\n{C.CYAN}{C.BOLD}[*] Launching Full Web Dashboard...{C.RESET}")
    print(f"{C.DIM}[*] Target Directory: {base_dir}{C.RESET}")

    # 1. Start Backend
    if not os.path.exists(backend_path):
        print(f"{C.RED}[!] Error: Cannot find backend.py at {backend_path}{C.RESET}")
        sys.exit(1)

    backend_cmd = [sys.executable, backend_path]
    if logfile and os.path.exists(logfile):
        backend_cmd.append(logfile) # Pass logfile to backend for initial scan
        
    print(f"{C.DIM}[*] Starting Flask Backend...{C.RESET}")
    # Popen runs the process in the background
    backend_process = subprocess.Popen(
    backend_cmd, 
    preexec_fn=os.setsid if is_unix else None
)

    # 2. Start Frontend
    if not os.path.exists(os.path.join(frontend_dir, "package.json")):
        print(f"{C.RED}[!] Error: Frontend directory or package.json not found at {frontend_dir}{C.RESET}")
        backend_process.terminate()
        sys.exit(1)

    # Windows uses npm.cmd, Mac/Linux use npm
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    frontend_cmd = [npm_cmd, "run", "dev"]
    
    print(f"{C.DIM}[*] Starting React Frontend in {frontend_dir}...{C.RESET}")
    frontend_process = subprocess.Popen(
    frontend_cmd, cwd=frontend_dir, 
    preexec_fn=os.setsid if is_unix else None
)

    # 3. Wait and watch for Ctrl+C
    try:
        print(f"\n{C.GREEN}{C.BOLD}[+] Dashboard is running! Press Ctrl+C to stop all servers.{C.RESET}\n")
        # Keep the main script alive while the subprocesses run
        backend_process.wait()
        frontend_process.wait()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Shutting down servers gracefully...{C.RESET}")
        if is_unix:
            os.killpg(os.getpgid(backend_process.pid), signal.SIGTERM)
            os.killpg(os.getpgid(frontend_process.pid), signal.SIGTERM)
        else:
            backend_process.terminate()
            frontend_process.terminate()
        sys.exit(0)
