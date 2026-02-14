import os
import psutil
import subprocess
from flask import Flask, render_template_string, request, redirect, url_for
from datetime import datetime
import json
import shlex

app = Flask(__name__)

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(SCRIPT_DIR, 'process_history.json')
LOG_DIR = os.path.join(SCRIPT_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)


def load_history():
    """Load process history from file"""
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading history: {e}")
    return []


def save_history(history):
    """Save process history to file"""
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
        print(f"✅ History saved to: {HISTORY_FILE}")
    except Exception as e:
        print(f"❌ Error saving history: {e}")


def add_history(action, cmdline, log_file=None):
    """Helper to append to history with optional log file path"""
    history = load_history()
    history.append({
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'action': action,
        'cmdline': cmdline,
        'log': log_file or ""
    })
    save_history(history)


def get_python_processes():
    """Get all running Python processes with detailed info"""
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'status']):
        try:
            info = p.info
            if info['name'] and 'python' in info['name'].lower():
                create_time = datetime.fromtimestamp(info['create_time']).strftime(
                    '%Y-%m-%d %H:%M:%S') if info['create_time'] else 'N/A'
                procs.append({
                    'pid': info['pid'],
                    'name': info['name'],
                    'cmdline': ' '.join(info['cmdline']) if info['cmdline'] else 'N/A',
                    'create_time': create_time,
                    'status': info['status'],
                    'running': True
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return sorted(procs, key=lambda x: x['pid'])


def kill_process(pid):
    """Terminate a process gracefully"""
    try:
        p = psutil.Process(pid)
        try:
            cmdline = ' '.join(p.cmdline()) if p.cmdline() else 'Unknown'
        except Exception:
            cmdline = f'PID: {pid}'

        p.terminate()
        p.wait(timeout=5)

        add_history('⏹️ Stopped', cmdline)
        return True, f"Process {pid} terminated"
    except psutil.NoSuchProcess:
        return False, f"Process {pid} not found"
    except Exception as e:
        print(f"Error in kill_process: {e}")
        return False, f"Error: {str(e)}"


def force_kill_process(pid):
    """Force kill a process"""
    try:
        p = psutil.Process(pid)
        try:
            cmdline = ' '.join(p.cmdline()) if p.cmdline() else 'Unknown'
        except Exception:
            cmdline = f'PID: {pid}'

        p.kill()
        p.wait(timeout=5)

        add_history('💥 Force Killed', cmdline)
        return True, f"Process {pid} force killed"
    except psutil.NoSuchProcess:
        return False, f"Process {pid} not found"
    except Exception as e:
        print(f"Error in force_kill_process: {e}")
        return False, f"Error: {str(e)}"


def infer_cwd_from_cmd(cmdline: str):
    """
    Try to infer a good working directory from the command line.

    Handles cases like:
    - /path/to/project/venv/bin/python runMe.py          -> cwd=/path/to/project
    - /path/to/project/venv/bin/python trade_report.py   -> cwd=/path/to/project
    - python /path/to/project/runMe.py                   -> cwd=/path/to/project
    - venv/bin/python src/runMe.py                       -> cwd=dir of src/runMe.py
    """
    try:
        parts = shlex.split(cmdline, posix=(os.name != 'nt'))
        if not parts:
            return None

        python_exe = parts[0]
        script_arg = None

        # Find the first .py argument
        for arg in parts[1:]:
            if arg.endswith('.py'):
                script_arg = arg
                break

        project_root = None

        # Detect venv layout and compute project root
        # Linux:  /path/to/project/venv/bin/python
        # Win:    C:\path\to\project\venv\Scripts\python.exe
        if ('/venv/bin/python' in python_exe) or ('\\venv\\Scripts\\python.exe' in python_exe):
            venv_dir = os.path.dirname(os.path.dirname(python_exe))   # .../project/venv
            project_root = os.path.dirname(venv_dir)                  # .../project

        if script_arg:
            # If script has explicit path, use its directory
            if '/' in script_arg or '\\' in script_arg:
                return os.path.dirname(os.path.abspath(script_arg))
            # Script name only (runMe.py) + venv python -> assume project_root
            if project_root:
                return project_root

        # Fallback: if we at least know project_root from venv, use that
        return project_root
    except Exception as e:
        print(f"Error inferring cwd: {e}")
        return None


def restart_process(cmdline):
    """Restart a process by command line (works for commands originally run with or without nohup)"""
    try:
        cmdline = (cmdline or "").strip()
        if not cmdline or cmdline.upper() in ("N/A", "UNKNOWN"):
            return False, "No valid command line to restart"

        # Figure out best cwd so relative scripts like runMe.py are found
        cwd = infer_cwd_from_cmd(cmdline)

        # Create a log file for this run
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = cmdline.replace(' ', '_').replace('/', '_').replace('\\', '_')
        log_file = os.path.join(LOG_DIR, f"{ts}_{safe_name}.log")

        log_fh = open(log_file, 'a')

        if os.name != 'nt':
            subprocess.Popen(
                cmdline,
                shell=True,
                cwd=cwd or None,
                stdout=log_fh,
                stderr=log_fh,
                stdin=subprocess.DEVNULL
            )
        else:
            subprocess.Popen(
                cmdline,
                shell=True,
                cwd=cwd or None,
                stdout=log_fh,
                stderr=log_fh
            )

        add_history('▶️ Started', cmdline, log_file=log_file)
        return True, "Process started"
    except Exception as e:
        print(f"Error in restart_process: {e}")
        return False, f"Error: {str(e)}"


@app.route('/')
def index():
    """Python Process Manager dashboard"""
    all_procs = get_python_processes()

    # Filter out process_manager.py from running processes display
    running_procs = [proc for proc in all_procs if 'process_manager.py' not in proc['cmdline']]

    raw_history = load_history()

    # Attach index to each history entry and filter out manager
    history_with_idx = []
    for idx, entry in enumerate(raw_history):
        if 'process_manager.py' in entry.get('cmdline', ''):
            continue
        e = entry.copy()
        e['idx'] = idx
        history_with_idx.append(e)

    # Show latest first
    history_reversed = list(reversed(history_with_idx))

    # Extract unique commands from history for "Saved Commands"
    saved_commands = []
    seen = set()
    for entry in history_with_idx:
        cmd = entry.get('cmdline', '')
        if cmd and cmd not in seen:
            seen.add(cmd)
            saved_commands.append(cmd)

    html = '''
    <html>
    <head>
        <title>Python Process Manager</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
            .container { max-width: 1400px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); overflow: hidden; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; }
            .header h1 { font-size: 28px; margin-bottom: 10px; }
            .header p { font-size: 14px; opacity: 0.9; }
            .content { padding: 30px; }
            .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }
            .stat-card { background: #f5f7fa; padding: 15px; border-radius: 8px; border-left: 4px solid #667eea; }
            .stat-card h3 { font-size: 24px; color: #667eea; margin-bottom: 5px; }
            .stat-card p { font-size: 12px; color: #666; }
            .section-title { font-size: 18px; font-weight: 600; margin: 30px 0 15px 0; color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
            .table-wrapper { overflow-x: auto; margin-bottom: 30px; }
            table { width: 100%; border-collapse: collapse; }
            th { background: #f5f7fa; padding: 15px; text-align: left; font-weight: 600; color: #333; border-bottom: 2px solid #e0e0e0; }
            td { padding: 15px; border-bottom: 1px solid #e0e0e0; }
            tr:hover { background: #f9fafb; }
            .btn { padding: 8px 14px; border-radius: 6px; border: none; cursor: pointer; font-size: 12px; font-weight: 600; transition: all 0.3s; }
            .btn-primary { background: #667eea; color: white; }
            .btn-primary:hover { background: #5568d3; }
            .btn-danger { background: #ef5350; color: white; }
            .btn-danger:hover { background: #e53935; }
            .btn-warning { background: #ffa726; color: white; }
            .btn-warning:hover { background: #fb8c00; }
            .btn-secondary { background: #9e9e9e; color: white; }
            .btn-secondary:hover { background: #757575; }
            .btn-group { display: flex; gap: 8px; flex-wrap: wrap; }
            .pid { font-weight: 600; color: #667eea; }
            .cmdline { font-family: 'Courier New', monospace; font-size: 12px; color: #555; word-break: break-all; max-width: 500px; }
            .status { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; background: #c8e6c9; color: #2e7d32; }
            .refresh-btn { float: right; margin-bottom: 20px; }
            .empty-message { text-align: center; padding: 40px; color: #999; }
            .history-time { color: #667eea; font-weight: 600; font-size: 12px; }
            .file-path { background: #f5f7fa; padding: 10px; border-radius: 4px; font-size: 11px; color: #666; margin-top: 20px; }
            pre.log { background: #111; color: #eee; padding: 20px; border-radius: 8px; max-height: 80vh; overflow: auto; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>⚙️ Python Process Manager</h1>
                <p>Monitor and manage Python processes</p>
            </div>
            <div class="content">
                <button class="btn btn-primary refresh-btn" onclick="location.reload()">🔄 Refresh</button>
                
                <div class="stats">
                    <div class="stat-card">
                        <h3>{{ running_count }}</h3>
                        <p>Running Processes</p>
                    </div>
                    <div class="stat-card">
                        <h3>{{ history_count }}</h3>
                        <p>Total History Entries</p>
                    </div>
                </div>
                
                <h2 class="section-title">🚀 Running Processes</h2>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>PID</th>
                                <th>Process Name</th>
                                <th>Command Line</th>
                                <th>Started</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for proc in running_procs %}
                            <tr>
                                <td><span class="pid">{{ proc['pid'] }}</span></td>
                                <td>{{ proc['name'] }}</td>
                                <td><span class="cmdline">{{ proc['cmdline'] }}</span></td>
                                <td>{{ proc['create_time'] }}</td>
                                <td><span class="status">{{ proc['status'] }}</span></td>
                                <td>
                                    <div class="btn-group">
                                        <form method="post" action="/restart" style="display:inline;">
                                            <input type="hidden" name="cmdline" value="{{ proc['cmdline'] }}">
                                            <button class="btn btn-primary" type="submit">🔁 Restart</button>
                                        </form>
                                        <form method="post" action="/kill" style="display:inline;">
                                            <input type="hidden" name="pid" value="{{ proc['pid'] }}">
                                            <button class="btn btn-warning" type="submit" onclick="return confirm('Stop {{ proc["pid"] }}?')">⏹️ Stop</button>
                                        </form>
                                        <form method="post" action="/force_kill" style="display:inline;">
                                            <input type="hidden" name="pid" value="{{ proc['pid'] }}">
                                            <button class="btn btn-danger" type="submit" onclick="return confirm('Force kill {{ proc["pid"] }}?')">💥 Force Kill</button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                
                {% if running_count == 0 %}
                <div class="empty-message">
                    <p>No Python processes currently running</p>
                </div>
                {% endif %}
                
                {% if saved_commands %}
                <h2 class="section-title">💾 Saved Commands</h2>
                <div style="margin-bottom: 20px;">
                    <form method="post" action="/restart_all" style="display:inline;">
                        <button class="btn btn-primary" type="submit" style="background: #4CAF50;">🚀 Restart All</button>
                    </form>
                </div>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Command</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for cmd in saved_commands %}
                            <tr>
                                <td><span class="cmdline">{{ cmd }}</span></td>
                                <td>
                                    <form method="post" action="/restart" style="display:inline;">
                                        <input type="hidden" name="cmdline" value="{{ cmd }}">
                                        <button class="btn btn-primary" type="submit">▶️ Start</button>
                                    </form>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% endif %}
                
                {% if history %}
                <h2 class="section-title">📋 Execution History</h2>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Action</th>
                                <th>Command</th>
                                <th>Log</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for entry in history %}
                            <tr>
                                <td><span class="history-time">{{ entry['time'] }}</span></td>
                                <td>{{ entry['action'] }}</td>
                                <td><span class="cmdline">{{ entry['cmdline'] }}</span></td>
                                <td>
                                    {% if entry['log'] %}
                                    <a class="btn btn-secondary" href="{{ url_for('view_log', idx=entry['idx']) }}" target="_blank">View Log</a>
                                    {% else %}
                                    -
                                    {% endif %}
                                </td>
                                <td>
                                    <form method="post" action="/restart" style="display:inline;">
                                        <input type="hidden" name="cmdline" value="{{ entry['cmdline'] }}">
                                        <button class="btn btn-primary" type="submit">▶️ Restart</button>
                                    </form>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% endif %}
                
                <div class="file-path">
                    <strong>📁 History File:</strong> {{ history_file }}<br/>
                    <strong>📁 Log Directory:</strong> {{ log_dir }}
                </div>
            </div>
        </div>
    </body>
    </html>
    '''
    return render_template_string(
        html,
        running_procs=running_procs,
        running_count=len(running_procs),
        history=history_reversed,
        history_count=len(history_with_idx),
        saved_commands=saved_commands,
        history_file=HISTORY_FILE,
        log_dir=LOG_DIR
    )


@app.route('/log/<int:idx>')
def view_log(idx):
    """Show log for a specific history entry"""
    history = load_history()
    if idx < 0 or idx >= len(history):
        return f"<h2>Invalid history index: {idx}</h2>", 404

    entry = history[idx]
    log_path = entry.get('log') or ""
    cmdline = entry.get('cmdline', '')

    if not log_path or not os.path.exists(log_path):
        return f"<h2>No log file found for this entry.</h2><p>Command: <code>{cmdline}</code></p>", 404

    try:
        with open(log_path, 'r') as f:
            content = f.read()
    except Exception as e:
        return f"<h2>Error reading log file:</h2><pre>{e}</pre>", 500

    return f"""
    <html>
    <head>
        <title>Log for: {cmdline}</title>
        <style>
            body {{ font-family: monospace; background: #111; color: #eee; padding: 20px; }}
            pre {{ white-space: pre-wrap; word-wrap: break-word; }}
            h2 {{ margin-bottom: 10px; }}
            code {{ color: #8bc34a; }}
        </style>
    </head>
    <body>
        <h2>Command:</h2>
        <p><code>{cmdline}</code></p>
        <h2>Log file:</h2>
        <p><code>{log_path}</code></p>
        <hr/>
        <pre>{content}</pre>
    </body>
    </html>
    """


@app.route('/kill', methods=['POST'])
def kill():
    pid = request.form.get('pid', type=int)
    kill_process(pid)
    return redirect(url_for('index'))


@app.route('/force_kill', methods=['POST'])
def force_kill():
    pid = request.form.get('pid', type=int)
    force_kill_process(pid)
    return redirect(url_for('index'))


@app.route('/restart', methods=['POST'])
def restart():
    cmdline = request.form.get('cmdline', '')
    restart_process(cmdline)
    return redirect(url_for('index'))


@app.route('/restart_all', methods=['POST'])
def restart_all():
    """Restart all saved commands"""
    history = load_history()

    # Extract unique commands (exclude process_manager.py)
    seen = set()
    for entry in history:
        cmd = entry.get('cmdline', '')
        if 'process_manager.py' in cmd:
            continue
        if cmd and cmd not in seen:
            seen.add(cmd)
            restart_process(cmd)

    return redirect(url_for('index'))


if __name__ == '__main__':
    print(f"📄 History file location: {HISTORY_FILE}")
    print(f"📁 Log directory: {LOG_DIR}")
    # For nohup on Linux:
    # cd /home/harshilkhatri2808/HTML && nohup /home/.../venv/bin/python process_manager.py > process_manager.log 2>&1 &
    app.run(debug=False, host='0.0.0.0', port=8001, use_reloader=False)
