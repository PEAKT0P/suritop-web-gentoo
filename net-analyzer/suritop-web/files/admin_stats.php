<?php
/**
 * /var/www/suritop-web/htdocs/admin_stats.php
 * v3.5 - Pure Data Edition + API Ban Integration + Unified UI + Sorting & UX
 */
require_once __DIR__ . '/config.php';

function getStatsDB() {
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO(
            "mysql:host=" . STATS_DB_HOST . ";dbname=" . STATS_DB_NAME . ";charset=utf8mb4",
            STATS_DB_USER, STATS_DB_PASS,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
        );
    }
    return $pdo;
}

$pdo = getStatsDB();

// ── API ЭНДПОИНТЫ (ЧТЕНИЕ ИЗ БД) ──
if (isset($_GET['api'])) {
    header('Content-Type: application/json; charset=utf-8');

    $date = $_GET['date'] ?? date('Y-m-d');
    $ip = $_GET['ip'] ?? '';
    $port = $_GET['port'] ?? '';
    $all_time = ($_GET['all_time'] ?? 'false') === 'true';

    $w_ipt = "1=1"; $w_waf = "1=1"; $w_ids = "1=1";
    $p_ipt = []; $p_waf = []; $p_ids = [];

    if (!$all_time) {
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
            $w_ipt .= " AND DATE(logged_at) = ?"; $p_ipt[] = $date;
            $w_waf .= " AND DATE(logged_at) = ?"; $p_waf[] = $date;
            $w_ids .= " AND DATE(logged_at) = ?"; $p_ids[] = $date;
        }
    }
    if ($ip) {
        $w_ipt .= " AND src_ip LIKE ?"; $p_ipt[] = "%$ip%";
        $w_waf .= " AND src_ip LIKE ?"; $p_waf[] = "%$ip%";
        $w_ids .= " AND src_ip LIKE ?"; $p_ids[] = "%$ip%";
    }
    if ($port) {
        $w_ipt .= " AND dst_port = ?"; $p_ipt[] = $port;
        $w_waf .= " AND 1=0";
        $w_ids .= " AND dst_port = ?"; $p_ids[] = $port;
    }

    if ($_GET['api'] === 'day_stats') {
        $result = [];

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM ipt_drops WHERE $w_ipt");
        $stmt->execute($p_ipt); $result['total_drops'] = $stmt->fetchColumn();

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM waf_blocks WHERE $w_waf");
        $stmt->execute($p_waf); $result['total_waf'] = $stmt->fetchColumn();

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM suricata_alerts WHERE $w_ids");
        $stmt->execute($p_ids); $result['total_ids'] = $stmt->fetchColumn();

        $sql_unique = "SELECT COUNT(DISTINCT src_ip) FROM (
            SELECT src_ip FROM ipt_drops WHERE $w_ipt
            UNION SELECT src_ip FROM waf_blocks WHERE $w_waf
            UNION SELECT src_ip FROM suricata_alerts WHERE $w_ids
        ) as u";
        $stmt = $pdo->prepare($sql_unique);
        $stmt->execute(array_merge($p_ipt, $p_waf, $p_ids));
        $result['unique_ips'] = $stmt->fetchColumn();

        $sql_top = "
            SELECT src_ip, COUNT(*) as total_events, MAX(max_source) as max_source, country FROM (
                SELECT src_ip, 'IPTables' as max_source FROM ipt_drops WHERE $w_ipt
                UNION ALL SELECT src_ip, 'WAF' as max_source FROM waf_blocks WHERE $w_waf
                UNION ALL SELECT src_ip, 'Suricata' as max_source FROM suricata_alerts WHERE $w_ids
            ) as combined
            LEFT JOIN geo_cache g ON combined.src_ip = g.ip
            GROUP BY src_ip, country
            ORDER BY total_events DESC LIMIT 150
        ";
        $stmt = $pdo->prepare($sql_top);
        $stmt->execute(array_merge($p_ipt, $p_waf, $p_ids));
        $result['top_attackers'] = $stmt->fetchAll();

        echo json_encode($result); exit;
    }

    if ($_GET['api'] === 'ip_details') {
        $req_ip = $_GET['req_ip'] ?? '';
        $timeline = [];

        $w_ipt_ip = $w_ipt . " AND src_ip = ?"; $p_ipt_ip = array_merge($p_ipt, [$req_ip]);
        $w_waf_ip = $w_waf . " AND src_ip = ?"; $p_waf_ip = array_merge($p_waf, [$req_ip]);
        $w_ids_ip = $w_ids . " AND src_ip = ?"; $p_ids_ip = array_merge($p_ids, [$req_ip]);

        $stmt = $pdo->prepare("SELECT 'IPTables' as type, CONCAT('Блок порта: ', dst_port) as info, DATE_FORMAT(logged_at, '%Y-%m-%d %H:%i:%s') as time, 'critical' as severity FROM ipt_drops WHERE $w_ipt_ip ORDER BY logged_at DESC LIMIT 50");
        $stmt->execute($p_ipt_ip); $timeline = array_merge($timeline, $stmt->fetchAll());

        $stmt = $pdo->prepare("SELECT 'WAF' as type, CONCAT('[', host, '] ', method, ' ', uri) as info, DATE_FORMAT(logged_at, '%Y-%m-%d %H:%i:%s') as time, rule_msg as severity FROM waf_blocks WHERE $w_waf_ip ORDER BY logged_at DESC LIMIT 50");
        $stmt->execute($p_waf_ip); $timeline = array_merge($timeline, $stmt->fetchAll());

        $stmt = $pdo->prepare("SELECT 'Suricata' as type, sig_msg as info, DATE_FORMAT(logged_at, '%Y-%m-%d %H:%i:%s') as time, CONCAT('Sev: ', severity) as severity FROM suricata_alerts WHERE $w_ids_ip ORDER BY logged_at DESC LIMIT 50");
        $stmt->execute($p_ids_ip); $timeline = array_merge($timeline, $stmt->fetchAll());

        usort($timeline, function($a, $b) { return strcmp($b['time'], $a['time']); });
        echo json_encode($timeline); exit;
    }
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>🛡️ Security Data Center</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-main: #0a0e14; --bg-panel: #111820; --bg-card: #1a2230;
            --text-main: #c5cdd8; --text-muted: #6b7a8d; --text-bright: #e8ecf1;
            --border-color: #1e2a3a;
            --accent-red: #ff4757; --accent-orange: #ff9f43; --accent-blue: #3498ff; --accent-purple: #a855f7; --accent-green: #2ed573;
            --font-mono: 'JetBrains Mono', monospace;
            --font-sans: 'IBM Plex Sans', sans-serif;
            --radius: 8px;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: var(--bg-main); color: var(--text-main); font-family: var(--font-sans); padding: 16px; font-size: 13px; -webkit-font-smoothing: antialiased; }

        /* Toolbar & Controls */
        .toolbar {
            display: flex; flex-wrap: wrap; gap: 16px; justify-content: space-between; align-items: center;
            background: var(--bg-panel); padding: 16px; border-radius: var(--radius); margin-bottom: 16px; border: 1px solid var(--border-color);
        }
        .filter-group { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; width: 100%; max-width: 850px; }

        .date-nav { display: flex; align-items: center; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; overflow: hidden; }
        .btn-nav { background: transparent; color: var(--text-muted); border: none; padding: 8px 14px; cursor: pointer; font-weight: bold; transition: 0.2s; }
        .btn-nav:hover { background: rgba(255,255,255,0.05); color: var(--text-bright); }

        input[type="date"], input[type="text"] {
            background: transparent; color: var(--text-bright); border: none; 
            padding: 8px 12px; font-family: var(--font-mono); outline: none; font-size: 13px;
        }
        input[type="date"] { border-left: 1px solid var(--border-color); border-right: 1px solid var(--border-color); width: 140px; }
        input[type="text"] { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; width: 180px;}
        input[type="text"]:focus { border-color: var(--accent-blue); }
        input[type="date"]::-webkit-calendar-picker-indicator { filter: invert(0.8); cursor: pointer; }

        /* Обертка для инпута с крестиком */
        .input-clear-wrap { position: relative; display: flex; align-items: center; }
        .input-clear-wrap input { width: 180px; padding-right: 32px; }
        .input-clear-btn {
            position: absolute; right: 10px; color: var(--text-muted);
            cursor: pointer; font-size: 18px; line-height: 1;
            display: none; transition: color 0.2s; user-select: none;
        }
        .input-clear-btn:hover { color: var(--accent-red); }

        .checkbox-lbl { display: flex; align-items: center; gap: 6px; cursor: pointer; color: var(--accent-orange); font-weight: 600; padding: 4px 8px; border-radius: 6px; transition: background 0.2s;}
        .checkbox-lbl:hover { background: rgba(255, 159, 67, 0.1); }

        .stats-summary { display: flex; flex-wrap: wrap; gap: 12px; }
        .stat-badge { background: var(--bg-card); padding: 8px 12px; border-radius: 6px; border-left: 3px solid var(--border-color); font-weight: 600; font-size: 12px; display: flex; gap: 8px; color: var(--text-bright); box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
        .stat-badge.drops { border-color: var(--accent-red); }
        .stat-badge.waf { border-color: var(--accent-orange); }
        .stat-badge.ids { border-color: var(--accent-purple); }
        .stat-badge.uniq { border-color: var(--accent-blue); }

        /* Table */
        .panel { background: var(--bg-panel); border: 1px solid var(--border-color); border-radius: var(--radius); overflow: hidden; }
        .panel-header { padding: 14px 16px; border-bottom: 1px solid var(--border-color); font-weight: 600; color: var(--text-bright); background: var(--bg-card); }
        .table-responsive { overflow-x: auto; scrollbar-width: thin; scrollbar-color: var(--border-color) var(--bg-panel); }
        .table-responsive::-webkit-scrollbar { height: 6px; }
        .table-responsive::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 3px; }

        table { width: 100%; border-collapse: collapse; min-width: 600px; }
        th, td { padding: 12px 16px; border-bottom: 1px solid var(--border-color); text-align: left; }
        th { background: rgba(0,0,0,0.2); color: var(--text-muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
        
        /* Сортируемые заголовки */
        th.sortable { cursor: pointer; user-select: none; transition: background 0.2s; position: relative; padding-right: 20px; }
        th.sortable:hover { background: rgba(255,255,255,0.05); color: var(--text-bright); }
        th.sortable::after { content: ' \2195'; position: absolute; right: 10px; opacity: 0.3; font-size: 12px; top: 50%; transform: translateY(-50%); }
        th.sortable.asc::after { content: ' \2191'; opacity: 1; color: var(--accent-blue); }
        th.sortable.desc::after { content: ' \2193'; opacity: 1; color: var(--accent-blue); }

        .attacker-row { cursor: pointer; transition: background 0.15s; }
        .attacker-row:hover { background: var(--bg-card); }

        .mono { font-family: var(--font-mono); }

        .copy-btn { background: transparent; border: none; color: var(--text-muted); cursor: pointer; font-size: 14px; margin-left: 10px; padding: 4px; border-radius: 4px; transition: 0.2s;}
        .copy-btn:hover { color: var(--text-bright); background: rgba(255,255,255,0.1); }

        /* Log Details & API Actions */
        .detail-wrapper { background: #070a0f; padding: 16px; border-left: 3px solid var(--accent-blue); box-shadow: inset 0 2px 10px rgba(0,0,0,0.2);}

        .cli-actions { margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-color); display: flex; gap: 12px; flex-wrap: wrap; align-items: center;}
        .cli-code { background: var(--bg-card); padding: 8px 12px; border-radius: 6px; border: 1px solid var(--border-color); font-size: 12px; font-weight: 600; cursor: pointer; color: var(--text-bright); transition: 0.2s;}
        .cli-code:hover { border-color: var(--accent-blue); box-shadow: 0 0 8px rgba(52, 152, 255, 0.2); }
        .cli-code.action-ban { color: var(--accent-red); border-color: rgba(255, 71, 87, 0.4); background: rgba(255, 71, 87, 0.1); }
        .cli-code.action-ban:hover { border-color: var(--accent-red); background: rgba(255, 71, 87, 0.15); box-shadow: 0 0 8px rgba(255, 71, 87, 0.3); }

        .timeline-item { display: flex; flex-wrap: wrap; gap: 12px; padding: 8px 0; border-bottom: 1px dotted rgba(255,255,255,0.05); font-size: 11px; align-items: baseline;}
        .timeline-item:last-child { border-bottom: none; }
        .timeline-time { color: var(--text-muted); width: 130px; flex-shrink: 0;}
        .timeline-type { width: 75px; font-weight: 600; flex-shrink: 0;}
        .timeline-type.IPTables { color: var(--accent-red); }
        .timeline-type.WAF { color: var(--accent-orange); }
        .timeline-type.Suricata { color: var(--accent-purple); }
        .timeline-info { flex-grow: 1; color: var(--text-bright); min-width: 250px; word-break: break-all; }

        /* Toast Notification */
        #toast { position: fixed; bottom: 24px; right: 24px; background: var(--accent-green); color: #fff; padding: 12px 24px; border-radius: var(--radius); font-weight: 600; font-family: var(--font-sans); opacity: 0; transform: translateY(20px); transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); pointer-events: none; z-index: 1000; box-shadow: 0 8px 24px rgba(0,0,0,0.3);}
        #toast.show { opacity: 1; transform: translateY(0); }

        @media (max-width: 900px) {
            .filter-group { flex-direction: column; align-items: stretch; }
            .input-clear-wrap, .input-clear-wrap input { width: 100%; }
            .filter-group input[type="text"] { width: 100%; }
            .date-nav { justify-content: space-between; }
            .date-nav input { flex-grow: 1; text-align: center; }
            .stats-summary { width: 100%; display: grid; grid-template-columns: repeat(2, 1fr); }
            .stat-badge { justify-content: space-between; }
            .timeline-time { width: 100%; padding-bottom: 4px; }
            .timeline-type { width: auto; }
        }
    </style>
</head>
<body>

<div class="toolbar">
    <div class="filter-group">
        <div class="date-nav">
            <button class="btn-nav" onclick="changeDate(-1)" title="Предыдущий день">◀</button>
            <input type="date" id="filterDate" value="<?= date('Y-m-d') ?>" onchange="fetchStats()">
            <button class="btn-nav" onclick="changeDate(1)" title="Следующий день">▶</button>
        </div>
        
        <div class="input-clear-wrap">
            <input type="text" id="filterIp" class="mono" placeholder="IP или подсеть (192.168.)" oninput="toggleClearBtn(); debounceFetch()">
            <span class="input-clear-btn" id="clearIpBtn" onclick="clearIpFilter()" title="Очистить">×</span>
        </div>
        
        <input type="text" id="filterPort" class="mono" placeholder="Порт атаки" oninput="debounceFetch()">
        <label class="checkbox-lbl">
            <input type="checkbox" id="filterAllTime" onchange="fetchStats()"> За всё время
        </label>
    </div>

    <div class="stats-summary">
        <div class="stat-badge uniq">Хостов <span id="sumUniq" class="mono">0</span></div>
        <div class="stat-badge drops">IPT <span id="sumDrops" class="mono">0</span></div>
        <div class="stat-badge waf">WAF <span id="sumWaf" class="mono">0</span></div>
        <div class="stat-badge ids">IDS <span id="sumIds" class="mono">0</span></div>
    </div>
</div>

<div class="panel">
    <div class="panel-header">Журнал Атакующих</div>
    <div class="table-responsive">
        <table>
            <thead>
                <tr>
                    <th style="width: 40px; text-align: center;"></th>
                    <th class="sortable" onclick="handleSort('ip', this)">IP-адрес</th>
                    <th class="sortable" onclick="handleSort('country', this)">Страна</th>
                    <th class="sortable desc" onclick="handleSort('events', this)" id="defaultSortTh">Инциденты</th>
                    <th class="sortable" onclick="handleSort('vector', this)">Вектор</th>
                </tr>
            </thead>
            <tbody id="attackerTable">
                <tr><td colspan="5" style="text-align: center; padding: 40px; color: var(--text-muted);">Сбор данных...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div id="toast"></div>

<script>
    let fetchTimer;
    let csrfToken = '';
    
    // Глобальные переменные для клиентской сортировки
    let attackersData = []; 
    let currentSort = { col: 'events', dir: 'desc' };

    async function initApi() {
        try {
            const res = await fetch('iptables/api.php?action=csrf_token');
            const data = await res.json();
            if (data.token) csrfToken = data.token;
        } catch (e) {
            console.error("API CSRF Error:", e);
        }
    }

    // ── Управление крестиком ──
    function toggleClearBtn() {
        const el = document.getElementById('filterIp');
        const btn = document.getElementById('clearIpBtn');
        btn.style.display = el.value.length > 0 ? 'block' : 'none';
    }

    function clearIpFilter() {
        const el = document.getElementById('filterIp');
        el.value = '';
        toggleClearBtn();
        fetchStats(); 
    }

    function showToast(text, isError = false) {
        const toast = document.getElementById('toast');
        toast.textContent = text;
        toast.style.backgroundColor = isError ? 'var(--accent-red)' : 'var(--accent-green)';
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 3000);
    }

    async function execBanIp(ip, event) {
        if (event) event.stopPropagation();
        if (!csrfToken) { showToast("Ошибка: CSRF токен не загружен", true); return; }
        if (!confirm(`Вы уверены, что хотите ЗАБЛОКИРОВАТЬ IP ${ip} через iptables?`)) return;

        try {
            const res = await fetch('iptables/api.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'block_ip', params: { ip: ip }, csrf: csrfToken })
            });
            const data = await res.json();
            if (data.error) showToast('Ошибка API: ' + data.error, true);
            else if (data.ok) showToast(`✅ IP ${ip} успешно забанен!`);
            else showToast('Неизвестный ответ сервера', true);
        } catch(e) {
            showToast('Ошибка сети при выполнении бана', true);
        }
    }

    function debounceFetch() {
        clearTimeout(fetchTimer);
        fetchTimer = setTimeout(fetchStats, 400);
    }

    function changeDate(offset) {
        const input = document.getElementById('filterDate');
        let d = new Date(input.value);
        if (isNaN(d.getTime())) d = new Date();
        d.setDate(d.getDate() + offset);
        input.value = d.toISOString().split('T')[0];
        document.getElementById('filterAllTime').checked = false;
        fetchStats();
    }

    function copyToClipboard(text, event) {
        if(event) event.stopPropagation();
        navigator.clipboard.writeText(text).then(() => {
            showToast('📋 Скорпировано: ' + text);
        });
    }

    // Вспомогательная функция для правильной сортировки IP адресов
    function ipSortVal(ip) {
        const parts = ip.split('.');
        if(parts.length === 4) {
            return parts.map(p => p.padStart(3, '0')).join('.');
        }
        return ip; // Если это IPv6 или не IP
    }

    // ── Сортировка таблицы ──
    function handleSort(col, el) {
        if (currentSort.col === col) {
            currentSort.dir = currentSort.dir === 'asc' ? 'desc' : 'asc';
        } else {
            currentSort.col = col;
            currentSort.dir = 'desc'; // По умолчанию для новой колонки ставим убывание
        }
        
        // Обновляем классы на заголовках
        document.querySelectorAll('th.sortable').forEach(th => th.classList.remove('asc', 'desc'));
        el.classList.add(currentSort.dir);

        renderTable();
    }

    // ── Отрисовка таблицы из памяти ──
    function renderTable() {
        const tbody = document.getElementById('attackerTable');
        tbody.innerHTML = '';

        if (!attackersData || attackersData.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px; color: var(--text-muted);">По заданным фильтрам данных нет.</td></tr>';
            return;
        }

        // Клонируем и сортируем массив
        const sortedData = [...attackersData].sort((a, b) => {
            let valA, valB;
            if (currentSort.col === 'events') {
                valA = parseInt(a.total_events) || 0;
                valB = parseInt(b.total_events) || 0;
                return currentSort.dir === 'asc' ? valA - valB : valB - valA;
            } else if (currentSort.col === 'ip') {
                valA = ipSortVal(a.src_ip);
                valB = ipSortVal(b.src_ip);
            } else if (currentSort.col === 'country') {
                valA = a.country || '';
                valB = b.country || '';
            } else if (currentSort.col === 'vector') {
                valA = a.max_source || '';
                valB = b.max_source || '';
            }

            if (valA < valB) return currentSort.dir === 'asc' ? -1 : 1;
            if (valA > valB) return currentSort.dir === 'asc' ? 1 : -1;
            return 0;
        });

        sortedData.forEach((row) => {
            const safeId = replaceDot(row.src_ip);
            tbody.innerHTML += `
                <tr class="attacker-row" onclick="toggleIPDetails('${escapeHtml(row.src_ip)}', this)">
                    <td class="mono" style="color: var(--text-muted); text-align:center; font-size:10px;">▶</td>
                    <td class="mono" style="font-weight:600; color:var(--text-bright);">
                        ${escapeHtml(row.src_ip)}
                        <button class="copy-btn" onclick="copyToClipboard('${escapeHtml(row.src_ip)}', event)" title="Скопировать IP">📋</button>
                    </td>
                    <td>${escapeHtml(row.country || 'Локальный')}</td>
                    <td class="mono" style="color:var(--accent-red); font-weight:600;">${row.total_events}</td>
                    <td><span class="mono" style="font-size:11px; padding:4px 8px; background:var(--bg-card); border-radius:4px; border:1px solid var(--border-color); color:var(--text-muted);">${row.max_source}</span></td>
                </tr>
                <tr id="details-${safeId}" style="display:none; background:var(--bg-main);">
                    <td colspan="5" style="padding:0;"><div class="detail-wrapper" id="content-${safeId}">Загрузка...</div></td>
                </tr>
            `;
        });
    }

    async function fetchStats() {
        const date = document.getElementById('filterDate').value;
        const ip = document.getElementById('filterIp').value.trim();
        const port = document.getElementById('filterPort').value.trim();
        const allTime = document.getElementById('filterAllTime').checked;

        try {
            const url = `?api=day_stats&date=${date}&ip=${ip}&port=${port}&all_time=${allTime}`;
            const res = await fetch(url);
            const data = await res.json();

            document.getElementById('sumDrops').textContent = data.total_drops || 0;
            document.getElementById('sumWaf').textContent = data.total_waf || 0;
            document.getElementById('sumIds').textContent = data.total_ids || 0;
            document.getElementById('sumUniq').textContent = data.unique_ips || 0;
            
            // Сохраняем полученные данные в глобальную переменную
            attackersData = data.top_attackers || [];
            
            // Запускаем рендеринг таблицы (с учетом текущей сортировки)
            renderTable();

        } catch (e) { console.error(e); }
    }

    async function toggleIPDetails(ip, rowElement) {
        const date = document.getElementById('filterDate').value;
        const allTime = document.getElementById('filterAllTime').checked;
        const safeId = replaceDot(ip);
        const detailRow = document.getElementById(`details-${safeId}`);
        const contentDiv = document.getElementById(`content-${safeId}`);
        const indicator = rowElement.querySelector('td');

        if(detailRow.style.display === 'table-row') {
            detailRow.style.display = 'none'; indicator.textContent = '▶'; return;
        }

        detailRow.style.display = 'table-row'; indicator.textContent = '▼';
        try {
            const url = `?api=ip_details&req_ip=${ip}&date=${date}&all_time=${allTime}`;
            const res = await fetch(url);
            const logs = await res.json();

            let html = `
                <div class="cli-actions">
                    <button class="cli-code action-ban mono" onclick="execBanIp('${ip}', event)">🚨 BAN IP (API)</button>
                    <span style="color:var(--text-muted); font-size: 12px; margin-left: 8px; margin-right: 4px;">CLI:</span>
                    <span class="cli-code mono" onclick="copyToClipboard('fail2ban-client set recidive banip ${ip}', event)">📋 f2b ban</span>
                    <span class="cli-code mono" onclick="copyToClipboard('whois ${ip}', event)">📋 whois</span>
                </div>
            `;

            if(logs.length > 0) {
                logs.forEach(log => {
                    html += `
                        <div class="timeline-item">
                            <span class="timeline-time mono">${escapeHtml(log.time)}</span>
                            <span class="timeline-type ${log.type}">${escapeHtml(log.type)}</span>
                            <span class="timeline-info mono">${escapeHtml(log.info)}
                                <span style="color:var(--text-muted); font-size:10px; display:inline-block; margin-left:6px;"> // ${escapeHtml(log.severity)}</span>
                            </span>
                        </div>
                    `;
                });
            } else {
                html += '<div style="color:var(--text-muted)">Нет детальной истории.</div>';
            }
            contentDiv.innerHTML = html;
        } catch(e) { contentDiv.innerHTML = '<div style="color:var(--accent-red)">Ошибка загрузки таймлайна.</div>'; }
    }

    function replaceDot(ip) { return ip.replace(/\./g, '_').replace(/:/g, '_'); }
    function escapeHtml(str) { return (str||'').toString().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

    document.addEventListener("DOMContentLoaded", () => {
        initApi();
        toggleClearBtn(); // Проверка на случай если браузер подставил старое значение
        
        // Устанавливаем изначальные классы сортировки (Инциденты - убывание)
        document.getElementById('defaultSortTh').classList.add('desc');
        
        fetchStats();
    });
</script>
</body>
</html>
