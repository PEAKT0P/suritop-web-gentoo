<?php
/**
 * /var/www/suritop-web/htdocs/nav.php
 * Navigation bar for suritop-web
 * Include in all pages: <?php include __DIR__ . '/nav.php'; ?>
 */
$currentPage = basename($_SERVER['PHP_SELF']);
$basePath = rtrim(dirname($_SERVER['PHP_SELF']), '/');
?>
<style>
.suritop-nav {
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    z-index: 10000;
    height: 28px;
    background: rgba(10, 14, 20, 0.92);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    border-top: 1px solid rgba(255,255,255,0.08);
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 4px;
    padding: 0 12px;
    font-family: 'JetBrains Mono', 'Share Tech Mono', monospace;
}
.suritop-nav a {
    color: #94a3b8;
    text-decoration: none;
    font-size: 9px;
    font-weight: 600;
    letter-spacing: 0.5px;
    padding: 3px 10px;
    border-radius: 4px;
    transition: all 0.2s;
    white-space: nowrap;
    border: 1px solid transparent;
}
.suritop-nav a:hover {
    color: #e2e8f0;
    background: rgba(255,255,255,0.06);
    border-color: rgba(255,255,255,0.1);
}
.suritop-nav a.active {
    color: #ff3b30;
    background: rgba(255,59,48,0.1);
    border-color: rgba(255,59,48,0.2);
}
.suritop-nav .nav-sep {
    width: 1px;
    height: 14px;
    background: rgba(255,255,255,0.08);
    margin: 0 2px;
}
body { margin-bottom: 32px !important; }
</style>
<nav class="suritop-nav">
    <a href="/attackmap/" target="_blank" rel="noopener" class="<?= strpos($currentPage, 'index') !== false ? 'active' : '' ?>">🗺 Attack Map</a>
    <span class="nav-sep"></span>
    <a href="/admin_stats.php" target="_blank" rel="noopener" class="<?= $currentPage === 'admin_stats.php' ? 'active' : '' ?>">📊 Admin Stats</a>
    <span class="nav-sep"></span>
    <a href="/service/iptables/" target="_blank" rel="noopener" class="<?= strpos($currentPage, 'iptables') !== false ? 'active' : '' ?>">⛨ Firewall</a>
    <span class="nav-sep"></span>
    <a href="javascript:void(0)" onclick="navigator.clipboard.writeText('ssh -p <?= getenv('SURITOP_SSH_PORT') ?: '61122' ?> root@<?= getenv('SURITOP_SERVER_IP') ?: 'SERVER_IP' ?>').then(()=>this.textContent='✓ Copied!')" title="Copy SSH command">💻 SSH</a>
</nav>
