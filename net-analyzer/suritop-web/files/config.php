<?php
/**
 * /var/www/suritop-web/htdocs/attackmap/config.php
 * Database configuration — reads from environment or defaults
 */

// Try environment variables first (set via nginx fastcgi_param or /etc/conf.d)
define('STATS_DB_HOST', getenv('SURITOP_DB_HOST') ?: 'localhost');
define('STATS_DB_NAME', getenv('SURITOP_DB_NAME') ?: 'server_stats');
define('STATS_DB_USER', getenv('SURITOP_DB_USER_R') ?: 'stats_reader');
define('STATS_DB_PASS', getenv('SURITOP_DB_PASS_R') ?: '');

// Fallback: read from collector.conf if env not set
if (!STATS_DB_PASS) {
    $conf_file = '/etc/suritop-web/collector.conf';
    if (file_exists($conf_file)) {
        $ini = parse_ini_file($conf_file, true);
        if (isset($ini['Database'])) {
            define('STATS_DB_HOST', $ini['Database']['host'] ?? 'localhost');
            define('STATS_DB_NAME', $ini['Database']['name'] ?? 'server_stats');
            define('STATS_DB_USER', $ini['Database']['user_r'] ?? 'stats_reader');
            define('STATS_DB_PASS', $ini['Database']['pass_r'] ?? '');
        }
    }
}

// Cache settings
define('CACHE_FILE', '/tmp/attack_replay_cache.json');
define('CACHE_TTL', 300);

// Realtime settings
define('RT_POLL_INTERVAL', 5000);
define('RT_MIN_DELAY', 200);
define('RT_FETCH_LIMIT', 50);

// Refresh intervals (ms)
define('STATS_REFRESH_INTERVAL', 30000);
define('CHARTS_REFRESH_INTERVAL', 120000);

// Theme
define('DEFAULT_THEME', 'dark');
