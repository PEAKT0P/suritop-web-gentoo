<?php
$conf_file = "/etc/suritop-web/collector.conf";
$defaults = [
    "host" => "localhost", "name" => "server_stats",
    "user_r" => "stats_reader", "pass_r" => "",
    "user_w" => "stats_writer", "pass_w" => ""
];
$db = $defaults;
if (file_exists($conf_file)) {
    $ini = parse_ini_file($conf_file, true);
    if (isset($ini["Database"])) $db = array_merge($db, $ini["Database"]);
}
define("STATS_DB_HOST", $db["host"]);
define("STATS_DB_NAME", $db["name"]);
define("STATS_DB_USER", $db["user_r"]);
define("STATS_DB_PASS", $db["pass_r"]);
define("CACHE_FILE", "/tmp/attack_replay_cache.json");
define("CACHE_TTL", 300);
define("RT_POLL_INTERVAL", 5000);
define("RT_MIN_DELAY", 200);
define("RT_FETCH_LIMIT", 50);
define("STATS_REFRESH_INTERVAL", 30000);
define("CHARTS_REFRESH_INTERVAL", 120000);
define("DEFAULT_THEME", "dark");
