# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

DESCRIPTION="Security monitoring system: Suricata IDS + ModSecurity WAF + Fail2Ban + iptables dashboard."
HOMEPAGE="https://github.com/PEAKT0P/suritop-web-gentoo"
SRC_URI=""

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="amd64 x86"
IUSE="iptables nat docker suricata geoip"

RDEPEND="
	net-analyzer/suricata
	net-analyzer/fail2ban
	dev-lang/php:=[pdo,mysql]
	dev-db/mariadb
	dev-python/pymysql
	www-servers/nginx
	sys-apps/shadow
	sys-apps/coreutils
	geoip? ( dev-libs/geoip )
"
BDEPEND="
	sys-apps/shadow
	sys-apps/coreutils
"

S="${WORKDIR}/${P}"

pkg_setup() {
	getent group stats_collector >/dev/null || groupadd -g 460 stats_collector
	getent passwd stats_collector >/dev/null || useradd -u 460 -g stats_collector -d /var/lib/stats_collector -s /sbin/nologin -c "suritop-web stats collector" stats_collector
}

src_unpack() {
	mkdir -p "${S}"
	cp -r "${FILESDIR}/"* "${S}/" 2>/dev/null || true
}

src_install() {
	diropts -m0755 -o stats_collector -g stats_collector
	dodir /opt/stats_collector
	insinto /opt/stats_collector
	insopts -m0755 -o stats_collector -g stats_collector
	doins "${S}"/stats_collector.py
	doins "${S}"/suricata_collector.py
	doins "${S}"/modsec_collector.py
	doins "${S}"/geo_fill.py
	doins "${S}"/utils.py

	insopts -m0755 -o stats_collector -g stats_collector
	doins "${S}"/suritop.py

	dosym /opt/stats_collector/suritop.py /usr/bin/suritop
	diropts -m0755 -o root -g root
	dodir /opt/iptables-manager
	insinto /opt/iptables-manager
	insopts -m0755 -o root -g root
	doins "${S}"/iptables_api.py

	insopts -m0755 -o stats_collector -g stats_collector
	insinto /opt/stats_collector
	doins "${S}"/suritop_config.py

	diropts -m0755 -o root -g root
	dodir /var/www/suritop-web/htdocs/attackmap
	dodir /var/www/suritop-web/htdocs/iptables

	insinto /var/www/suritop-web/htdocs
	insopts -m0644
	doins "${S}"/admin_stats.php
	newins "${S}"/root-index.php index.php
	newins "${S}"/root-config.php config.php

	insinto /var/www/suritop-web/htdocs/attackmap
	doins "${S}"/index.php
	doins "${S}"/attackmap/config.php

	insinto /var/www/suritop-web/htdocs/iptables
	doins "${S}"/api.php
	doins "${S}"/index.html

	insopts -m0644
	insinto /etc/suritop-web
	doins "${S}"/nginx-vhost.conf
	doins "${S}"/suricata.yaml
	doins "${S}"/drop.conf
	doins "${S}"/classification.config
	doins "${S}"/reference.config
	doins "${S}"/threshold.config
	doins "${S}"/disable.conf

	diropts -m0755 -o root -g root
	dodir /etc/suritop-web/rules
	insinto /etc/suritop-web/rules
	insopts -m0644
	doins "${S}"/local.rules

	insinto /etc/conf.d
	insopts -m0644
	newins "${S}"/suritop-web.conf suritop-web

	insinto /etc/suritop-web
	insopts -m0644
	newins "${S}"/suritop.conf suritop.conf

	newinitd "${S}"/suritop-stats.initd suritop-stats
	newinitd "${S}"/suritop-suri.initd suritop-suri
	newinitd "${S}"/suritop-waf.initd suritop-waf
	newinitd "${S}"/suritop-geo.initd suritop-geo
	newinitd "${S}"/suritop-iptables.initd suritop-iptables

	if use iptables; then
		newinitd "${S}"/suritop-iptables-setup suritop-iptables-setup
	fi

	insinto /etc/logrotate.d
	newins "${S}"/suritop-web.logrotate suritop-web

	dodir /usr/share/suritop-web
	insinto /usr/share/suritop-web
	newins "${S}"/schema.sql schema.sql

	diropts -m0755 -o stats_collector -g stats_collector
	keepdir /var/lib/stats_collector

	dodir /etc/nginx/vhosts.d

	dodoc "${S}"/README.gentoo
}

pkg_preinst() {
	# Remove stale init scripts from v0.1.1 and earlier
	for old_svc in iptables-manager suricata_ids suricata_stats suricata_waf; do
		if [[ -f "${EROOT}/etc/init.d/${old_svc}" ]]; then
			ewarn "Removing stale init script: ${old_svc}"
			rc-update del "${old_svc}" default 2>/dev/null
			rc-service "${old_svc}" stop 2>/dev/null
			rm -f "${EROOT}/etc/init.d/${old_svc}"
		fi
	done
}

pkg_postinst() {
	einfo ""
	einfo "suritop-web installed successfully!"
	einfo ""

	if [[ ! -f "${EROOT}/etc/suritop-web/.configured" ]]; then
		einfo "First installation detected."
		einfo ""
		einfo "Run interactive setup:"
		einfo "  emerge --config net-analyzer/suritop-web"
		einfo ""
		einfo "Or configure manually:"
		einfo "  1. Edit /etc/suritop-web/suritop.conf"
		einfo "  2. Import schema: mariadb -u root < /usr/share/suritop-web/schema.sql"
		einfo "  3. Enable services: rc-update add suritop-stats default"
		einfo "  4. Start: rc-service suritop-stats start"
		einfo ""
	else
		einfo "Configuration found at /etc/suritop-web/suritop.conf"
		einfo "Re-run config: emerge --config net-analyzer/suritop-web"
		einfo ""
	fi
}

pkg_config() {
	einfo ""
	einfo "suritop-web Interactive Configuration"
	einfo "======================================"
	einfo ""

	DEFAULT_IF=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{print $5}' | head -1)
	DEFAULT_IF=${DEFAULT_IF:-eth0}
	DEFAULT_IP=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -1)
	if [[ -z "${DEFAULT_IP}" ]]; then
		DEFAULT_IP=$(ip -4 addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -1)
	fi
	if [[ -z "${DEFAULT_IP}" ]]; then
		DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
	fi
	DEFAULT_IP=${DEFAULT_IP:-127.0.0.1}
	DEFAULT_SSH=$(grep -E "^Port\s+" "${EROOT}/etc/ssh/sshd_config" 2>/dev/null | awk '{print $2}' | head -1)
	DEFAULT_SSH=${DEFAULT_SSH:-22}

	# Auto-detect server location from public IP
	DEFAULT_LAT="55.75"
	DEFAULT_LON="37.62"
	SERVER_LOC=$(python3 -c "
import json
from urllib.request import urlopen
try:
    pub = json.loads(urlopen('http://api.ipify.org?format=json', timeout=3).read())['ip']
    geo = json.loads(urlopen(f'http://ip-api.com/json/{pub}?fields=lat,lon', timeout=5).read())
    print(f\"{geo.get('lat', 55.75)},{geo.get('lon', 37.62)}\")
except: print('55.75,37.62')
" 2>/dev/null)
	DEFAULT_LAT="${SERVER_LOC%%,*}"
	DEFAULT_LON="${SERVER_LOC##*,}"

	einfo "Detected network:"
	einfo "  Interface: ${DEFAULT_IF}"
	einfo "  Server IP: ${DEFAULT_IP}"
	einfo "  SSH Port:  ${DEFAULT_SSH}"
	einfo "  Location:  ${DEFAULT_LAT}, ${DEFAULT_LON}"
	einfo ""

	# ── 1. Substitute placeholders in suritop.conf ──
	sed -i "s|@@SERVER_IP@@|${DEFAULT_IP}|g" "${EROOT}/etc/suritop-web/suritop.conf" 2>/dev/null
	sed -i "s|@@NET_INTERFACE@@|${DEFAULT_IF}|g" "${EROOT}/etc/suritop-web/suritop.conf" 2>/dev/null
	sed -i "s|@@SSH_PORT@@|${DEFAULT_SSH}|g" "${EROOT}/etc/suritop-web/suritop.conf" 2>/dev/null
	sed -i "s|@@SERVER_LAT@@|${DEFAULT_LAT}|g" "${EROOT}/etc/suritop-web/suritop.conf" 2>/dev/null
	sed -i "s|@@SERVER_LON@@|${DEFAULT_LON}|g" "${EROOT}/etc/suritop-web/suritop.conf" 2>/dev/null

	# ── 2. Substitute placeholders in conf.d ──
	sed -i "s|@@SERVER_IP@@|${DEFAULT_IP}|g" "${EROOT}/etc/conf.d/suritop-web" 2>/dev/null
	sed -i "s|@@NET_INTERFACE@@|${DEFAULT_IF}|g" "${EROOT}/etc/conf.d/suritop-web" 2>/dev/null
	sed -i "s|@@SSH_PORT@@|${DEFAULT_SSH}|g" "${EROOT}/etc/conf.d/suritop-web" 2>/dev/null

	# ── 3. Substitute suricata.yaml (only if not already configured) ──
	if grep -q '@@SERVER_IP@@' "${EROOT}/etc/suritop-web/suricata.yaml" 2>/dev/null; then
		sed -i "s|@@SERVER_IP@@|${DEFAULT_IP}|g" "${EROOT}/etc/suritop-web/suricata.yaml" 2>/dev/null
		sed -i "s|@@NET_INTERFACE@@|${DEFAULT_IF}|g" "${EROOT}/etc/suritop-web/suricata.yaml" 2>/dev/null
		sed -i "s|@@SSH_PORT@@|${DEFAULT_SSH}|g" "${EROOT}/etc/suritop-web/suricata.yaml" 2>/dev/null
	fi

	# ── 4. Generate collector.conf (INI format for PHP/Python) ──
	DB_PASS_R=$(python3 -c "
import configparser
c = configparser.ConfigParser()
c.read('${EROOT}/etc/suritop-web/suritop.conf')
print(c.get('Database', 'pass_r', fallback='suritop_read_2026'))
" 2>/dev/null)
	DB_PASS_R=${DB_PASS_R:-suritop_read_2026}
	DB_PASS_W=$(python3 -c "
import configparser
c = configparser.ConfigParser()
c.read('${EROOT}/etc/suritop-web/suritop.conf')
print(c.get('Database', 'pass_w', fallback='suritop_write_2026'))
" 2>/dev/null)
	DB_PASS_W=${DB_PASS_W:-suritop_write_2026}

	cat > "${EROOT}/etc/suritop-web/collector.conf" << COLLECTOR_CONF
# /etc/suritop-web/collector.conf
# suritop-web collector configuration
# Generated by: emerge --config net-analyzer/suritop-web

[Network]
our_ip = ${DEFAULT_IP}

[Database]
host = localhost
name = server_stats
user_r = stats_reader
pass_r = ${DB_PASS_R}
user_w = stats_writer
pass_w = ${DB_PASS_W}

[Interfaces]
monitor = ${DEFAULT_IF}
COLLECTOR_CONF
	einfo "Generated /etc/suritop-web/collector.conf"

	# ── 5. Generate PHP config files ──
	cat > "${EROOT}/var/www/suritop-web/htdocs/config.php" << PHPCONFIG
<?php
/**
 * suritop-web root config — generated by: emerge --config net-analyzer/suritop-web
 * Do NOT edit manually — re-run emerge --config to regenerate.
 */
\$conf_file = "/etc/suritop-web/collector.conf";
\$defaults = [
    "host" => "localhost", "name" => "server_stats",
    "user_r" => "stats_reader", "pass_r" => "",
    "user_w" => "stats_writer", "pass_w" => ""
];
\$db = \$defaults;
\$our_ip = "${DEFAULT_IP}";
if (file_exists(\$conf_file)) {
    \$section = "";
    \$ini = [];
    foreach (file(\$conf_file) as \$line) {
        \$line = trim(\$line);
        if (\$line === "" || \$line[0] === "#" || \$line[0] === ";") continue;
        if (preg_match('/^\[(.+)\]$/', \$line, \$m)) { \$section = \$m[1]; continue; }
        if (preg_match('/^(\w+)\s*=\s*(.+)$/', \$line, \$m)) { \$ini[\$section][\$m[1]] = trim(\$m[2]); }
    }
    if (isset(\$ini["Database"])) \$db = array_merge(\$db, \$ini["Database"]);
    if (isset(\$ini["Network"]["our_ip"])) \$our_ip = \$ini["Network"]["our_ip"];
}
define("STATS_DB_HOST", \$db["host"]);
define("STATS_DB_NAME", \$db["name"]);
define("STATS_DB_USER", \$db["user_r"]);
define("STATS_DB_PASS", \$db["pass_r"]);
define("OUR_IP", \$our_ip);
define("CACHE_FILE", "/tmp/attack_replay_cache.json");
define("CACHE_TTL", 300);
define("RT_POLL_INTERVAL", 5000);
define("RT_MIN_DELAY", 200);
define("RT_FETCH_LIMIT", 50);
define("STATS_REFRESH_INTERVAL", 30000);
define("CHARTS_REFRESH_INTERVAL", 120000);
define("DEFAULT_THEME", "dark");
define("ATTACKMAP_BASE_URL", "/attackmap/");
define("WAF_BASE_URL", "/admin_stats.php");

function getServerLocation() {
    \$ip = defined('OUR_IP') ? OUR_IP : '';
    if (!\$ip || \$ip === '127.0.0.1') return [55.75, 37.62];
    \$cache = '/tmp/suritop_server_geo.json';
    if (file_exists(\$cache) && (time() - filemtime(\$cache)) < 86400) {
        \$data = json_decode(file_get_contents(\$cache), true);
        if (\$data && isset(\$data['lat']) && isset(\$data['lon'])) return [\$data['lat'], \$data['lon']];
    }
    \$ctx = stream_context_create(['http' => ['timeout' => 3]]);
    \$json = @file_get_contents("http://ip-api.com/json/{\$ip}?fields=lat,lon", false, \$ctx);
    if (\$json) {
        \$d = json_decode(\$json, true);
        if (\$d && isset(\$d['lat']) && isset(\$d['lon'])) {
            file_put_contents(\$cache, json_encode(\$d));
            return [\$d['lat'], \$d['lon']];
        }
    }
    return [55.75, 37.62];
}
PHPCONFIG

	cat > "${EROOT}/var/www/suritop-web/htdocs/attackmap/config.php" << ATTACKMAP_CONFIG
<?php
/**
 * suritop-web attackmap config — generated by: emerge --config net-analyzer/suritop-web
 * Reads DB credentials from collector.conf (INI format)
 */
\$conf_file = '/etc/suritop-web/collector.conf';
\$defaults = ['host' => 'localhost', 'name' => 'server_stats', 'user_r' => 'stats_reader', 'pass_r' => '', 'user_w' => 'stats_writer', 'pass_w' => ''];
\$db = \$defaults;
\$our_ip = '${DEFAULT_IP}';
\$server_lat = ${DEFAULT_LAT};
\$server_lon = ${DEFAULT_LON};
if (file_exists(\$conf_file)) {
    \$section = ""; \$ini = [];
    foreach (file(\$conf_file) as \$l) { \$l = trim(\$l); if (\$l === "" || \$l[0] === "#" || \$l[0] === ";") continue; if (preg_match('/^\[(.+)\]$/', \$l, \$m)) { \$section = \$m[1]; continue; } if (preg_match('/^(\w+)\s*=\s*(.+)$/', \$l, \$m)) { \$ini[\$section][\$m[1]] = trim(\$m[2]); } }
    if (isset(\$ini["Database"])) \$db = array_merge(\$db, \$ini["Database"]);
    if (isset(\$ini["Network"]["our_ip"])) \$our_ip = \$ini["Network"]["our_ip"];
    if (isset(\$ini["Network"]["server_lat"])) \$server_lat = (float)\$ini["Network"]["server_lat"];
    if (isset(\$ini["Network"]["server_lon"])) \$server_lon = (float)\$ini["Network"]["server_lon"];
}
define('STATS_DB_HOST', \$db["host"]);
define('STATS_DB_NAME', \$db["name"]);
define('STATS_DB_USER', \$db["user_r"]);
define('STATS_DB_PASS', \$db["pass_r"]);
define('OUR_IP', \$our_ip);
define('SERVER_LAT', \$server_lat);
define('SERVER_LON', \$server_lon);
define('CACHE_FILE', '/tmp/attack_replay_cache.json');
define('CACHE_TTL', 300);
define('RT_POLL_INTERVAL', 5000);
define('RT_MIN_DELAY', 200);
define('RT_FETCH_LIMIT', 50);
define('STATS_REFRESH_INTERVAL', 30000);
define('CHARTS_REFRESH_INTERVAL', 120000);
define('DEFAULT_THEME', 'dark');
define('ATTACKMAP_BASE_URL', '/attackmap/');
define('WAF_BASE_URL', '/admin_stats.php');
ATTACKMAP_CONFIG

	# Set proper ownership for PHP config files
	for nginx_grp in nginx www-data http; do
		if getent group "${nginx_grp}" >/dev/null 2>&1; then
			chown root:"${nginx_grp}" "${EROOT}/var/www/suritop-web/htdocs/config.php" 2>/dev/null
			chown root:"${nginx_grp}" "${EROOT}/var/www/suritop-web/htdocs/attackmap/config.php" 2>/dev/null
			break
		fi
	done
	chmod 640 "${EROOT}/var/www/suritop-web/htdocs/config.php" 2>/dev/null
	chmod 640 "${EROOT}/var/www/suritop-web/htdocs/attackmap/config.php" 2>/dev/null
	einfo "Config files generated: suritop.conf + collector.conf + PHP configs"

	einfo "Setup nginx with basic auth (admin:admin)? [Y/n]"
	read -r REPLY
	if [[ "${REPLY}" != "n" && "${REPLY}" != "N" ]]; then
		cp "${EROOT}/etc/suritop-web/nginx-vhost.conf" "${EROOT}/etc/nginx/vhosts.d/suritop-web.conf"
		einfo "Nginx vhost installed"

		# Create htpasswd with admin:admin
		HASH=$(python3 -c "
import subprocess, base64, os
salt = base64.b64encode(os.urandom(16)).decode()
r = subprocess.run(['openssl', 'passwd', '-6', '-salt', salt, 'admin'], capture_output=True, text=True)
print(f'admin:{r.stdout.strip()}')
" 2>/dev/null)
		if [[ -n "${HASH}" ]]; then
			# Append to existing acc file or create new one
			if [[ -f "${EROOT}/etc/nginx/acc" ]]; then
				echo "${HASH}" >> "${EROOT}/etc/nginx/acc"
			else
				echo "${HASH}" > "${EROOT}/etc/nginx/acc"
			fi
			einfo "Basic auth user 'admin' added to /etc/nginx/acc"
		fi
		einfo ""
	fi

	einfo "Setup database (import schema + create users)? [Y/n]"
	read -r REPLY
	if [[ "${REPLY}" != "n" && "${REPLY}" != "N" ]]; then
		# Try to find running MariaDB/MySQL
		MYSQL_SVC=""
		for svc in mysql mysqld mariadb; do
			if rc-service "${svc}" status >/dev/null 2>&1; then
				MYSQL_SVC="${svc}"
				break
			fi
		done
		if [[ -z "${MYSQL_SVC}" ]]; then
			for svc in mysql mysqld mariadb; do
				if rc-service "${svc}" start >/dev/null 2>&1; then
					MYSQL_SVC="${svc}"
					sleep 2
					break
				fi
			done
		fi

		if command -v mariadb >/dev/null 2>&1 || command -v mysql >/dev/null 2>&1; then
			DB_CMD=$(command -v mariadb 2>/dev/null || command -v mysql)

			DB_OK=0
			DB_OPTS=""
			if ${DB_CMD} -u root -e "SELECT 1" >/dev/null 2>&1; then
				DB_OK=1
				DB_OPTS="-u root"
			fi

			if [[ ${DB_OK} -eq 0 ]]; then
				einfo "MariaDB requires root password."
				einfo "Enter MariaDB root password (leave empty if none):"
				read -rs DB_ROOT_PASS
				echo
				if [[ -n "${DB_ROOT_PASS}" ]]; then
					if ${DB_CMD} -u root -p"${DB_ROOT_PASS}" -e "SELECT 1" >/dev/null 2>&1; then
						DB_OK=1
						DB_OPTS="-u root -p${DB_ROOT_PASS}"
					else
						ewarn "Cannot connect to MariaDB with provided password"
					fi
				else
					ewarn "Cannot connect to MariaDB as root without password"
					ewarn "Run manually: mariadb -u root -p < /usr/share/suritop-web/schema.sql"
				fi
			fi

			if [[ ${DB_OK} -eq 1 ]]; then
				einfo "MariaDB connected"

				if ${DB_CMD} ${DB_OPTS} < "${EROOT}/usr/share/suritop-web/schema.sql" 2>/dev/null; then
					einfo "Schema imported"
				else
					ewarn "Schema import failed (tables may already exist — safe to ignore)"
				fi

				if ${DB_CMD} ${DB_OPTS} -e "
					CREATE USER IF NOT EXISTS 'stats_reader'@'localhost' IDENTIFIED BY '${DB_PASS_R}';
					GRANT SELECT ON server_stats.* TO 'stats_reader'@'localhost';
					CREATE USER IF NOT EXISTS 'stats_writer'@'localhost' IDENTIFIED BY '${DB_PASS_W}';
					GRANT INSERT,SELECT,DELETE ON server_stats.* TO 'stats_writer'@'localhost';
					FLUSH PRIVILEGES;
				" 2>/dev/null; then
					einfo "DB users created (stats_reader / stats_writer)"
				else
					ewarn "DB user creation failed"
				fi
			else
				ewarn "Cannot connect to MariaDB as root"
				ewarn "Run manually: mariadb -u root -p < /usr/share/suritop-web/schema.sql"
			fi
		else
			ewarn "mariadb/mysql not found — skip database setup"
		fi
		einfo ""
	fi

	if use suricata; then
		einfo "Install suricata configs? [Y/n]"
		read -r REPLY
		if [[ "${REPLY}" != "n" && "${REPLY}" != "N" ]]; then
			if [[ -d "${EROOT}/etc/suricata" ]]; then
				for f in suricata.yaml classification.config reference.config threshold.config; do
					cp "${EROOT}/etc/suritop-web/${f}" "${EROOT}/etc/suricata/" 2>/dev/null
				done
				cp "${EROOT}/etc/suritop-web/rules/local.rules" "${EROOT}/etc/suricata/rules/" 2>/dev/null
				einfo "Suricata configs installed"
			fi
		fi
		einfo ""
	fi

	einfo "Setup fail2ban jails? [Y/n]"
	read -r REPLY
	if [[ "${REPLY}" != "n" && "${REPLY}" != "N" ]]; then
		cat > "${EROOT}/etc/fail2ban/jail.local" 2>/dev/null << F2B_EOF
[DEFAULT]
whitelistip = 127.0.0.1/8 ::1 ${DEFAULT_IP}
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ${DEFAULT_SSH}
filter = sshd
logpath = /var/log/messages
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error_80.log
maxretry = 3

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
logpath = /var/log/nginx/access_80.log
maxretry = 2

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/error_80.log
maxretry = 5
F2B_EOF
		einfo "Fail2ban jail.local configured"
		einfo ""
	fi

	if use iptables; then
		einfo "Enable iptables auto-setup on boot? [y/N]"
		einfo "  WARNING: This will REPLACE your current iptables rules!"
		einfo "  Choose N if you have custom firewall (NAT, Docker, port forwarding)"
		read -r REPLY
		if [[ "${REPLY}" == "y" || "${REPLY}" == "Y" ]]; then
			sed -i 's|^SURITOP_AUTO_IPTABLES=.*|SURITOP_AUTO_IPTABLES="yes"|' "${EROOT}/etc/conf.d/suritop-web" 2>/dev/null
			rc-update add suritop-iptables-setup default 2>/dev/null
			einfo "iptables auto-setup ENABLED"
		else
			sed -i 's|^SURITOP_AUTO_IPTABLES=.*|SURITOP_AUTO_IPTABLES="no"|' "${EROOT}/etc/conf.d/suritop-web" 2>/dev/null
			einfo "iptables auto-setup DISABLED — your existing rules preserved"
		fi
		einfo ""
	fi

	if use nat; then
		einfo "Enable NAT masquerade? [y/N]"
		read -r REPLY
		if [[ "${REPLY}" == "y" || "${REPLY}" == "Y" ]]; then
			sed -i 's|^SURITOP_NAT_ENABLE=.*|SURITOP_NAT_ENABLE="yes"|' "${EROOT}/etc/conf.d/suritop-web" 2>/dev/null
			einfo "NAT masquerade enabled"
		fi
		einfo ""
	fi

	if use docker; then
		einfo "Enable Docker integration (DOCKER-USER chain)? [y/N]"
		read -r REPLY
		if [[ "${REPLY}" == "y" || "${REPLY}" == "Y" ]]; then
			sed -i 's|^SURITOP_DOCKER_ENABLE=.*|SURITOP_DOCKER_ENABLE="yes"|' "${EROOT}/etc/conf.d/suritop-web" 2>/dev/null
			einfo "Docker integration enabled"
		fi
		einfo ""
	fi

	einfo "Enable services in default runlevel? [Y/n]"
	read -r REPLY
	if [[ "${REPLY}" != "n" && "${REPLY}" != "N" ]]; then
		for svc in suritop-stats suritop-suri suritop-waf suritop-geo suritop-iptables; do
			rc-update add ${svc} default 2>/dev/null
		done
		rc-update add iptables default 2>/dev/null
		einfo "Services added to default runlevel"
	fi

	touch "${EROOT}/etc/suritop-web/.configured"
	einfo ""
	einfo "Configuration complete!"
	einfo ""
	einfo "Start all services:"
	einfo "  rc-service suritop-iptables start"
	einfo "  rc-service suritop-stats start"
	einfo "  rc-service suritop-suri start"
	einfo "  rc-service suritop-waf start"
	einfo "  rc-service suritop-geo start"
	einfo "  rc-service suricata start"
	einfo "  rc-service nginx restart"
	einfo "  rc-service fail2ban restart"
	einfo ""
	einfo "Login: admin / admin"
	einfo ""
}
