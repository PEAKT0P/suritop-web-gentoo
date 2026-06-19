# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

DESCRIPTION="Security monitoring system: Suricata IDS + ModSecurity WAF + Fail2Ban + iptables dashboard.
 USE flags: +iptables (firewall rules), +nat (masquerade/NAT), +docker (Docker integration),
 +suricata (IPS rules). Run 'emerge --config net-analyzer/suritop-web' for interactive setup.
 Does NOT auto-configure iptables — safe for existing firewall setups."
HOMEPAGE="https://github.com/denjik/suritop-web"
SRC_URI=""

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="amd64 x86"
IUSE="+iptables nat docker +suricata geoip"

RDEPEND="
	net-analyzer/suricata
	net-analyzer/fail2ban
	dev-lang/php:=[pdo,mysql]
	dev-db/mariadb
	dev-python/pymysql
	www-servers/nginx
	sys-apps/shadow
	sys-apps/coreutils
	geoip? ( dev-libs/GeoIP )
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
	insopts -m0644 -o stats_collector -g stats_collector
	doins "${S}"/collector.conf

	insopts -m0755 -o stats_collector -g stats_collector
	doins "${S}"/suritop.py

	dosym /opt/stats_collector/suritop.py /usr/bin/suritop
	diropts -m0755 -o root -g root
	dodir /opt/iptables-manager
	insinto /opt/iptables-manager
	insopts -m0755 -o root -g root
	doins "${S}"/iptables_api.py

	insopts -m0644 -o stats_collector -g stats_collector
	insinto /opt/stats_collector
	doins "${S}"/suritop_config.py

	insopts -m0755
	dodir /usr/lib/suritop-web
	insinto /usr/lib/suritop-web
	doins "${S}"/suritop-patch.py

	diropts -m0755 -o root -g root
	dodir /var/www/suritop-web/htdocs/attackmap
	dodir /var/www/suritop-web/htdocs/iptables

	insinto /var/www/suritop-web/htdocs
	insopts -m0644
	doins "${S}"/admin_stats.php
	doins "${S}"/root-index.php index.php
	doins "${S}"/root-config.php config.php

	insinto /var/www/suritop-web/htdocs/attackmap
	doins "${S}"/index.php
	doins "${S}"/config.php

	insinto /var/www/suritop-web/htdocs/iptables
	doins "${S}"/api.php
	doins "${S}"/iptables_index.html iptables/index.html

	insopts -m0644
	insinto /etc/suritop-web
	doins "${S}"/nginx-vhost.conf
	doins "${S}"/collector.conf
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

	doinitd "${S}"/suritop-stats.initd
	doinitd "${S}"/suritop-suri.initd
	doinitd "${S}"/suritop-waf.initd
	doinitd "${S}"/suritop-iptables.initd

	if use iptables; then
		doinitd "${S}"/suritop-iptables-setup
	fi

	insinto /etc/logrotate.d
	newins "${S}"/suritop-web.logrotate suritop-web

	dodir /usr/share/suritop-web
	insinto /usr/share/suritop-web
	newins "${S}"/schema.sql schema.sql

	diropts -m0755 -o stats_collector -g stats_collector
	dodir /var/lib/stats_collector

	dodir /etc/nginx/vhosts.d

	dodoc "${S}"/README.gentoo
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
		einfo "  1. Edit /etc/conf.d/suritop-web"
		einfo "  2. Import schema: mariadb -u root < /usr/share/suritop-web/schema.sql"
		einfo "  3. Enable services: rc-update add suritop-stats default"
		einfo "  4. Start: rc-service suritop-stats start"
		einfo ""
	else
		einfo "Configuration found at /etc/conf.d/suritop-web"
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
	DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
	DEFAULT_IP=${DEFAULT_IP:-127.0.0.1}
	DEFAULT_SSH=$(grep -oP "(?<=Port )\d+" "${EROOT}/etc/ssh/sshd_config" 2>/dev/null | head -1)
	DEFAULT_SSH=${DEFAULT_SSH:-22}

	einfo "Detected network:"
	einfo "  Interface: ${DEFAULT_IF}"
	einfo "  Server IP: ${DEFAULT_IP}"
	einfo "  SSH Port:  ${DEFAULT_SSH}"
	einfo ""

	sed -i "s|@@SERVER_IP@@|${DEFAULT_IP}|g" "${EROOT}/etc/conf.d/suritop-web" 2>/dev/null
	sed -i "s|@@NET_INTERFACE@@|${DEFAULT_IF}|g" "${EROOT}/etc/conf.d/suritop-web" 2>/dev/null
	sed -i "s|@@SSH_PORT@@|${DEFAULT_SSH}|g" "${EROOT}/etc/conf.d/suritop-web" 2>/dev/null
	sed -i "s|@@SERVER_IP@@|${DEFAULT_IP}|g" "${EROOT}/etc/suritop-web/collector.conf" 2>/dev/null
	sed -i "s|@@NET_INTERFACE@@|${DEFAULT_IF}|g" "${EROOT}/etc/suritop-web/collector.conf" 2>/dev/null
	sed -i "s|@@SERVER_IP@@|${DEFAULT_IP}|g" "${EROOT}/etc/suritop-web/suricata.yaml" 2>/dev/null
	sed -i "s|@@NET_INTERFACE@@|${DEFAULT_IF}|g" "${EROOT}/etc/suritop-web/suricata.yaml" 2>/dev/null
	einfo "Config files templated with detected values"

	einfo "Setup nginx with basic auth (admin:admin)? [Y/n]"
	read -r REPLY
	if [[ "${REPLY}" != "n" && "${REPLY}" != "N" ]]; then
		cp "${EROOT}/etc/suritop-web/nginx-vhost.conf" "${EROOT}/etc/nginx/vhosts.d/suritop-web.conf"
		einfo "Nginx vhost installed"

		if command -v python3 >/dev/null 2>&1; then
			HASH=$(python3 -c "
import subprocess, base64, os
salt = base64.b64encode(os.urandom(16)).decode()
r = subprocess.run(['openssl', 'passwd', '-6', '-salt', salt, 'admin'], capture_output=True, text=True)
print(f'admin:{r.stdout.strip()}')
" 2>/dev/null)
			if [[ -n "${HASH}" ]]; then
				echo "${HASH}" > "${EROOT}/etc/nginx/.htpasswd"
				einfo "Basic auth created: admin / admin"
			fi
		fi
		einfo ""
	fi

	einfo "Setup database (import schema + create users)? [Y/n]"
	read -r REPLY
	if [[ "${REPLY}" != "n" && "${REPLY}" != "N" ]]; then
		if ! rc-service mysql status >/dev/null 2>&1; then
			einfo "Starting MariaDB..."
			rc-service mysql start 2>/dev/null
			sleep 2
		fi

		if command -v mariadb >/dev/null 2>&1 || command -v mysql >/dev/null 2>&1; then
			DB_CMD=$(command -v mariadb 2>/dev/null || command -v mysql)

			DB_OK=0
			if ${DB_CMD} -u root -e "SELECT 1" >/dev/null 2>&1; then
				DB_OK=1
				DB_OPTS="-u root"
			elif ${DB_CMD} -u root -p'' -e "SELECT 1" >/dev/null 2>&1; then
				DB_OK=1
				DB_OPTS="-u root"
			fi

			if [[ ${DB_OK} -eq 1 ]]; then
				einfo "MariaDB connected"

				if ${DB_CMD} ${DB_OPTS} < "${EROOT}/usr/share/suritop-web/schema.sql" 2>/dev/null; then
					einfo "Schema imported"
				else
					ewarn "Schema import failed (tables may already exist)"
				fi

				if ${DB_CMD} ${DB_OPTS} -e "
					CREATE USER IF NOT EXISTS 'stats_reader'@'localhost' IDENTIFIED BY 'suritop_read_2026';
					GRANT SELECT ON server_stats.* TO 'stats_reader'@'localhost';
					CREATE USER IF NOT EXISTS 'stats_writer'@'localhost' IDENTIFIED BY 'suritop_write_2026';
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
		for svc in suritop-stats suritop-suri suritop-waf suritop-iptables iptables-manager fail2ban suricata; do
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
	einfo "  rc-service suricata start"
	einfo "  rc-service iptables-manager start"
	einfo "  rc-service nginx restart"
	einfo "  rc-service fail2ban restart"
	einfo ""
	einfo "Login: admin / admin"
	einfo ""
}
