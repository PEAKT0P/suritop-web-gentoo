# suritop-web — Security Monitoring System for Gentoo Linux

## Описание

suritop-web — система мониторинга безопасности для Gentoo Linux:
- **Suricata IDS/IPS** — обнаружение вторжений
- **ModSecurity WAF** — защита веб-приложений
- **Fail2Ban** — блокировка атак
- **iptables** — файрвол с веб-управлением
- **Attack Map** — карта атак в реальном времени
- **Admin Stats** — статистика и мониторинг

## Быстрая установка на чистый Gentoo + OpenRC

### 1. Установить зависимости

```bash
emerge --sync
emerge -av app-admin/sudo
```

### 2. Установить overlay

```bash
# Скопировать архив на сервер
scp suritop-web-overlay.tar.gz root@server:/tmp/

# На сервере:
cd /tmp
tar xzf suritop-web-overlay.tar.gz

# Зарегистрировать overlay
mkdir -p /etc/portage/repos.conf
cat > /etc/portage/repos.conf/suritop-web.conf << 'EOF'
[suritop-web]
location = /usr/local/portage/local
masters = gentoo
auto-sync = false
priority = 50
EOF

# Скопировать overlay
mkdir -p /usr/local/portage/local
cp -r suritop-web-overlay/* /usr/local/portage/local/
```

### 3. Настроить USE flags

```bash
# Принять ключи для пакетов
mkdir -p /etc/portage/package.accept_keywords
cat > /etc/portage/package.accept_keywords/suritop-web << 'EOF'
net-analyzer/suritop-web **
net-analyzer/suricata **
net-libs/libhtp **
EOF

# Настроить USE flags
cat > /etc/portage/package.use/suritop-web << 'EOF'
net-analyzer/suritop-web -iptables -nat -docker +suricata
EOF
```

### 4. Установить пакет

```bash
# Сначала установить зависимости
emerge -av --backtrack=30 net-analyzer/suritop-web

# Интерактивная настройка (nginx, БД, fail2ban, iptables)
emerge --config net-analyzer/suritop-web
```

### 5. Запустить сервисы

```bash
# Базовые сервисы
rc-service mysql start
rc-service nginx start
rc-service php-fpm start

# Suritop компоненты
rc-service suritop-stats start
rc-service suritop-suri start
rc-service suritop-waf start
rc-service iptables-manager start

# Защита
rc-service suricata start
rc-service fail2ban start
```

### 6. Добавить в автозагрузку

```bash
rc-update add mysql default
rc-update add nginx default
rc-update add php-fpm default
rc-update add suritop-stats default
rc-update add suritop-suri default
rc-update add suritop-waf default
rc-update add iptables-manager default
rc-update add suricata default
rc-update add fail2ban default
rc-update add iptables default
```

## USE Flags

| Flag | По умолчанию | Описание |
|------|-------------|----------|
| `+iptables` | вкл | Автогенерация iptables правил |
| `-nat` | выкл | NAT masquerade (для раздачи интернета) |
| `-docker` | выкл | Интеграция с Docker (DOCKER-USER chain) |
| `+suricata` | вкл | IPS правила Suricata |
| `-geoip` | выкл | GeoIP определение |

## Конфигурация

### /etc/conf.d/suritop-web

```bash
# Автоматическая настройка iptables при загрузке
SURITOP_AUTO_IPTABLES="no"

# Сеть
SURITOP_SERVER_IP="172.23.230.169"
SURITOP_NET_INTERFACE="enp6s0"
SURITOP_SSH_PORT="61122"

# Whitelist IP (никогда не блокировать)
SURITOP_WHITELIST_IP="172.23.230.169 172.23.224.1"

# БД
SURITOP_DB_NAME="server_stats"
SURITOP_DB_USER_R="stats_reader"
SURITOP_DB_PASS_R="suritop_read_2026"
SURITOP_DB_USER_W="stats_writer"
SURITOP_DB_PASS_W="suritop_write_2026"

# NAT (для раздачи интернета)
SURITOP_NAT_ENABLE="no"

# Docker
SURITOP_DOCKER_ENABLE="no"
```

## Структура файлов

```
/etc/conf.d/suritop-web          — Конфигурация
/etc/suritop-web/                — Конфиги suricata
/etc/nginx/vhosts.d/suritop-web.conf — Nginx vhost
/opt/stats_collector/            — Python коллекторы
/opt/iptables-manager/           — iptables API daemon
/var/www/suritop-web/htdocs/     — PHP файлы сайта
/usr/share/suritop-web/schema.sql — Схема БД
/etc/init.d/suritop-*            — Init scripts
```

## Доступ

- **URL:** http://server-ip/
- **Логин:** admin
- **Пароль:** admin

## Сервисы

| Сервис | Команда | Описание |
|--------|---------|----------|
| mysql | `rc-service mysql start` | MariaDB база данных |
| nginx | `rc-service nginx start` | Веб-сервер |
| php-fpm | `rc-service php-fpm start` | PHP процессор |
| suritop-stats | `rc-service suritop-stats start` | Сбор метрик системы |
| suritop-suri | `rc-service suritop-suri start` | Коллектор suricata (Attack Map) |
| suritop-waf | `rc-service suritop-waf start` | Коллектор modsecurity |
| iptables-manager | `rc-service iptables-manager start` | API управления файрволом |
| suricata | `rc-service suricata start` | IDS/IPS движок |
| fail2ban | `rc-service fail2ban start` | Блокировкаатак |
| iptables | `rc-service iptables start` | Файрвол |

## Удаление

```bash
emerge -C net-analyzer/suritop-web
rm -rf /etc/suritop-web
rm -rf /var/www/suritop-web
rm -rf /opt/stats_collector
rm -rf /opt/iptables-manager
rm -rf /etc/portage/repos.conf/suritop-web.conf
rm -rf /usr/local/portage/local
```
