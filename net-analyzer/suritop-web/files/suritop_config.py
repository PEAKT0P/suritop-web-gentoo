#!/usr/bin/env python3
"""
suritop_config.py — Shared configuration reader for suritop-web
Reads from /etc/suritop-web/suritop.conf (INI format, single source of truth)

Usage in other scripts:
    from suritop_config import get_db, get_config
    cfg = get_config()
    conn = get_db()
"""

import os
import configparser

CONFIG_PATH = '/etc/suritop-web/suritop.conf'

_config = None


def _get_int(conf, section, option, default):
    """Get int value, handle @@ placeholders gracefully"""
    try:
        val = conf.get(section, option, fallback=str(default))
        if '@@' in val:
            return default
        return int(val)
    except (ValueError, TypeError):
        return default


def get_config():
    """Get all config values as a dict"""
    global _config
    if _config is not None:
        return _config

    conf = configparser.ConfigParser()
    conf.read(CONFIG_PATH)

    _config = {
        'db_host': conf.get('Database', 'host', fallback='localhost'),
        'db_name': conf.get('Database', 'name', fallback='server_stats'),
        'db_user_r': conf.get('Database', 'user_r', fallback='stats_reader'),
        'db_pass_r': conf.get('Database', 'pass_r', fallback=''),
        'db_user_w': conf.get('Database', 'user_w', fallback='stats_writer'),
        'db_pass_w': conf.get('Database', 'pass_w', fallback=''),
        'our_ip': conf.get('Network', 'our_ip', fallback='127.0.0.1'),
        'net_interface': conf.get('Network', 'interface', fallback=''),
        'ssh_port': _get_int(conf, 'Network', 'ssh_port', 22),
        'whitelist_ip': conf.get('Network', 'whitelist_ip', fallback=''),
        'home_net': conf.get('Network', 'home_net', fallback=''),
        'server_lat': conf.getfloat('Network', 'server_lat', fallback=55.75),
        'server_lon': conf.getfloat('Network', 'server_lon', fallback=37.62),
        'docker_enable': conf.get('Docker', 'enable', fallback='no'),
        'docker_bridge': conf.get('Docker', 'bridge', fallback='172.17.0.0/16'),
        'nat_enable': conf.get('NAT', 'enable', fallback='no'),
    }
    return _config


def get_db(readonly=False):
    """Get a database connection. Set readonly=True for reader account."""
    cfg = get_config()

    if readonly:
        user = cfg['db_user_r']
        passwd = cfg['db_pass_r']
    else:
        user = cfg['db_user_w']
        passwd = cfg['db_pass_w']

    try:
        import MySQLdb
        conn = MySQLdb.connect(
            host=cfg['db_host'], user=user, passwd=passwd,
            db=cfg['db_name'], charset='utf8mb4',
            connect_timeout=5
        )
        conn.autocommit(True)
        return conn
    except ImportError:
        import pymysql
        conn = pymysql.connect(
            host=cfg['db_host'], user=user, password=passwd,
            database=cfg['db_name'], charset='utf8mb4',
            connect_timeout=5, autocommit=True
        )
        return conn
