import os
import json
import platform
import re
import psycopg2
from datetime import datetime, timezone

SECRET_PATTERNS = [
    r'(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|bearer|credential)',
    r'(?i)(aws|gcp|azure|github|gitlab|slack|stripe|twilio|sendgrid|mailgun)',
    r'[A-Za-z0-9+/]{40,}={0,2}',
    r'[0-9a-f]{32,}',
]

SENSITIVE_DIRS = ['/', '/etc', '/tmp', '/var', '/home', '/root', '/proc/self/fd']
KEY_FILES_CHECK = ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/resolv.conf']

def mask_value(val: str) -> str:
    if len(val) <= 4:
        return '***'
    return val[:2] + '***' + val[-2:]

def is_suspicious_env(key: str, val: str) -> bool:
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, key) or re.search(pattern, val):
            return True
    return False

def collect_env_data():
    env = dict(os.environ)
    suspicious = []
    safe_env = {}
    for k, v in env.items():
        if is_suspicious_env(k, v):
            suspicious.append(k)
            safe_env[k] = mask_value(v)
        else:
            safe_env[k] = v[:100] if len(v) > 100 else v
    return {
        'total_count': len(env),
        'suspicious_keys': suspicious,
        'suspicious_count': len(suspicious),
        'masked_env': safe_env,
    }

def collect_fs_data():
    result = {}
    suspicious_files = []
    for directory in SENSITIVE_DIRS:
        try:
            entries = os.listdir(directory)
            result[directory] = entries[:50]
        except Exception as e:
            result[directory] = str(e)
    for fpath in KEY_FILES_CHECK:
        try:
            with open(fpath, 'r', errors='replace') as f:
                content = f.read(500)
            result[f'content:{fpath}'] = content
            if fpath in ['/etc/shadow']:
                suspicious_files.append(fpath)
        except Exception as e:
            result[f'content:{fpath}'] = str(e)
    return {
        'directories': result,
        'suspicious_files': suspicious_files,
        'suspicious_count': len(suspicious_files),
    }

def collect_network_data():
    resolv = ''
    try:
        with open('/etc/resolv.conf', 'r') as f:
            resolv = f.read(1000)
    except Exception as e:
        resolv = str(e)
    hosts = ''
    try:
        with open('/etc/hosts', 'r') as f:
            hosts = f.read(1000)
    except Exception as e:
        hosts = str(e)
    return {
        'resolv_conf': resolv,
        'hosts': hosts,
    }

def collect_process_data():
    status = ''
    try:
        with open('/proc/self/status', 'r') as f:
            status = f.read(2000)
    except Exception as e:
        status = str(e)
    return {
        'proc_status': status,
    }

def collect_platform_data():
    info = platform.uname()
    return {
        'system': info.system,
        'node': info.node,
        'release': info.release,
        'version': info.version,
        'machine': info.machine,
        'processor': info.processor,
        'python_version': platform.python_version(),
    }

def calculate_risk(env_data, fs_data):
    score = 0
    if env_data['suspicious_count'] > 5:
        score += 3
    elif env_data['suspicious_count'] > 0:
        score += 1
    if fs_data['suspicious_count'] > 0:
        score += 3
    if score >= 4:
        return 'critical'
    elif score >= 2:
        return 'high'
    elif score >= 1:
        return 'medium'
    return 'low'

def handler(event: dict, context) -> dict:
    """
    Запускает аудит безопасности текущей среды выполнения:
    собирает переменные окружения, файловую систему, сетевые настройки,
    информацию о процессе и платформе. Результаты сохраняются в БД.
    Возвращает только краткое summary — без чувствительных данных.
    Требует заголовок X-Admin-Token.
    """
    if event.get('httpMethod') == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token',
                'Access-Control-Max-Age': '86400',
            },
            'body': '',
        }

    admin_token = os.environ.get('ADMIN_TOKEN', '')
    request_token = event.get('headers', {}).get('X-Admin-Token', '')
    if not admin_token or request_token != admin_token:
        return {
            'statusCode': 403,
            'headers': {'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': 'Forbidden'}),
        }

    env_data = collect_env_data()
    fs_data = collect_fs_data()
    network_data = collect_network_data()
    process_data = collect_process_data()
    platform_data = collect_platform_data()

    risk_level = calculate_risk(env_data, fs_data)

    summary = {
        'env_vars_count': env_data['total_count'],
        'secrets_found': env_data['suspicious_count'],
        'suspicious_keys': env_data['suspicious_keys'],
        'suspicious_files': fs_data['suspicious_count'],
        'risk_level': risk_level,
        'platform': f"{platform_data['system']} {platform_data['release']}",
        'node': platform_data['node'],
        'scanned_at': datetime.now(timezone.utc).isoformat(),
    }

    schema = os.environ.get('MAIN_DB_SCHEMA', 'public')
    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    cur = conn.cursor()
    cur.execute(f"""
        INSERT INTO {schema}.scan_results
            (status, risk_level, env_vars_count, secrets_found, suspicious_files,
             platform_info, env_snapshot, fs_snapshot, network_info, process_info, summary, raw_data)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id, scan_id
    """, (
        'completed',
        risk_level,
        env_data['total_count'],
        env_data['suspicious_count'],
        fs_data['suspicious_count'],
        json.dumps(platform_data),
        json.dumps({'suspicious_keys': env_data['suspicious_keys'], 'masked_env': env_data['masked_env']}),
        json.dumps(fs_data['directories']),
        json.dumps(network_data),
        json.dumps(process_data),
        json.dumps(summary),
        json.dumps({'env': env_data, 'fs': fs_data, 'network': network_data, 'process': process_data, 'platform': platform_data}),
    ))
    row = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    return {
        'statusCode': 200,
        'headers': {'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json'},
        'body': json.dumps({
            'scan_id': str(row[1]),
            'db_id': row[0],
            'summary': summary,
        }),
    }
