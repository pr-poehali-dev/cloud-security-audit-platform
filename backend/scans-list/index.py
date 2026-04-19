import os
import json
import psycopg2

def handler(event: dict, context) -> dict:
    """
    Возвращает список последних сканов безопасности из БД.
    Поддерживает параметр limit (по умолчанию 20).
    """
    if event.get('httpMethod') == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Max-Age': '86400',
            },
            'body': '',
        }

    params = event.get('queryStringParameters') or {}
    limit = min(int(params.get('limit', 20)), 100)
    schema = os.environ.get('MAIN_DB_SCHEMA', 'public')

    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    cur = conn.cursor()
    cur.execute(f"""
        SELECT id, scan_id, created_at, status, risk_level,
               env_vars_count, secrets_found, suspicious_files, summary
        FROM {schema}.scan_results
        ORDER BY created_at DESC
        LIMIT {limit}
    """)
    rows = cur.fetchall()

    cur.execute(f"SELECT COUNT(*) FROM {schema}.scan_results")
    total = cur.fetchone()[0]

    cur.execute(f"""
        SELECT
            COUNT(*) FILTER (WHERE risk_level = 'critical') AS critical,
            COUNT(*) FILTER (WHERE risk_level = 'high') AS high,
            COUNT(*) FILTER (WHERE risk_level = 'medium') AS medium,
            COUNT(*) FILTER (WHERE risk_level = 'low') AS low,
            AVG(secrets_found) AS avg_secrets,
            MAX(secrets_found) AS max_secrets
        FROM {schema}.scan_results
    """)
    stats_row = cur.fetchone()

    cur.close()
    conn.close()

    scans = []
    for r in rows:
        scans.append({
            'id': r[0],
            'scan_id': str(r[1]),
            'created_at': r[2].isoformat() if r[2] else None,
            'status': r[3],
            'risk_level': r[4],
            'env_vars_count': r[5],
            'secrets_found': r[6],
            'suspicious_files': r[7],
            'summary': r[8],
        })

    return {
        'statusCode': 200,
        'headers': {'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json'},
        'body': json.dumps({
            'scans': scans,
            'total': total,
            'stats': {
                'critical': stats_row[0] or 0,
                'high': stats_row[1] or 0,
                'medium': stats_row[2] or 0,
                'low': stats_row[3] or 0,
                'avg_secrets': float(stats_row[4] or 0),
                'max_secrets': stats_row[5] or 0,
            }
        }),
    }
