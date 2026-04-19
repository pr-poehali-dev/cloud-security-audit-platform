import os
import json
import psycopg2
from datetime import datetime, timezone

SCHEMA = None

def get_schema():
    global SCHEMA
    if SCHEMA is None:
        SCHEMA = os.environ.get('MAIN_DB_SCHEMA', 'public')
    return SCHEMA

def check_auth(event: dict) -> bool:
    admin_token = os.environ.get('ADMIN_TOKEN', '')
    request_token = event.get('headers', {}).get('X-Admin-Token', '')
    return bool(admin_token) and request_token == admin_token

def get_conn():
    return psycopg2.connect(os.environ['DATABASE_URL'])

def handler(event: dict, context) -> dict:
    """
    Синхронизация S3-конфигурации между функциями через БД.
    POST: сохраняет AWS_ACCESS_KEY_ID и AWS_SECRET_ACCESS_KEY из env в таблицу s3_config
          для указанного service_name (из body).
    GET:  читает конфиги из таблицы; значения ключей маскируются.
    Требует X-Admin-Token.
    """
    cors = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token',
        'Access-Control-Max-Age': '86400',
    }

    if event.get('httpMethod') == 'OPTIONS':
        return {'statusCode': 200, 'headers': cors, 'body': ''}

    if not check_auth(event):
        return {
            'statusCode': 403,
            'headers': {**cors, 'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Forbidden'}),
        }

    method = event.get('httpMethod', 'GET')
    schema = get_schema()

    if method == 'GET':
        params = event.get('queryStringParameters') or {}
        service_filter = params.get('service_name', '')

        conn = get_conn()
        cur = conn.cursor()
        if service_filter:
            cur.execute(
                f"SELECT service_name, config_key, config_value, updated_at "
                f"FROM {schema}.s3_config WHERE service_name = %s ORDER BY service_name, config_key",
                (service_filter,)
            )
        else:
            cur.execute(
                f"SELECT service_name, config_key, config_value, updated_at "
                f"FROM {schema}.s3_config ORDER BY service_name, config_key"
            )
        rows = cur.fetchall()
        cur.close()
        conn.close()

        def mask(val: str) -> str:
            if len(val) <= 6:
                return '***'
            return val[:3] + '***' + val[-3:]

        entries = []
        for row in rows:
            entries.append({
                'service_name': row[0],
                'config_key': row[1],
                'config_value': mask(row[2]),
                'updated_at': row[3].isoformat() if row[3] else None,
            })

        return {
            'statusCode': 200,
            'headers': {**cors, 'Content-Type': 'application/json'},
            'body': json.dumps({'configs': entries, 'count': len(entries)}),
        }

    if method == 'POST':
        body = {}
        try:
            body = json.loads(event.get('body') or '{}')
        except Exception:
            return {
                'statusCode': 400,
                'headers': {**cors, 'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Invalid JSON body'}),
            }

        service_name = body.get('service_name', '').strip()
        if not service_name:
            return {
                'statusCode': 400,
                'headers': {**cors, 'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'body.service_name is required'}),
            }

        access_key = os.environ.get('AWS_ACCESS_KEY_ID', '')
        secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY', '')

        if not access_key or not secret_key:
            return {
                'statusCode': 500,
                'headers': {**cors, 'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'AWS credentials not found in environment'}),
            }

        now = datetime.now(timezone.utc)
        upsert_sql = f"""
            INSERT INTO {schema}.s3_config (service_name, config_key, config_value, updated_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (service_name, config_key)
            DO UPDATE SET config_value = EXCLUDED.config_value, updated_at = EXCLUDED.updated_at
        """
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(upsert_sql, (service_name, 'AWS_ACCESS_KEY_ID', access_key, now))
        cur.execute(upsert_sql, (service_name, 'AWS_SECRET_ACCESS_KEY', secret_key, now))
        conn.commit()
        cur.close()
        conn.close()

        return {
            'statusCode': 200,
            'headers': {**cors, 'Content-Type': 'application/json'},
            'body': json.dumps({
                'saved': True,
                'service_name': service_name,
                'keys': ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'],
                'updated_at': now.isoformat(),
            }),
        }

    return {
        'statusCode': 405,
        'headers': {**cors, 'Content-Type': 'application/json'},
        'body': json.dumps({'error': 'Method not allowed'}),
    }
