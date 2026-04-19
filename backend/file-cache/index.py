import os
import json
import boto3
from pathlib import Path

TMP_DIR = Path('/tmp')

def get_s3():
    return boto3.client(
        's3',
        endpoint_url='https://bucket.poehali.dev',
        aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
        aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
    )

def check_auth(event: dict) -> bool:
    admin_token = os.environ.get('ADMIN_TOKEN', '')
    request_token = event.get('headers', {}).get('X-Admin-Token', '')
    return bool(admin_token) and request_token == admin_token

def handler(event: dict, context) -> dict:
    """
    Кэширует файлы из S3 в /tmp между вызовами функции.
    GET — список файлов в /tmp с размерами.
    POST body.s3_key — скачивает файл из S3 bucket 'files' и сохраняет в /tmp/.
    Требует X-Admin-Token.
    """
    cors_headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token',
        'Access-Control-Max-Age': '86400',
    }

    if event.get('httpMethod') == 'OPTIONS':
        return {'statusCode': 200, 'headers': cors_headers, 'body': ''}

    if not check_auth(event):
        return {
            'statusCode': 403,
            'headers': {'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Forbidden'}),
        }

    method = event.get('httpMethod', 'GET')

    if method == 'GET':
        files = []
        for f in sorted(TMP_DIR.iterdir()):
            if f.is_file():
                stat = f.stat()
                files.append({
                    'name': f.name,
                    'path': str(f),
                    'size_bytes': stat.st_size,
                    'size_kb': round(stat.st_size / 1024, 2),
                    'modified': int(stat.st_mtime),
                })
        return {
            'statusCode': 200,
            'headers': {**cors_headers, 'Content-Type': 'application/json'},
            'body': json.dumps({
                'files': files,
                'count': len(files),
                'tmp_dir': str(TMP_DIR),
            }),
        }

    if method == 'POST':
        body = {}
        try:
            body = json.loads(event.get('body') or '{}')
        except Exception:
            return {
                'statusCode': 400,
                'headers': {'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Invalid JSON body'}),
            }

        s3_key = body.get('s3_key', '').strip()
        if not s3_key:
            return {
                'statusCode': 400,
                'headers': {'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'body.s3_key is required'}),
            }

        filename = Path(s3_key).name
        local_path = TMP_DIR / filename

        already_cached = local_path.exists()
        if not already_cached:
            s3 = get_s3()
            s3.download_file('files', s3_key, str(local_path))

        stat = local_path.stat()
        return {
            'statusCode': 200,
            'headers': {**cors_headers, 'Content-Type': 'application/json'},
            'body': json.dumps({
                'cached': already_cached,
                'downloaded': not already_cached,
                's3_key': s3_key,
                'local_path': str(local_path),
                'filename': filename,
                'size_bytes': stat.st_size,
                'size_kb': round(stat.st_size / 1024, 2),
            }),
        }

    return {
        'statusCode': 405,
        'headers': {'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json'},
        'body': json.dumps({'error': 'Method not allowed'}),
    }
