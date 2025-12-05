import os
import requests
import json

# Find API key from .env if not in environment
key = os.environ.get('OPENROUTER_API_KEY')
if not key:
    env_file = os.path.join(os.path.dirname(__file__), '..', '.env')
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                if line.strip().startswith('OPENROUTER_API_KEY'):
                    key = line.strip().split('=', 1)[1].strip()
                    break

if not key:
    print('No OPENROUTER_API_KEY found in env or .env file')
    raise SystemExit(1)

url = 'https://openrouter.ai/api/v1/chat/completions'
headers = {
    'Authorization': f'Bearer {key}',
    'Content-Type': 'application/json'
}

payload = {
    'model': 'openai/gpt-oss-20b:free',
    'messages': [
        {'role': 'user', 'content': 'Hello LLM, are you reachable?'}
    ],
    'temperature': 0.1
}

try:
    r = requests.post(url, json=payload, headers=headers, timeout=10)
    r.raise_for_status()
    print('Status:', r.status_code)
    try:
        data = r.json()
        print('Response JSON:', json.dumps(data, indent=2)[:2000])
    except Exception as e:
        print('Response text:', r.text[:2000])
except Exception as e:
    print('API call failed:', str(e))
    raise
