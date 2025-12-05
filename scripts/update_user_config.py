import os
import shutil
import yaml
from pathlib import Path
from datetime import datetime

def migrate_config():
    # Paths
    home_dir = Path.home()
    config_dir = home_dir / ".homepentest"
    config_path = config_dir / "config.yaml"
    env_path = Path(__file__).parent.parent / ".env"
    
    print(f"Checking configuration at: {config_path}")
    
    # 1. Read .env to get the key
    api_key = None
    if env_path.exists():
        print(f"Reading API key from: {env_path}")
        with open(env_path, 'r') as f:
            for line in f:
                if line.strip().startswith("OPENROUTER_API_KEY="):
                    api_key = line.strip().split("=", 1)[1].strip()
                    break
    
    if not api_key:
        print("WARNING: No OPENROUTER_API_KEY found in .env. Config will be updated without key.")
    else:
        print(f"Found API key: {api_key[:4]}...{api_key[-4:]}")

    # 2. Read existing config or create default if missing
    if config_path.exists():
        # Backup
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = config_path.with_suffix(f".yaml.bak_{timestamp}")
        shutil.copy2(config_path, backup_path)
        print(f"Created backup at: {backup_path}")
        
        with open(config_path, 'r') as f:
            try:
                config = yaml.safe_load(f) or {}
            except yaml.YAMLError:
                print("Error reading existing config, starting fresh.")
                config = {}
    else:
        print("No existing config found. Creating new one.")
        config_dir.mkdir(parents=True, exist_ok=True)
        config = {}

    # 3. Update values
    config['llm_provider'] = "openrouter"
    config['llm_endpoint'] = "https://openrouter.ai/api/v1"
    config['llm_model'] = "openai/gpt-oss-20b:free"
    
    if api_key:
        config['llm_api_key'] = api_key
        print("Injecting API key into config.")

    # Preserve comments is hard with standard yaml lib, but we'll dump clean yaml
    # This effectively enforces the "single file" policy by ensuring the key is there
    
    with open(config_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    
    print("Configuration updated successfully.")
    print("-" * 30)
    print("New Settings:")
    print(f"Provider: {config.get('llm_provider')}")
    print(f"Model:    {config.get('llm_model')}")
    print(f"API Key:  {'Set' if config.get('llm_api_key') else 'Not Set'}")

if __name__ == "__main__":
    migrate_config()
