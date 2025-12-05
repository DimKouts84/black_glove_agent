from agent.models import load_config_from_file
from agent.llm_client import create_llm_client, LLMMessage
import logging

logging.basicConfig(level=logging.DEBUG)

config = load_config_from_file()
print('Loaded config model from file:')
print('Provider:', config.llm_provider)
print('Endpoint:', config.llm_endpoint)
print('Model (before):', config.llm_model)

# Force model to the OSS GPT free model for this test
config.llm_model = 'openai/gpt-oss-20b:free'
print('Model (forced):', config.llm_model)

client = create_llm_client(config)

msg = LLMMessage(role='user', content='Hello, this is a test from LLMClient integration')
response = client.generate([msg])
print('LLM Client response:')
print(response)