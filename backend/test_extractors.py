import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "backend")))

from app.engine.targets import extract_chatbot_response_text

# OpenAI
d_openai = {'choices': [{'message': {'content': 'Hi from OpenAI'}}]}
assert extract_chatbot_response_text(d_openai) == 'Hi from OpenAI', 'Failed OpenAI'

# Anthropic
d_anthropic = {'content': [{'type': 'text', 'text': 'Hi from Claude'}]}
assert extract_chatbot_response_text(d_anthropic) == 'Hi from Claude', 'Failed Anthropic'

# Gemini
d_gemini = {'candidates': [{'content': {'parts': [{'text': 'Hi from Gemini'}]}}]}
assert extract_chatbot_response_text(d_gemini) == 'Hi from Gemini', 'Failed Gemini'

# Custom LangChain / FastAPI / Flask
d_custom1 = {'reply': 'Hi from Custom Bot'}
assert extract_chatbot_response_text(d_custom1) == 'Hi from Custom Bot', 'Failed Custom 1'

d_custom2 = {'response': 'Hi from FastAPI response'}
assert extract_chatbot_response_text(d_custom2) == 'Hi from FastAPI response', 'Failed Custom 2'

d_custom3 = {'text': 'Hi from Webhook text'}
assert extract_chatbot_response_text(d_custom3) == 'Hi from Webhook text', 'Failed Custom 3'

print('All format extractors passed cleanly!')
