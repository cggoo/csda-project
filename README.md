
# Setup
Install dotenv:
```bash
pip install openai python-dotenv
```

Create an `.env` file to save your API keys under keywords:
```
GROQ_API_KEY
GEMINI_API_KEY
```

# Running
Use `run_all.py` to run all scenarios for a specified model:
```bash
python run_all.py groq-gptoss
python run_all.py groq-qwen
python run_all.py gemini-flash
```
The script can be stopped and restarted at any time: finished runs are skipped, half-finished runs are redone, and it stops when the provider's rate limit is hit.

Score runs using:
```bash
python score.py
```