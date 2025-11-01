# Phishing Trainer — Local Simulation (Python)

Local phishing awareness trainer built with Python stdlib.  
Generates simulated `.eml` emails (not included in repo) and serves a tracking page for training purposes.

**Usage:**
```bash
# Run tracker
python Phishing_Trainer.py serve --host 127.0.0.1 --port 8000

# Generate a test email
python Phishing_Trainer.py gen-email --recipient test@local --sender "IT <it@local>" --subject "Action required" --body "Click here: {link}" --host 127.0.0.1 --port 8000
