# Phishing Trainer — Local Simulation (Python)

**Type:** Educational / Lab Tool  
**Language:** Python 3  
**Status:** Safe for local testing only  

---

## Overview

Phishing Trainer is a **simulated phishing awareness tool** built entirely with Python's standard library.  
It allows you to:  

- Generate **test `.eml` emails** for training simulations (local only).  
- Serve a **tracking landing page** that logs click activity.  
- Safely capture **simulated credentials** submitted via the page (stored locally, not sent anywhere).  
- Test phishing awareness in a controlled lab environment.

> ⚠️ **Safety note:** Never use this on real users without explicit permission. All tracking and logging is local and for educational purposes only.

---

## Features

- **Click tracking** with unique tracking IDs (`uid`)  
- **Simulated credential capture** (email + password input)  
- **Report button** to simulate phishing reports  
- **Local `.eml` email generation** for safe testing  
- Fully **self-contained**, requires no external dependencies  

---

## Quick Start

1. **Run the tracker server**  
```bash
python Phishing_Trainer.py serve --host_
