# check_env.py
"""
Diagnostic script — run this in the project root to see exactly which
SECRET_KEY and SECURITY_PASSWORD_SALT values Flask will use at startup.

Run with:
    python check_env.py

Location: check_env.py  (root of the project, temporary — delete after use)
"""

import os

# ── 1. Before load_dotenv ────────────────────────────────────────────────────
print("=" * 60)
print("BEFORE load_dotenv():")
print(f"  SECRET_KEY             = {os.environ.get('SECRET_KEY', '(not set)')}")
print(f"  SECURITY_PASSWORD_SALT = {os.environ.get('SECURITY_PASSWORD_SALT', '(not set)')}")
print(f"  PG_USER                = {os.environ.get('PG_USER', '(not set)')}")

# ── 2. After load_dotenv (default — does NOT override existing vars) ─────────
from dotenv import load_dotenv, dotenv_values

load_dotenv()
print()
print("AFTER load_dotenv() [default — does not override existing env vars]:")
print(f"  SECRET_KEY             = {os.environ.get('SECRET_KEY', '(not set)')}")
print(f"  SECURITY_PASSWORD_SALT = {os.environ.get('SECURITY_PASSWORD_SALT', '(not set)')}")

# ── 3. What is actually IN the .env file right now ───────────────────────────
env_file = os.path.join(os.path.dirname(__file__), '.env')
print()
if os.path.exists(env_file):
    values = dotenv_values(env_file)
    print(f"CONTENTS OF .env  ({env_file}):")
    for k, v in values.items():
        # Mask passwords but show keys fully so we can compare
        if 'PASSWORD' in k.upper() and k.upper() not in ('SECURITY_PASSWORD_SALT',):
            display = v[:4] + '****' if v else '(empty)'
        else:
            display = v
        print(f"  {k} = {display}")
else:
    print(f".env NOT FOUND at {env_file}")

# ── 4. After load_dotenv(override=True) ──────────────────────────────────────
load_dotenv(override=True)
print()
print("AFTER load_dotenv(override=True) [forces .env values over system env]:")
print(f"  SECRET_KEY             = {os.environ.get('SECRET_KEY', '(not set)')}")
print(f"  SECURITY_PASSWORD_SALT = {os.environ.get('SECURITY_PASSWORD_SALT', '(not set)')}")

# ── 5. What Config actually sees ─────────────────────────────────────────────
print()
print("WHAT Config WOULD READ (os.environ.get):")
secret = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production'
salt   = os.environ.get('SECURITY_PASSWORD_SALT') or 'super-secret-random-salt'
print(f"  SECRET_KEY             = {secret}")
print(f"  SECURITY_PASSWORD_SALT = {salt}")

if secret == 'dev-key-change-in-production':
    print()
    print("  ⚠  WARNING: SECRET_KEY is the fallback value!")
    print("     Either .env was not found, or a system environment variable")
    print("     is overriding the .env value.")
else:
    print()
    print("  ✓  SECRET_KEY is set from .env correctly.")

print("=" * 60)