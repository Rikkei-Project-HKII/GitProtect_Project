"""Test configuration; Redis scripts execute through fakeredis[lua], never a stub."""
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
os.environ.setdefault('GITPROTECT_AES_MASTER_KEY', secrets.token_hex(32))
