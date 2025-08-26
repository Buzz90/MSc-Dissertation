
import signal
import hashlib
import os
import json
import csv
from typing import List, Tuple, Any, Dict, Optional
from datetime import datetime

def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()

def ensure_dir(path: str):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)

def save_json(path: str, obj: Any):
    ensure_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def append_jsonl(path: str, obj: Any):
    ensure_dir(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")

def graceful_sigint():
    stop = {"flag": False}
    def handler(sig, frame):
        stop["flag"] = True
        print("\n[!] SIGINT received; finishing current payload then stopping.")
    signal.signal(signal.SIGINT, handler)
    return stop
