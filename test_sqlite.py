import sqlite3
import json
import hashlib
import re
import math

def calculate_hash(content):
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def format_time(secs):
    m = math.floor(secs / 60)
    s = math.floor(secs % 60)
    return f"{m:02d}:{s:02d}"

db_path = r"c:\Users\devas\Documents\Alfred_Joe_Devasia\Talktrace_backend\talktrace.db"

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Get the most recent transcript revision
cursor.execute("SELECT * FROM transcript_revisions WHERE type='transcript' ORDER BY edited_at DESC LIMIT 1")
row = cursor.fetchone()

if not row:
    print("No revisions found.")
else:
    print(f"Checking revision {row['id']} for meeting {row['meeting_id']} version {row['version']}")
    
    # Needs decryption? Ah! The file is encrypted!
    # "edited_at", "file_path", "content_hash"
    print(f"File path: {row['file_path']}")
    print(f"DB Content Hash: {row['content_hash']}")
    
    # We cannot easily decrypt standard AES-256-GCM without the keys from the DB and Node crypto
