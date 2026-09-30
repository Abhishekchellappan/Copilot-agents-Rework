#!/usr/bin/env python3
"""
Script to enable SQLite WAL (Write-Ahead Logging) mode for concurrent access.
Allows concurrent readers and writer without locking errors.
"""
import os
import sys
import sqlite3

def enable_wal(db_path: str):
    print(f"Connecting to database at: {db_path}")
    if not os.path.exists(db_path):
        print(f"Warning: Database file '{db_path}' does not exist yet. Creating database...")
    
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        mode = cursor.fetchone()[0]
        print(f"Success! SQLite journal_mode is now: {mode.upper()}")
        
        cursor.execute("PRAGMA synchronous=NORMAL;")
        print("Set PRAGMA synchronous=NORMAL for optimal performance.")
    finally:
        conn.close()

if __name__ == "__main__":
    db_file = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DB_PATH", "/tmp/gpos_portal.db")
    enable_wal(db_file)
