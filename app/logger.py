import sqlite3
from datetime import datetime

DB_NAME = "campusdefender.db"

def log_event(attack_type, ip, action, details):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            INSERT INTO attacks (timestamp, attack_type, ip, action, details)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, attack_type, ip, action, details))

        conn.commit()
        conn.close()

    except Exception as e:
        print("Database Logging Error:", e)
