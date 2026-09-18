import sqlite3

DB_NAME = "campusdefender.db"

def initialize_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            ip TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT
        )
    """)

    conn.commit()
    conn.close()

    print("✅ Database initialized successfully.")

if __name__ == "__main__":
    initialize_database()
