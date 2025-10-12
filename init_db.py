import sqlite3

conn = sqlite3.connect('attendance.db')
conn.executescript("""
CREATE TABLE IF NOT EXISTS students (
    student_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT,
    device_id TEXT
);
""")
conn.commit()
conn.close()
print("DB ve students tablosu hazır.")
