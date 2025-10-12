import sqlite3

conn = sqlite3.connect("database/attendance.db")
cursor = conn.cursor()

# IP sütununu ekle
cursor.execute("ALTER TABLE attendance ADD COLUMN ip_address TEXT")

conn.commit()
conn.close()
print("✅ attendance tablosuna ip_address sütunu eklendi.")
