import sqlite3
import pandas as pd
from tabulate import tabulate
import os

# Veritabanı yolu (proje kökünden)
DB_PATH = os.path.join("database", "attendance.db")

# Veritabanı bağlantısı
if not os.path.exists(DB_PATH):
    print(f"❌ Veritabanı bulunamadı: {DB_PATH}")
    print("Lütfen database/attendance.db dosyasının mevcut olduğundan emin olun.")
    exit()

conn = sqlite3.connect(DB_PATH)

# Öğrenci kayıtları
students_df = pd.read_sql_query("SELECT id, student_number, name FROM students", conn)
print("=== Öğrenci Kayıtları ===")
if students_df.empty:
    print("Öğrenci kaydı bulunamadı.")
else:
    print(tabulate(students_df, headers='keys', tablefmt='fancy_grid', showindex=False))

# Yoklama kayıtları
attendance_df = pd.read_sql_query("""
    SELECT a.id, a.student_name, s.student_number, a.timestamp, a.ip_address
    FROM attendance a
    LEFT JOIN students s ON a.student_id = s.id
""", conn)

print("\n=== Yoklamalar ===")
if attendance_df.empty:
    print("Henüz yoklama kaydı yok.")
else:
    print(tabulate(attendance_df, headers='keys', tablefmt='fancy_grid', showindex=False))

conn.close()
