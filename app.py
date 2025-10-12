from flask import Flask, render_template, request, redirect, url_for, session, flash
import qrcode, io, base64, sqlite3, os
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import date, datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_change_this")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# NGROK URL'si
NGROK_URL = os.environ.get("NGROK_URL", "https://hammeringly-unenquired-coralee.ngrok-free.dev")
DB_PATH = "database/attendance.db"

# --- DB yardımcıları ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_number TEXT UNIQUE NOT NULL,
            name TEXT,
            password_hash TEXT NOT NULL
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            FOREIGN KEY(student_id) REFERENCES students(id)
        );
    """)
    conn.commit()
    conn.close()

def initialize_app():
    print("🔧 Veritabanı kontrol ediliyor / oluşturuluyor...")
    init_db()
    print("✅ Başlatma tamamlandı!")

# --- Decoratorlar ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated

def teacher_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'teacher' not in session:
            return redirect(url_for('teacher_login'))
        return f(*args, **kwargs)
    return decorated

# --- Yoklama ekleme ---
def add_attendance(student_id, student_name):
    conn = get_db()
    c = conn.cursor()
    today = date.today().isoformat()

    # Aynı gün iki kez yoklama alınmasın
    c.execute("SELECT COUNT(*) FROM attendance WHERE student_id = ? AND date(timestamp) = ?", (student_id, today))
    already = c.fetchone()[0]

    if already:
        conn.close()
        total = get_db().execute("SELECT COUNT(*) FROM attendance").fetchone()[0]
        socketio.emit("update_count", {"count": total})
        return total, False

    ip_address = request.remote_addr
    c.execute(
        "INSERT INTO attendance (student_id, student_name, ip_address) VALUES (?, ?, ?)",
        (student_id, student_name, ip_address)
    )
    conn.commit()
    total = c.execute("SELECT COUNT(*) FROM attendance").fetchone()[0]
    conn.close()
    socketio.emit("update_count", {"count": total})
    return total, True

# --- QR üret ---
def generate_qr(url):
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('utf-8')

# --- Ana Sayfa ---
@app.route('/')
def index():
    qr_base64 = generate_qr(f"{NGROK_URL}/attendance_form")
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM attendance").fetchone()[0]
    conn.close()
    return render_template("index.html", qr_code=qr_base64, count=count)

# --- Öğrenci Kayıt ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        student_number = request.form.get('student_number', '').strip()
        name = request.form.get('name', '').strip()
        password = request.form.get('password', '')

        if not student_number or not password:
            flash("Öğrenci numarası ve şifre gerekli.")
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password)
        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO students (student_number, name, password_hash) VALUES (?, ?, ?)",
                (student_number, name, password_hash),
            )
            conn.commit()
            conn.close()
            
            flash("Kayıt başarılı. Lütfen giriş yapın.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Bu öğrenci numarası zaten kayıtlı.")
            return redirect(url_for('register'))
    
    return render_template('register.html')

# --- Öğrenci Giriş ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    next_url = request.args.get('next') or url_for('attendance_form')
    if request.method == 'POST':
        student_number = request.form.get('student_number', '').strip()
        password = request.form.get('password', '')
        conn = get_db()
        row = conn.execute("SELECT * FROM students WHERE student_number = ?", (student_number,)).fetchone()
        conn.close()

        if row and check_password_hash(row['password_hash'], password):
            session['user_id'] = row['id']
            session['student_number'] = row['student_number']
            session['name'] = row['name']
            flash("Giriş başarılı.")
            return redirect(request.form.get('next') or url_for('attendance_form'))

        flash("Kullanıcı adı veya şifre hatalı.")
        return redirect(url_for('login', next=next_url))
    return render_template('login.html', next=next_url)

# --- Öğretmen Giriş ---
@app.route('/teacher_login', methods=['GET', 'POST'])
def teacher_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if username == "admin" and password == "123":
            session['teacher'] = True
            flash("Öğretmen girişi başarılı.")
            return redirect(url_for('dashboard'))
        else:
            flash("Kullanıcı adı veya şifre hatalı.")
            return redirect(url_for('teacher_login'))
    return render_template('teacher_login.html')

# --- Dashboard (öğretmen paneli) ---
@app.route('/dashboard')
@teacher_required
def dashboard():
    conn = get_db()
    rows = conn.execute("""
        SELECT a.id, a.student_name, s.student_number, a.timestamp, a.ip_address
        FROM attendance a
        LEFT JOIN students s ON a.student_id = s.id
        ORDER BY a.timestamp DESC
    """).fetchall()
    
    adjusted_rows = []
    for row in rows:
        utc_time = datetime.strptime(row['timestamp'], "%Y-%m-%d %H:%M:%S")
        local_time = utc_time + timedelta(hours=3)
        row_dict = dict(row)
        row_dict['timestamp'] = local_time.strftime("%Y-%m-%d %H:%M:%S")
        adjusted_rows.append(row_dict)

    total = len(adjusted_rows)
    conn.close()
    return render_template('dashboard.html', attendances=adjusted_rows, total=total)

# --- Kayıt Silme ---
@app.route('/delete_attendance/<int:id>', methods=['POST'])
@teacher_required
def delete_attendance(id):
    conn = get_db()
    conn.execute("DELETE FROM attendance WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Yoklama kaydı silindi.")
    return redirect(url_for('dashboard'))

# --- 👇 Kullanıcı Yönetimi (Liste / Ekle / Düzenle / Sil) ---
@app.route('/kullanicilar')
@teacher_required
def kullanicilar():
    conn = get_db()
    kullanicilar = conn.execute("SELECT * FROM students").fetchall()
    conn.close()
    return render_template('kullanicilar.html', kullanicilar=kullanicilar)

@app.route('/kullanici_yeni', methods=['GET', 'POST'])
@teacher_required
def kullanici_yeni():
    if request.method == 'POST':
        ad = request.form['ad']
        soyad = request.form['soyad']
        email = request.form['email']
        sifre = request.form['sifre']
        sifre_hash = generate_password_hash(sifre)
        conn = get_db()
        conn.execute("INSERT INTO students (name, student_number, password_hash) VALUES (?, ?, ?)", 
                     (f"{ad} {soyad}", email, sifre_hash))
        conn.commit()
        conn.close()
        flash("Yeni kullanıcı eklendi.")
        return redirect(url_for('kullanicilar'))
    return render_template('kullanicilar_form.html', kullanici=None)

@app.route('/kullanici_duzenle/<int:id>', methods=['GET', 'POST'])
@teacher_required
def kullanici_duzenle(id):
    conn = get_db()
    kullanici = conn.execute("SELECT * FROM students WHERE id = ?", (id,)).fetchone()
    if request.method == 'POST':
        ad = request.form['ad']
        soyad = request.form['soyad']
        email = request.form['email']
        sifre = request.form['sifre']

        if sifre.strip():
            sifre_hash = generate_password_hash(sifre)
            conn.execute("UPDATE students SET name=?, student_number=?, password_hash=? WHERE id=?", 
                         (f"{ad} {soyad}", email, sifre_hash, id))
        else:
            conn.execute("UPDATE students SET name=?, student_number=? WHERE id=?", 
                         (f"{ad} {soyad}", email, id))
        conn.commit()
        conn.close()
        flash("Kullanıcı bilgileri güncellendi.")
        return redirect(url_for('kullanicilar'))
    conn.close()
    return render_template('kullanicilar_form.html', kullanici=kullanici)

@app.route('/kullanici_sil/<int:id>', methods=['POST'])
@teacher_required
def kullanici_sil(id):
    conn = get_db()
    conn.execute("DELETE FROM students WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Kullanıcı silindi.")
    return redirect(url_for('kullanicilar'))

# --- Çıkış ---
@app.route('/logout')
def logout():
    session.clear()
    flash("Çıkış yapıldı.")
    return redirect(url_for('index'))

# --- Yoklama Formu ---
@app.route('/attendance_form')
@login_required
def attendance_form():
    student_id = session['user_id']
    name = session.get('name') or session.get('student_number')
    qr_link = f"{NGROK_URL}/scan_qr/{student_id}"
    qr_base64 = generate_qr(qr_link)
    return render_template('attendance_form.html', name=name, qr_code=qr_base64)

@app.route('/kullanicilar_sil_tumu', methods=['POST'])
@teacher_required
def kullanicilar_sil_tumu():
    conn = get_db()
    conn.execute("DELETE FROM students")
    # 🔽 AUTOINCREMENT sayacını da sıfırla
    conn.execute("DELETE FROM sqlite_sequence WHERE name='students'")
    conn.commit()
    conn.close()
    flash("Tüm kullanıcılar silindi ve ID sıfırlandı.")
    return redirect(url_for('kullanicilar'))



# --- QR Okuma ve Yoklama Alma ---
@app.route('/scan_qr/<int:student_id>')
def scan_qr(student_id):
    conn = get_db()
    row = conn.execute("SELECT name FROM students WHERE id = ?", (student_id,)).fetchone()
    conn.close()
    student_name = row['name'] if row else "Bilinmeyen Öğrenci"

    total, created = add_attendance(student_id, student_name)

    if created:
        message = f"✅ {student_name}, yoklamanız başarıyla alınmıştır."
        success = True
    else:
        message = f"⚠️ {student_name}, bugün zaten yoklama vermişsiniz."
        success = False

    return render_template('qr_success.html', message=message, success=success, name=student_name)

# --- Uygulama başlat ---
if __name__ == '__main__':
    initialize_app()
    print("🚀 Flask SocketIO sunucusu başlatılıyor...")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
