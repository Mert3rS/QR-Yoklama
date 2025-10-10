from flask import Flask, render_template_string
import qrcode
import io
import base64

app = Flask(__name__)

# Buraya ngrok tünel URL'sini yazacağız
# Örnek: https://1234abcd.ngrok.io
NGROK_URL = "https://hammeringly-unenquired-coralee.ngrok-free.dev"  # <-- ngrok çalıştırdıktan sonra buraya URL'i yapıştır

@app.route('/')
def index():
    # QR kod URL'si artık ngrok üzerinden
    data = f"{NGROK_URL}/attendance"
    img = qrcode.make(data)

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    html = f"""
    <h1>📋 Yoklama QR Kodu</h1>
    <img src="data:image/png;base64,{img_base64}" alt="QR Code">
    <p>Bu kodu öğrenciler telefondan okutacak.</p>
    """
    return render_template_string(html)

@app.route('/attendance')
def attendance():
    return "<h2>✅ Yoklamanız alındı!</h2>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
