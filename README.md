CyberScan - Multi-Layer Vulnerability Scanner (Versi 1.0 PoC)

Repository ini berisi skrip Python 3 untuk CyberScan Pro, sebuah tool pemindaian kerentanan keamanan yang ringkas dan modular. Skrip ini berfungsi sebagai Proof-of-Concept (PoC) untuk mendemonstrasikan bagaimana berbagai teknik dapat digabungkan untuk melakukan pemindaian keamanan yang komprehensif.

Fitur Utama:

    🔍 Web Vulnerability Scan: Menggunakan pustaka requests untuk mengidentifikasi celah keamanan berbasis web seperti SQL Injection (SQLi) dan Cross-Site Scripting (XSS).

    💻 Server Scan: Mengintegrasikan python-nmap untuk melakukan pemindaian port dan deteksi versi layanan, membantu mengidentifikasi software server yang sudah usang atau rentan.

    💾 Database Vulnerability Scan: Mensimulasikan deteksi kerentanan database, menunjukkan cara kerja potensial untuk mengidentifikasi celah SQLi pada parameter URL.

    📄 Report Generation: Menghasilkan laporan konsol yang mudah dibaca, merangkum semua temuan kerentanan berdasarkan kategori.

Catatan: Tool ini adalah versi PoC dan tidak dimaksudkan untuk penggunaan dalam lingkungan produksi. Selalu pastikan Anda memiliki izin sebelum melakukan pemindaian pada sistem apa pun.

# Installasi 
git clone https://github.com/Mrx112/cyberscan.git
cd cyberscan
pip install -r requirements.txt

# Dependencies:

    Python 3.8+

    Nmap

    SQLMap (Opsional)

    Metasploit Framework (Opsional)

# Penggunaan
python cyberscan.py --target <URL/IP> --mode <web/server/db/all> --output <report.html>

# Example
1. Scan Website untuk SQLi & XSS:
python cyberscan.py --target https://example.com --mode web

2. Scan Server untuk Open Ports & Services:
python cyberscan.py --target 192.168.1.1 --mode server

3. Scan Database untuk SQL Injection:
python cyberscan.py --target https://example.com/login.php --mode db

4. Full Penetration Test:
python cyberscan.py --target https://example.com --mode all --output report.html

# Keamanan & Etika 
- Hanya gunakan di lingkungan yang diizinkan.
- Jangan gunakan untuk aktivitas ilegal.
- Simpan hasil scan secara aman.

# Peningkatan di Masa Depan
- Tambahan Brute Force Protection Checker
- Integrasi OWASP ZAP untuk scan otomatis
- Tambahkan Dashboard Grafana untuk visualisasi

⚠️ Gunakan dengan tanggung jawab! ⚠️
