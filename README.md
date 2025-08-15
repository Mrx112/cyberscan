CyberScan Pro - Multi-Layer Vulnerability Scanner (Versi 1.0 PoC)

Repository ini berisi skrip Python 3 untuk CyberScan Pro, sebuah tool pemindaian kerentanan keamanan yang ringkas dan modular. Skrip ini berfungsi sebagai Proof-of-Concept (PoC) untuk mendemonstrasikan bagaimana berbagai teknik dapat digabungkan untuk melakukan pemindaian keamanan yang komprehensif.

Fitur Utama:

    🔍 Web Vulnerability Scan: Menggunakan pustaka requests untuk mengidentifikasi celah keamanan berbasis web seperti SQL Injection (SQLi) dan Cross-Site Scripting (XSS).

    💻 Server Scan: Mengintegrasikan python-nmap untuk melakukan pemindaian port dan deteksi versi layanan, membantu mengidentifikasi software server yang sudah usang atau rentan.

    💾 Database Vulnerability Scan: Mensimulasikan deteksi kerentanan database, menunjukkan cara kerja potensial untuk mengidentifikasi celah SQLi pada parameter URL.

    📄 Report Generation: Menghasilkan laporan konsol yang mudah dibaca, merangkum semua temuan kerentanan berdasarkan kategori.

Catatan: Tool ini adalah versi PoC dan tidak dimaksudkan untuk penggunaan dalam lingkungan produksi. Selalu pastikan Anda memiliki izin sebelum melakukan pemindaian pada sistem apa pun.
