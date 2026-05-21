# 🔐 CipherLab

**Simulasi Kriptografi Klasik Edukatif**

CipherLab adalah aplikasi web interaktif yang dikembangkan untuk memfasilitasi pembelajaran dan pengujian algoritma kriptografi klasik. Aplikasi ini tidak hanya menghasilkan *output* teks terenkripsi atau terdekripsi, tetapi juga menampilkan **langkah-langkah perhitungan matematis secara detail**, menjadikannya alat yang sangat cocok untuk keperluan edukasi.

---

## ✨ Fitur Utama

* **5 Algoritma Kriptografi Klasik**:
    * **Caesar Cipher**: Substitusi pergeseran karakter sederhana.
    * **Vigenère Cipher**: Substitusi polialfabetik dengan kata kunci.
    * **Affine Cipher**: Substitusi linier menggunakan fungsi matematika (ax + b) mod 26.
    * **Hill Cipher**: Substitusi blok berbasis aljabar linear dan perkalian matriks (mendukung matrik 2x2 dan 3x3).
    * **Playfair Cipher**: Enkripsi digraf (pasangan huruf) menggunakan matriks kunci 5x5.
* **Rincian Langkah Edukatif (Step-by-Step)**: Visualisasi proses dari *plaintext* ke *ciphertext* (dan sebaliknya) secara interaktif dengan animasi *dropdown* berurutan yang mulus.
* **Antarmuka Modern & Responsif**: Desain *clean*, profesional, dan responsif untuk layar *mobile* maupun *desktop*, lengkap dengan fitur **Dark Mode / Light Mode**.
* **Riwayat Operasi (History)**: Panel interaktif untuk melihat dan menghapus riwayat operasi enkripsi dan dekripsi yang telah dilakukan selama sesi aktif.

---

## 🛠️ Teknologi yang Digunakan

* **Backend**: Python, Flask
* **Frontend**: HTML5, CSS3 (Custom Properties & Animations), Vanilla JavaScript
* **Templating**: Jinja2
* **UI Framework**: Bootstrap 5, Bootstrap Icons
* **Tipografi**: Syne (Display), Outfit (Body), JetBrains Mono (Code/Math) via Google Fonts

---

## 🚀 Panduan Instalasi dan Penggunaan

Pastikan Anda telah menginstal **Python 3.8+** di komputer Anda.

1.  **Clone Repository** (atau unduh *source code* zip):
    ```bash
    git clone [https://github.com/NelaNurazizah/kripto-nelanurazizah.git](https://github.com/NelaNurazizah/kripto-nelanurazizah.git)
    cd kripto-nelanurazizah
    ```

2.  **Buat Virtual Environment (Sangat disarankan)**:
    ```bash
    python -m venv venv
    
    # Aktivasi di Windows:
    venv\Scripts\activate
    
    # Aktivasi di Mac/Linux:
    source venv/bin/activate
    ```

3.  **Instal Dependensi**:
    Cukup instal Flask melalui pip:
    ```bash
    pip install Flask
    ```

4.  **Jalankan Aplikasi**:
    ```bash
    python app.py
    ```

5.  **Akses di Browser**:
    Buka browser web Anda dan kunjungi server lokal di:
    `http://127.0.0.1:5000/`

---

## 📁 Struktur Direktori

```text
CipherLab/
│
├── app.py                  # Entry point aplikasi Flask & routing
├── crypto_logic.py         # File berisi fungsi matematis algoritma kriptografi
├── static/
│   └── css/
│       └── style.css       # Custom stylesheet & animasi global
└── templates/
    ├── base.html           # Layout utama (Navbar, Footer, Modal, JS)
    ├── caesar.html         # Tampilan antarmuka Caesar Cipher
    ├── vigenere.html       # Tampilan antarmuka Vigenère Cipher
    ├── affine.html         # Tampilan antarmuka Affine Cipher
    ├── hill.html           # Tampilan antarmuka Hill Cipher
    └── playfair.html       # Tampilan antarmuka Playfair Cipher

👤 Pengembang
Dikembangkan oleh Nela Nurazizah.
Proyek ini dibangun sebagai bentuk implementasi dan visualisasi interaktif dari algoritma keamanan data dan kriptografi.