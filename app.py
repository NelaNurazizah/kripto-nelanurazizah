"""
app.py
======
File utama Flask untuk Aplikasi Web Simulasi Kriptografi Klasik Edukatif.
Menangani routing, form processing, validasi input, integrasi crypto_logic,
dan manajemen riwayat berbasis session.

Struktur proyek yang diharapkan:
    .
    ├── app.py
    ├── crypto_logic.py
    └── templates/
        ├── base.html
        ├── caesar.html
        ├── vigenere.html
        ├── affine.html
        ├── hill.html
        └── playfair.html

Jalankan:
    pip install flask
    python app.py
"""

import os
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    session,
    redirect,
    url_for,
)

from crypto_logic import (
    caesar_cipher,
    vigenere_cipher,
    affine_cipher,
    hill_cipher,
    playfair_cipher,
)

# ──────────────────────────────────────────────────────────────────
#  INISIALISASI APLIKASI
# ──────────────────────────────────────────────────────────────────

app = Flask(__name__)

# Secret key untuk enkripsi data session (cookie).
# Di production, ganti dengan nilai acak yang kuat dan simpan di env variable.
# Contoh: os.environ.get('SECRET_KEY', os.urandom(32))
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "cipherlab-dev-key-2025-ganti-di-production!"
)

# Konfigurasi session
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Jumlah maksimal entri riwayat yang disimpan
MAX_HISTORY = 10


# ──────────────────────────────────────────────────────────────────
#  HELPER FUNCTIONS
# ──────────────────────────────────────────────────────────────────

def _save_to_history(algorithm: str, mode: str, input_text: str, result: str) -> None:
    """
    Menyimpan satu entri riwayat proses kriptografi ke dalam flask.session.

    Setiap entri berupa dict:
        {
            "algorithm" : str   — nama algoritma, misal "Caesar"
            "mode"      : str   — "encrypt" atau "decrypt"
            "input"     : str   — teks asli (dipotong jika > 60 karakter)
            "result"    : str   — hasil cipher (dipotong jika > 60 karakter)
            "timestamp" : str   — waktu proses, format "HH:MM:SS"
        }

    Riwayat disimpan sebagai list dengan urutan terbaru di indeks 0.
    Hanya MAX_HISTORY (10) entri terbaru yang dipertahankan.
    """
    # Inisialisasi list jika belum ada
    if "history" not in session:
        session["history"] = []

    # Ambil salinan agar Flask mendeteksi perubahan pada session
    history: list[dict] = list(session["history"])

    # Buat entri baru
    entry = {
        "algorithm": algorithm,
        "mode"     : mode,
        "input"    : input_text[:60] + ("…" if len(input_text) > 60 else ""),
        "result"   : result[:60]     + ("…" if len(result)     > 60 else ""),
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }

    # Sisipkan di awal (terbaru di atas) dan potong jika melebihi batas
    history.insert(0, entry)
    session["history"] = history[:MAX_HISTORY]

    # Tandai session sebagai modified agar Flask menyimpannya
    session.modified = True


def _get_history() -> list[dict]:
    """Kembalikan daftar riwayat dari session (list kosong jika belum ada)."""
    return session.get("history", [])


def _base_context(**kwargs) -> dict:
    """
    Buat konteks dasar yang selalu dikirim ke setiap render_template.
    Menggabungkan riwayat session dengan data tambahan dari pemanggil.

    Contoh penggunaan:
        return render_template('caesar.html',
                               **_base_context(result=result, steps=steps))
    """
    return {"history": _get_history(), **kwargs}


def _extract_crypto_result(data: dict) -> tuple[str | None, list, str | None]:
    """
    Ekstrak result, steps, dan error dari dictionary yang dikembalikan
    oleh fungsi-fungsi di crypto_logic.py.

    Sebuah fungsi dianggap mengembalikan error jika result-nya adalah
    string kosong ('') — dalam hal itu, baris pertama steps dijadikan
    pesan error dan steps dikosongkan.

    Return:
        (result, steps, error)
    """
    result: str  = data.get("result", "")
    steps:  list = data.get("steps",  [])

    if result == "":
        # Gabungkan semua step awal sebagai pesan error
        error_msg = " | ".join(str(s) for s in steps[:3] if isinstance(s, str))
        return None, [], error_msg or "Terjadi kesalahan saat memproses cipher."

    return result, steps, None


# ──────────────────────────────────────────────────────────────────
#  ROUTE: INDEX (Landing Page)
# ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """
    Halaman utama: redirect ke Caesar sebagai halaman default,
    atau bisa diubah menjadi halaman landing tersendiri.
    """
    return redirect(url_for("caesar"))


# ──────────────────────────────────────────────────────────────────
#  ROUTE: CAESAR CIPHER  —  /caesar
# ──────────────────────────────────────────────────────────────────

@app.route("/caesar", methods=["GET", "POST"])
def caesar():
    """
    Caesar Cipher: geser setiap huruf sebanyak `shift` posisi.

    Form fields:
        text  (str)  — teks input
        shift (int)  — nilai pergeseran, 1–25
        mode  (str)  — 'encrypt' atau 'decrypt'
    """
    result, steps, error = None, [], None

    if request.method == "POST":
        text  = request.form.get("text",  "").strip()
        mode  = request.form.get("mode",  "encrypt").strip()
        shift_raw = request.form.get("shift", "")

        # ── Validasi & Type Casting ────────────────────────────
        if not text:
            error = "Teks input tidak boleh kosong."

        else:
            try:
                shift = int(shift_raw)
                if not (1 <= shift <= 25):
                    raise ValueError("Shift di luar rentang.")
            except (ValueError, TypeError):
                error = (
                    f"Nilai shift '{shift_raw}' tidak valid. "
                    "Masukkan bilangan bulat antara 1 dan 25."
                )
                shift = None

            if mode not in ("encrypt", "decrypt"):
                error = "Mode harus 'encrypt' atau 'decrypt'."

            # ── Eksekusi Algoritma ─────────────────────────────
            if error is None and shift is not None:
                try:
                    data = caesar_cipher(text, shift, mode)
                    result, steps, error = _extract_crypto_result(data)

                    if result is not None:
                        _save_to_history("Caesar", mode, text, result)

                except Exception as exc:
                    error = f"Kesalahan tidak terduga: {exc}"

    return render_template(
        "caesar.html",
        **_base_context(result=result, steps=steps, error=error),
    )


# ──────────────────────────────────────────────────────────────────
#  ROUTE: VIGENÈRE CIPHER  —  /vigenere
# ──────────────────────────────────────────────────────────────────

@app.route("/vigenere", methods=["GET", "POST"])
def vigenere():
    """
    Vigenère Cipher: substitusi polialfabetik berbasis kata kunci string.

    Form fields:
        text (str) — teks input
        key  (str) — kata kunci (hanya huruf yang digunakan)
        mode (str) — 'encrypt' atau 'decrypt'
    """
    result, steps, error = None, [], None

    if request.method == "POST":
        text = request.form.get("text", "").strip()
        key  = request.form.get("key",  "").strip()
        mode = request.form.get("mode", "encrypt").strip()

        # ── Validasi ───────────────────────────────────────────
        if not text:
            error = "Teks input tidak boleh kosong."
        elif not key:
            error = "Kunci (key) tidak boleh kosong."
        elif not any(ch.isalpha() for ch in key):
            error = "Kunci harus mengandung minimal satu huruf."
        elif mode not in ("encrypt", "decrypt"):
            error = "Mode harus 'encrypt' atau 'decrypt'."

        # ── Eksekusi Algoritma ─────────────────────────────────
        if error is None:
            try:
                data = vigenere_cipher(text, key, mode)
                result, steps, error = _extract_crypto_result(data)

                if result is not None:
                    _save_to_history("Vigenère", mode, text, result)

            except Exception as exc:
                error = f"Kesalahan tidak terduga: {exc}"

    return render_template(
        "vigenere.html",
        **_base_context(result=result, steps=steps, error=error),
    )


# ──────────────────────────────────────────────────────────────────
#  ROUTE: AFFINE CIPHER  —  /affine
# ──────────────────────────────────────────────────────────────────

@app.route("/affine", methods=["GET", "POST"])
def affine():
    """
    Affine Cipher: C = (a·P + b) mod 26.

    Form fields:
        text (str) — teks input
        a    (int) — koefisien pengali, harus koprima dengan 26
        b    (int) — konstanta geser, 0–25
        mode (str) — 'encrypt' atau 'decrypt'

    Nilai 'a' yang valid: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
    (semua bilangan yang koprima dengan 26).
    """
    result, steps, error = None, [], None

    # Sediakan daftar nilai 'a' yang valid untuk ditampilkan di template
    from math import gcd as _gcd
    valid_a_values = [v for v in range(1, 26) if _gcd(v, 26) == 1]

    if request.method == "POST":
        text  = request.form.get("text", "").strip()
        mode  = request.form.get("mode", "encrypt").strip()
        a_raw = request.form.get("a", "")
        b_raw = request.form.get("b", "")

        # ── Validasi & Type Casting ────────────────────────────
        validation_ok = True

        if not text:
            error = "Teks input tidak boleh kosong."
            validation_ok = False

        if validation_ok:
            try:
                a = int(a_raw)
            except (ValueError, TypeError):
                error = f"Nilai 'a' ({a_raw!r}) harus berupa bilangan bulat."
                validation_ok = False

        if validation_ok:
            try:
                b = int(b_raw)
                if not (0 <= b <= 25):
                    raise ValueError("b harus antara 0 dan 25.")
            except (ValueError, TypeError):
                error = (
                    f"Nilai 'b' ({b_raw!r}) tidak valid. "
                    "Masukkan bilangan bulat antara 0 dan 25."
                )
                validation_ok = False

        if validation_ok and mode not in ("encrypt", "decrypt"):
            error = "Mode harus 'encrypt' atau 'decrypt'."
            validation_ok = False

        # ── Eksekusi Algoritma ─────────────────────────────────
        if validation_ok:
            try:
                data = affine_cipher(text, a, b, mode)
                result, steps, error = _extract_crypto_result(data)

                if result is not None:
                    _save_to_history(
                        "Affine", mode, text, result
                    )

            except Exception as exc:
                error = f"Kesalahan tidak terduga: {exc}"

    return render_template(
        "affine.html",
        **_base_context(
            result=result,
            steps=steps,
            error=error,
            valid_a_values=valid_a_values,
        ),
    )


# ──────────────────────────────────────────────────────────────────
#  ROUTE: HILL CIPHER  —  /hill
# ──────────────────────────────────────────────────────────────────

@app.route("/hill", methods=["GET", "POST"])
def hill():
    """
    Hill Cipher: enkripsi blok berbasis perkalian matriks mod 26.
    Mendukung matriks kunci 2×2 dan 3×3.

    Form fields:
        text        (str)    — teks input
        mode        (str)    — 'encrypt' atau 'decrypt'
        dimension   (int)    — 2 atau 3 (ukuran matriks)
        m{r}{c}     (int)    — elemen matriks baris r, kolom c
                               misal: m00, m01, m10, m11  (untuk 2×2)
                                      m00 … m22            (untuk 3×3)
    """
    result, steps, error = None, [], None
    dimension = 2       # default; diperbarui dari form jika POST

    if request.method == "POST":
        text      = request.form.get("text",      "").strip()
        mode      = request.form.get("mode",      "encrypt").strip()
        dim_raw   = request.form.get("dimension", "2")

        # ── Validasi dimensi ───────────────────────────────────
        try:
            dimension = int(dim_raw)
            if dimension not in (2, 3):
                raise ValueError("Dimensi harus 2 atau 3.")
        except (ValueError, TypeError):
            error = (
                f"Dimensi matriks '{dim_raw}' tidak valid. "
                "Pilih 2 (untuk 2×2) atau 3 (untuk 3×3)."
            )
            dimension = 2

        # ── Validasi teks ──────────────────────────────────────
        if error is None and not text:
            error = "Teks input tidak boleh kosong."

        if error is None and mode not in ("encrypt", "decrypt"):
            error = "Mode harus 'encrypt' atau 'decrypt'."

        # ── Parsing matriks dari form ──────────────────────────
        matrix = []
        if error is None:
            try:
                for r in range(dimension):
                    row = []
                    for c in range(dimension):
                        field_name = f"m{r}{c}"
                        raw_val    = request.form.get(field_name, "")
                        if raw_val.strip() == "":
                            raise ValueError(
                                f"Elemen matriks [{r}][{c}] kosong."
                            )
                        row.append(int(raw_val))
                    matrix.append(row)

            except ValueError as ve:
                error = (
                    f"Input matriks tidak valid: {ve} "
                    "Pastikan semua sel terisi bilangan bulat."
                )

        # ── Eksekusi Algoritma ─────────────────────────────────
        if error is None:
            try:
                data = hill_cipher(text, matrix, mode)
                result, steps, error = _extract_crypto_result(data)

                if result is not None:
                    mat_str = str(matrix)       # ringkasan matriks untuk history
                    _save_to_history(
                        f"Hill {dimension}×{dimension}",
                        mode,
                        text,
                        result,
                    )

            except Exception as exc:
                error = f"Kesalahan tidak terduga: {exc}"

    return render_template(
        "hill.html",
        **_base_context(
            result=result,
            steps=steps,
            error=error,
            dimension=dimension,
        ),
    )


# ──────────────────────────────────────────────────────────────────
#  ROUTE: PLAYFAIR CIPHER  —  /playfair
# ──────────────────────────────────────────────────────────────────

@app.route("/playfair", methods=["GET", "POST"])
def playfair():
    """
    Playfair Cipher: enkripsi digraf dengan matriks 5×5.
    I dan J dianggap karakter yang sama.

    Form fields:
        text (str) — teks input (hanya huruf yang diproses)
        key  (str) — kata kunci untuk membangun matriks 5×5
        mode (str) — 'encrypt' atau 'decrypt'
    """
    result, steps, error = None, [], None

    if request.method == "POST":
        text = request.form.get("text", "").strip()
        key  = request.form.get("key",  "").strip()
        mode = request.form.get("mode", "encrypt").strip()

        # ── Validasi ───────────────────────────────────────────
        if not text:
            error = "Teks input tidak boleh kosong."
        elif not any(ch.isalpha() for ch in text):
            error = "Teks input harus mengandung minimal satu huruf."
        elif not key:
            error = "Kunci tidak boleh kosong."
        elif not any(ch.isalpha() for ch in key):
            error = "Kunci harus mengandung minimal satu huruf."
        elif mode not in ("encrypt", "decrypt"):
            error = "Mode harus 'encrypt' atau 'decrypt'."

        # ── Eksekusi Algoritma ─────────────────────────────────
        if error is None:
            try:
                data = playfair_cipher(text, key, mode)
                result, steps, error = _extract_crypto_result(data)

                if result is not None:
                    _save_to_history("Playfair", mode, text, result)

            except Exception as exc:
                error = f"Kesalahan tidak terduga: {exc}"

    return render_template(
        "playfair.html",
        **_base_context(result=result, steps=steps, error=error),
    )


# ──────────────────────────────────────────────────────────────────
#  ROUTE: HAPUS RIWAYAT  —  /history/clear
# ──────────────────────────────────────────────────────────────────

@app.route("/history/clear", methods=["POST"])
def clear_history():
    """
    Hapus semua riwayat dari session, lalu redirect ke halaman sebelumnya
    (atau ke /caesar jika referer tidak tersedia).

    Dipanggil oleh tombol "Hapus Riwayat" di navbar atau sidebar.
    Menggunakan POST (bukan GET) untuk menghindari penghapusan tidak sengaja
    saat browser melakukan prefetch link.
    """
    session.pop("history", None)
    session.modified = True

    # Kembalikan user ke halaman yang sama
    referrer = request.referrer
    if referrer:
        return redirect(referrer)
    return redirect(url_for("caesar"))


# ──────────────────────────────────────────────────────────────────
#  ERROR HANDLERS
# ──────────────────────────────────────────────────────────────────

@app.errorhandler(404)
def page_not_found(e):
    """Redirect halaman 404 ke halaman utama."""
    return redirect(url_for("caesar"))


@app.errorhandler(500)
def internal_error(e):
    """
    Tangani error server; reset session jika terjadi masalah session-related.
    """
    session.clear()
    return redirect(url_for("caesar"))


# ──────────────────────────────────────────────────────────────────
#  CONTEXT PROCESSOR — Tersedia di semua template secara otomatis
# ──────────────────────────────────────────────────────────────────

@app.context_processor
def inject_globals():
    """
    Menginject variabel global ke semua template Jinja2 tanpa perlu
    mengirimnya secara eksplisit di setiap render_template().

    Tersedia di template sebagai:
        {{ history }}       — daftar riwayat (identik dengan yang dikirim
                              via _base_context, disediakan sebagai fallback)
        {{ algo_list }}     — metadata untuk membangun navigasi dinamis
        {{ current_year }}  — tahun berjalan untuk footer copyright
    """
    algo_list = [
        {
            "id"         : "caesar",
            "name"       : "Caesar",
            "number"     : "01",
            "description": "Geser huruf sebanyak n posisi",
            "icon"       : "bi-shuffle",
        },
        {
            "id"         : "vigenere",
            "name"       : "Vigenère",
            "number"     : "02",
            "description": "Substitusi polialfabetik",
            "icon"       : "bi-key",
        },
        {
            "id"         : "affine",
            "name"       : "Affine",
            "number"     : "03",
            "description": "Enkripsi linear C=(aP+b) mod 26",
            "icon"       : "bi-calculator",
        },
        {
            "id"         : "hill",
            "name"       : "Hill",
            "number"     : "04",
            "description": "Enkripsi berbasis perkalian matriks",
            "icon"       : "bi-grid-3x3-gap-fill",
        },
        {
            "id"         : "playfair",
            "name"       : "Playfair",
            "number"     : "05",
            "description": "Enkripsi digraf matriks 5×5",
            "icon"       : "bi-table",
        },
    ]

    return {
        "history"     : _get_history(),
        "algo_list"   : algo_list,
        "current_year": datetime.now().year,
    }


# ──────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # debug=True hanya untuk development.
    # Di production, gunakan Gunicorn: gunicorn -w 4 app:app
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "1") == "1",
    )