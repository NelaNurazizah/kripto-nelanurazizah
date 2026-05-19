"""
crypto_logic.py
===============
Modul logika algoritma kriptografi klasik untuk Aplikasi Web Simulasi Kriptografi Edukatif.

Setiap fungsi mengembalikan dict dengan format:
{
    "result": str,          -> hasil enkripsi/dekripsi
    "steps": list           -> daftar langkah edukatif;
                               elemen bisa berupa str ATAU list-of-lists (matriks)
                               agar Jinja2 bisa merender <table> secara kondisional.
}

Kompatibel: Python 3.8+
"""

from math import gcd

# ============================================================
#  UTILITAS INTERNAL
# ============================================================

def _mod_inverse(a: int, m: int) -> int | None:
    """Hitung invers modular a^-1 mod m menggunakan Extended Euclidean.
    Mengembalikan None jika invers tidak ada."""
    if gcd(a, m) != 1:
        return None
    # pow(a, -1, m) tersedia sejak Python 3.8
    return pow(a, -1, m)


def _matrix_det_mod26(mat: list[list[int]], n: int) -> int:
    """Hitung determinan matriks n×n lalu mod 26 (rekursif, cofactor expansion)."""
    if n == 1:
        return mat[0][0] % 26
    if n == 2:
        return (mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0]) % 26

    det = 0
    for col in range(n):
        sub = [[mat[r][c] for c in range(n) if c != col]
               for r in range(1, n)]
        cofactor = ((-1) ** col) * _matrix_det_mod26(sub, n - 1)
        det = (det + mat[0][col] * cofactor) % 26
    return det % 26


def _matrix_cofactor(mat: list[list[int]], row: int, col: int, n: int) -> int:
    """Hitung kofaktor elemen (row, col) dari matriks n×n."""
    sub = [[mat[r][c] for c in range(n) if c != col]
           for r in range(n) if r != row]
    sign = (-1) ** (row + col)
    return sign * _matrix_det_mod26(sub, n - 1)


def _matrix_inverse_mod26(mat: list[list[int]]) -> list[list[int]] | None:
    """
    Hitung invers matriks n×n (n=2 atau 3) modulo 26.
    Mengembalikan None jika tidak invertible.
    """
    n = len(mat)
    det = _matrix_det_mod26(mat, n) % 26
    det_inv = _mod_inverse(det, 26)
    if det_inv is None:
        return None

    # Matriks adjugat (transpose kofaktor)
    adj = [[0] * n for _ in range(n)]
    for r in range(n):
        for c in range(n):
            adj[c][r] = _matrix_cofactor(mat, r, c, n) % 26  # transpose

    # Invers = det_inv * adjugat (mod 26)
    inv = [[(det_inv * adj[r][c]) % 26 for c in range(n)]
           for r in range(n)]
    return inv


def _matrix_multiply_mod26(mat: list[list[int]],
                            vec: list[int], n: int) -> list[int]:
    """Kalikan matriks n×n dengan vektor kolom n×1, hasilnya mod 26."""
    return [sum(mat[r][c] * vec[c] for c in range(n)) % 26
            for r in range(n)]


def _matrix_to_display(mat: list[list[int]]) -> list[list[str]]:
    """Konversi matriks int ke string agar lebih rapi di tabel Jinja2."""
    return [[str(v) for v in row] for row in mat]


# ============================================================
#  1. CAESAR CIPHER
# ============================================================

def caesar_cipher(text: str, shift: int, mode: str) -> dict:
    """
    Caesar Cipher — substitusi monoalfabetik dengan pergeseran tetap.

    Parameter:
        text  : teks input (mendukung huruf besar/kecil, spasi, tanda baca)
        shift : bilangan bulat 1–25
        mode  : 'encrypt' atau 'decrypt'

    Return:
        dict {"result": str, "steps": list}
    """
    shift = int(shift)
    if not (1 <= shift <= 25):
        return {
            "result": "",
            "steps": [f"ERROR: Shift harus antara 1 dan 25, "
                      f"tetapi diterima shift = {shift}."]
        }

    effective_shift = shift if mode == "encrypt" else -shift
    mode_label = "Enkripsi" if mode == "encrypt" else "Dekripsi"

    steps = [
        f"── Mode         : {mode_label}",
        f"── Teks Input   : '{text}'",
        f"── Shift        : {shift}",
        (f"── Rumus Enkripsi: C = (P + {shift}) mod 26  "
         f"[huruf besar: basis=65, huruf kecil: basis=97]")
        if mode == "encrypt"
        else
        (f"── Rumus Dekripsi: P = (C − {shift}) mod 26"),
        "── Proses per karakter:",
    ]

    result_chars = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            p = ord(ch) - base
            c = (p + effective_shift) % 26
            new_ch = chr(c + base)
            arrow = "→"
            steps.append(
                f"     '{ch}' (P={p:>2})  {arrow}  "
                f"({p} {'+' if effective_shift >= 0 else '−'} "
                f"{abs(effective_shift)}) mod 26 = {c}  {arrow}  '{new_ch}'"
            )
            result_chars.append(new_ch)
        else:
            steps.append(f"     '{ch}'  →  '{ch}'  (bukan huruf, dibiarkan utuh)")
            result_chars.append(ch)

    result = "".join(result_chars)
    steps.append(f"── Hasil Akhir  : '{result}'")
    return {"result": result, "steps": steps}


# ============================================================
#  2. VIGENÈRE CIPHER
# ============================================================

def vigenere_cipher(text: str, key: str, mode: str) -> dict:
    """
    Vigenère Cipher — substitusi polialfabetik berbasis kata kunci.

    Parameter:
        text : teks input
        key  : kata kunci (string, hanya huruf)
        mode : 'encrypt' atau 'decrypt'

    Return:
        dict {"result": str, "steps": list}
    """
    key_clean = "".join(ch.upper() for ch in key if ch.isalpha())
    if not key_clean:
        return {
            "result": "",
            "steps": ["ERROR: Kunci tidak boleh kosong dan harus mengandung huruf."]
        }

    mode_label = "Enkripsi" if mode == "encrypt" else "Dekripsi"

    steps = [
        f"── Mode         : {mode_label}",
        f"── Teks Input   : '{text}'",
        f"── Kunci (asli) : '{key}'",
        f"── Kunci (bersih, uppercase): '{key_clean}'",
        (f"── Rumus Enkripsi: C = (P + K) mod 26")
        if mode == "encrypt"
        else
        (f"── Rumus Dekripsi: P = (C − K) mod 26"),
        "── Kunci diperpanjang secara siklis sesuai panjang teks berupa huruf.",
        "── Proses per karakter:",
    ]

    result_chars = []
    key_idx = 0

    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            p = ord(ch) - base
            k_char = key_clean[key_idx % len(key_clean)]
            k = ord(k_char) - ord('A')
            key_idx += 1

            if mode == "encrypt":
                c = (p + k) % 26
                op_str = f"({p} + {k})"
            else:
                c = (p - k) % 26
                op_str = f"({p} − {k})"

            new_ch = chr(c + base)
            steps.append(
                f"     '{ch}' (P={p:>2}) + kunci '{k_char}' (K={k:>2})  →  "
                f"{op_str} mod 26 = {c}  →  '{new_ch}'"
            )
            result_chars.append(new_ch)
        else:
            steps.append(f"     '{ch}'  →  '{ch}'  (bukan huruf, dibiarkan utuh)")
            result_chars.append(ch)

    result = "".join(result_chars)
    steps.append(f"── Hasil Akhir  : '{result}'")
    return {"result": result, "steps": steps}


# ============================================================
#  3. AFFINE CIPHER
# ============================================================

def affine_cipher(text: str, a: int, b: int, mode: str) -> dict:
    """
    Affine Cipher — enkripsi linear C = (a·P + b) mod 26.

    Parameter:
        text : teks input
        a    : koefisien pengali (harus koprima dengan 26)
               Nilai valid: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
        b    : konstanta geser (0–25)
        mode : 'encrypt' atau 'decrypt'

    Return:
        dict {"result": str, "steps": list}
    """
    a, b = int(a), int(b)
    mode_label = "Enkripsi" if mode == "encrypt" else "Dekripsi"

    # Validasi a
    g = gcd(a, 26)
    if g != 1:
        valid_a = [v for v in range(1, 26) if gcd(v, 26) == 1]
        return {
            "result": "",
            "steps": [
                f"ERROR: Nilai a = {a} TIDAK koprima dengan 26 "
                f"(gcd({a}, 26) = {g} ≠ 1).",
                f"Nilai 'a' yang valid: {valid_a}",
            ]
        }

    a_inv = _mod_inverse(a, 26)  # dijamin ada karena gcd(a,26)=1

    steps = [
        f"── Mode         : {mode_label}",
        f"── Teks Input   : '{text}'",
        f"── Parameter    : a = {a}, b = {b}",
        f"── Validasi     : gcd({a}, 26) = {gcd(a, 26)} ✓ (koprima)",
    ]

    if mode == "encrypt":
        steps.append(f"── Rumus Enkripsi: C = ({a}·P + {b}) mod 26")
    else:
        steps.append(f"── Invers modular: {a}⁻¹ mod 26 = {a_inv}  "
                     f"(karena {a} × {a_inv} mod 26 = {(a * a_inv) % 26})")
        steps.append(f"── Rumus Dekripsi: P = {a_inv}·(C − {b}) mod 26")

    steps.append("── Proses per karakter:")

    result_chars = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            p = ord(ch) - base

            if mode == "encrypt":
                c = (a * p + b) % 26
                expr = f"({a}×{p} + {b}) mod 26 = {a*p+b} mod 26 = {c}"
            else:
                c = (a_inv * (p - b)) % 26
                expr = f"{a_inv}×({p} − {b}) mod 26 = {a_inv*(p-b)} mod 26 = {c}"

            new_ch = chr(c + base)
            steps.append(f"     '{ch}' (P={p:>2})  →  {expr}  →  '{new_ch}'")
            result_chars.append(new_ch)
        else:
            steps.append(f"     '{ch}'  →  '{ch}'  (bukan huruf, dibiarkan utuh)")
            result_chars.append(ch)

    result = "".join(result_chars)
    steps.append(f"── Hasil Akhir  : '{result}'")
    return {"result": result, "steps": steps}


# ============================================================
#  4. HILL CIPHER
# ============================================================

def hill_cipher(text: str, matrix: list[list[int]], mode: str) -> dict:
    """
    Hill Cipher — enkripsi matriks blok mod 26.

    Parameter:
        text   : teks input (huruf saja yang diproses, non-huruf dikembalikan ke posisi)
        matrix : matriks kunci 2×2 atau 3×3 (list of lists berisi int)
        mode   : 'encrypt' atau 'decrypt'

    Return:
        dict {"result": str, "steps": list}
        Elemen steps bertipe list-of-lists (matriks) akan dirender sebagai <table>
        oleh Jinja2; elemen bertipe str dirender sebagai <p>/<li>.
    """
    n = len(matrix)
    if n not in (2, 3):
        return {
            "result": "",
            "steps": ["ERROR: Matriks harus berukuran 2×2 atau 3×3."]
        }
    if any(len(row) != n for row in matrix):
        return {
            "result": "",
            "steps": [f"ERROR: Matriks tidak berbentuk bujur sangkar {n}×{n}."]
        }

    mode_label = "Enkripsi" if mode == "encrypt" else "Dekripsi"
    det_val = _matrix_det_mod26(matrix, n)

    steps = [
        f"── Mode          : {mode_label}",
        f"── Teks Input    : '{text}'",
        f"── Ukuran Matriks: {n}×{n}",
        f"── Matriks Kunci (K):",
        _matrix_to_display(matrix),   # <-- list-of-lists → Jinja2 <table>
        f"── det(K) mod 26 = {det_val}",
    ]

    # Tentukan matriks kerja
    if mode == "decrypt":
        inv = _matrix_inverse_mod26(matrix)
        if inv is None:
            return {
                "result": "",
                "steps": steps + [
                    f"ERROR: Matriks tidak dapat diinversi mod 26. "
                    f"det(K) mod 26 = {det_val} tidak koprima dengan 26. "
                    f"Pilih matriks kunci lain."
                ]
            }
        working_matrix = inv
        g_det = gcd(det_val, 26)
        det_inv_val = _mod_inverse(det_val, 26)
        steps += [
            f"── gcd({det_val}, 26) = {g_det} ✓ (invertible)",
            f"── det⁻¹ mod 26 = {det_inv_val}",
            f"── Matriks Kunci Invers (K⁻¹) untuk Dekripsi:",
            _matrix_to_display(inv),   # <-- list-of-lists → Jinja2 <table>
        ]
    else:
        working_matrix = matrix
        g_det = gcd(det_val, 26)
        steps.append(f"── gcd({det_val}, 26) = {g_det} "
                     f"{'✓ (invertible — dekripsi dimungkinkan)' if g_det == 1 else '⚠ (tidak invertible, dekripsi tidak bisa dilakukan dengan kunci ini)'}")

    # Pisahkan huruf dari non-huruf, catat posisi non-huruf
    non_alpha = [(i, ch) for i, ch in enumerate(text) if not ch.isalpha()]
    letters   = [ch for ch in text if ch.isalpha()]

    # Padding dengan 'X' jika belum kelipatan n
    padded_letters = letters[:]
    padding_count = 0
    while len(padded_letters) % n != 0:
        padded_letters.append('X')
        padding_count += 1

    steps.append(f"── Huruf yang diproses    : '{''.join(letters)}'")
    if padding_count:
        steps.append(f"── Padding 'X' ditambahkan: {padding_count} karakter "
                     f"(total blok: {''.join(padded_letters)})")
    steps.append(f"── Jumlah Blok           : {len(padded_letters) // n} blok ({n} karakter/blok)")
    steps.append(f"── Rumus: vektor_hasil = K {'(K⁻¹)' if mode == 'decrypt' else ''} × vektor_blok  (mod 26)")
    steps.append("── Proses per blok:")

    result_letters = []
    for blk_idx in range(0, len(padded_letters), n):
        block = padded_letters[blk_idx: blk_idx + n]
        vec   = [ord(ch.upper()) - ord('A') for ch in block]

        res_vec  = _matrix_multiply_mod26(working_matrix, vec, n)
        res_block = [chr(v + ord('A')) for v in res_vec]

        steps.append(
            f"     Blok {blk_idx // n + 1}: "
            f"[{''.join(block)}] = {vec}  ×  matriks  →  {res_vec}  →  "
            f"[{''.join(res_block)}]"
        )
        result_letters.extend(res_block)

    # Kembalikan non-huruf ke posisi semula
    result_iter = iter(result_letters)
    final_chars = []
    for ch in text:
        if ch.isalpha():
            final_chars.append(next(result_iter, 'X'))
        else:
            final_chars.append(ch)
    # Sisa dari padding (kalau ada) ditambahkan di akhir
    for extra in result_iter:
        final_chars.append(extra)

    result = "".join(final_chars)
    steps.append(f"── Hasil Akhir  : '{result}'")
    return {"result": result, "steps": steps}


# ============================================================
#  5. PLAYFAIR CIPHER
# ============================================================

def playfair_cipher(text: str, key: str, mode: str) -> dict:
    """
    Playfair Cipher — enkripsi digraf dengan matriks 5×5 (I dan J digabung).

    Parameter:
        text : teks input (hanya huruf yang diproses)
        key  : kata kunci string (huruf)
        mode : 'encrypt' atau 'decrypt'

    Return:
        dict {"result": str, "steps": list}
        Matriks 5×5 dikembalikan sebagai list-of-lists di dalam steps.

    Aturan:
        • I dan J dianggap sama (J diganti I).
        • Digraf dengan huruf kembar: sisipkan 'X' di antara keduanya.
        • Huruf ganjil: tambahkan 'X' di akhir.
        • Enkripsi: baris sama → geser kanan; kolom sama → geser bawah; lainnya → tukar kolom.
        • Dekripsi: kebalikan arah geser.
    """
    mode_label = "Enkripsi" if mode == "encrypt" else "Dekripsi"

    # ── Bangun matriks 5×5 ───────────────────────────────────────────────
    key_upper = "".join(ch.upper() for ch in key if ch.isalpha()).replace('J', 'I')
    seen: set[str] = set()
    matrix_chars: list[str] = []

    for ch in key_upper:
        if ch not in seen:
            seen.add(ch)
            matrix_chars.append(ch)

    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":   # tanpa J
        if ch not in seen:
            seen.add(ch)
            matrix_chars.append(ch)

    # Susun matriks 5×5
    matrix_5x5: list[list[str]] = [
        matrix_chars[r * 5: (r + 1) * 5] for r in range(5)
    ]

    # Lookup posisi
    pos_map: dict[str, tuple[int, int]] = {
        matrix_5x5[r][c]: (r, c)
        for r in range(5) for c in range(5)
    }

    def find_pos(ch: str) -> tuple[int, int]:
        return pos_map.get(ch.upper().replace('J', 'I'), (-1, -1))

    # ── Langkah awal ─────────────────────────────────────────────────────
    steps = [
        f"── Mode         : {mode_label}",
        f"── Teks Input   : '{text}'",
        f"── Kunci        : '{key}'",
        f"── Kunci (bersih, J→I): '{key_upper}'",
        "── Matriks Playfair 5×5 (I=J):",
        matrix_5x5,    # <-- list-of-lists → Jinja2 <table>
    ]

    # ── Bersihkan teks: uppercase, J→I, huruf saja ───────────────────────
    clean = "".join(ch.upper() for ch in text if ch.isalpha()).replace('J', 'I')
    steps.append(f"── Teks dibersihkan (J→I, huruf saja): '{clean}'")

    # ── Bentuk digraf ─────────────────────────────────────────────────────
    digraphs: list[tuple[str, str]] = []
    i = 0
    while i < len(clean):
        a = clean[i]
        if i + 1 >= len(clean):
            # Huruf terakhir ganjil → pasangkan dengan 'X'
            filler = 'Q' if a == 'X' else 'X'
            digraphs.append((a, filler))
            i += 1
        elif clean[i] == clean[i + 1]:
            # Huruf kembar → sisipkan 'X'
            filler = 'Q' if a == 'X' else 'X'
            digraphs.append((a, filler))
            i += 1
        else:
            digraphs.append((a, clean[i + 1]))
            i += 2

    steps.append(
        f"── Digraf yang terbentuk: "
        f"{[a + b for a, b in digraphs]}  ({len(digraphs)} pasang)"
    )

    # ── Enkripsi / Dekripsi setiap digraf ────────────────────────────────
    shift = 1 if mode == "encrypt" else -1
    result_chars: list[str] = []
    pair_steps: list[str] = []

    for a, b in digraphs:
        r1, c1 = find_pos(a)
        r2, c2 = find_pos(b)

        if r1 == -1 or r2 == -1:
            pair_steps.append(f"     '{a}{b}': ⚠ karakter tidak ditemukan di matriks")
            result_chars.extend([a, b])
            continue

        if r1 == r2:
            # Baris sama → geser kolom
            nc1 = (c1 + shift) % 5
            nc2 = (c2 + shift) % 5
            res_a = matrix_5x5[r1][nc1]
            res_b = matrix_5x5[r2][nc2]
            rule = "baris sama → geser kolom ke kanan" if mode == "encrypt" else "baris sama → geser kolom ke kiri"
        elif c1 == c2:
            # Kolom sama → geser baris
            nr1 = (r1 + shift) % 5
            nr2 = (r2 + shift) % 5
            res_a = matrix_5x5[nr1][c1]
            res_b = matrix_5x5[nr2][c2]
            rule = "kolom sama → geser baris ke bawah" if mode == "encrypt" else "kolom sama → geser baris ke atas"
        else:
            # Persegi panjang → tukar kolom
            res_a = matrix_5x5[r1][c2]
            res_b = matrix_5x5[r2][c1]
            rule = "persegi panjang → tukar sudut kolom"

        pair_steps.append(
            f"     '{a}'({r1},{c1}) + '{b}'({r2},{c2})  [{rule}]"
            f"  →  '{res_a}{res_b}'"
        )
        result_chars.extend([res_a, res_b])

    steps.append("── Proses per pasang digraf:")
    steps.extend(pair_steps)

    result = "".join(result_chars)
    steps.append(f"── Hasil Akhir  : '{result}'")
    return {"result": result, "steps": steps}


# ============================================================
#  CONTOH PENGGUNAAN (jalankan langsung untuk tes)
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("CAESAR CIPHER")
    r = caesar_cipher("Hello, World!", 3, "encrypt")
    print("Enkripsi:", r["result"])
    for s in r["steps"]:
        print(s)

    print("\n" + "=" * 60)
    print("VIGENÈRE CIPHER")
    r = vigenere_cipher("Attack at dawn", "LEMON", "encrypt")
    print("Enkripsi:", r["result"])
    for s in r["steps"]:
        print(s)

    print("\n" + "=" * 60)
    print("AFFINE CIPHER")
    r = affine_cipher("Hello World", 7, 3, "encrypt")
    print("Enkripsi:", r["result"])
    for s in r["steps"]:
        print(s)

    print("\n" + "=" * 60)
    print("HILL CIPHER 2x2")
    key_matrix = [[3, 3], [2, 5]]
    r = hill_cipher("HELP", key_matrix, "encrypt")
    print("Enkripsi:", r["result"])
    for s in r["steps"]:
        print(s if isinstance(s, str) else str(s))

    print("\n" + "=" * 60)
    print("PLAYFAIR CIPHER")
    r = playfair_cipher("Hello World", "MONARCHY", "encrypt")
    print("Enkripsi:", r["result"])
    for s in r["steps"]:
        print(s if isinstance(s, str) else str(s))