# OATSIDE — block cipher enam cabang

Implementasi tugas IF4020 berupa block cipher eksperimental dengan enam cabang
asimetris, satu tahap Feistel per sisi, kompresi non-destruktif sebagai mask XOR,
S-box tabel buatan, dan difusi global. Lima mode tersedia: ECB, CBC, CFB, OFB,
dan CTR. Konstruksi tabel substitusi dijelaskan di
[SBOX_OATSIDE.md](docs/SBOX_OATSIDE.md); implementasi aktif berada di `src/`.

Program memproses berkas sebagai byte sehingga mendukung teks dan data biner.
Kesamaan hasil dekripsi diuji byte demi byte. Lima mode yang tersedia tidak memberi
autentikasi ciphertext; round-trip yang berhasil bukan bukti bahwa manipulasi selalu
dapat dideteksi.

## Anggota

1. Brian A. Hadian - 13523048
2. Zulfaqqar Nayaka Athadiansyah - 13523094
3. Azfa Radhiyya Hakim - 13523115

## Teknologi dan dependensi

- Python 3.10 atau lebih baru pada Windows atau Linux.
- Cipher, mode, CLI, dan test hanya memakai Python standard library; tidak ada
  pustaka kriptografi pihak ketiga.
- `matplotlib` opsional untuk grafik histogram.

Semua perintah berikut dijalankan dari root repository.

## Format key, IV, dan counter

- Ukuran blok: 64, 96, 128, atau 192 bit.
- Key heksadesimal harus tepat `block_bits / 4` digit di luar awalan `0x`.
- CBC, CFB, dan OFB memerlukan IV tepat satu blok.
- CTR memerlukan counter awal tepat satu blok. Counter dibaca big-endian dan dinaikkan
  satu setiap blok. Operasi ditolak jika counter akan melewati batas ukuran blok.
- ECB tidak memakai IV.
- IV/counter **tidak disimpan di ciphertext**. Pengguna wajib menyimpan dan
  memberikan nilai yang sama saat dekripsi.

Pada pemanggilan API `src.modes` secara langsung, gunakan IV/counter eksplisit.
API berkas dan CLI mewajibkannya untuk mode selain ECB; IV/counter tidak dibuat
otomatis karena tidak disimpan bersama ciphertext.

Jangan menggunakan ulang pasangan key-IV atau key-counter untuk data berbeda.

## Penggunaan CLI

Tampilkan bantuan:

```shell
python main.py --help
python main.py encrypt --help
```

Contoh CBC 64 bit:

```shell
python main.py encrypt -i sample.bin -o sample.enc -k 0x1234567890ABCDEF -m CBC --iv 0x8765432187654321
python main.py decrypt -i sample.enc -o sample.restored.bin -k 0x1234567890ABCDEF -m CBC --iv 0x8765432187654321
```

Contoh ECB dan CTR:

```shell
python main.py encrypt -i sample.bin -o sample.ecb -k 0x1234567890ABCDEF -m ECB
python main.py encrypt -i sample.bin -o sample.ctr -k 0x1234567890ABCDEF -m CTR --iv 0x0000000000000001
```

| Opsi | Keterangan |
|---|---|
| `encrypt` / `decrypt` | Operasi |
| `-i`, `--input` | Path input |
| `-o`, `--output` | Path output; harus berbeda dari input |
| `-k`, `--key` | Master key heksadesimal atau integer desimal |
| `-m`, `--mode` | ECB, CBC, CFB, OFB, atau CTR |
| `-b`, `--block-bits` | 64, 96, 128, atau 192; default 64 |
| `--iv` | IV atau counter awal heksadesimal |
| `-r`, `--rounds` | Jumlah putaran positif; default 16 |

ECB/CBC memakai PKCS#7, termasuk satu blok padding penuh bila input sudah kelipatan
ukuran blok. CFB/OFB/CTR memproses blok terakhir parsial tanpa padding.

## Dokumentasi API

Dokumentasi API publik adalah bonus dan belum tersedia pada versi repositori ini.
Antarmuka yang dapat digunakan sekarang adalah CLI di atas serta fungsi Python
di `src/cipher_core.py` dan `src/modes.py`.

## Menjalankan test

```shell
python -m unittest discover -s tests -v
```

Suite mencakup invers round dan block acak pada semua ukuran, key schedule,
file biner pada lima mode, padding, CLI, panjang IV/counter, wrap CTR,
serta batas panjang berkas pada semua ukuran blok.
Jalankan kembali uji dan vektor setelah setiap perubahan core: ciphertext
prototipe lama tidak kompatibel dengan rancangan saat ini.

## Eksperimen keamanan

Jalankan avalanche, entropi, dan histogram untuk seluruh mode:

```shell
python -m analysis.run_experiments --trials 64 --sample-bytes 512 --seed 4020 --plots
```

Hasil JSON, CSV mentah, dan PNG disimpan di `analysis/results/` saat eksperimen dijalankan. Seed, key,
IV/counter, dan parameter lain ikut disimpan agar eksperimen dapat direproduksi.
Angka avalanche dan entropi adalah pengukuran empiris, bukan bukti keamanan.

## Struktur repository

```text
config/       parameter ukuran blok
src/          cipher, mode, CLI, dan fungsi analisis
analysis/     runner eksperimen dan hasil
tests/        unit, boundary, construction, dan integration tests
docs/         diagram rancangan cipher dan key schedule
main.py       entry point CLI
```

## Keterbatasan keamanan

- Rancangan belum melalui kriptanalisis publik.
- ECB membocorkan pola blok berulang.
- Penggunaan ulang IV/counter berbahaya, terutama untuk OFB/CTR.
- Tidak ada MAC atau authenticated encryption.
- Padding error bukan mekanisme autentikasi.
- Hasil avalanche, entropi, dan histogram hanya diagnostik sampel; bukan bukti
  keamanan. Key schedule dan cipher belum diaudit secara independen.

## Design Simplification

Versi aktif menghapus Feistel kedua, kompresi kedua, `ShiftRows` lokal,
dan rotasi luar satu bit setelah pengukuran awal yang tidak menunjukkan manfaat
difusi konsisten pada sampel tersebut. Struktur enam cabang dan difusi global
tetap dipakai. Default 16 putaran adalah pilihan rancangan, bukan jaminan
keamanan; hasil eksperimen final masih perlu dijalankan dan dilaporkan.
