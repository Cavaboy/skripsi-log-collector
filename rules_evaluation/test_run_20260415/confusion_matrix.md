## Tabel 4.X — Confusion Matrix (5×5)

**Konfigurasi:** Support = 0.01, Confidence = 0.30 | Data Uji = 2.500 baris seimbang (500/kelas)

| **Aktual \ Prediksi** | **NORMAL** | **LINK_FAILURE** | **UPSTREAM_FAILURE** | **DDOS_ATTACK** | **BROADCAST_STORM** |
|---|---|---|---|---|---|
| **NORMAL** | 168 | 5 | 15 | 312 | 0 |
| **LINK_FAILURE** | 73 | 203 | 133 | 91 | 0 |
| **UPSTREAM_FAILURE** | 55 | 117 | 240 | 88 | 0 |
| **DDOS_ATTACK** | 168 | 0 | 6 | 326 | 0 |
| **BROADCAST_STORM** | 101 | 99 | 96 | 204 | 0 |
