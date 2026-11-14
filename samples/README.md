# Файли для перехресної перевірки (команда T01)

Три репліки LOG3, створені нашою системою, і початкові дані, з яких їх створено. Кожна `*.replica.bin` — одна репліка за `FORMAT_SPEC_P3.md`: заголовок 43 байти, шифротекст, HMAC-SHA256.

**Пароль сеансу:** `algo2026` (`пароль_сеансу` з `team_config.json`).

| Файл репліки | Початкові дані | Записів | Режим навантаження | Розмір |
|---|---|---|---|---|
| `01_one_record.replica.bin` | `01_one_record.records.bin` / `.csv` | 1 | NO_COMPRESSION (Гаффман із таблицею довший за 16 сирих байтів) | 105 байтів |
| `02_window48.replica.bin` | `02_window48.records.bin` / `.csv` | 48 | канонічний Гаффман | 733 байти |
| `03_no_compression.replica.bin` | `03_no_compression.records.bin` / `.csv` | 32 | NO_COMPRESSION (примусово, `--raw`) | 601 байт |

`*.records.bin` — записи по 16 байтів (розділ 1 специфікації), саме їх треба порівнювати з відновленими побайтово. `*.records.csv` — ті самі записи рядками журналу. Записи взято з виданого `data/session.csv`: перші 48 і записи 48–79. `flags & 0x03 = 0`, `class_table` немає, тож перевіряється лише базовий формат.

SHA-256 початкових даних:

```text
1c86ea02b84b50686dde35a7550e3850b3e45a68e5a0be54d41f87e14681de3d  01_one_record.records.bin
44b83af5b5033e3c9f707c053c0436141076a57a828a48f25880fe72bf608266  02_window48.records.bin
6c0052a26c295157d884bb9cda23dceb7adfd24541e22304ba59a053e84a3da0  03_no_compression.records.bin
```

Як створено (сіль і nonce випадкові, тож повторний запуск дасть інші байти тих самих реплік):

```bash
dotnet run -c Release --project src/SecureLog.App -- pack samples/01_one_record.records.bin samples/01_one_record.replica.bin
dotnet run -c Release --project src/SecureLog.App -- pack samples/02_window48.records.bin samples/02_window48.replica.bin
dotnet run -c Release --project src/SecureLog.App -- pack samples/03_no_compression.records.bin samples/03_no_compression.replica.bin --raw
```

Як перевірити нашою системою:

```bash
dotnet run -c Release --project src/SecureLog.App -- unpack samples/02_window48.replica.bin back.bin
cmp samples/02_window48.records.bin back.bin
```

На Windows у cmd замість `cmp`: `fc /b samples\02_window48.records.bin back.bin`.
