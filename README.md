# SecureLog — розумна захищена система пріоритетної реплікації журналів подій

Командний семестровий проєкт з дисципліни «Алгоритми і оптимізація програмних рішень» (Проєкт 3, команда T01).

Система складається з трьох частин: **агент журналу** класифікує події перцептроном, стискає їх канонічним Гаффманом і пакує в репліки LOG3; **планувальник** обирає кількість копій динамічним програмуванням і розкладає їх по вузлах жадібною евристикою; **відновлювач** перевіряє HMAC, розшифровує AES-256-CTR, усуває дублікати й відновлює журнал. Генетичний алгоритм налаштовує три параметри системи, окремий модуль атакує навмисно слабкий шифр.

> **Стан.** Усе працює на виданих матеріалах команди T01: `FORMAT_SPEC_P3.md`, `team_config.json` і `replication.py` (обидва в корені без змін), `data/train.csv`, `valid.csv`, `session.csv`, `session.bin`, еталонні пакети в `reference/`. Модель `replication.py` перенесено в C# і звірено з оригіналом на Python; усі 13 еталонних пакетів читаються, а 6 валідних наш передавач збирає байт у байт. Деталі — у [docs/decisions.md](docs/decisions.md), п. 1, 3 і 7.

## Встановлення

Потрібні лише **.NET SDK 10** (https://dotnet.microsoft.com/download/dotnet/10.0; перевірка — `dotnet --version`, має бути 10.x) і git. Працює на Windows, Linux і macOS. Під час першої збірки NuGet завантажує пакети тестів (xUnit), тому потрібен інтернет. Python не потрібен: `replication.py` лежить у репозиторії як оригінал, з яким звірено порт.

```bash
git clone https://github.com/sergeymal1/ATOPR_project_SecureLog.git
cd ATOPR_project_SecureLog
dotnet build -c Release
dotnet test -c Release
```

`dotnet test` запускає всі тести однією командою: 46 тестів, після збірки — близько 15 секунд. Навчена модель (`data/model.json`) і параметри ГА (`data/ga_params.json`) уже в репозиторії, тож нічого готувати перед тестами не треба.

## Команди

Усі команди мають вигляд `dotnet run -c Release --project src/SecureLog.App -- <команда>`. Без команди програма друкує довідку.

| Команда | Що робить |
|---|---|
| `pack <вхід> <репліка> [--raw]` | записи → файл реплік LOG3. Вхід — `.csv` журналу (як `data/session.csv`) або будь-який інший файл із записами по 16 байтів (як `data/session.bin`). `--raw` примушує NO_COMPRESSION |
| `unpack <репліка> <вихід>` | файл реплік → записи: у `.csv`, якщо вихід має це розширення, інакше сирі 16-байтові записи для побайтового порівняння |
| `check [каталог]` | звірити еталонні пакети викладача: `ref_*` мають відновитися, `bad_*` — відхилитися з кодом з `expected_failures.json`. Типово `reference/` |
| `run [сценарій] [seed]` | повний прогін: `normal`, `degraded` або `emergency` (без аргументів — усі три), показники S, R, T, Q. Без seed — відкритий `427243` з конфігу |
| `train` | навчити перцептрон (3 ініціалізації, вибір за macro-F1 на valid) → `data/model.json` |
| `ga` | ГА проти випадкового пошуку → `data/ga_params.json` (близько 2 хв) |
| `attack` | атака ГА на слабкий шифр і перевірка цілісності репліки |
| `report` | шість таблиць звіту → `docs/results/tables.md` (близько 2 хв) |

`pack`, `unpack` і `check` приймають `--password <пароль>`; без нього — `пароль_сеансу` з `team_config.json` (`algo2026`), а змінна середовища `SECURELOG_PASSWORD` його перекриває.

**Поведінка на поганих даних.** Пошкоджена, обрізана, чужа чи підписана іншим паролем репліка не дає ні аварії, ні часткового результату. `unpack` друкує `ВІДХИЛЕНО <код>: репліка N (байти …): причина`, не записує вихідний файл і завершується з кодом 1. Коди — з розділу 5 специфікації: `E_SHORT`, `E_MAGIC`, `E_LENGTH`, `E_HMAC`, `E_PAYLOAD`, `E_CODE`. Вхід `pack`, що не відповідає розділу 1 (довжина не кратна 16, поле поза діапазоном, наприклад `category` > 15), відхиляється з поясненням і кодом виходу 2.

**Довгий вхід.** `record_count` у репліці — u16, тому понад 65535 записів `pack` пише кілька реплік поспіль в один файл, а `unpack` читає їх по черзі. Файл з однією реплікою — звичайна репліка за специфікацією.

## Перехресне оцінювання: як перевірити кожен пункт

Команди нижче — для Linux, macOS або Git Bash; у Windows cmd замість `cmp a b` пишіть `fc /b a b`. `SL` тут — скорочення для `dotnet run -c Release --project src/SecureLog.App --`.

| № | Пункт аркуша | Як перевірити |
|---|---|---|
| 1 | встановлення й запуск за README | розділ «Встановлення» вище |
| 2 | усі тести однією командою | `dotnet test -c Release` — 46 із 46 |
| 3 | є unit і round-trip тести | `tests/SecureLog.Tests.Unit/UnitTests.cs` (алгоритми окремо), `RoundTripTests.cs` (round-trip і пошкодження файлів), `tests/SecureLog.Tests.C1` (12 приймальних кейсів) |
| 4 | round-trip на ваших даних | `SL pack ваші.bin out.bin` → `SL unpack out.bin back.bin` → `cmp ваші.bin back.bin`. Можна подати й `.csv` |
| 5 | крайні випадки | порожній файл, один запис (16 байтів), той самий байт `0x01` у кожному записі, вхід понад 1 МБ — усі відновлюються побайтово. Байти, що порушують розділ 1, відхиляються з поясненням: наприклад, 16 байтів `A` дають `source_id = 0x4141 > 4095` |
| 6 | правильні еталони читаються | `SL check` — `ref_01…ref_06` OK; або окремо `SL unpack reference/ref_04_session.bin r.bin` |
| 7 | пошкоджені еталони — з очікуваним кодом | `SL check` — `bad_01…bad_07` OK, `пройдено 13 з 13`; або окремо `SL unpack reference/bad_07_extra_bitstream.bin x.bin` → `ВІДХИЛЕНО E_PAYLOAD` |
| 8 | ваша система читає наші файли | [samples/](samples/README.md): три репліки, їхні початкові дані й пароль |
| 9 | наша система читає ваші файли | `SL unpack ваша_репліка.bin back.bin --password <ваш пароль>` → `cmp ваші_дані.bin back.bin` |
| 10 | пошкоджені файли без аварії й хибних даних | змініть байт, обріжте файл, запишіть інше число в `ciphertext_len` (байти 39–42) → `SL unpack` дає `E_HMAC` / `E_LENGTH` / `E_SHORT` і не пише вихід |
| 11 | код зрозумілий і відповідає специфікації | таблиця нижче: розділ специфікації → файл |

### Де в коді кожен розділ FORMAT_SPEC_P3

| Розділ | Що | Файл |
|---|---|---|
| 1 | запис 16 байтів, big-endian, діапазони полів | `src/SecureLog.Compression/EventCodec.cs` |
| 2 | заголовок 43 байти, HMAC 32 байти, повна довжина | `src/SecureLog.Security/Log3.cs` |
| 3, 3.1, 3.3 | навантаження, flags, `symbol_count = 16 × record_count`, `class_table` | `src/SecureLog.Compression/Payload.cs` |
| 3.2 | канонічний Гаффман: довжини 1…15, `bl_count`/`next_code`, Крафт, нульове доповнення | `src/SecureLog.Compression/Huffman.cs`, `BitIO.cs` |
| 3.5 | ДП для кількості копій, вага в бітах, кумулятивні коефіцієнти | `src/SecureLog.DP/Knapsack.cs`, `src/SecureLog.App/Pipeline.cs` |
| 4 | PBKDF2 100000 ітерацій, `K_enc`/`K_mac`, AES-256-CTR з лічильником від 1 | `src/SecureLog.Security/Crypto.cs` |
| 5 | порядок приймання й коди `E_*` | `Log3.Open`, `Payload.Unpack`, `src/SecureLog.Core/ReplicaException.cs` |
| 6 | еталонні артефакти | `src/SecureLog.App/Reference.cs`, тест `C12` |

## Вебконсоль

```bash
dotnet run -c Release --project src/SecureLog.Web    # відкрити http://localhost:5080
```

Сторінка подає ту саму систему як консоль журналів інфраструктури. Після вибору сценарію й seed сервер виконує повний прогін, а сторінка відтворює його вікно за вікном. Видно потік подій із класом від перцептрона, копії на вузлах A/B/C, бюджет ДП поточного вікна й показники S, R, T, Q. Після прогону можна змінити 1 біт у пакеті на вузлі й відновити журнал (зокрема з невірним паролем): відхилені репліки показано з кодами E_*. Там само запускається атака ГА на слабкий шифр. Імена хостів і категорій на сторінці — лише підписи до `source_id` і `category`. Адресу можна змінити змінною `SECURELOG_URL`.

## Повне відтворення результатів

```bash
dotnet build -c Release
dotnet run -c Release --project src/SecureLog.App -- check
dotnet run -c Release --project src/SecureLog.App -- train
dotnet run -c Release --project src/SecureLog.App -- ga
dotnet run -c Release --project src/SecureLog.App -- report
dotnet test -c Release
```

Навчання й ГА мають фіксовані seeds, а модель реплікації детермінована за seed, тому ваги моделі, рішення планувальника й відмови відтворюються. Складова T залежить від швидкості машини, а сіль і nonce випадкові, тож Q збігається до третього знака, а не побітово. Міряти треба саме Release-збірку: у Debug оптимізації вимкнені, ДП працює удвічі повільніше, і складова T занижується.

## Структура та зони відповідальності

| Зона | Що реалізовано | Файли |
|---|---|---|
| **A — Compression & Format** | канонічний Гаффман (черга з пріоритетами, коди з довжин до 15, перевірка Крафта), навантаження репліки з NO_COMPRESSION і строгим розбором, парсер CSV і 16-байтових записів | `src/SecureLog.Compression/` |
| **B — DP & Replication** | багатоваріантний рюкзак (ДП), жадібний baseline, жадібний порядок реплікації, порт `replication.py` | `src/SecureLog.DP/` |
| **C — ML & GA** | часові ознаки з ковзного вікна, перцептрон із backpropagation і Adam, macro-F1, генетичний алгоритм і випадковий пошук | `src/SecureLog.ML/` |
| **D — Security + Integration** | PBKDF2, AES-256-CTR, HMAC, заголовок LOG3 і коди помилок E_*, слабкий шифр; конвеєр із ремонтом втрачених batch, відновлювач, файли реплік (`pack`/`unpack`), звірка з еталонами, налаштування ГА, атака, звіт, CLI, вебконсоль | `src/SecureLog.Security/`, `src/SecureLog.Core/`, `src/SecureLog.App/`, `src/SecureLog.Web/` |

Тести (46): `tests/SecureLog.Tests.C1` — 12 приймальних кейсів C1; `tests/SecureLog.Tests.D1` — кейси 4 і 5 з розділу 9.2; `tests/SecureLog.Tests.Unit` — окремі алгоритми, звірка порту з `replication.py`, round-trip файлів реплік і негативні тести: кожен змінений байт, кожна довжина обрізання, неможливі `ciphertext_len`, 3000 випадково зіпсованих навантажень із правильним HMAC.

## Результати

- [docs/results/tables.md](docs/results/tables.md) — шість обов'язкових таблиць;
- [docs/results/c1.md](docs/results/c1.md) — результати 12 приймальних кейсів C1;
- [docs/results/confusion.md](docs/results/confusion.md) — матриця помилок перцептрона на valid;
- [docs/attack.md](docs/attack.md) — сценарій атаки;
- [docs/results/ga_log.csv](docs/results/ga_log.csv) — журнал збіжності ГА і випадкового пошуку;
- [docs/decisions.md](docs/decisions.md) — лог рішень і перелік припущень;
- [META-USAGE.md](META-USAGE.md) — використання ШІ.
