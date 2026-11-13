# SecureLog — розумна захищена система пріоритетної реплікації журналів подій

Командний семестровий проєкт з дисципліни «Алгоритми і оптимізація програмних рішень» (Проєкт 3).

Система складається з трьох частин: **агент журналу** класифікує події перцептроном, стискає їх канонічним Гаффманом і пакує в репліки LOG3; **планувальник** обирає кількість копій динамічним програмуванням і розкладає їх по вузлах жадібною евристикою; **відновлювач** перевіряє HMAC, розшифровує AES-256-CTR, усуває дублікати й відновлює журнал. Генетичний алгоритм налаштовує три параметри системи, окремий модуль атакує навмисно слабкий шифр.

> **Стан.** Запис, репліку LOG3 і задачу реплікації реалізовано за `FORMAT_SPEC_P3.md`. Інших матеріалів із завдання (`REPLICATION_SPEC.md`, `replication.py`, `team_config.json`, датасети, еталонні пакети) команді не видано, тому модель вузлів, конфіг, дані й еталони — власні. Що з цього випливає — у [docs/decisions.md](docs/decisions.md), п. 1.

## Запуск

Потрібен .NET SDK 10.

```bash
dotnet build -c Release
dotnet run -c Release --project src/SecureLog.App -- gen       # дані й еталонні репліки: data/, reference/
dotnet run -c Release --project src/SecureLog.App -- train     # перцептрон, 3 ініціалізації → data/model.json
dotnet run -c Release --project src/SecureLog.App -- run       # повний прогін у трьох сценаріях: S, R, T, Q
dotnet run -c Release --project src/SecureLog.App -- ga        # ГА проти випадкового пошуку → data/ga_params.json (1–2 хв)
dotnet run -c Release --project src/SecureLog.App -- attack    # атака на слабкий шифр і перевірка цілісності
dotnet run -c Release --project src/SecureLog.App -- report    # шість таблиць звіту → docs/results/tables.md
dotnet test -c Release                                         # C1 (12 кейсів), D1, модульні тести
```

Міряти треба саме Release-збірку: у Debug оптимізації вимкнені, ДП працює удвічі повільніше, і складова T занижується.

## Вебконсоль

```bash
dotnet run -c Release --project src/SecureLog.Web    # відкрити http://localhost:5080
```

Сторінка подає ту саму систему як консоль журналів інфраструктури. Після вибору сценарію й seed сервер виконує повний прогін, а сторінка відтворює його вікно за вікном. Видно потік подій із класом від перцептрона, копії на вузлах A/B/C, бюджет ДП поточного вікна й показники S, R, T, Q. Після прогону можна змінити 1 біт у пакеті на вузлі й відновити журнал (зокрема з невірним паролем): відхилені репліки показано з кодами E_*. Там само запускається атака ГА на слабкий шифр. Потрібні ті самі `gen` і `train`. Імена хостів і категорій на сторінці — лише підписи до `source_id` і `category`. Адресу можна змінити змінною `SECURELOG_URL`.

`run` приймає сценарій і seed: `run emergency 3`. Пароль береться зі змінної середовища `SECURELOG_PASSWORD`; без неї використовується навчальне значення. Тести C1 і D1 читають `data/` і `reference/`, тому перед `dotnet test` мають бути виконані `gen` і `train`. Каталоги з файлом-позначкою `STANDIN` згенеровані; `gen` не перезаписує каталог без позначки.

## Повне відтворення результатів

```bash
dotnet build -c Release
dotnet run -c Release --project src/SecureLog.App -- gen
dotnet run -c Release --project src/SecureLog.App -- train
dotnet run -c Release --project src/SecureLog.App -- ga
dotnet run -c Release --project src/SecureLog.App -- report
dotnet test -c Release
```

Генератор даних, навчання й ГА мають фіксовані seeds, тому класи, ваги моделі та рішення планувальника відтворюються. Складова T залежить від швидкості машини, а сіль і nonce випадкові, тож Q збігається до третього знака, а не побітово.

## Структура та зони відповідальності

| Зона | Що реалізовано | Файли |
|---|---|---|
| **A — Compression & Format** | канонічний Гаффман (черга з пріоритетами, коди з довжин до 15, перевірка Крафта), навантаження репліки з NO_COMPRESSION і строгим розбором, парсер CSV і 16-байтових записів | `src/SecureLog.Compression/` |
| **B — DP & Replication** | багатоваріантний рюкзак (ДП), жадібний baseline, жадібний порядок реплікації, модель вузлів | `src/SecureLog.DP/` |
| **C — ML & GA** | ознаки з вікном історії, перцептрон із backpropagation і Adam, macro-F1, генетичний алгоритм і випадковий пошук | `src/SecureLog.ML/` |
| **D — Security + Integration** | PBKDF2, AES-256-CTR, HMAC, заголовок LOG3 і коди помилок E_*, слабкий шифр; конвеєр, відновлювач, налаштування ГА, атака, звіт, CLI, вебконсоль | `src/SecureLog.Security/`, `src/SecureLog.Core/`, `src/SecureLog.App/`, `src/SecureLog.Web/` |

Тести: `tests/SecureLog.Tests.C1` — 12 приймальних кейсів, `tests/SecureLog.Tests.D1` — кейси 4 і 5 з розділу 9.2, `tests/SecureLog.Tests.Unit` — окремі алгоритми без файлів даних.

## Результати

- [docs/results/tables.md](docs/results/tables.md) — шість обов'язкових таблиць;
- [docs/results/c1.md](docs/results/c1.md) — результати 12 приймальних кейсів C1;
- [docs/results/confusion.md](docs/results/confusion.md) — матриця помилок перцептрона на holdout;
- [docs/attack.md](docs/attack.md) — сценарій атаки;
- [docs/results/ga_log.csv](docs/results/ga_log.csv) — журнал збіжності ГА і випадкового пошуку;
- [docs/decisions.md](docs/decisions.md) — лог рішень і перелік припущень;
- [META-USAGE.md](META-USAGE.md) — використання ШІ.
