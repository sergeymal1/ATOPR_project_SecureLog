# Ролі та зони відповідальності

## Таблиця ролей

| Роль | Зона | Рівень | Учасник |
|------|------|--------|---------|
| A | Compression & Format | Basic | |
| B | DP & Replication | Basic | |
| C | ML & GA | Basic | |
| D | Security + Integration | Basic | |

## Легенда рівнів

- **Basic** — базовий рівень (обов'язковий для всіх)
- **Advanced** — просунутий рівень (за бажанням)
- **Expert** — експертний рівень (за бажанням, бонус)

## Зріз 0

- **Дата фіксації:** (заповнити)
- **Примітки:** (хто що обрав і чому)

## Зони відповідальності

### A — Compression & Format
- Задачі: T1.4, T2.1, T2.2, T2.3
- Файли: `src/SecureLog.Compression/`

### B — DP & Replication
- Задачі: T1.3, T2.4, T2.5, T2.6, T3.5
- Файли: `src/SecureLog.DP/`

### C — ML & GA
- Задачі: T3.1, T3.2, T3.3, T3.4, T4.3, T4.4, T4.5
- Файли: `src/SecureLog.ML/`

### D — Security + Integration
- Задачі: T1.1, T1.2, T1.5, T4.1, T4.2, T5.1–T5.6, T6.1–T6.6
- Файли: `src/SecureLog.Security/`, `src/SecureLog.App/`, `src/SecureLog.Core/`
## Що де реалізовано і що питатимуть на захисті

### A — Compression & Format
- `Huffman.cs` — дерево через чергу з пріоритетами, канонічні коди, кодер і декодер; `Payload.cs` — навантаження репліки, вибір NO_COMPRESSION і строгий розбір; `BitIO.cs`; `EventCodec.cs` — CSV і двійковий запис.
- Питання: чому код Гаффмана оптимальний серед префіксних; як відновити коди лише з довжин (`bl_count`, `next_code`); що означає сума Крафта = 1; що робити з алфавітом з одного символа; чому шифротекст не стискається.

### B — DP & Replication
- `Knapsack.cs` — ДП і жадібний baseline; `Placement.cs` — порядок реплікації; `Replication.cs` — порт виданого `replication.py` (модель вузлів і генератор Python).
- Питання: рекурентне співвідношення і складність O(n·W·R); контрприклад для жадібного (тест `Knapsack_GreedyCounterExample`); що зміниться, якщо один вузол стане вдвічі менш надійним або бюджет зменшиться на 30 %.

### C — ML & GA
- `Features.cs` — ознаки з вікном історії; `Mlp.cs` — прямий прохід, backpropagation, Adam, macro-F1; `Ga.cs` — ГА і випадковий пошук.
- Питання: які ознаки відрізняють клас 2 і чому миттєвих замало; звідки `p − onehot` у вихідному шарі; роль елітизму; як додати новий клас подій.

### D — Security + Integration
- `Crypto.cs`, `Log3.cs`, `WeakCipher.cs`; `Pipeline.cs`, `Replica.cs` (тут же відновлювач), `Tuning.cs`, `Attack.cs`, `Report.cs`, `Program.cs`; вебконсоль `src/SecureLog.Web/` (`Program.cs` — API над тим самим конвеєром, `wwwroot/` — сторінка; дані вікон приходять через `RunOptions.OnWindow`).
- Питання: чому Encrypt-then-MAC; що буде, якщо nonce повториться; навіщо два різні ключі; як кількість копій і бюджет впливають на S, R і Q.
