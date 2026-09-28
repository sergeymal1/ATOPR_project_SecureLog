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