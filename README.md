# CVE Notification Bot (Telegram + NVD API)

Телеграм-бот, который получает новые CVE из NVD API за заданный период, фильтрует их по **ключевым словам** и отправляет в чат/топик.  
Поддерживает:
- хранение секретов в `.env`;
- выбор периода (30 минут / час / сутки / неделя / месяц);
- отправку в **форумные топики** (Telegram `message_thread_id`);
- строгий поиск ключевых фраз (по словам/фразам с границами и поддержкой пробел/дефис), **без матчей внутри URL**;
- формат «More information» со списком ссылок из `references`.

---

## Требования

- Python **3.10+**
- Доступ в интернет к:
  - `https://services.nvd.nist.gov/rest/json/cves/2.0`
  - `https://api.telegram.org/bot...`

## Установка

```bash
git clone https://github.com/Toxich4/CVE_Telegram_Bot
cd CVE_Telegram_Bot

python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

> Зависимости: `requests`, `python-dotenv`

---

## Конфигурация

### 1) `.env`

Создайте файл `.env` в корне:

```dotenv
# Telegram
TELEGRAM_BOT_TOKEN=123456:ABCdef...
TELEGRAM_CHAT_ID=-100*********
# Для форумной темы (опционально)
# CHAT_ID = -100*********, THREAD_ID = 1
THREAD_ID=3461

# Период выгрузки: 30m (по умолчанию), hour, day, week, month
PERIOD=30m

# Если true — игнорируем ключевые слова и шлём все CVE
ALLOW_ALL=false

# Путь к файлу со списком ключевых слов
KEYWORDS_FILE=keywords.txt
```

### 2) `keywords.txt`

Файл со списком ключей/фраз (по одной в строке). Пустые строки и строки, начинающиеся с `#`, игнорируются. Разрешается несколько значений через запятую в одной строке.

Пример:

```
# Вендоры/продукты
Cisco
IOS XE
ASA
AnyConnect
Palo Alto
PAN-OS
Check Point
Citrix
Confluence
HashiCorp Vault
VMware
IIS
ESXi
vCenter
vSphere
Nexus
GitLab
Jenkins
Azure AD
Keycloak
Nginx
Grafana
Swagger
Kibana
Kubernetes
Nagios
Spring Boot
Next JS
MySQL
PostgreSQL
Redis
Airflow
Apache
Node.js
Vaadin
Laravel
```

---

## Запуск

### Разовый запуск

```bash
. .venv/bin/activate
python3 cve_bot.py
```

В логах увидите:
- выбранный период / allow_all / путь к `keywords.txt`;
- точный URL, который ушёл в NVD (удобно для отладки);
- количество полученных CVE;
- строки вида `[MATCH] CVE-XXXX-YYYY by 'Azure AD'` — показывают, по какому ключу прошло.

### Периодический запуск (cron)

Надёжный пример:

```cron
*/30 * * * * python3 cve_bot.py >> bot.log 2>&1'
```

### Отправка в конкретный топик (форум)

- `TELEGRAM_CHAT_ID` — `-100` + внутренний id из ссылки (`https://t.me/c/<id>/<topic>/<msg>`).
- `THREAD_ID` — средний сегмент `<topic>`.

Пример:

```
https://t.me/c/2461133703/5
CHAT_ID = -1002461133703
THREAD_ID = 5
```

---

## Формат сообщения

```
🚨  CVE-2025-12345 (https://nvd.nist.gov/vuln/detail/CVE-2025-12345) 🚨
💥  CVSS: 9.8
📅  Published: 2025-10-03
📓  Description: <англ. описание CVE>
ℹ️  More information:
1. <url>
2. <url>
```
