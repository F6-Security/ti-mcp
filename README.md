<p align="center">
  <img src="https://raw.githubusercontent.com/F6-Security/ti-mcp/HEAD/docs/logo.png" alt="F6" width="220">
</p>

# F6 Threat Intelligence MCP Server

<p align="right"><a href="https://github.com/F6-Security/ti-mcp/blob/HEAD/README.en.md">English</a></p>

[![PyPI](https://img.shields.io/pypi/v/ti-mcp)](https://pypi.org/project/ti-mcp/)
[![Python](https://img.shields.io/pypi/pyversions/ti-mcp)](https://pypi.org/project/ti-mcp/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/F6-Security/ti-mcp/blob/HEAD/LICENSE)
[![CI](https://github.com/F6-Security/ti-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/F6-Security/ti-mcp/actions/workflows/ci.yml)

MCP-сервер к API [F6 Threat Intelligence](https://ti.f6.security). Даёт ИИ-ассистенту
доступ к коллекциям TI: утечки, вредоносное ПО, атаки, подозрительные IP, угрозы
и профили группировок — поиском по индикаторам и выборкой с фильтрами.

## Тулы

| Тул | Назначение |
| --- | --- |
| `ti_list_collections` | Коллекции, доступные учётной записи; заодно проверка ключа и IP |
| `ti_global_search` | В каких коллекциях встречается индикатор и сколько записей в каждой |
| `ti_get_collection` | Выборка и поиск по коллекции, постранично |
| `ti_get_updates` | Изменения в коллекции с заданной точки последовательности |
| `ti_get_sequence_list` | Стартовые точки для `ti_get_updates`, в том числе на дату |
| `ti_get_item` | Одна запись по id |
| `ti_graph_lookup` | WHOIS-обогащение по IP или домену |
| `ti_describe_collections` | Справочник коллекций: поля, лимиты, методы; без запроса к API |
| `ti_request` | Любой документированный read-only эндпоинт под `/api/v2` |

Все тулы только читают. `ti_request` не пропускает пути, которые меняют данные
на стороне TI, и не отдаёт бинарные файлы.

## Быстрый старт

Нужен Python 3.10+, логин веб-портала TI и персональный API-ключ
(Личный кабинет → Безопасность и доступ → Персональный токен). Адрес, с которого
работает сервер, должен быть в списке доверенных IP учётной записи.

```json
{
  "mcpServers": {
    "ti": {
      "command": "uvx",
      "args": ["ti-mcp"],
      "env": {
        "TI_LOGIN": "user@example.com",
        "TI_API_KEY": "<key>"
      }
    }
  }
}
```

Этот блок подходит для Claude Desktop и Cursor. Для VS Code — файл `.vscode/mcp.json`:

```json
{
  "servers": {
    "ti": {
      "type": "stdio",
      "command": "uvx",
      "args": ["ti-mcp"],
      "env": {
        "TI_LOGIN": "user@example.com",
        "TI_API_KEY": "<key>"
      }
    }
  }
}
```

Для Claude Code:

```sh
claude mcp add ti \
  -e TI_LOGIN=user@example.com -e TI_API_KEY=<key> \
  -- uvx ti-mcp
```

Для OpenCode — ключ `mcp` в `~/.config/opencode/opencode.json` (все проекты)
или в `opencode.json` в корне проекта:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ti": {
      "type": "local",
      "command": ["uvx", "ti-mcp"],
      "enabled": true,
      "timeout": 660000,
      "environment": {
        "TI_LOGIN": "user@example.com",
        "TI_API_KEY": "{file:~/.config/ti-mcp/key}"
      }
    }
  }
}
```

В отличие от конфигов выше, `command` — массив вместе с аргументами, переменные —
в `environment`, а `"type": "local"` обязателен. Ключ можно не держать в конфиге:
OpenCode подставляет содержимое файла (`{file:…}`) или переменную окружения
(`{env:TI_API_KEY}`). `timeout` — в миллисекундах, по умолчанию 30 с на запрос, а
один вызов тула может длиться дольше: на 429 и 5xx сервер повторяет запрос до
`TI_RETRIES` раз (по умолчанию 3), каждая попытка ждёт портал до `TI_TIMEOUT`
(120 с), а между попытками выдерживается пауза `Retry-After`. 660 с покрывают
четыре попытки и паузы по минуте; если меняете `TI_TIMEOUT` или `TI_RETRIES`,
пересчитайте. Проверить подключение — `opencode mcp list`.

Вместо `uvx` можно использовать `pip install ti-mcp` и команду `ti-mcp`, либо
контейнер — `docker run -i --rm -e TI_LOGIN -e TI_API_KEY ghcr.io/f6-security/ti-mcp`
(образ собран под `linux/amd64` и `linux/arm64`).

Чтобы запустить сервер из исходников — например, проверить ещё не вышедшие в
релиз изменения, — поставьте его в отдельное окружение из клона репозитория:

```sh
git clone https://github.com/F6-Security/ti-mcp.git
cd ti-mcp
python3 -m venv venv
./venv/bin/pip install --require-hashes -r requirements.lock
./venv/bin/pip install --no-deps -e .
```

На Windows вместо `venv/bin/` — `venv\Scripts\`, в том числе в пути для клиента ниже.

Затем укажите клиенту команду из этого окружения вместо `uvx ti-mcp`:

```sh
claude mcp add ti \
  -e TI_LOGIN=user@example.com -e TI_API_KEY=<key> \
  -- /path/to/ti-mcp/venv/bin/ti-mcp
```

В JSON-конфиге — `"command": "/path/to/ti-mcp/venv/bin/ti-mcp"` без `args`, в
OpenCode — `"command": ["/path/to/ti-mcp/venv/bin/ti-mcp"]`.
Пакет установлен в editable-режиме, поэтому правки кода подхватываются при
следующем запуске сервера. Для тестового стенда задайте его адрес в `TI_BASE_URL`.

Первым вызовом сделайте `ti_list_collections`: он подтверждает, что ключ, IP и
доступ к коллекциям в порядке.

## Переменные окружения

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `TI_LOGIN` | — | логин (email) в веб-портале TI |
| `TI_API_KEY` | — | персональный API-ключ |
| `TI_BASE_URL` | `https://ti.f6.security` | адрес портала; только `https://` |
| `TI_CA_BUNDLE` | — | PEM-бандл УЦ для проверки сертификата портала, например внутреннего УЦ прокси; заменяет системные УЦ, поэтому в нём должны быть все нужные |
| `TI_PROXY` | — | прокси `http://host:port`; `HTTP_PROXY` и `HTTPS_PROXY` из окружения не читаются |
| `TI_TIMEOUT` | `120` | таймаут запроса, секунд |
| `TI_RETRIES` | `3` | повторов при 429/500/502/503/504, с учётом `Retry-After` |
| `TI_MIN_FEED_INTERVAL` | `1` | минимальный интервал между запросами к одной коллекции, секунд |
| `TI_RESULT_ID_TTL` | `150` | сколько секунд сервер помнит открытую выборку `scroll=true` |

## Примеры запросов

```
ti_global_search        query="8.8.8.8"
ti_describe_collections collection="ioc/common"
ti_get_collection       collection="ioc/common" query="ip:8.8.8.8"
ti_get_collection       collection="osi/vulnerability" date_from="2026-10-01" extra_params={"has_exploit": 1}
ti_get_collection       collection="apt/threat" limit=10 offset=10
ti_get_updates          collection="malware/cnc" seq_update=16394859
```

Типичный путь: `ti_global_search` по индикатору показывает, в каких коллекциях
он встречается; `ti_describe_collections` подсказывает поля и лимиты нужной;
`ti_get_collection` с тем же запросом отдаёт записи.

Фильтр `query` — свободный текст по всем атрибутам (`"8.8.8.8"`) или
`атрибут:значение` (`"domain:example.com"`). Атрибуты — поля ответа коллекции,
их показывает `ti_describe_collections`. Даты `date_from`/`date_to` — `YYYY-MM-DD`
или `YYYY-MM-DDTHH:MM:SSZ`.

Страницы `ti_get_collection` листаются параметром `offset` с шагом `limit` до
`count`. Для выгрузки большого набора или полного обхода коллекции передайте
`scroll=true`: сервер сам продолжит выборку при следующем вызове. Для
непрерывного отслеживания ленты используйте `ti_get_updates` с `seqUpdate` из
предыдущего ответа, стартовую точку даёт `ti_get_sequence_list`.

## Безопасность

Всё, что возвращают тулы, попадает в контекст языковой модели: скомпрометированные
учётные записи, карты, индикаторы, отчёты об угрозах. Выбирайте провайдера
модели с учётом этого и выдавайте серверу ключ пользователя с минимально
необходимым набором коллекций.

Ключ уходит только на адрес из `TI_BASE_URL` и только по `https://`; ответ больше
1 МБ отклоняется, чтобы один вызов не заполнил контекст.

Модель угроз и порядок сообщения об уязвимостях —
[SECURITY.md](https://github.com/F6-Security/ti-mcp/blob/HEAD/SECURITY.md).

## Участие в разработке

См. [CONTRIBUTING.md](https://github.com/F6-Security/ti-mcp/blob/HEAD/CONTRIBUTING.md).

## Лицензия

[Apache License 2.0](https://github.com/F6-Security/ti-mcp/blob/HEAD/LICENSE)
