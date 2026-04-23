
# ТЗ: HSP — Hybrid Storage Protocol
**Версия документа:** Draft 0.1  
**Дата:** 2026-04-20  
**Статус:** рабочее ТЗ на разработку публичного открытого протокола  
**Цель документа:** зафиксировать требования к разработке HSP v1.0 как открытого сетевого протокола хранения данных с публичной спецификацией, эталонной реализацией и набором тестов на совместимость.

**Примечание по security baseline:** для профиля `public multi-tenant` HSP v1.0 фиксирует обязательные client-side E2EE для object payload, server-side encryption для всех persisted stores, channel-bound authorization, строгую tenant isolation и Rust как основной язык reference runtime для server/gateway/conformance.

---

## 1. Назначение

HSP (Hybrid Storage Protocol) — сетевой протокол хранения и передачи данных, объединяющий:

1. content-addressed immutable object storage;
2. mutable namespace layer поверх immutable-объектов;
3. chunked upload/download;
4. частичное чтение и streaming-first доставку;
5. встроенные события и подписки;
6. edge-aware доставку;
7. capability-based authorization;
8. HTTP/3 compatibility gateway для массового внедрения.

HSP не должен быть «ещё одним REST API». HSP v1.0 должен быть самостоятельным application protocol поверх QUIC, с обязательной защитой соединения и формальным публичным описанием wire format.

---

## 2. Цели проекта

### 2.1 Основные цели
1. Разработать открытый протокол, пригодный для публичного использования третьими сторонами без привязки к одному вендору.
2. Обеспечить детерминированную адресацию контента и совместимость независимых реализаций.
3. Обеспечить эффективную загрузку больших объектов за счёт chunked ingest и дедупликации.
4. Обеспечить нативную работу с:
   - объектами по CID;
   - именованными путями;
   - диапазонами байт;
   - событиями;
   - подписками;
   - политиками хранения.
5. Выпустить вместе со спецификацией:
   - reference server;
   - reference client/SDK на Go;
   - CLI;
   - gateway по HTTP/3;
   - набор conformance tests;
   - публикацию регистров протокола.

### 2.2 Бизнес-цели
1. Упростить миграцию из систем уровня S3/HTTP object storage.
2. Создать основу для публичной экосистемы: сторонние серверы, прокси, клиенты, SDK, браузерные gateway.
3. Снизить стоимость повторных загрузок одинакового контента.
4. Сделать протокол пригодным для CDN/edge/media/use-cases без обязательного Web3, blockchain или глобального consensus слоя.

---

## 3. Ограничения и границы

### 3.1 Входит в рамки v1.0
- Native wire protocol поверх QUIC.
- TLS 1.3 в обязательном порядке.
- Обязательный public multi-tenant security profile: client-side E2EE object data, server-side encryption всех persisted stores, KMS/HSM-backed key hierarchy и strict tenant isolation.
- Адресация по content ID и namespace path.
- Объекты, manifests, namespace records, events, tokens.
- Chunked upload/download.
- Range retrieval.
- Capability tokens.
- HTTP/3 gateway.
- Репликационные hints.
- Public registries.
- Эталонная реализация и тестовый набор.

### 3.2 Не входит в рамки v1.0
- Глобальный permissionless decentralized consensus.
- Экономическая модель хранения и расчёты между узлами.
- Blockchain-интеграция.
- Полноценный multi-writer CRDT namespace как обязательный режим.
- Полное S3 API покрытие.
- Встроенная transcoding/preview/media processing pipeline.
- Глобальная анонимная P2P-сеть без trusted bootstrap.

### 3.3 Формальные расширения, но не обязательная часть MVP
- Peer-assisted transfer.
- Content-defined chunking второго профиля.
- Multi-master CRDT namespace extension.
- S3 compatibility gateway subset.
- End-to-end encrypted collaborative sharing profiles поверх базового E2EE-профиля.

---

## 4. Проблема, которую решает HSP

Классическая object storage модель удобна для хранения blob-объектов, но обычно:
- опирается на именование по ключу, а не по содержимому;
- не делает дедупликацию базовым объектом протокола;
- не имеет нативного event/subscription слоя;
- плохо формализует namespace mutation как отдельную сущность;
- часто оставляет partial-transfer, edge distribution и capability-scoped access как внешнюю надстройку;
- не задаёт единый открытый wire protocol для независимых реализаций.

HSP должен устранить эти ограничения на уровне самого протокола.

---

## 5. Базовые принципы протокола

1. **Immutability-first**  
   Данные объекта после commit не изменяются.

2. **Content addressing**  
   Объект и чанки идентифицируются по hash-based identifier.

3. **Namespace over immutable content**  
   Человек работает через путь; система хранит binding path -> CID.

4. **Transport-native streaming**  
   Загрузка и выдача должны работать потоково, без обязательной буферизации всего объекта в памяти.

5. **Deterministic encoding**  
   Все структуры, влияющие на вычисление CID или подпись, кодируются детерминированно.

6. **Extensibility without ambiguity**  
   Расширения допустимы, но критичные расширения должны явно согласовываться.

7. **Security by default**  
   Незащищённый transport для production не допускается.

8. **Interop-first**  
   Спецификация должна позволять двум независимым реализациям пройти conformance suite без договорённостей «в коде».

---

## 6. Роли и сущности

### 6.1 Роли
- **Client** — инициирует операции протокола.
- **Origin Node** — authoritative storage node для namespace и object ingest.
- **Edge Node** — узел для ускоренной выдачи и кэширования.
- **Relay Node** — промежуточный узел для проксирования/маршрутизации.
- **Gateway** — HTTP/3 и/или HTTP API фасад над native HSP.
- **Namespace Authority** — логический владелец и источник истины для namespace revisions.

### 6.2 Основные сущности
- **CID** — content identifier.
- **Chunk** — минимальная хранимая единица данных.
- **Manifest** — описание объекта и его chunk layout.
- **Namespace Record** — операция bind/unbind/tombstone для path -> CID.
- **Capability Token** — bearer-токен с ограниченными правами.
- **Event Record** — запись об изменении объекта/namespace.
- **Upload Session** — временное состояние для загрузки объекта до commit.

---

## 7. Архитектурная модель v1.0

### 7.1 Уровни
1. **Transport Layer:** QUIC v1.
2. **Security Layer:** TLS 1.3 в составе QUIC.
3. **Session/Control Layer:** HSP control stream + settings negotiation.
4. **Request Streams:** операции GET/PUT/RESOLVE/BIND/LIST/SUBSCRIBE.
5. **Data Model Layer:** manifests, namespace records, events, tokens.
6. **Gateway Layer:** HTTP/3 gateway и bootstrap.

### 7.2 Обязательные свойства архитектуры
- Один QUIC connection может обслуживать много параллельных HSP request streams.
- Сервер обязан отправить SETTINGS после установления control stream.
- Все критичные лимиты и capability flags должны объявляться сервером явно.
- Объект становится видимым только после успешного COMMIT.
- Namespace update должен быть атомарным на уровне одного path.

---

## 8. Транспорт

### 8.1 Native transport
- HSP v1.0 **MUST** работать поверх QUIC v1.
- ALPN идентификатор native протокола: `hsp/1`.
- HSP v1.0 **MUST NOT** иметь production-профиль без криптографической защиты канала.
- TCP-only профиль не входит в v1.0.

### 8.2 Причина выбора транспорта
QUIC выбран как транспорт по следующим причинам:
- stream multiplexing;
- flow control;
- low-latency connection establishment;
- connection migration;
- пригодность для больших параллельных transfers.

### 8.3 Gateway transport
- Reference implementation **MUST** включать HTTP/3 gateway.
- HTTP/3 gateway **MUST** быть совместим по semantics с native HSP операциями.
- HTTP/1.1/2 gateway **MAY** существовать как отдельный adapter, но не является обязательной частью v1.0.

---

## 9. Безопасность транспорта и идентичность узлов

### 9.1 Обязательные требования
- Все native соединения должны использовать TLS 1.3 через QUIC.
- Клиент обязан валидировать identity сервера по имени authority.
- Несовпадение authority и certificate identity должно приводить к ошибке соединения.
- Наличие self-signed сертификата допускается только в profile `private-deployment`, явно включаемом конфигурацией.

### 9.2 Профили аутентификации канала
1. **Server-authenticated** — обязателен в v1.0.
2. **mTLS** — опциональный профиль.
3. **Anonymous transport + signed token** — не допускается в production profile.

---

## 10. Адресация и идентификаторы

### 10.1 CID
CID — строковый идентификатор контента.

#### Требования v1.0
- CID объекта вычисляется из детерминированно сериализованного manifest body.
- CID чанка вычисляется из фактически хранимых байтов чанка.
- Обязательный hash algorithm v1.0: `sha-256`.
- Формат CID v1.0: `base32-lower-no-padding(multihash-like payload)`.

### 10.2 Namespace path
Namespace path — человекоориентированный путь.

Примеры:
- `avatars/user-42/original.png`
- `rooms/ab12/messages/2026-04-20/000001.json`

#### Правила
- Path хранится и сравнивается как UTF-8 string.
- Разделитель сегментов: `/`.
- Сегменты `.` и `..` не имеют специальных семантик.
- Сервер **MUST NOT** выполнять файловую нормализацию в стиле POSIX.
- Один и тот же байтовый путь после percent-decoding считается тем же path.
- Двойное percent-decoding запрещено.

### 10.3 URI scheme
HSP использует URI scheme `hsp:`.

Канонические формы v1.0:
- `hsp://authority/cid/<cid>`
- `hsp://authority/ns/<namespace>/<path>`
- `hsp://authority/manifest/<cid>`

Примеры:
- `hsp://store.example/cid/bafy...`
- `hsp://store.example/ns/public/videos/intro.mp4`

### 10.4 Authority
Authority в URI указывает logical service authority, а не обязательно конкретную storage machine. Discovery может вернуть альтернативный endpoint.

---

## 11. Discovery

### 11.1 Обязательный bootstrap-механизм
Каждый public HSP deployment **MUST** отдавать bootstrap-документ по:
- `https://<authority>/.well-known/hsp`

Формат bootstrap v1.0: JSON.

### 11.2 Bootstrap schema
Минимальная структура:
```json
{
  "version": 1,
  "authority": "store.example",
  "native": {
    "alpn": "hsp/1",
    "host": "store.example",
    "port": 443
  },
  "gateway": {
    "base_url": "https://store.example/v1/"
  },
  "features": [
    "cid",
    "namespace",
    "events",
    "http3-gateway"
  ],
  "limits": {
    "max_chunk_size": 1048576,
    "max_manifest_size": 8388608
  }
}
```

### 11.3 DNS-based discovery
- Deployment **SHOULD** публиковать DNS SVCB/HTTPS записи для ускорения discovery.
- Использование DNS discovery не должно быть единственным обязательным способом bootstrap.
- Клиент без доступа к SVCB обязан иметь возможность начать работу через `.well-known/hsp`.

---

## 12. Модель данных

### 12.1 Общая модель
HSP разделяет:
1. immutable object content;
2. mutable namespace bindings;
3. событийную ленту изменений.

### 12.2 Object
Object — логическая единица данных, представленная manifest-ом.

Object состоит из:
- manifest body;
- optional manifest signature;
- списка chunk references;
- optional metadata;
- optional encryption descriptor;
- optional link set.

### 12.3 Chunk
Chunk — минимальная адресуемая binary единица.

#### Требования v1.0
- Минимальный допустимый размер чанка: 64 KiB.
- Максимальный допустимый размер чанка: 4 MiB.
- Рекомендуемый target size: 1 MiB.
- Reference implementation **MUST** поддерживать fixed-size chunking.
- Content-defined chunking может быть добавлен как extension profile.

### 12.4 Manifest
Manifest описывает:
- logical size;
- stored size;
- chunk list;
- content type;
- content encoding;
- chunking strategy;
- encryption parameters;
- application metadata;
- object links.

### 12.5 Namespace Record
Namespace Record — append-only логическая операция:

- `bind`
- `rebind`
- `unbind`
- `tombstone`

Namespace Record должен содержать:
- namespace id;
- path;
- revision;
- target CID;
- previous revision reference;
- timestamp;
- actor / issuer;
- optional ACL policy reference;
- optional signature.

### 12.6 Event Record
Event Record должен содержать:
- event sequence;
- event timestamp;
- event type;
- subject selector;
- namespace/path if applicable;
- object CID if applicable;
- revision if applicable;
- idempotency key if applicable;
- trace id;
- compact payload.

---

## 13. Консистентность

### 13.1 Object semantics
- Объекты immutable.
- После `COMMIT` объект по CID считается неизменяемым.
- Повторный `COMMIT` другого содержимого под тем же CID невозможен.

### 13.2 Namespace semantics
Core v1.0 использует **single-authority per namespace** модель.

Обязательные свойства:
- Namespace Authority присваивает monotonically increasing revision.
- `BIND` и `UNBIND` поддерживают optimistic concurrency через `if_revision`.
- Успешный `BIND` или `UNBIND` должен быть немедленно виден на authoritative read.
- Edge caches могут быть eventual-consistent, но authoritative source обязан быть согласованным.

### 13.3 Tombstones
- Удаление пути оформляется tombstone record.
- Tombstone должен храниться не менее configurable grace period.
- Возрождение path после tombstone допускается только новым bind с новой revision.

---

## 14. Пайплайн данных

### 14.1 Trusted-storage mode
Режим по умолчанию для v1.0:
1. клиент подготавливает bytes;
2. применяет optional compression;
3. разбивает на chunks;
4. вычисляет CID каждого chunk;
5. строит manifest;
6. загружает только отсутствующие chunks;
7. выполняет commit.

### 14.2 E2EE mode
Обязательный профиль для `public multi-tenant` deployment:
1. optional compression;
2. chunking;
3. client-side encryption каждого chunk;
4. CID считается по ciphertext chunk;
5. manifest несёт encryption descriptor.
6. object key публикуется только в wrapped form для авторизованных читателей.

### 14.3 Следствия
- В trusted-storage режиме дедупликация максимальна, но этот режим не является public default.
- В E2EE режиме дедупликация ограничена границами одинакового encryption context и не должна раскрывать cross-tenant plaintext equality.
- v1.0 reference implementation **MUST** реализовать public E2EE profile.
- Trusted-storage mode **MAY** существовать как private-deployment profile, но не должен ослаблять public multi-tenant semantics.

---

## 15. Кодирование сообщений

### 15.1 Основной формат
Native HSP metadata **MUST** кодироваться в CBOR.

### 15.2 Требования к кодированию
Все структуры, влияющие на:
- CID;
- подпись;
- проверку авторства;
- capability token validation;

должны использовать **детерминированное CBOR-кодирование**.

### 15.3 Ключи map
- Для wire structures рекомендуется использовать целочисленные ключи.
- Текстовые ключи допускаются только в gateway-профиле и bootstrap JSON.
- Порядок ключей в deterministic CBOR должен быть фиксирован правилами протокола.

### 15.4 Описание схем
- Все основные CBOR structures **MUST** быть формально описаны в CDDL.
- CDDL файлы являются нормативным приложением к спецификации.

---

## 16. Wire format native HSP

### 16.1 Общая схема stream interaction
После завершения QUIC/TLS handshake:
1. клиент открывает control stream;
2. сервер открывает control stream;
3. стороны обмениваются SETTINGS;
4. клиент открывает bidirectional request streams под операции.

### 16.2 Типы stream-ов
- `control`
- `request`
- `event`
- `upload-data` (опционально как специализированный request stream profile)

### 16.3 Frame envelope
Каждый HSP frame имеет вид:
- `type` — QUIC varint
- `length` — QUIC varint
- `payload` — bytes

### 16.4 Основные frame types v1.0
| Код | Имя | Направление | Назначение |
|---|---|---|---|
| 0x01 | SETTINGS | both | параметры соединения |
| 0x02 | ERROR | both | ошибка уровня stream/connection |
| 0x03 | NOTICE | server->client | информационное сообщение |
| 0x10 | REQ_HEADER | client->server | заголовок операции |
| 0x11 | RES_HEADER | server->client | ответ на операцию |
| 0x12 | DATA | both | бинарный payload |
| 0x13 | END | both | завершение payload |
| 0x14 | EVENT | server->client | событие |
| 0x15 | ACK | both | явное подтверждение для некоторых режимов |
| 0x16 | AUTH | client->server | передача capability / auth context |
| 0x17 | GOAWAY | server->client | мягкое завершение соединения |

### 16.5 REQ_HEADER payload
REQ_HEADER payload — CBOR map:
```cddl
req-header = {
  0: 1,                         ; protocol version
  1: tstr,                      ; op
  ? 2: uint,                    ; request id
  ? 3: uint,                    ; payload mode
  ? 4: uint,                    ; payload length if known
  ? 5: { * int / tstr => any }, ; params
  ? 6: { * int / tstr => any }  ; extensions
}
```

### 16.6 RES_HEADER payload
```cddl
res-header = {
  0: 1,                         ; protocol version
  1: uint,                      ; status code
  ? 2: uint,                    ; request id
  ? 3: uint,                    ; payload mode
  ? 4: uint,                    ; payload length if known
  ? 5: { * int / tstr => any }, ; result/meta
  ? 6: { * int / tstr => any }  ; extensions
}
```

### 16.7 DATA frame
`DATA` frame передаёт raw bytes.  
Если `payload mode = chunk-stream`, то каждый DATA frame относится к одному chunk fragment и должен сопровождаться chunk metadata в параметрах stream-а либо в отдельном descriptor frame.

---

## 17. SETTINGS negotiation

### 17.1 SETTINGS must include
- `max_chunk_size`
- `max_manifest_size`
- `max_object_size`
- `max_parallel_streams`
- `supported_chunkers`
- `supported_content_encodings`
- `supported_token_profiles`
- `supported_extensions`
- `server_instance_id`
- `event_replay_window_sec`
- `limits_revision`

### 17.2 Обязательное поведение
- Неизвестные некритичные settings могут игнорироваться.
- Неизвестные критичные settings должны вызывать `421 unsupported_setting` или connection error.
- Клиент обязан проверить лимиты до начала upload session.

---

## 18. Операции протокола

## 18.1 `INFO`
Назначение: получить server info / limits / capabilities.  
Payload: отсутствует.  
Ответ: metadata map.

### Результат
- features
- limits
- deployment id
- `e2ee_required`
- `storage_encryption_required`
- `crypto_suite`
- `key_wrapping_suite`
- `tenant_isolation_profile`
- optional supported auth issuers
- optional replication classes

---

## 18.2 `HEAD`
Назначение: получить manifest metadata без payload.

### Входные параметры
- `selector`: `cid` или `ns`
- `cid`?: string
- `namespace`?: string
- `path`?: string
- `if_match_cid`?
- `want_signature`?: bool

### Выход
- object cid
- manifest
- etag-like cid
- storage class
- logical size
- stored size
- content type
- revision (если обращение через namespace)

### Ограничения public profile
- Application metadata в `HEAD` по умолчанию не должна раскрываться без явной policy.
- Сервер **MUST** отличать server-visible metadata от encrypted client metadata.

---

## 18.3 `GET`
Назначение: получить объект или его часть.

### Входные параметры
- `selector`: `cid` | `ns`
- `cid`?
- `namespace`?
- `path`?
- `range_start`?
- `range_end`?
- `prefer`: `raw` | `chunk-stream` | `manifest-only`
- `if_none_match_cid`?
- `want_peer_hints`?: bool

### Поведение
- По умолчанию сервер может выдавать либо raw assembled object, либо chunk-stream согласно negotiation.
- Для large objects клиент **SHOULD** использовать `chunk-stream`.
- При range request сервер обязан либо:
  - вернуть 206 с запрошенным диапазоном;
  - либо вернуть ошибку 416.

### Требования
- Чтение по CID **MUST** обходить namespace.
- Чтение по namespace должно вернуть current binding revision.
- При `prefer=manifest-only` сервер возвращает только metadata.

---

## 18.4 `PUT_INIT`
Назначение: открыть upload session.

### Входные параметры
- `manifest`
- `idempotency_key`
- `encryption_profile_id`
- `key_policy_id`
- `metadata_visibility`
- `storage_class`
- `retention_until`?
- `pin`?: bool
- `dedup_probe`?: bool
- `atomic_bind`?: {
    namespace,
    path,
    if_revision?
  }

### Выход
- `session_id`
- `missing_chunks`
- `accepted_manifest`
- `upload_deadline`
- `max_parallel_chunk_streams`

### Поведение
Сервер сравнивает chunk list из manifest с already-present chunk store и отвечает списком отсутствующих chunks.

---

## 18.5 `PUT_CHUNK`
Назначение: загрузить один chunk для открытой upload session.

### Входные параметры
- `session_id`
- `chunk_index`
- `chunk_cid`
- `chunk_offset`
- `chunk_length`
- `content_encoding`

### Payload
Raw bytes chunk-а.

### Выход
- `stored`: bool
- `duplicate`: bool
- `verified_cid`: bool

### Требования
- Сервер обязан вычислить CID из принятых bytes и сравнить с `chunk_cid`.
- При mismatch сервер обязан отклонить chunk.
- Сервер не должен делать объект видимым до `PUT_COMMIT`.

---

## 18.6 `PUT_COMMIT`
Назначение: завершить upload session.

### Входные параметры
- `session_id`
- `manifest_cid`
- `idempotency_key`

### Выход
- `object_cid`
- `committed`: bool
- `bound_revision`? если был atomic bind
- `event_seq`?

### Требования
- Commit должен быть атомарным.
- Если atomic bind включён, объект и bind должны появиться как единая транзакция видимости.
- Повтор с тем же `idempotency_key` должен возвращать тот же результат.

---

## 18.7 `RESOLVE`
Назначение: получить current binding по namespace path.

### Входные параметры
- `namespace`
- `path`
- `at_revision`?
- `if_revision`?

### Выход
- `revision`
- `target_cid`
- `manifest_cid`
- `record_cid`
- `metadata`
- `tombstone`: bool

---

## 18.8 `BIND`
Назначение: создать или обновить mapping path -> CID.

### Входные параметры
- `namespace`
- `path`
- `target_cid`
- `if_revision`?
- `metadata`?
- `ttl`?
- `idempotency_key`

### Выход
- `revision`
- `record_cid`
- `event_seq`

### Требования
- `BIND` без `if_revision` допускается только если policy namespace это разрешает.
- Для production profile reference server **SHOULD** требовать `if_revision` на mutation operations.

---

## 18.9 `UNBIND`
Назначение: создать tombstone или удалить binding.

### Входные параметры
- `namespace`
- `path`
- `if_revision`
- `hard_delete`?: bool
- `idempotency_key`

### Выход
- `revision`
- `tombstone`: bool
- `event_seq`

### Требования
- По умолчанию `UNBIND` означает tombstone.
- `hard_delete` — административная операция и не должна быть доступна обычному токену записи.

---

## 18.10 `LIST`
Назначение: перечислить записи namespace.

### Входные параметры
- `namespace`
- `prefix`?
- `cursor`?
- `limit`?
- `recursive`?: bool
- `include_tombstones`?: bool

### Выход
- `items`
- `next_cursor`
- `truncated`
- `namespace_revision_snapshot`

### Требования
- Listing должен быть snapshot-consistent в рамках одной страницы ответа.
- Если нужен долгий список, сервер должен вернуть cursor.

---

## 18.11 `SUBSCRIBE`
Назначение: подписка на события.

### Входные параметры
- `filter`: one or many
- `cursor`?
- `from_seq`?
- `heartbeat_ms`?
- `batch_max`?

### Фильтры v1.0
- `namespace_prefix`
- `path_exact`
- `object_cid`
- `event_type`
- `tenant_scope`

### Выход
- server открывает event stream и отправляет:
  - `EVENT`
  - `NOTICE`
  - heartbeat

### Гарантии
- Доставка событий как минимум **at-least-once**.
- Порядок гарантируется в пределах одного event partition.
- Каждое событие имеет monotonic `seq`.

---

## 18.12 `PIN`
Назначение: запросить retention для объекта.

### Входные параметры
- `cid`
- `pin_until`
- `reason`?
- `idempotency_key`

### Выход
- `pin_accepted`
- `effective_until`

---

## 19. Capability tokens и модель авторизации

### 19.1 Общая модель
HSP v1.0 использует capability-based authorization.

Токен должен ограничивать:
- who
- what
- where
- until when
- with which rights

### 19.2 Формат
Базовый формат токена v1.0:
- CBOR claims set
- COSE protection
- transport как token в native `AUTH` frame или в gateway header
- proof-of-possession / channel-binding context для public multi-tenant profile

### 19.3 Минимальные claims
- `iss`
- `sub`
- `aud`
- `exp`
- `nbf`?
- `jti`
- `ops`
- `namespace_prefix`?
- `path_prefix`?
- `cid_allowlist`?
- `max_object_size`?
- `storage_classes`?

### 19.4 Права v1.0
- `read`
- `write`
- `bind`
- `unbind`
- `list`
- `subscribe`
- `pin`
- `replicate`
- `admin.metrics.read`
- `admin.audit.read`
- `admin.repair`
- `admin.key.rotate`
- `admin.policy.write`

### 19.5 Правила валидации
- Token без `exp` недопустим.
- Token с неизвестным issuer недопустим.
- Token с опами шире server policy должен быть отклонён.
- `jti` **MUST** использоваться для replay protection на mutation operations в public profile.
- Bearer-only semantics без channel binding не допускаются как public default.

---

## 20. Подписи и encryption descriptors

### 20.1 Manifest signature
Manifest может быть:
- unsigned;
- signed.

Подписанный manifest обязателен для профилей:
- public provenance;
- supply-chain;
- notarized content.

### 20.2 Namespace record signature
Namespace mutation в public multi-tenant deployment **MUST** быть сохраняема с cryptographic proof:
- либо сохранённая подпись записи;
- либо аудиторский след с проверяемым issuer.

### 20.3 Algorithm profile v1.0
Нужно определить minimum-to-implement algorithm suite в отдельном registry/profile документе.  
В профиль v1.0 должны войти:
- `Ed25519` для signatures;
- `COSE_Sign1` для capability tokens и signed records;
- `XChaCha20-Poly1305` для client-side object encryption;
- `AES-256-GCM` для server-side envelope encryption persisted stores;
- `HPKE/X25519` для wrapped object-key delivery;
- `SHA-256` для CID hashing.
- Для public profile должна быть определена key hierarchy: tenant master key, object data key, wrapped object-key records и server-side KEK/DEK layers.

---

## 21. Сжатие и content encoding

### 21.1 Supported encodings
Обязательный encoding:
- `identity`

Опциональный encoding:
- `zstd`

### 21.2 Правила
- Manifest обязан указывать logical content encoding.
- Если chunk хранится в сжатом виде, это должно быть отражено в chunk metadata.
- CID чанка считается по реально хранимым bytes чанка.

### 21.3 Ограничения
- Сервер не должен молча менять content encoding после commit.
- Recompression допустим только в storage-class profile, где CID не зависит от post-processing, что не входит в core v1.0.

---

## 22. Репликация и storage classes

### 22.1 Storage classes v1.0
- `local`
- `edge`
- `durable`
- `archive`

### 22.2 Семантика
- `local` — минимальная durability гарантия, быстрый локальный доступ.
- `edge` — объект должен быть доступен на edge nodes по policy deployment.
- `durable` — объект должен храниться согласно policy durability.
- `archive` — доступ может быть медленнее, но retention дольше.

### 22.3 Replica hints
Клиент может указывать:
- desired storage class;
- preferred geo scope;
- retention class.

Но сервер имеет право:
- понизить класс;
- отклонить запрос;
- вернуть effective policy.

---

## 23. Peer-assisted transfer extension

### 23.1 Статус
Необязательное расширение v1.0-ext.

### 23.2 Назначение
Для уменьшения нагрузки на origin/edge при раздаче больших и популярных объектов.

### 23.3 Требования
- Peer hints выдаются только при явной server policy.
- Peer hints должны быть краткоживущими.
- Peer hints должны быть подписаны/заверены сервером.
- Клиент не должен доверять peer content без проверки chunk CID.

### 23.4 Важно
Peer-assisted transfer не должен влиять на trust model:
- доверяем только проверяемым chunk hashes и manifest.

---

## 24. События и подписки

### 24.1 Event types v1.0
- `object.committed`
- `namespace.bound`
- `namespace.unbound`
- `namespace.tombstoned`
- `pin.accepted`
- `replica.available`
- `replica.evicting`
- `policy.changed`

### 24.2 Event record schema
```cddl
event-record = {
  0: 1,                ; schema version
  1: uint,             ; seq
  2: uint,             ; unix ts ms
  3: tstr,             ; event type
  4: tstr,             ; subject kind
  ? 5: tstr,           ; namespace
  ? 6: tstr,           ; path
  ? 7: tstr,           ; cid
  ? 8: uint,           ; revision
  ? 9: tstr,           ; trace id
  ? 10: any            ; compact payload
}
```

### 24.3 Replay
- Сервер обязан хранить replay window не меньше значения, объявленного в SETTINGS.
- Cursor должен быть устойчивым в рамках replay window.
- При истекшем cursor сервер возвращает специальную ошибку и рекомендуемый restart point.

### 24.4 Heartbeats
- При отсутствии событий сервер обязан слать heartbeat.
- Heartbeat интервал должен быть configurable.
- По умолчанию рекомендуется не более 30 секунд.

---

## 25. Ошибки и статусы

### 25.1 Статусы v1.0
Используется HTTP-like модель кодов.

#### Успех
- `200 ok`
- `201 created`
- `202 accepted`
- `204 no_content`
- `206 partial_content`

#### Ошибки клиента
- `400 bad_request`
- `401 auth_required`
- `403 forbidden`
- `404 not_found`
- `409 conflict`
- `410 gone`
- `412 precondition_failed`
- `413 payload_too_large`
- `416 range_not_satisfiable`
- `422 invalid_object`
- `429 too_many_requests`

#### Ошибки сервера
- `500 internal_error`
- `501 not_implemented`
- `503 overloaded`
- `504 upstream_timeout`

### 25.2 Error frame body
```cddl
error-body = {
  0: 1,          ; schema version
  1: uint,       ; status
  2: tstr,       ; name
  3: bool,       ; retryable
  ? 4: tstr,     ; detail
  ? 5: tstr,     ; trace id
  ? 6: any       ; extra
}
```

### 25.3 Требования
- Каждая ошибка должна иметь machine-readable name.
- Каждая ошибка mutation operations должна содержать trace id.
- Retryable ошибки обязаны быть явно маркированы.

---

## 26. Идемпотентность и повторы

### 26.1 Операции, требующие idempotency key
- `PUT_INIT`
- `PUT_COMMIT`
- `BIND`
- `UNBIND`
- `PIN`

### 26.2 Поведение сервера
- Сервер должен кэшировать результат idempotent mutation в течение configurable window.
- Повтор с тем же `idempotency_key` должен вернуть тот же результат либо явно указать, что операция уже была завершена.

### 26.3 Требования
- Отсутствие idempotency key на mutation profile `public` должно считаться невалидным запросом, если deployment policy так настроена.
- Reference implementation в multi-tenant public mode **MUST** требовать idempotency key.

---

## 27. Версионирование и расширения

### 27.1 Версия протокола
Major version кодируется в ALPN:
- `hsp/1`

### 27.2 Версия схем
Отдельно версионируются:
- manifest schema
- namespace record schema
- event schema
- token profile

### 27.3 Расширения
Расширения делятся на:
- `non-critical`
- `critical`

### 27.4 Правила обработки
- Unknown non-critical extension можно игнорировать.
- Unknown critical extension должен приводить к отказу операции.
- Для каждой extension требуется:
  - идентификатор;
  - краткое имя;
  - статус;
  - ссылка на спецификацию;
  - правила backward compatibility.

---

## 28. Регистры протокола

На старте проекта нужно создать публичные регистры в репозитории.

### 28.1 Обязательные registries
- frame types
- operation names
- status names
- extension ids
- event types
- chunkers
- content encodings
- storage classes
- token profiles
- signature/encryption profiles

### 28.2 Формат registry
Каждый registry:
- machine-readable JSON/CBOR/YAML
- human-readable markdown table
- уникальные immutable записи
- policy для provisional/final статусов

---

## 29. HTTP/3 gateway

### 29.1 Назначение
Gateway нужен для:
- браузерной интеграции;
- curl/dev tooling;
- плавной миграции;
- CDN interoperability;
- public bootstrap.

### 29.2 Обязательные endpoints v1.0
- `GET /.well-known/hsp`
- `GET /v1/info`
- `HEAD /v1/objects/cid/{cid}`
- `GET /v1/objects/cid/{cid}`
- `POST /v1/uploads`
- `PUT /v1/uploads/{session_id}/chunks/{chunk_index}`
- `POST /v1/uploads/{session_id}:commit`
- `GET /v1/namespaces/{namespace}/resolve/{path}`
- `PUT /v1/namespaces/{namespace}/bind/{path}`
- `DELETE /v1/namespaces/{namespace}/bind/{path}`
- `GET /v1/namespaces/{namespace}/list`
- `GET /v1/events`

### 29.3 Сопоставление семантик
- Gateway не должен менять object model.
- Gateway не должен генерировать другие CID.
- Gateway не должен подменять revision semantics.

### 29.4 Форматы gateway
- JSON для bootstrap and control responses.
- Raw bytes для object payload.
- SSE или WebTransport для event delivery допускаются как gateway profile.

---

## 30. Совместимость с S3-стилем

### 30.1 Статус
Не часть core v1.0, но желательная опция reference ecosystem.

### 30.2 Маппинг
- `bucket` -> `namespace`
- `key` -> `path`
- `object metadata` -> manifest metadata
- `ETag` -> object CID либо derived compatibility tag
- `PUT Object` -> `PUT_INIT + PUT_CHUNK + PUT_COMMIT`
- `GET Object` -> `GET`

### 30.3 Ограничения
- Multipart upload semantics S3 не обязаны совпадать 1:1.
- ACL model S3 не переносится напрямую.
- Версионирование bucket/key не должно ломать native revision model HSP.

---

## 31. Reference implementation

### 31.1 Обязательные deliverables
1. `hspd` — reference server на Rust.
2. `hsp-go` — reference client SDK/library на Go.
3. `hspctl` — CLI.
4. `hsp-gw` — HTTP/3 gateway на Rust.
5. `hsp-conformance` — тестовый набор на Rust.
6. `hsp-spec` — публичная спецификация.
7. `hsp-registry` — публичные регистры.

### 31.2 Обязательные свойства reference server
- Native QUIC listener.
- Deterministic CID generation.
- Chunk dedup.
- Namespace authority.
- Event stream.
- Token validation.
- Audit log.
- Server-side encryption для всех persisted stores.
- KMS/HSM-backed key hierarchy.
- Strict tenant isolation и channel-bound auth для public profile.
- Configurable storage backend interface.

### 31.3 Storage backend abstraction
Reference server должен поддерживать backend abstraction:
- chunk store
- manifest store
- namespace store
- event log
- token/issuer cache
- pin/retention store
- kms/key-management adapter

### 31.4 Важно
Storage backend interface не должна протаскивать S3-like assumptions в ядро HSP.
Storage backend interface не должна хранить plaintext keys на диске и не должна допускать cross-tenant plaintext dedup как неявную оптимизацию.

---

## 32. Набор тестов и валидация совместимости

### 32.1 Типы тестов
- unit tests
- golden tests
- cross-implementation tests
- fuzz tests
- property-based tests
- benchmark tests
- security regression tests

### 32.2 Обязательные golden vectors
Нужно подготовить публичный набор test vectors для:
- CID generation
- manifest canonicalization
- chunk hash verification
- namespace record signing
- token validation
- range assembly
- event replay cursor

### 32.3 Interop suite
Interop suite должна проверять:
1. одна реализация генерирует объект;
2. вторая читает его по CID;
3. вторая читает по namespace path;
4. третья валидирует manifest signature;
5. четвёртая возобновляет subscription по cursor.

### 32.4 Fuzzing
Обязательный fuzzing scope:
- CBOR decoder
- frame parser
- range parser
- bootstrap parser
- token parser
- namespace mutation validation

---

## 33. Наблюдаемость и эксплуатация

### 33.1 Метрики
Reference implementation должна экспортировать:
- active_connections
- active_streams
- bytes_in
- bytes_out
- chunk_dedup_ratio
- object_commit_latency
- namespace_mutation_latency
- event_queue_lag
- auth_failures
- retryable_errors
- storage_backend_latency
- replay_window_usage

### 33.2 Логи
Логи должны содержать:
- timestamp
- trace id
- request id
- operation
- namespace/path or cid
- status
- actor/issuer
- latency
- bytes

Логи **MUST NOT** содержать plaintext payload, raw capability tokens или необернутые key identifiers.

### 33.3 Аудит
Для public mode нужен отдельный audit channel для:
- bind/unbind
- token rejection
- pin changes
- storage class decisions
- admin.metrics.read
- admin.audit.read
- admin.repair
- admin.key.rotate
- admin.policy.write

---

## 34. Требования по производительности

### 34.1 Функциональные performance goals
1. Загрузка объекта не должна требовать полной буферизации объекта в памяти.
2. Выдача range не должна требовать сборки всего объекта целиком.
3. Dedup probe должен позволять повторной загрузке передавать только отсутствующие chunks.
4. При большом числе параллельных streams сервер обязан использовать backpressure, а не падать.

### 34.2 Минимальные проверяемые acceptance targets
На эталонном стенде должны выполняться:
- повторная загрузка объекта с полностью совпадающими chunks передаёт не более 5% от объёма объекта служебных данных;
- range read первых 4 MiB большого объекта выполняется без чтения всех последующих чанков;
- mutation operation с idempotency key безопасно повторяется после обрыва соединения;
- commit объекта размером не менее 4 GiB проходит в потоковом режиме.

---

## 35. Требования по безопасности

### 35.1 Threat model v1.0 должен покрывать
- passive network observer
- active MITM
- replay attacker
- unauthorized writer
- namespace race attacker
- malicious event subscriber
- storage exhaustion attacker
- malformed CBOR attacker
- poisoned peer hints
- chunk corruption / bitrot
- permission escalation via path confusion
- cross-tenant confidentiality attacker
- wrapped-key misuse attacker

### 35.2 Обязательные меры
- TLS 1.3 only for native transport
- authority identity validation
- deterministic CBOR for signed/CID-bearing structures
- bounded parser resource usage
- replay protection for mutation tokens
- channel-bound authorization for public profile
- encryption at rest для всех persisted stores
- workload identity + KMS/HSM для KEK/DEK management
- quotas и rate limiting
- explicit path handling without filesystem semantics
- segment-aware path authorization without prefix confusion
- chunk hash verification on ingest and read path where applicable
- auditability of namespace mutations
- signed namespace mutations in public multi-tenant mode
- plaintext keys must not be persisted on disk
- cross-tenant plaintext deduplication is forbidden in v1.0

### 35.3 Перед публичным релизом v1.0
Обязательно:
- завершённый threat model документ;
- статический анализ;
- dependency review;
- fuzzing report;
- внешний security review либо независимый internal review board.

---

## 36. Публикация протокола в открытый доступ

### 36.1 Обязательные публичные артефакты
- Спецификация в markdown + rendered HTML/PDF.
- CDDL схемы.
- Public registries.
- Reference implementation.
- Conformance suite.
- Test vectors.
- Changelog и version policy.
- Security policy и disclosure process.

### 36.2 Governance
Нужно определить процесс изменений:
- draft
- accepted
- provisional
- final
- deprecated

Рекомендуемый механизм:
- HEP (HSP Enhancement Proposal)
- semver для спецификации артефактов
- отдельный registry review process

### 36.3 Лицензирование
Нужно разделить:
- спецификацию;
- код;
- тестовые векторы;
- примеры.

Рекомендуемая модель:
- спецификация — permissive documentation license;
- reference code — permissive open-source license;
- test vectors — максимально свободная лицензия.

---

## 37. Этапы разработки

### Этап 0. Архитектурное проектирование
**Результат:**
- architecture decision record
- draft protocol model
- threat model v0
- initial registries

### Этап 1. Core native transport
**Результат:**
- QUIC listener/client
- control stream
- SETTINGS negotiation
- frame parser
- basic errors

### Этап 2. Object ingest/read
**Результат:**
- CID generation
- manifest parser
- PUT_INIT / PUT_CHUNK / PUT_COMMIT
- HEAD / GET
- range read
- dedup probe

### Этап 3. Namespace layer
**Результат:**
- RESOLVE / BIND / UNBIND / LIST
- revisions
- tombstones
- atomic bind on commit

### Этап 4. Auth and events
**Результат:**
- AUTH frame
- capability validation
- SUBSCRIBE
- event log and cursor replay

### Этап 5. Gateway and ecosystem
**Результат:**
- HTTP/3 gateway
- bootstrap `.well-known/hsp`
- CLI
- public docs

### Этап 6. Public release hardening
**Результат:**
- conformance suite
- golden vectors
- benchmarks
- security review
- v1.0 release candidate

---

## 38. Критерии готовности v1.0

HSP v1.0 считается готовым к публичному релизу только если выполнены все условия ниже.

### 38.1 Спецификация
- Есть полный protocol spec.
- Есть CDDL.
- Есть registries.
- Есть описание extension policy.
- Есть security considerations.

### 38.2 Реализация
- Есть reference server на Rust.
- Есть reference Go SDK.
- Есть CLI.
- Есть HTTP/3 gateway на Rust.

### 38.3 Interop
- Не менее двух независимых клиентов проходят conformance tests против reference server.
- CID и manifest canonicalization совпадают на всех реализациях.
- Event replay и cursor resume проверены тестами.

### 38.4 Security
- Пройден security review.
- Есть replay protection.
- Есть parser bounds.
- Есть channel-bound auth для public profile.
- Есть encryption at rest для persisted stores и проверяемая key-management модель.
- Есть disclosure process.

### 38.5 Public readiness
- Есть публичный сайт/репозиторий спецификации.
- Есть release notes.
- Есть migration guide.
- Есть compatibility statement для gateway.

---

## 39. Основные риски проекта

1. **Перегрузка MVP лишними фичами**  
   Слишком раннее включение CRDT/P2P/fully decentralized mode сорвёт сроки.

2. **Смешение object semantics и namespace semantics**  
   Нужно жёстко разделять immutable objects и mutable bindings.

3. **Нестабильная canonicalization**  
   Если детерминированное кодирование описано расплывчато, независимые реализации будут генерировать разные CID.

4. **Слишком сложная auth model**  
   Нужно не тащить в ядро весь OAuth-мир; capability profile должен оставаться компактным.

5. **Скрытое наследование S3-модели**  
   Нельзя проектировать HSP как «S3 поверх QUIC». Namespace и CID — это разные сущности.

6. **Неопределённость gateway semantics**  
   HTTP gateway не должен менять семантику native HSP.

---

## 40. Рекомендуемый минимальный scope для первого публичного релиза

### Включить обязательно
- QUIC + TLS
- CBOR + deterministic encoding
- fixed chunking
- SHA-256 CID
- client-side encrypted object data для public profile
- server-side encryption для persisted stores
- manifests
- GET / HEAD / PUT_INIT / PUT_CHUNK / PUT_COMMIT
- namespace bind/unbind/list/resolve
- capability tokens
- channel-bound auth
- events + cursor
- HTTP/3 gateway
- conformance suite
- strict tenant isolation
- отсутствие cross-tenant plaintext dedup

### Отложить
- peer-assisted transfer
- CRDT namespace
- content-defined chunking
- E2EE collaboration profiles поверх базового object encryption
- S3 subset gateway
- complex geo policy syntax

---

## 41. Приложение A. CDDL (минимальный стартовый скелет)

```cddl
cid = tstr
namespace = tstr
path = tstr

chunk-ref = {
  1: cid,
  2: uint,     ; object offset
  3: uint,     ; logical len
  4: uint,     ; stored len
  ? 5: tstr,   ; content encoding
  ? 6: tstr    ; digest alg
}

manifest = {
  1: 1,                ; schema version
  2: "blob",
  3: uint,             ; logical size
  4: uint,             ; stored size
  5: tstr,             ; chunker
  6: [ + chunk-ref ],
  ? 7: tstr,           ; content type
  ? 8: tstr,           ; content encoding
  ? 9: uint,           ; created at ms
  ? 10: uint,          ; expires at ms
  11: any,             ; encryption descriptor
  ? 12: { * tstr => any },
  ? 13: [ * any ]      ; links
}

namespace-record = {
  1: 1,                ; schema version
  2: namespace,
  3: path,
  4: uint,             ; revision
  5: tstr,             ; op
  ? 6: cid,            ; target
  ? 7: cid,            ; prev record cid
  8: uint,             ; timestamp ms
  ? 9: tstr,           ; actor
  ? 10: { * tstr => any }
}

capability-claims = {
  1: tstr,             ; iss
  2: tstr,             ; sub
  3: tstr,             ; aud
  4: uint,             ; exp
  ? 5: uint,           ; nbf
  6: tstr,             ; jti
  7: [ + tstr ],       ; ops
  ? 8: namespace,      ; namespace prefix
  ? 9: path,           ; path prefix
  ? 10: [ * cid ],     ; cid allowlist
  ? 11: uint           ; max object size
}

event-record = {
  1: 1,
  2: uint,             ; seq
  3: uint,             ; ts ms
  4: tstr,             ; event type
  5: tstr,             ; subject kind
  ? 6: namespace,
  ? 7: path,
  ? 8: cid,
  ? 9: uint,           ; revision
  ? 10: tstr,          ; trace id
  ? 11: any
}
```

---

## 42. Приложение B. Пример сценария upload с дедупликацией

1. Клиент chunk-ит локальный файл.
2. Строит manifest.
3. Вычисляет `manifest_cid`.
4. Вызывает `PUT_INIT(manifest, idempotency_key)`.
5. Сервер отвечает `missing_chunks = [3, 8, 9]`.
6. Клиент передаёт только отсутствующие chunks через `PUT_CHUNK`.
7. Клиент вызывает `PUT_COMMIT(session_id, manifest_cid)`.
8. Сервер возвращает `object_cid`.
9. При включённом atomic bind сервер сразу публикует namespace binding.
10. Event stream публикует `object.committed` и `namespace.bound`.

---

## 43. Приложение C. Пример сценария чтения диапазона

1. Клиент вызывает `HEAD` и получает manifest.
2. Определяет, какие chunks перекрывают байтовый диапазон.
3. Вызывает `GET` с `range_start`/`range_end`.
4. Сервер возвращает только нужные bytes или chunk fragments.
5. Клиент собирает ответ без загрузки полного объекта.

---

## 44. Приложение D. Финальное решение по MVP

Для первого публичного релиза зафиксировать:

- Native HSP — обязателен.
- HTTP/3 gateway — обязателен.
- SHA-256 CID — обязателен.
- fixed-size chunking — обязателен.
- deterministic CBOR — обязателен.
- capability tokens — обязателен.
- namespace revisions with optimistic concurrency — обязателен.
- peer-assisted transfer — extension.
- CRDT namespace — extension.
- E2EE advanced profiles — extension.

---

## 45. Итог

HSP v1.0 должен быть выпущен как:
1. открытая спецификация;
2. воспроизводимая эталонная реализация;
3. совместимый набор клиентов;
4. набор тестов и векторов;
5. формализованный и расширяемый protocol ecosystem.

Ключевая инженерная идея HSP:
- **контент immutable и addressable по CID;**
- **имена mutable и управляются через namespace records;**
- **transport построен вокруг потоковой передачи и параллельных streams;**
- **события и авторизация являются нативной частью протокола, а не внешней надстройкой.**
