# HSP - Hybrid Storage Protocol
## Backlog реализации v1.0 по epics и tasks

**Версия:** Draft 0.1  
**Дата:** 2026-04-20  
**Основание:** ТЗ HSP Draft 0.1

**Security baseline этой редакции:** Rust для reference runtime (`hspd`, `hsp-gw`, `hsp-conformance`), обязательный public multi-tenant E2EE profile, server-side encryption всех persisted stores, channel-bound auth, строгая tenant isolation и отсутствие cross-tenant plaintext dedup в v1.0.

## 1. Как читать backlog

Этот backlog не меняет scope ТЗ. Он раскладывает реализацию HSP v1.0 на epics, tasks, milestone-срезы, зависимости и критерии приемки.

### Приоритеты
- **P0** - обязательная задача для выпуска v1.0
- **P1** - нужна для production-readiness, но может идти после core MVP
- **P2** - post-v1 или отложенная задача без права расширять MVP

### Оценка
- **S** - до 2-3 рабочих дней относительной сложности
- **M** - 3-7 рабочих дней относительной сложности
- **L** - более 1 недели и/или требует разбиения на подзадачи

### Definition of Ready
- Есть ссылка на раздел ТЗ или ADR, откуда следует задача.
- Определены входы, выходы и критерии приемки.
- Зависимости закрыты или явно обозначены как блокирующие.
- Понятен владелец задачи и ожидаемый артефакт результата.

### Definition of Done
- Код или спецификация находятся в репозитории и привязаны к задаче.
- Есть unit tests и, если задача влияет на wire semantics, integration/conformance tests.
- Обновлены спецификация, change log, примеры или operator docs там, где это нужно.
- Есть negative cases для ошибочных входных данных и boundary conditions.
- Для внешне наблюдаемого поведения заданы метрики/логи/диагностика, если это применимо.
- Результат проверен на совместимость с native и gateway слоями, если задача затрагивает оба режима.

## 2. Milestone-срезы

### M0. Инициализация проекта
- **Состав:** E0-T1..E0-T8
- **Exit criterion:** Есть monorepo, CI, ADR, dev/test среда, политика релизов и security/disclosure.

### M1. Spec baseline frozen
- **Состав:** E1-T1..E1-T10
- **Exit criterion:** Зафиксированы модель данных, canonical CBOR, CID profile, registries и golden vectors.

### M2. Native transport skeleton
- **Состав:** E2-T1..E2-T10
- **Exit criterion:** Поднимается QUIC connection, работает SETTINGS negotiation и INFO, parser устойчив к malformed input.

### M3. Object storage MVP
- **Состав:** E3-T1..E3-T12
- **Exit criterion:** Работают upload/commit/read/range/dedup и cleanup незавершенных загрузок.

### M4. Namespace + auth
- **Состав:** E4-T1..E4-T10, E5-T1..E5-T6
- **Exit criterion:** Работают resolve/bind/unbind/list, revision checks, capability-based authorization, channel binding и replay protection для public profile.

### M5. Events + gateway beta
- **Состав:** E5-T7..E5-T10, E6-T1..E6-T10, E7-T1..E7-T6
- **Exit criterion:** Есть event log, subscribe/replay, discovery и функциональный HTTP/3 gateway.

### M6. SDK/CLI + operations beta
- **Состав:** E7-T7..E7-T10, E8-T1..E8-T10, E9-T1..E9-T8
- **Exit criterion:** Есть рабочий Go SDK, CLI и эксплуатационный минимум для тестовых инсталляций.

### M7. Public release readiness
- **Состав:** E9-T9..E9-T10, E10-T1..E10-T10
- **Exit criterion:** Conformance, interop, security review, docs site, RC и GA пакет готовы.

### Критический путь
- E0 -> E1 -> E2 -> E3 -> E4 + E5(core) -> E6 + E7(core) -> E8 -> E10
- E9 идет параллельно после стабилизации object/namespace/auth слоев, но его задачи обязательны для production-ready релиза.
- E11 не входит в критический путь v1.0 и должен вестись отдельным roadmap.

## 3. Сводка по epics

- **E0 Основа проекта и процесс поставки** | Приоритет: P0 | Milestone: M0-M1 | Зависимости: -
- **E1 Каноническая модель протокола и регистры** | Приоритет: P0 | Milestone: M1 | Зависимости: E0
- **E2 Транспорт QUIC и ядро wire protocol** | Приоритет: P0 | Milestone: M2 | Зависимости: E1
- **E3 Object ingest и read path** | Приоритет: P0 | Milestone: M3 | Зависимости: E2, E1
- **E4 Namespace layer и консистентность** | Приоритет: P0 | Milestone: M4 | Зависимости: E3, E1
- **E5 Capability auth, подписи и security controls** | Приоритет: P0 | Milestone: M4-M5 | Зависимости: E1, E2, E4
- **E6 Events, SUBSCRIBE и replay** | Приоритет: P0 | Milestone: M5 | Зависимости: E3, E4, E5
- **E7 Discovery, URI и HTTP/3 gateway** | Приоритет: P0 | Milestone: M5-M6 | Зависимости: E1, E2, E3, E4, E5
- **E8 Reference Go SDK и CLI** | Приоритет: P0 | Milestone: M6 | Зависимости: E2-E7
- **E9 Наблюдаемость, эксплуатация и storage policies** | Приоритет: P1 | Milestone: M6-M7 | Зависимости: E3-E8
- **E10 Conformance, interop, performance и публичный релиз** | Приоритет: P0 | Milestone: M7 | Зависимости: E1-E9
- **E11 Post-v1 расширения** | Приоритет: P2 | Milestone: Post-v1 | Зависимости: После GA

## 4. Детализация backlog по epics и tasks

## E0. Основа проекта и процесс поставки
**Цель:** Подготовить репозиторий, правила разработки, CI/CD и публикационный контур, чтобы дальнейшая реализация протокола шла по воспроизводимому и открыто публикуемому процессу.

**Выход из epic:** Есть рабочий monorepo, CI, ADR-процесс, версия спецификации, политика релизов, лицензия и security-процедуры.

**Приоритет / milestone:** P0 / M0-M1

**Зависимости:** -

### E0-T1. Сформировать структуру monorepo
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** -
- **Результат:** Создан каркас репозитория: /spec, /server, /sdk/go, /cli, /gateway, /conformance, /testdata, /docs, /deploy, корневой Cargo workspace для Rust runtime и go.work для SDK/CLI.
- **Критерии приемки:**
  - Структура каталогов зафиксирована в README и не требует ручных договоренностей в команде.
  - Сборка и тесты запускаются из корня репозитория единым способом (`cargo test --workspace`, `go test ./sdk/go/... ./cli/hspctl/...`).

### E0-T2. Ввести ADR и журнал архитектурных решений
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E0-T1
- **Результат:** Для спорных решений используется формализованный ADR-шаблон с нумерацией и статусами proposed/accepted/superseded.
- **Критерии приемки:**
  - Есть шаблон ADR и не менее 5 стартовых решений: transport, encoding, CID, auth model, gateway parity.
  - Изменение ключевой архитектуры без ADR считается нарушением процесса.

### E0-T3. Зафиксировать политику версионирования спецификации и кода
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E0-T2
- **Результат:** Определены правила для spec versions, compatibility statement, RC, GA и patch/minor breaking policy.
- **Критерии приемки:**
  - В репозитории есть отдельный документ Versioning Policy.
  - Для spec и reference implementation описано, что считается breaking change.

### E0-T4. Поднять базовый CI pipeline
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E0-T1
- **Результат:** CI проверяет форматирование, линтеры, unit tests, сборку бинарей и валидацию документов спецификации.
- **Критерии приемки:**
  - Каждый pull request проходит обязательный набор проверок.
  - Провал любой обязательной проверки блокирует merge.

### E0-T5. Описать матрицу артефактов релиза
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E0-T3
- **Результат:** Определено, какие артефакты публикуются: spec, CDDL, golden vectors, server, SDK, CLI, gateway, benchmarks, release notes.
- **Критерии приемки:**
  - Список артефактов и каналов публикации задокументирован.
  - Для каждого артефакта указан владелец и критерий готовности.

### E0-T6. Подготовить security policy и disclosure process
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E0-T1
- **Результат:** Опубликована процедура приема security-отчетов, SLA реакции и правила работы с секретными issue.
- **Критерии приемки:**
  - Есть SECURITY.md и выделенный канал disclosure.
  - Указано, какие версии считаются поддерживаемыми с точки зрения security fixes.

### E0-T7. Подготовить contributor guide, code style и issue templates
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E0-T1
- **Результат:** Новые участники могут локально собрать проект и создать issue/PR по единому шаблону.
- **Критерии приемки:**
  - Есть CONTRIBUTING.md, шаблоны issue/PR и локальная инструкция запуска.
  - Описание code style согласовано для Rust, Go, docs и testdata.

### E0-T8. Собрать базовую dev/test среду
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E0-T1
- **Результат:** Подготовлены docker-compose/контейнеры для локального сервера, gateway, тестовых сертификатов и интеграционных прогонов.
- **Критерии приемки:**
  - Новый разработчик поднимает окружение одной командой.
  - Интеграционные тесты можно гонять локально и в CI без ручной настройки.

## E1. Каноническая модель протокола и регистры
**Цель:** Зафиксировать неизменяемую модель данных, детерминированное кодирование и машиночитаемые регистры, от которых зависят CID, совместимость и независимые реализации.

**Выход из epic:** Зафиксированы core schemas, canonical CBOR profile, CID rules, registries, golden vectors и versioned spec sections.

**Приоритет / milestone:** P0 / M1

**Зависимости:** E0

### E1-T1. Заморозить словарь терминов и инварианты модели
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E0-T2
- **Результат:** Однозначно определены object, chunk, manifest, namespace record, event record, upload session, authority, gateway, edge node.
- **Критерии приемки:**
  - В глоссарии нет конфликтующих или дублирующих терминов.
  - Ключевые инварианты вынесены в отдельный раздел и используются далее без переименований.

### E1-T2. Описать schema manifest и chunk-ref
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E1-T1
- **Результат:** Определен состав manifest body, структура chunk references, object metadata и обязательные поля для CID расчета.
- **Критерии приемки:**
  - CDDL и текстовая спецификация описывают одинаковую структуру без расхождений.
  - Есть как минимум 10 валидных и 10 невалидных примеров manifest.

### E1-T3. Описать schema namespace records и revisions
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E1-T1
- **Результат:** Формализованы bind, unbind, tombstone, revision preconditions и конфликтующие сценарии записи.
- **Критерии приемки:**
  - Определено поведение при одновременных мутациях одного path.
  - Есть тестовые векторы для bind, rebind, unbind и conflict case.

### E1-T4. Описать schema event record и cursor
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E1-T1
- **Результат:** Стандартизованы поля событий, event types, cursor encoding и правила replay/resume.
- **Критерии приемки:**
  - Курсор является детерминированной сериализуемой сущностью.
  - Есть примеры event stream для object commit, bind, unbind, pin и auth failure.

### E1-T5. Зафиксировать deterministic CBOR profile
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E1-T2, E1-T3, E1-T4
- **Результат:** Описаны правила canonical CBOR для всех подписываемых и хешируемых структур, включая запреты на неоднозначные представления.
- **Критерии приемки:**
  - Есть negative cases для non-canonical encodings.
  - Две независимые реализации на golden vectors получают идентичные байты.

### E1-T6. Зафиксировать профиль CID v1.0
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E1-T2, E1-T5
- **Результат:** Определены hash algorithm, multihash-like payload, base32-lower-no-padding и правила расчета CID для manifest и chunk.
- **Критерии приемки:**
  - CID из официальных векторов воспроизводится в spec tests и code tests.
  - Нет неоднозначности между binary form и string form CID.

### E1-T7. Создать регистр ошибок, статусов и SETTINGS
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E1-T1
- **Результат:** Стандартизованы error codes, operation statuses, server settings и policy по резервированию кодов.
- **Критерии приемки:**
  - Каждый код имеет текстовую семантику, category и expected client action.
  - Зарезервирован диапазон для будущих расширений.

### E1-T8. Создать регистры algorithms, claims, capabilities и extensions
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E1-T5, E1-T6
- **Результат:** Формализованы registries для crypto suites, token claims, operation names, extension IDs и media/content encodings.
- **Критерии приемки:**
  - Каждый registry имеет owner policy и process внесения изменений.
  - Формат registry машиночитаем и используется генераторами тестов.

### E1-T9. Подготовить golden vectors для canonicalization и CID
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E1-T2, E1-T3, E1-T4, E1-T5, E1-T6
- **Результат:** В репозитории есть тестовые данные для manifest, namespace records, event records, tokens и ожидаемых CIDs/подписей.
- **Критерии приемки:**
  - Golden vectors используются в conformance suite и unit tests.
  - Любое изменение canonicalization ломает тесты и требует формального решения.

### E1-T10. Упаковать спецификацию в versioned документы
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E1-T1..E1-T9
- **Результат:** Спецификация разделена на core, security, gateway, registries, conformance и release notes sections.
- **Критерии приемки:**
  - У документа есть версия, change log и статусы draft/rc/ga.
  - Читатель может найти минимально необходимый набор правил без чтения внутреннего кода.

## E2. Транспорт QUIC и ядро wire protocol
**Цель:** Реализовать native HSP transport поверх QUIC v1 с control stream, negotiation SETTINGS, базовой маршрутизацией операций и безопасным парсером кадров.

**Выход из epic:** Поднимается native connection, проходит SETTINGS negotiation, работают INFO/HEAD каркасы, парсер покрыт negative/fuzz тестами.

**Приоритет / milestone:** P0 / M2

**Зависимости:** E1

### E2-T1. Собрать QUIC server/client skeleton
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E0-T8, E1-T1
- **Результат:** Есть минимальный native listener и клиент, которые устанавливают QUIC connection и открывают HSP control stream.
- **Критерии приемки:**
  - Соединение поднимается в локальном окружении и в CI.
  - Есть smoke test на успешное открытие control stream.

### E2-T2. Реализовать ALPN hsp/1 и authority validation
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E2-T1
- **Результат:** Клиент согласует ALPN hsp/1 и валидирует identity authority по сертификату и bootstrap endpoint.
- **Критерии приемки:**
  - Несовпадение authority и certificate identity приводит к предсказуемой ошибке.
  - Есть отдельные тесты для public profile и private-deployment profile.

### E2-T3. Реализовать control stream и SETTINGS negotiation
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E1-T7, E2-T1
- **Результат:** После установки соединения сервер публикует SETTINGS, клиент проверяет обязательные и неизвестные параметры.
- **Критерии приемки:**
  - Проверены сценарии missing required setting, duplicated setting и unsupported extension.
  - SETTINGS доступен в логах и в debug API клиента.

### E2-T4. Реализовать frame envelope и безопасный parser
- **Приоритет:** P0
- **Оценка:** L
- **Зависимости:** E1-T5, E1-T7, E2-T3
- **Результат:** Определены framing rules, длины, типы сообщений и parser с явными bounds checks.
- **Критерии приемки:**
  - Парсер отрабатывает malformed, truncated и oversized frames без паники и утечек.
  - Есть table-driven tests и fuzz harness.

### E2-T5. Описать и реализовать lifecycle request streams
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E2-T4
- **Результат:** Каждая операция выполняется в отдельном request stream с унифицированным request/response жизненным циклом.
- **Критерии приемки:**
  - Сервер поддерживает несколько параллельных запросов в одном connection.
  - Есть тесты на cancel, timeout и half-close сценарии.

### E2-T6. Добавить лимиты, flow control и backpressure hooks
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E2-T5
- **Результат:** Сервер и клиент учитывают лимиты на stream count, frame size, inflight bytes и upload window.
- **Критерии приемки:**
  - При превышении лимита возвращается стандартизованная ошибка, а не произвольный disconnect.
  - Есть нагрузочные тесты на конкурентные запросы.

### E2-T7. Сопоставить ошибки протокола с connection close и stream close
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E1-T7, E2-T4
- **Результат:** Для каждого класса ошибок определено, закрывается stream, connection или только операция.
- **Критерии приемки:**
  - Ошибка одного request stream не роняет connection без необходимости.
  - Таблица сопоставления ошибок есть в spec и reference code.

### E2-T8. Подготовить primitives для retry/idempotency mutation операций
- **Приоритет:** P1
- **Оценка:** M
- **Зависимости:** E2-T5, E1-T7
- **Результат:** Описаны client request IDs, retry hints и базовые правила безопасного повтора мутаций.
- **Критерии приемки:**
  - Повторная отправка PUT_INIT/BIND не приводит к немым дубликатам состояния.
  - Поведение клиента при retry документировано и покрыто тестами.

### E2-T9. Сделать INFO как первую сквозную операцию
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E2-T3, E2-T5
- **Результат:** INFO возвращает server capabilities, version profile, limits и поддержку extensions.
- **Критерии приемки:**
  - Операция доступна и через native transport, и в будущих gateway parity tests.
  - Ответ INFO детерминированно сериализуется и может использоваться в diagnostics.

### E2-T10. Включить fuzzing и property-based тесты для framing
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E2-T4
- **Результат:** Для wire parser настроены fuzz jobs и набор инвариантов на decode/encode round-trip.
- **Критерии приемки:**
  - Fuzzing запускается в CI по расписанию и локально.
  - Найденные краши автоматически сохраняются как regression cases.

## E3. Object ingest и read path
**Цель:** Реализовать загрузку, дедупликацию, публикацию и чтение immutable-объектов по CID с поддержкой chunking, range retrieval и безопасного commit semantics.

**Выход из epic:** Работают PUT_INIT, PUT_CHUNK, PUT_COMMIT, HEAD, GET, range read, dedup probe и cleanup незавершенных загрузок.

**Приоритет / milestone:** P0 / M3

**Зависимости:** E2, E1

### E3-T1. Реализовать fixed chunking profile v1
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E1-T2, E1-T6
- **Результат:** Есть детерминированный fixed-size chunker с задокументированными правилами для последнего чанка и пустых объектов.
- **Критерии приемки:**
  - Одинаковые входные данные на разных реализациях дают одинаковую chunk sequence.
  - Есть тесты на малые, большие и boundary-sized объекты.

### E3-T2. Сделать chunk storage abstraction
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E3-T1
- **Результат:** Сервер пишет и читает чанки через абстракцию backend, не привязанную к одной физической реализации.
- **Критерии приемки:**
  - Есть минимум один файловый backend для dev/test и один production-like backend interface.
  - API backend не требует изменений при добавлении нового storage driver.

### E3-T3. Реализовать state machine для PUT_INIT
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E2-T5, E3-T1, E3-T2
- **Результат:** Создаются upload sessions с ограничениями по размеру, TTL, expected manifest profile и auth context.
- **Критерии приемки:**
  - Сессия имеет уникальный ID и четкие состояния new/active/committable/expired/aborted.
  - Превышение лимитов валидируется до начала массовой загрузки данных.

### E3-T4. Реализовать PUT_CHUNK и dedup probe
- **Приоритет:** P0
- **Оценка:** L
- **Зависимости:** E3-T3, E1-T6
- **Результат:** Сервер принимает чанки, проверяет их CID и умеет не загружать уже существующий chunk повторно без раскрытия cross-tenant plaintext equality.
- **Критерии приемки:**
  - Повторная загрузка уже известного чанка не дублирует физическое хранение.
  - Cross-tenant plaintext dedup не реализован как неявная оптимизация в public profile.
  - Есть сценарии partial upload, duplicate chunk, wrong hash и replayed chunk.

### E3-T5. Реализовать сборку и валидацию manifest
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E3-T4, E1-T2, E1-T5
- **Результат:** Перед commit сервер валидирует, что все chunk refs присутствуют, длины корректны, а manifest сериализован канонически.
- **Критерии приемки:**
  - Некорректный manifest не может быть опубликован ни по CID, ни через namespace bind.
  - Проверки выполняются без сканирования всего хранилища вне необходимых индексов.

### E3-T6. Реализовать PUT_COMMIT с атомарной публикацией объекта
- **Приоритет:** P0
- **Оценка:** L
- **Зависимости:** E3-T5, E2-T8
- **Результат:** Объект становится видимым только после успешного commit; частично загруженный объект не виден клиентам.
- **Критерии приемки:**
  - После сбоя между последним PUT_CHUNK и COMMIT объект не появляется как валидный.
  - Повторный COMMIT одной сессии имеет детерминированное поведение.

### E3-T7. Реализовать HEAD для CID и namespace-resolved объекта
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E3-T6
- **Результат:** HEAD возвращает metadata, length, manifest CID, timestamps, storage class и capability-видимые поля.
- **Критерии приемки:**
  - HEAD не передает тело объекта и работает быстрее полного GET.
  - Проверены сценарии для прямого CID и после RESOLVE.

### E3-T8. Реализовать GET полного объекта
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E3-T6, E2-T6
- **Результат:** Клиент получает поток байтов объекта по CID или после разрешения path -> CID.
- **Критерии приемки:**
  - GET работает без обязательной сборки всего объекта в память сервера.
  - Есть тесты на прерывание клиента и корректное освобождение ресурсов.

### E3-T9. Реализовать range retrieval
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E3-T8
- **Результат:** Сервер умеет отдавать диапазон байт поверх чанкового представления без нарушения CID semantics.
- **Критерии приемки:**
  - Поддержаны edge cases: начало с середины чанка, последний байт, пустой диапазон, invalid range.
  - Результат диапазона совпадает с подмножеством полного GET.

### E3-T10. Добавить контроль целостности и checksum verification
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E3-T4, E3-T8
- **Результат:** На загрузке и выдаче доступны проверки соответствия chunk/object hash ожидаемым значениям.
- **Критерии приемки:**
  - Поврежденный chunk детектируется до передачи клиенту.
  - Диагностика ошибок различает corruption, missing chunk и hash mismatch.

### E3-T11. Реализовать уборку abandoned upload sessions
- **Приоритет:** P1
- **Оценка:** M
- **Зависимости:** E3-T3, E3-T6
- **Результат:** Протухшие незавершенные загрузки очищаются планировщиком без удаления валидных опубликованных chunk refs.
- **Критерии приемки:**
  - GC не удаляет chunk, если на него уже ссылается committed object.
  - Есть тест на concurrent GC и активную загрузку.

### E3-T12. Подготовить ingest/read benchmarks
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E3-T8, E3-T9
- **Результат:** Есть репрезентативные бенчмарки для малых объектов, крупных файлов и диапазонного чтения.
- **Критерии приемки:**
  - Bench suite воспроизводима в CI и локально.
  - Для каждого сценария публикуются baseline numbers и методика измерения.

## E4. Namespace layer и консистентность
**Цель:** Построить mutable namespace поверх immutable-объектов с atomic bind/unbind semantics, ревизиями, tombstones и конкурентно безопасными precondition checks.

**Выход из epic:** Работают RESOLVE, BIND, UNBIND, LIST, revision checks, tombstones и bind-on-commit без нарушения object semantics.

**Приоритет / milestone:** P0 / M4

**Зависимости:** E3, E1

### E4-T1. Определить storage model для namespace authority
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E1-T3, E3-T6
- **Результат:** Выбран способ хранения namespace state и history: текущие bindings, revision journal, tombstones, индексы по prefix.
- **Критерии приемки:**
  - Модель хранит текущее состояние и историю мутаций раздельно, без смешения с object store.
  - Проверен сценарий восстановления состояния из журнала.

### E4-T2. Реализовать RESOLVE
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E4-T1
- **Результат:** Путь разрешается в текущий binding с возвратом CID, revision, metadata и признака tombstone/absence.
- **Критерии приемки:**
  - Поведение для отсутствующего path и для tombstone различается и задокументировано.
  - Есть тесты на percent-decoding и нормализацию path.

### E4-T3. Реализовать BIND c preconditions
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E4-T2, E3-T6
- **Результат:** Клиент может привязать path к CID с условиями if-current-revision, if-absent, expected namespace prefix.
- **Критерии приемки:**
  - Конфликт revision возвращает предсказуемую ошибку и не меняет состояние.
  - Проверен сценарий повторной привязки на тот же CID.

### E4-T4. Реализовать UNBIND и tombstone semantics
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E4-T3
- **Результат:** Удаление path фиксируется как мутация с revision и tombstone, если это требует policy.
- **Критерии приемки:**
  - LIST и RESOLVE корректно работают с tombstoned paths.
  - Поведение retention/tombstone TTL явно задокументировано.

### E4-T5. Реализовать LIST с prefix, pagination и ordering policy
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E4-T1
- **Результат:** Можно перечислять bindings по namespace/prefix с курсорами, лимитами и стабильным порядком выдачи.
- **Критерии приемки:**
  - Pagination не пропускает и не дублирует записи при статическом наборе данных.
  - Есть тесты на большие каталоги и разные prefixes.

### E4-T6. Реализовать revision model и compare-and-swap логику
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E1-T3, E4-T3, E4-T4
- **Результат:** Каждая мутация path или namespace увеличивает ревизию по зафиксированным правилам; сравнение revision используется в BIND/UNBIND.
- **Критерии приемки:**
  - Есть формально описанное поведение при двух конкурентных writers.
  - Тесты подтверждают отсутствие silent lost update.

### E4-T7. Реализовать atomic bind-on-commit
- **Приоритет:** P0
- **Оценка:** L
- **Зависимости:** E3-T6, E4-T3, E4-T6
- **Результат:** Опубликованный объект может быть атомарно привязан к path в рамках одного commit workflow.
- **Критерии приемки:**
  - Не возникает состояния, где path уже указывает на несуществующий объект.
  - Сбой между commit и bind обрабатывается как единая транзакционная операция или детерминированный rollback.

### E4-T8. Подготовить recovery/rebuild namespace state
- **Приоритет:** P1
- **Оценка:** M
- **Зависимости:** E4-T1, E6-T2
- **Результат:** Сервер умеет восстанавливать текущее namespace state из журнала событий и журналов ревизий.
- **Критерии приемки:**
  - Есть offline rebuild tool и тест на восстановление после потери snapshot.
  - Проверена идентичность восстановленного и исходного состояния.

### E4-T9. Добавить namespace quotas и валидацию path policy
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E4-T3, E5-T4
- **Результат:** Сервер ограничивает длину path, depth, запрещенные префиксы и quota по числу bindings.
- **Критерии приемки:**
  - Нарушение policy возвращает стандартизованную ошибку.
  - Ограничения отражаются в INFO/SETTINGS или policy docs.

### E4-T10. Покрыть race cases и конкурентные сценарии
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E4-T3, E4-T4, E4-T6, E4-T7
- **Результат:** Есть отдельный набор concurrency tests для lost update, double bind, bind/unbind race и resume after reconnect.
- **Критерии приемки:**
  - Тесты воспроизводят конфликтующие сценарии детерминированно.
  - Не зафиксировано silent corruption namespace state.

## E5. Capability auth, подписи и security controls
**Цель:** Реализовать авторизацию на capability tokens, channel binding, защиту от replay, проверку подписей и единые security semantics для native и gateway режимов.

**Выход из epic:** Работают AUTH frame, token validation, policy engine, channel binding, replay protection, crypto profile и security parity между native/gateway.

**Приоритет / milestone:** P0 / M4-M5

**Зависимости:** E1, E2, E4

### E5-T1. Реализовать AUTH frame и binding токена к операции
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E1-T8, E2-T5
- **Результат:** Token передается в AUTH frame и связывается с request context без неявного наследования прав; для public profile добавляется proof-of-possession/channel-binding context.
- **Критерии приемки:**
  - Токен либо привязан к конкретной операции, либо правила наследования явно описаны и протестированы.
  - Пустой или недействительный токен не приводит к неопределенному состоянию операции.
  - Bearer-only auth не используется как public default.

### E5-T2. Зафиксировать и реализовать claims model capability token
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E1-T8
- **Результат:** Поддержаны iss, sub, aud, exp, nbf, jti, ops, namespace/path prefixes, size limits, storage class claims, key policy identifiers, metadata visibility mode и granular admin scopes.
- **Критерии приемки:**
  - Отсутствие обязательных claims приводит к формализованной ошибке.
  - Claims model отражен и в spec, и в reference validator.

### E5-T3. Интегрировать COSE verification и key registry
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E1-T8, E5-T2
- **Результат:** Сервер проверяет подпись capability token по выбранному crypto profile и trusted issuer registry.
- **Критерии приемки:**
  - Есть тесты на неизвестный issuer, просроченный ключ, неподдерживаемый algorithm ID.
  - Ключи и issuer metadata обновляются без перекомпиляции кода.

### E5-T4. Сделать policy engine для ops/path/size/storage restrictions
- **Приоритет:** P0
- **Оценка:** L
- **Зависимости:** E5-T2, E5-T3, E4-T3, E3-T3
- **Результат:** Каждая операция проверяется на разрешенные права, namespace/path scope, max object size и storage class policy; path-проверки выполняются segment-aware без prefix confusion.
- **Критерии приемки:**
  - Одинаковый token дает одинаковое решение в native и gateway режимах.
  - Есть подробный denial reason без утечки лишних деталей безопасности.

### E5-T5. Реализовать replay protection по jti и mutation context
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E5-T2, E2-T8
- **Результат:** Для мутаций используется replay cache или эквивалентная защита, предотвращающая повторное применение того же авторизованного действия.
- **Критерии приемки:**
  - `jti` обязателен для каждой mutation operation в public profile.
  - Повтор ранее использованного jti отклоняется по policy.
  - Есть тесты на окна времени, повтор после reconnect и race between replicas.

### E5-T6. Подготовить hooks для mTLS/private-deployment profile
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E2-T2, E5-T4
- **Результат:** Reference implementation поддерживает опциональный профиль private deployment с mTLS или self-signed trust roots.
- **Критерии приемки:**
  - Профиль не влияет на public default semantics.
  - Есть отдельные конфигурации и тесты на включение/выключение режима.

### E5-T7. Реализовать manifest signature profile
- **Приоритет:** P1
- **Оценка:** M
- **Зависимости:** E1-T2, E1-T5, E1-T8
- **Результат:** Manifest может содержать или сопровождаться подписью provenance профиля, проверяемой клиентом и сервером по policy; для public profile encryption descriptor обязателен.
- **Критерии приемки:**
  - Подписанный и неподписанный manifest различаются формально и однозначно.
  - Есть тесты на неверную подпись, unknown signer и mismatched content.

### E5-T8. Добавить доказуемый audit trail для namespace mutations
- **Приоритет:** P1
- **Оценка:** M
- **Зависимости:** E4-T3, E4-T4, E5-T3
- **Результат:** Для bind/unbind сохраняется криптографически или процедурно проверяемый след issuer/token/decision.
- **Критерии приемки:**
  - Можно установить, кто и на каком основании выполнил мутацию.
  - Аудит лог не нарушает privacy policy и retention rules.

### E5-T9. Синхронизировать auth semantics для HTTP/3 gateway
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E7-T4, E5-T4
- **Результат:** Заголовки gateway и native AUTH frame приводят к одинаковой policy evaluation и одинаковым error categories, включая channel-binding checks.
- **Критерии приемки:**
  - Есть cross-protocol tests для allow/deny сценариев.
  - Не появляется скрытых привилегий только в одном из режимов.

### E5-T11. Реализовать key wrapping и channel-bound proof validation
- **Приоритет:** P0
- **Оценка:** L
- **Зависимости:** E5-T1, E5-T3, E3-T6
- **Результат:** Reference implementation поддерживает wrapped object keys, HPKE/X25519 delivery для authorized readers и проверку proof-of-possession/channel binding в public profile.
- **Критерии приемки:**
  - Object keys не сохраняются на диск в plaintext form.
  - Есть тесты на wrong recipient key, tampered wrapped key и invalid channel binding proof.

### E5-T10. Провести security test pack для auth и parser surfaces
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E5-T1..E5-T9
- **Результат:** Подготовлен набор тестов на token tampering, replay, oversized claims, parser abuse и privilege escalation attempts.
- **Критерии приемки:**
  - Все критичные негативные сценарии автоматизированы.
  - Regression tests добавляются для каждой найденной security defect.

## E6. Events, SUBSCRIBE и replay
**Цель:** Сделать событийный слой протокола: emission, durable event log, live subscriptions, cursor resume/replay и observability лагов доставки.

**Выход из epic:** События публикуются для ключевых мутаций, SUBSCRIBE работает в live и replay режиме, клиенты умеют восстанавливаться по cursor.

**Приоритет / milestone:** P0 / M5

**Зависимости:** E3, E4, E5

### E6-T1. Зафиксировать модель emission и event types
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E1-T4, E3-T6, E4-T3, E4-T4
- **Результат:** Определен перечень событий: object committed, object pinned, path bound, path unbound, upload aborted, auth denied, admin repair.
- **Критерии приемки:**
  - Каждое событие имеет четко определенный trigger и payload schema.
  - Список event types синхронизирован с регистром extensions/error codes.

### E6-T2. Реализовать durable event log
- **Приоритет:** P0
- **Оценка:** L
- **Зависимости:** E1-T4, E6-T1
- **Результат:** События сохраняются в append-only журнал с курсором, индексами по namespace/path и retention policy.
- **Критерии приемки:**
  - После рестарта сервера event log не теряет committed records.
  - Есть тесты на восстановление и корректную монотонность cursor.

### E6-T3. Реализовать SUBSCRIBE live stream
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E2-T5, E6-T2
- **Результат:** Клиент подписывается на поток событий по namespace/prefix/filter и получает новые записи в порядке журнала.
- **Критерии приемки:**
  - Подписка не блокирует другие запросы в том же connection.
  - Есть тесты на несколько параллельных подписчиков.

### E6-T4. Реализовать cursor replay и resume after disconnect
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E6-T2, E6-T3
- **Результат:** Клиент может переподключиться и продолжить чтение с известного cursor без пропуска событий.
- **Критерии приемки:**
  - Повторный запуск с курсора дает тот же event suffix, что и непрерывное чтение.
  - Определено поведение для cursor-too-old и invalid cursor.

### E6-T5. Добавить фильтры по namespace/path/op
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E6-T3
- **Результат:** Подписка может ограничиваться namespace, prefix, operation type и, при необходимости, авторизованным scope.
- **Критерии приемки:**
  - Фильтр не выдает данные за пределами capability scope клиента.
  - Есть тесты на несколько фильтров и их пересечения.

### E6-T6. Реализовать heartbeats, backpressure и idle timeout policy
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E2-T6, E6-T3
- **Результат:** Длинные подписки поддерживают keepalive и контролируемое завершение при медленном клиенте или неактивности.
- **Критерии приемки:**
  - Сервер не копит неограниченный буфер для зависшего подписчика.
  - Политика timeouts и buffer limits описана в spec и settings.

### E6-T7. Задокументировать delivery semantics
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E6-T2, E6-T4
- **Результат:** Явно описано, что гарантирует event layer: at-least-once, порядок внутри authority, replay windows, дедуп на клиенте.
- **Критерии приемки:**
  - Клиентская библиотека знает, как обрабатывать дубликаты и восстановление.
  - Не остается двусмысленности между live и replay режимом.

### E6-T8. Покрыть reconnect/partition сценарии интеграционными тестами
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E6-T4, E6-T6
- **Результат:** Есть сценарии потери сети, рестарта сервера, частичной доставки и повторного подключения с курсора.
- **Критерии приемки:**
  - После reconnect клиент либо догоняет события, либо получает формализованную ошибку и способ восстановления.
  - Потеря связи не приводит к silent gap.

### E6-T9. Добавить метрики и диагностику lag/throughput для subscriptions
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E6-T3, E9-T1, E9-T2
- **Результат:** Сервер публикует lag, queue depth, subscriber count и replay hit rate.
- **Критерии приемки:**
  - Метрики доступны для алертов и capacity planning.
  - Диагностика позволяет найти узкие места медленной доставки.

### E6-T10. Сделать инструменты repair и event-log inspection
- **Приоритет:** P1
- **Оценка:** M
- **Зависимости:** E6-T2, E8-T8
- **Результат:** CLI и админ-инструменты умеют читать event log, проверять целостность и инициировать rebuild/reindex.
- **Критерии приемки:**
  - Repair tools не требуют прямого редактирования хранилища вручную.
  - Действия админа логируются и безопасны для production use.

## E7. Discovery, URI и HTTP/3 gateway
**Цель:** Сделать публичный вход в HSP через well-known discovery, URI resolution и semantically equivalent HTTP/3 gateway для массовой интеграции.

**Выход из epic:** Работают bootstrap discovery, URI parsing/resolution, HTTP/3 gateway mapping, streaming parity и cross-protocol compatibility tests.

**Приоритет / milestone:** P0 / M5-M6

**Зависимости:** E1, E2, E3, E4, E5

### E7-T1. Определить bootstrap schema для /.well-known/hsp
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E1-T1, E1-T7
- **Результат:** Bootstrap документ описывает authority, endpoints, supported profiles, crypto suites, gateway URLs, limits, e2ee-required, storage-encryption-required и tenant-isolation-profile.
- **Критерии приемки:**
  - JSON schema bootstrap документа опубликована и валидируется в CI.
  - Минимальный bootstrap достаточен для настройки клиента без чтения внутренних конфигов сервера.

### E7-T2. Реализовать discovery client и authority resolution
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E7-T1, E2-T2
- **Результат:** Клиент получает bootstrap, сопоставляет authority с endpoint и кеширует данные по policy.
- **Критерии приемки:**
  - Определено поведение при устаревшем bootstrap и при смене endpoint.
  - Есть тесты на bootstrap fetch failure и fallback logic.

### E7-T3. Реализовать parser/resolver для hsp:// URI
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E1-T6, E4-T2, E7-T2
- **Результат:** Поддержаны канонические формы URI для cid, manifest и namespace path без двусмысленных преобразований.
- **Критерии приемки:**
  - Невалидные и неоднозначные URI детектируются до начала сетевой операции.
  - Есть тесты на percent-decoding, namespace parsing и authority comparison.

### E7-T4. Составить mapping table native operations -> HTTP/3 routes
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E2-T9, E3-T9, E4-T5, E5-T1
- **Результат:** Для INFO, HEAD, GET, PUT_INIT, PUT_CHUNK, PUT_COMMIT, RESOLVE, BIND, UNBIND, LIST, SUBSCRIBE, PIN описана эквивалентная gateway семантика, включая crypto/key-policy metadata и auth binding requirements.
- **Критерии приемки:**
  - Для каждой операции указаны method, path, headers, body schema и status mapping.
  - Gateway не меняет смысл операции по сравнению с native HSP.

### E7-T5. Реализовать HTTP/3 gateway server
- **Приоритет:** P0
- **Оценка:** L
- **Зависимости:** E7-T4, E3-T8, E4-T3, E5-T4, E6-T3
- **Результат:** Gateway принимает HTTP/3 запросы и транслирует их в те же внутренние операции и policy checks, что и native server.
- **Критерии приемки:**
  - Поддержаны streaming upload/download и long-lived subscription responses.
  - Ошибки и заголовки не теряют диагностическую информацию.

### E7-T6. Обеспечить parity для status/error/auth semantics
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E7-T5, E5-T9
- **Результат:** Native и gateway режимы возвращают эквивалентные категории ошибок, ограничения доступа и metadata fields.
- **Критерии приемки:**
  - Есть матрица parity tests по основным операциям и negative cases.
  - Скрытые различия документированы только там, где они неизбежны из-за transport specifics.

### E7-T7. Добавить reverse proxy / deployment reference
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E7-T5
- **Результат:** Есть референсная схема развертывания public authority с TLS termination, gateway и native endpoint.
- **Критерии приемки:**
  - Документировано минимальное production-развертывание.
  - Есть пример конфигурации для локального и публичного режима.

### E7-T8. Покрыть native/gateway cross-protocol integration tests
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E7-T5, E8-T1
- **Результат:** Набор тестов выполняет одну и ту же операцию через native и через gateway и сравнивает состояние/ответы.
- **Критерии приемки:**
  - Parity tests входят в обязательный CI pipeline.
  - Расхождения фиксируются как bug или как явно задокументированное ограничение.

### E7-T9. Подготовить gateway migration guide
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E7-T4, E8-T9
- **Результат:** Описано, как потребитель HTTP object storage может перейти на HSP gateway и где меняется модель данных.
- **Критерии приемки:**
  - Документ явно объясняет разницу между key-based storage и namespace over immutable content.
  - Есть рабочие примеры curl/CLI/SDK.

### E7-T10. Зафиксировать backlog для non-MVP adapters
- **Приоритет:** P2
- **Оценка:** S
- **Зависимости:** E7-T4
- **Результат:** HTTP/1.1/2 adapter и S3-subset gateway описаны как post-v1 эпики, но не смешаны с core backlog.
- **Критерии приемки:**
  - MVP scope не размывается дополнительной совместимостью.
  - Необходимые интерфейсы расширения зарезервированы заранее.

## E8. Reference Go SDK и CLI
**Цель:** Дать разработчикам рабочий SDK на Go и CLI, которые реализуют рекомендуемый способ использования протокола и служат основой для внешней экосистемы.

**Выход из epic:** Есть стабильный Go SDK, CLI, примеры использования, retry/resume helpers и пакет для интеграционных тестов клиентов против Rust reference runtime.

**Приоритет / milestone:** P0 / M6

**Зависимости:** E2-E7

### E8-T1. Сделать low-level Go client для native transport
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E2-T5, E2-T6, E2-T9
- **Результат:** Клиент умеет открывать connection, проходить discovery, отправлять HSP operations и обрабатывать SETTINGS/errors.
- **Критерии приемки:**
  - SDK скрывает transport internals, но оставляет hooks для advanced control.
  - Есть integration tests против reference server.

### E8-T2. Сделать high-level object API
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E3-T6, E3-T8, E3-T9, E8-T1
- **Результат:** SDK предоставляет Upload, Download, Head, RangeRead, ResolveAndRead с потоковыми интерфейсами.
- **Критерии приемки:**
  - API не вынуждает пользователя буферизовать весь объект в памяти.
  - Есть примеры для файлов, bytes.Reader и streaming writer.

### E8-T3. Сделать namespace API
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E4-T5, E8-T1
- **Результат:** SDK поддерживает Resolve, Bind, Unbind, List и revision preconditions.
- **Критерии приемки:**
  - Ошибки конфликтов и отсутствия path различимы типами/кодами.
  - Есть examples для optimistic concurrency.

### E8-T4. Сделать events/subscriptions API
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E6-T4, E8-T1
- **Результат:** SDK поддерживает Subscribe, ReplayFromCursor, AutoResume и delivery callbacks/iterators.
- **Критерии приемки:**
  - Есть пример восстановление подписки после disconnect.
  - SDK не скрывает факт возможных дубликатов событий.

### E8-T5. Интегрировать auth/token handling в SDK
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E5-T4, E8-T1
- **Результат:** SDK умеет подставлять capability tokens, обновлять их по callback, различать auth failures и передавать channel-binding / wrapped-key context.
- **Критерии приемки:**
  - Токен может быть задан на клиент, на запрос или на конкретный operation scope.
  - Есть тесты на refresh callback и ошибку просроченного токена.

### E8-T6. Сделать retry/resume helpers
- **Приоритет:** P1
- **Оценка:** M
- **Зависимости:** E2-T8, E3-T3, E6-T4, E8-T2
- **Результат:** SDK предоставляет безопасные примитивы для повтора операций и возобновления загрузки/подписки после разрыва.
- **Критерии приемки:**
  - Поведение повторов документировано по каждой мутационной операции.
  - Есть тесты на сетевые разрывы и идемпотентность.

### E8-T7. Сделать CLI upload/download/head/get-range
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E8-T2
- **Результат:** CLI покрывает базовые object operations и выводит как human-readable, так и machine-readable формат.
- **Критерии приемки:**
  - Команды удобны для shell automation и CI.
  - Есть примеры команд для upload, dedup probe, full download и range download.

### E8-T8. Сделать CLI для namespace, events и diagnostics
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E8-T3, E8-T4, E2-T9
- **Результат:** CLI умеет resolve/bind/unbind/list/subscribe, смотреть INFO и отладочные данные authority.
- **Критерии приемки:**
  - Все команды имеют стабильный формат ошибок и exit codes.
  - Есть examples для администраторских и клиентских сценариев.

### E8-T9. Подготовить examples и sample apps
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E8-T2, E8-T3, E8-T4, E7-T9
- **Результат:** В репозитории есть минимальные примеры: file mirror, namespace-based media store, event consumer, gateway integration.
- **Критерии приемки:**
  - Каждый пример собирается и запускается в CI.
  - Примеры не используют скрытые internal APIs.

### E8-T10. Зафиксировать stability policy для SDK/CLI
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E0-T3, E8-T1..E8-T9
- **Результат:** Определены правила API stability, deprecation и совместимости CLI output.
- **Критерии приемки:**
  - Пользователь понимает, какие части SDK/CLI стабильны на v1.0.
  - Breaking changes требуют change log и migration notes.

## E9. Наблюдаемость, эксплуатация и storage policies
**Цель:** Подготовить протокол и reference implementation к реальной эксплуатации: метрики, логи, трейсинг, health checks, storage classes, encryption-at-rest, KMS/HSM, hardened deployment и админ-процедуры.

**Выход из epic:** Есть операционные метрики, structured logs, tracing hooks, health/readiness probes, replication/pin semantics, encrypted persisted stores и runbook для восстановления.

**Приоритет / milestone:** P1 / M6-M7

**Зависимости:** E3-E8

### E9-T1. Определить обязательный набор метрик
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E2-T6, E3-T12, E6-T9
- **Результат:** Стандартизованы метрики по connection, requests, upload sessions, chunk store, namespace mutations, subscriptions и gateway.
- **Критерии приемки:**
  - Для каждой метрики описана единица измерения и cardinality policy.
  - Метрики пригодны для алертов, capacity planning и SLA отчетности.

### E9-T2. Внедрить structured logging
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E2-T5, E5-T8
- **Результат:** Сервер и gateway пишут структурированные логи с request ID, authority, op, result code, latency и auth decision IDs.
- **Критерии приемки:**
  - Логи не содержат секретов, raw capability tokens, plaintext keys и лишних payload bytes.
  - Запрос можно проследить по всем слоям системы.

### E9-T3. Добавить tracing hooks
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E2-T5, E7-T5
- **Результат:** Интегрированы tracing spans для discovery, connect, auth, upload, commit, resolve, list, subscribe и gateway proxying.
- **Критерии приемки:**
  - Трассировка может быть отключена без изменения внешней семантики.
  - Накладные расходы трассировки измерены и задокументированы.

### E9-T4. Реализовать storage class semantics и валидацию
- **Приоритет:** P1
- **Оценка:** M
- **Зависимости:** E1-T8, E3-T6, E5-T4
- **Результат:** Поддержаны storage classes, server-side policy checks и обязательная envelope encryption для chunk store, manifest store, namespace store, event log, audit log, token cache и backups.
- **Критерии приемки:**
  - Запрос на неподдерживаемый класс хранения отклоняется предсказуемо.
  - Storage class и encryption requirements отражаются в HEAD/INFO и в policy docs.

### E9-T5. Реализовать replication hints и PIN semantics
- **Приоритет:** P1
- **Оценка:** M
- **Зависимости:** E3-T6, E6-T1, E9-T4
- **Результат:** PIN и replica hints влияют на хранение/удержание объекта без изменения его CID и namespace semantics.
- **Критерии приемки:**
  - PIN не превращается в скрытую мутацию данных объекта.
  - Есть тесты на pin/unpin и сохранение объекта при GC.

### E9-T6. Добавить rate limits, quotas и overload policy
- **Приоритет:** P1
- **Оценка:** M
- **Зависимости:** E2-T6, E5-T4
- **Результат:** Сервер умеет ограничивать concurrent streams, upload throughput, namespace ops и subscription fan-out по policy.
- **Критерии приемки:**
  - При перегрузке сервер отказывает управляемо, а не деградирует бесконтрольно.
  - Коды отказа и retry hints задокументированы.

### E9-T7. Подготовить config profiles для public, private, edge roles
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E2-T2, E5-T6, E7-T7
- **Результат:** Есть понятные профили конфигурации для origin node, edge node, gateway-only и private deployment, включая rootless containers, read-only filesystem, seccomp/AppArmor/SELinux и workload identity для KMS/HSM.
- **Критерии приемки:**
  - Профили можно включать без переписывания кода.
  - Каждый профиль имеет список разрешенных и запрещенных опций.

### E9-T8. Сделать health/readiness/admin endpoints
- **Приоритет:** P1
- **Оценка:** S
- **Зависимости:** E7-T5, E9-T1
- **Результат:** Есть отдельные probes для liveness, readiness, dependency health и диагностических админ-операций.
- **Критерии приемки:**
  - Readiness отражает состояние chunk store, namespace store и event log.
  - Админ-эндпойнты защищены, scope-ограничены и не торчат в public profile по умолчанию.

### E9-T9. Описать backup/restore и disaster recovery
- **Приоритет:** P1
- **Оценка:** M
- **Зависимости:** E3-T11, E4-T8, E6-T2, E9-T8
- **Результат:** Есть runbook для snapshot, backup, восстановления chunk store, namespace state и event log; backup-артефакты шифруются по умолчанию и учитывают key recovery/rewrap процедуры.
- **Критерии приемки:**
  - Проведено хотя бы одно тестовое восстановление на чистой среде.
  - Процедура восстановления имеет измеримый RPO/RTO baseline.

### E9-T10. Собрать dashboards и alert rules
- **Приоритет:** P2
- **Оценка:** S
- **Зависимости:** E9-T1, E9-T2, E9-T3
- **Результат:** Подготовлены базовые dashboards для latency, error rates, storage growth, lag и saturation.
- **Критерии приемки:**
  - Есть минимум один набор алертов для production-ready развертывания.
  - Dashboards соответствуют выбранной метрике и naming scheme.

## E10. Conformance, interop, performance и публичный релиз
**Цель:** Закрыть публичный релиз HSP v1.0: тесты совместимости, golden vectors, интероперабельность независимых реализаций, security review, benchmarks и выпуск RC/GA.

**Выход из epic:** Есть conformance suite, interop matrix, security review, performance baselines, release site и v1.0 RC/GA пакет.

**Приоритет / milestone:** P0 / M7

**Зависимости:** E1-E9

### E10-T1. Собрать conformance suite harness
- **Приоритет:** P0
- **Оценка:** L
- **Зависимости:** E1-T9, E7-T8, E8-T1
- **Результат:** Набор тестов проверяет canonicalization, CID, operations, auth, events, gateway parity и error handling на black-box уровне.
- **Критерии приемки:**
  - Тесты можно запускать против внешнего сервера без внутренних зависимостей.
  - Результат прогона формируется в машиночитаемом и human-readable виде.

### E10-T2. Опубликовать golden vectors package
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E1-T9, E10-T1
- **Результат:** Отдельный пакет golden vectors versioned вместе со спецификацией и используется сторонними реализациями.
- **Критерии приемки:**
  - Сторонний разработчик может скачать vectors и проверить свою реализацию локально.
  - Изменение vectors требует version bump и change log.

### E10-T3. Провести интероперабельность минимум двух независимых клиентов
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E10-T1, E8-T1
- **Результат:** Не менее двух отдельных клиентских реализаций проходят conformance tests и совместимы по CID/event/gateway semantics.
- **Критерии приемки:**
  - Есть документированный interop matrix с версиями и результатами.
  - Зафиксированы известные несовместимости и решения по ним.

### E10-T4. Расширить fuzzing, property tests и malformed corpus
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E2-T10, E5-T10, E10-T1
- **Результат:** Покрыты parser surfaces, token parsing, bootstrap, gateway request translation и chunk/manifest validation.
- **Критерии приемки:**
  - Есть централизованный corpus негативных кейсов.
  - Каждый найденный дефект закрепляется как regression case.

### E10-T5. Собрать performance suite и baseline numbers
- **Приоритет:** P1
- **Оценка:** M
- **Зависимости:** E3-T12, E6-T9, E9-T1
- **Результат:** Подготовлены профили latency/throughput для upload, range read, list, subscribe и gateway proxy scenarios.
- **Критерии приемки:**
  - Методика тестирования и аппаратная среда задокументированы.
  - Есть целевые и фактические baseline показатели для RC.

### E10-T6. Обновить threat model и пройти security review
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E5-T10, E7-T6, E9-T9
- **Результат:** Проект проходит внутренний/внешний security review, а threat model синхронизирован с реальным scope v1.0.
- **Критерии приемки:**
  - Все критичные findings закрыты или явно вынесены в accepted risk register.
  - Есть публичный раздел Security Considerations и disclosure policy.

### E10-T7. Подготовить публичный documentation site
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E1-T10, E7-T9, E8-T9
- **Результат:** Публикуются спецификация, quickstart, migration guide, SDK docs, CLI docs, registries и conformance guide.
- **Критерии приемки:**
  - Сайт собирается из репозитория и versioned вместе с релизом.
  - Навигация по документам не требует чтения исходного кода.

### E10-T8. Собрать release candidate checklist
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E10-T1..E10-T7
- **Результат:** Есть формальный чеклист RC: frozen registries, tests pass, benchmarks recorded, known issues triaged, migration docs ready.
- **Критерии приемки:**
  - Ни один RC не выпускается без заполненного чеклиста.
  - Чеклист привязан к артефактам релиза и владельцам.

### E10-T9. Опубликовать registries и release artifacts
- **Приоритет:** P0
- **Оценка:** S
- **Зависимости:** E10-T7, E10-T8
- **Результат:** Spec, registries, server, gateway, SDK, CLI, vectors и notes публикуются как единый release set.
- **Критерии приемки:**
  - Релиз воспроизводим по тегу репозитория.
  - Пользователь может скачать все обязательные артефакты без внутренних доступов.

### E10-T10. Выпустить v1.0 RC и GA
- **Приоритет:** P0
- **Оценка:** M
- **Зависимости:** E10-T1..E10-T9
- **Результат:** Сначала выпускается v1.0 RC, затем после окна стабилизации и закрытия blocker issues выпускается v1.0 GA.
- **Критерии приемки:**
  - Есть release notes, compatibility statement и список известных ограничений.
  - GA выпуск опирается на результаты interop, security и performance пакетов.

## E11. Post-v1 расширения
**Цель:** Собрать направления, которые не должны ломать MVP, но должны быть подготовлены как следующий слой развития HSP после стабильного публичного релиза v1.0.

**Выход из epic:** Есть отдельный roadmap extensions без смешения с обязательным scope v1.0.

**Приоритет / milestone:** P2 / Post-v1

**Зависимости:** После GA

### E11-T1. Peer-assisted transfer extension
- **Приоритет:** P2
- **Оценка:** L
- **Зависимости:** E3, E6, E10
- **Результат:** Добавить расширение peer-assisted data transfer с relay/fallback semantics и отдельным security profile.
- **Критерии приемки:**
  - Расширение не меняет core semantics object/CID.
  - Описаны NAT traversal, relay fallback и trust boundaries.

### E11-T2. Content-defined chunking profile
- **Приоритет:** P2
- **Оценка:** M
- **Зависимости:** E3-T1, E10-T5
- **Результат:** Подготовить альтернативный chunking профиль для лучшей дедупликации изменяющихся файлов.
- **Критерии приемки:**
  - Новый профиль имеет отдельный registry ID и не ломает fixed chunking v1.
  - Есть benchmark сравнение с fixed chunking.

### E11-T3. CRDT namespace extension
- **Приоритет:** P2
- **Оценка:** L
- **Зависимости:** E4, E6, E10
- **Результат:** Исследовать multi-writer CRDT namespace для collaborative/offline-first сценариев.
- **Критерии приемки:**
  - Расширение изолировано от core single-authority namespace model.
  - Определены merge rules и conflict visibility для клиентов.

### E11-T4. E2EE collaboration profiles
- **Приоритет:** P2
- **Оценка:** L
- **Зависимости:** E5-T7, E8, E10
- **Результат:** Подготовить профили end-to-end encrypted sharing и совместной работы поверх базового object-encryption профиля и namespace records.
- **Критерии приемки:**
  - Ключевое управление не перекладывается в core v1 без отдельного профиля.
  - Есть document threat model для shared encrypted namespace.

### E11-T5. S3-subset compatibility gateway
- **Приоритет:** P2
- **Оценка:** M
- **Зависимости:** E7-T10
- **Результат:** Сделать отдельный adapter для ограниченного S3-подобного входа без подмены core HSP модели.
- **Критерии приемки:**
  - Совместимость описана как adapter layer, а не как semantics HSP.
  - Явно перечислены не поддерживаемые части S3 модели.

### E11-T6. Geo-placement и placement policy language
- **Приоритет:** P2
- **Оценка:** M
- **Зависимости:** E9-T4, E9-T5
- **Результат:** Подготовить язык политик размещения и репликации по регионам/edge roles.
- **Критерии приемки:**
  - Политики не ломают CID и object immutability.
  - Есть отдельный registry или policy schema для placement rules.

### E11-T7. Browser/WASM client profile
- **Приоритет:** P2
- **Оценка:** M
- **Зависимости:** E7-T5, E8-T1
- **Результат:** Проработать клиентский профиль для браузера через gateway или web-совместимый transport layer.
- **Критерии приемки:**
  - Ограничения браузерной среды явно описаны.
  - Не требуется менять core protocol только ради browser compatibility.

### E11-T8. Federation и relay discovery
- **Приоритет:** P2
- **Оценка:** L
- **Зависимости:** E7, E11-T1
- **Результат:** Определить, как authority могут делегировать relay/discovery и не терять проверяемую идентичность.
- **Критерии приемки:**
  - Федерация не ломает authority model v1.0.
  - Описаны trust chains и downgrade risks.

## 5. Рекомендации по исполнению backlog
- Не расширять MVP за счет задач из E11 до фиксации RC scope.
- Все изменения canonicalization, CID, auth claims и gateway parity проводить только через ADR и пересборку golden vectors.
- Параллельную работу команд разделять по слоям: spec, transport, storage, namespace/auth, events/gateway, SDK/CLI, conformance/release.
- После milestone M3 начать ранние black-box тесты внешнего клиента, не дожидаясь полного GA.
- Вести backlog в двух представлениях: документ текущего уровня и трекер задач с разбивкой L-задач на подзадачи.
