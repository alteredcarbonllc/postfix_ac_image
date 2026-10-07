# Кандидаты образов Dovecot и Postfix

Этот архив добавляет сборку, изолированные интеграционные проверки и локальный
импорт образов. Он НЕ переключает production и НЕ меняет работающий mail runtime.

Состав:
- nginx_container/ops/ci-builder: новые проекты/locks и retention кандидатов
  dovecot, postfix и их временных тестовых образов.
- dovecot_ac_image: Containerfile.ci, pipeline и ops/ci.
- postfix_ac_image: аналогичный самостоятельный pipeline и ops/ci.

Старые Dockerfile не заменяются. Для CI используется Containerfile.ci.
Серверный import wrapper отдельный для каждого сервиса, с собственными inbox,
lock и immutable import receipt. Конфигурационные репозитории не меняются.

## Порядок установки

1. Ноутбук: в чистом main nginx_container скопировать предоставленные файлы
   ops/ci-builder поверх соответствующих файлов. Выполнить:
   python3 -m unittest discover -s ops/ci-builder/tests -v
   Проверить diff, commit/push.

2. Ноутбук: в каждом чистом main dovecot_ac_image и postfix_ac_image добавить
   Containerfile.ci, .woodpecker.yaml и новую ops/ci. Если такой путь уже есть —
   остановиться и сравнить, не перезаписывать автоматически.
   python3 -m unittest discover -s ops/ci/tests -v
   Проверить diff, commit/push каждого репозитория.

3. VPS: git pull --ff-only для nginx_container и обоих mail image репозиториев.
   sudo sh /root/git/nginx_container/ops/ci-builder/install.sh
   sudo python3 /root/git/dovecot_ac_image/ops/ci/install-import.py
   sudo python3 /root/git/postfix_ac_image/ops/ci/install-import.py

4. Только после успешной установки подключить/перезапустить main pipeline
   обоих репозиториев в Woodpecker. Если push запустил CI раньше, первый запуск
   может отказать из-за отсутствующего project lock или importer: повторить
   после установки. Ничего не создавать вручную для обхода проверок.

5. Ожидать MAIL_IMAGE_TEST_OK, IMPORT_OK и MAIL_CANDIDATE_READY.
   Код 0 на cleanup не заменяет успех build-test-import-candidate.

## Сборка и граница совместимости

База ubuntu:24.04; устанавливаются доступные на момент первой сборки
обновления пакетов этой ветки. Это не побитово воспроизводимая сборка из apt
snapshot. Полный список пакетов и версия записаны в образе:
  /usr/local/share/ac-mail/packages.txt
  /usr/local/share/ac-mail/version.txt

Полный Git SHA — тег localhost/dovecot-ac:SHA или localhost/postfix-ac:SHA.
Уже существующий локальный тег повторно тестируется, не пересобирается.
Rootful import не допускает замены tag/receipt другим image ID.
Если сборщик очистил старый тег и повторная сборка того же SHA дала другой
image ID, импорт откажет. Для новой сборки нужен новый commit; квитанции
не удалять ради обхода этой проверки.

Поддерживаются Dovecot 2.3.x и Postfix 3.8.x. Другая ветка требует отдельного
анализа конфигурации. Зафиксированы полученные с VPS UID/GID:
dovecot 100:102, dovenull 101:103, postfix 100:102, postdrop GID 103,
vmail 55004:55004. Проверяются владельцы/режимы очереди и /var/lib/postfix.

## Интеграционные тесты

CI строит вспомогательный образ на Ubuntu 24.04 с PostgreSQL 16, Python,
OpenSSL и Dovecot. Эти пакеты не добавляются в production-кандидат.
Тестовые конфиги лежат в ops/ci/fixtures: это самостоятельные синтетические
fixtures, а не копия текущего production release.

Fixture работает с --network=none. Кандидат присоединяется только к его
сетевому пространству через --network=container:ID. Порты не публикуются.
Никакие host volumes, production PGDATA, queue, Maildir, сертификаты или
секреты не подключаются. Внутри — probe@ci.invalid, тестовый пароль,
свежая БД и краткосрочный самоподписанный сертификат с SAN.
Проверка сертификата включена и доверяет именно этому тестовому сертификату.

Dovecot:
- версия, UID/GID, схемы ARGON2I/ARGON2ID/CRYPT;
- реальный SQL passdb/userdb на временной PostgreSQL;
- свежий ARGON2I verifier тестового пользователя;
- LMTP доставка синтетического письма;
- TLS IMAP login, поиск точного Message-ID, POP3 login и наличие письма.

Postfix:
- версия, UID/GID, драйвер pgsql и Dovecot SASL;
- SQL-проверка известного/неизвестного домена;
- SMTP25 STARTTLS без AUTH, отказ неизвестному адресату и внешнему relay;
- TLS+AUTH 587/465 и отказ отправителю, не принадлежащему пользователю;
- фактическая доставка через LMTP в Dovecot из fixture, проверка через IMAP;
- пустая очередь после доставки.

Fixture Dovecot при Postfix-тесте — пакет из тестового образа, а не второй
production-кандидат. Совместную проверку двух импортированных кандидатов
с реальными версиями конфигураций выполняем перед будущим переключением.

После теста ожидается штатное завершение обоих контейнеров. При ошибке
контейнеры и отчёт сохраняются, принудительное удаление не применяется.
REPORT содержит только данные синтетического теста. Если стенд не остановился,
его нужно разобрать до повторного запуска, чтобы не копить процессы.

## Импорт и права

Rootless builder UID 1001, существующие XDG пути и общие builder locks.
Архив docker-archive до 3 GiB, root importer делает частную копию,
проверяет manifest, platform, revision label, root user, CMD, StopSignal,
отсутствие anonymous volumes. В Podman передаются только проверенные
manifest/config/layers, без внешних ссылок и сторонних archive members.

Сборщик — доверенный пользователь CI. Импорт image не является проверкой
безопасности всего произвольного кода внутри image. Тесты запускаются до
импорта в pipeline. Root importer проверяет структуру/идентичность, но сам
не повторяет rootless integration tests.

  /var/spool/ac-mail-images/SERVICE/inbox
  /var/lib/ac-mail/image-imports/SERVICE/FULL_SHA.json
  /usr/local/sbin/ac-SERVICE-import
  /etc/sudoers.d/ac-SERVICE-import

Установщик выставляет права каталогов явно при umask 077 и использует
/usr/sbin/visudo. Повторная установка одинакового importer разрешена;
другая установленная версия требует отдельного контролируемого обновления.

## Retention

В существующий builder store добавлены четыре семейства тегов.
Сохраняются последние три image ID на семейство и образы моложе семи дней;
образы контейнеров, родители, неизвестные/дополнительные теги защищены.
Все это относится только к rootless builder storage. Rootful production
и импортированные кандидаты автоматически не удаляются этим механизмом.

## Ограничение локальной проверки пакета

Unit tests и синтаксис проверены при подготовке пакета. Podman в среде
подготовки отсутствует, поэтому сборка apt-пакетов и интеграционные сценарии
впервые выполняются вашим Woodpecker. До их успеха кандидаты не готовы
к production. Автоматического image deployment в этом пакете нет.

Ссылки на первичную документацию:
https://doc.dovecot.org/2.3/configuration_manual/authentication/sql/
https://www.postfix.org/SASL_README.html
