# Подготовка почтовых релизов — этап 1

Этот пакет готовит релизы Dovecot и Postfix из уже проверенных коммитов.
Он НЕ переводит рабочие контейнеры под runit, НЕ применяет конфигурацию,
НЕ меняет legacy-скрипты, restart policy, PostgreSQL или firewall.
Автоматический GitHub/Woodpecker deploy и переключение production — следующие этапы.

## Размещение

Координатор пары хранится в `postfix_ac_image/ops/mail-deploy`.
Конфигурации остаются в отдельных `dovecot_config` и `postfix_config`.
Исходники не содержат паролей, почты, ключей или содержимого SQL-карт.

## Установка и подготовка

На ноутбуке, в репозитории postfix_ac_image:

```
python3 -m unittest discover -s ops/mail-deploy/tests -v
git add ops/mail-deploy
git diff --cached --check
git commit -m "Add private mail configuration release preparation"
git push origin main
```

На сервере после получения этого коммита:

```
sudo python3 ops/mail-deploy/install.py
sudo /usr/local/sbin/ac-mail-release prepare dovecot /root/git/dovecot_config
sudo /usr/local/sbin/ac-mail-release prepare postfix /root/git/postfix_config
```

Обе рабочие копии должны быть чистыми и стоять точно на разрешённых коммитах:
Dovecot `78d852e2f61d5769aaf5ccb8115d2775f43e6524`, Postfix `df0940e`.
Сокращённый SHA Postfix разрешается Git однозначно в полный SHA и записывается
в manifest; неоднозначность приводит к отказу. В следующих версиях инструмента
следует закрепить полный SHA, полученный в manifest.

Используются существующие секреты:

- `/etc/ac/secrets/dovecot/sql.json`: объект с полем `connect`.
- `/etc/ac/secrets/postfix/sql.json`: объект `maps` с четырьмя картами,
  каждая имеет `hosts`, `dbname`, `user`, `password`.

Права секретов: root, 0600; родительские каталоги без групповой/общей записи.
Установка идемпотентна; существующий отличающийся инструмент не перезаписывается.
Никакие systemd/runit-службы не устанавливаются на этом этапе.

## Хранение и воспроизводимость

Релизы: `/var/lib/ac-mail/releases/<service>/<commit>-<digest>`.
Это приватное хранилище root: 0700 каталоги, 0600 файлы.
Релиз содержит config, отрендеренные secrets, manifest и приватные журналы.
Не публиковать релизы или журналы в Git/CI: они могут содержать секреты.

Git читается по object ID, shell/source/eval для секретов не используются.
Символические ссылки и нестандартные режимы исходных файлов отвергаются.
Подстановка однопроходная; смена секрета изменяет ID релиза.
Повторная подготовка возвращает существующий релиз после проверки целостности.
Неудачный кандидат сохраняется в `.prepare-*` и не получает `VALIDATED`.

Проверка уже созданного релиза:

```
sudo ac-mail-release verify dovecot /var/lib/ac-mail/releases/dovecot/<release>
```

Manifest и его хеши — проверка случайного изменения, а не подпись против root.

## Проверка в контейнере

Используются только текущие закреплённые image ID, `--pull=never`,
`--network=none`, без рабочих очередей/Maildir и без опубликованных портов.
Dovecot: `doveconf -n` с конфигурацией релиза и сертификатами RO.
Postfix: копирование только main.cf/master.cf и SQL-карт в слой отдельного
контейнера; служебные файлы образа сохраняются; `postfix check`, `postconf -M`.
В тесте Postfix `inet_interfaces=loopback-only`, чтобы не требовать production-IP.
Отрендеренный main.cf в релизе остаётся неизменным.

Это parse/preflight-проверка, НЕ повторная интеграционная проверка SMTP/LMTP.
При таймауте Podman CLI возможен оставшийся проверочный контейнер: требуется
осмотр. Инструмент не выполняет принудительное удаление или общий prune.

## Проверенная интеграция до этого пакета

- Dovecot: конфигурация, userdb, passdb, LMTP во временный Maildir.
- Postfix: доменные/получательские SQL-карты, запрет релея на 25.
- 587/465: TLS, AUTH, запрет подмены envelope sender.
- Письмо через AUTH Postfix -> LMTP Dovecot найдено в тестовом INBOX.
- BCC был отключён только в интеграционном тесте, его работа не подтверждена.
- DKIM, DNS/PTR/SPF/DMARC и внешняя доставляемость ещё не проверены.

## Результат анализа присланного runtime

В текущем `ac-pg-runtime.py` stage-1 migrate/check-legacy запрещены, НО
`config-deploy.py:guard()` вызывает `r.script_status()` и требует точного
совпадения launcher-скриптов с `legacy/*.after`.
Поэтому менять общие start/stop скрипты без согласованного обновления эталонов
PostgreSQL нельзя. Подмена этой проверки на безусловный успех не допускается.

План переключения (не реализован в этом пакете):

1. Общая блокировка и блокировка деплоя PostgreSQL; остановка legacy-таймера,
   проверка отсутствия выполняющихся launcher-скриптов.
2. Установка runit-служб в down, журнал транзакции, снимки старых параметров.
3. Согласованное исключение обеих mail-служб из legacy и обновление проверенных
   эталонов PostgreSQL; никогда не останавливать ac_containers.service.
4. Остановка Postfix, затем Dovecot без SIGKILL; согласованная копия очереди,
   /var/lib/postfix и Maildir (сохранение UID/GID/ACL/xattrs).
5. Создание кандидатов с закреплёнными images/config/secrets, уникальным MAC
   Postfix, постоянным /var/lib/postfix и без mail bind mount у Postfix.
6. Запуск Dovecot, затем Postfix под runit, проверка health и SMTP/LMTP.
7. При ошибке сначала подтверждённая остановка кандидатов, затем восстановление
   прежних контейнеров и согласованных launcher-эталонов. Нельзя одновременно
   запускать два владельца одной очереди или Maildir.

После этого — полноценный механизм конфигурационного деплоя и автоматизация CI.
