* [Детекция десериализации по языкам программирования](#Детекция-десериализации-по-языкам-программирования)
	* [PHP](#PHP)
	* [Python](#Python)
	* [Java](#Java)
	* [C#](#C)
	* [JavaScript/Node.js](#JavaScriptNodejs)
	* [Ruby](#Ruby)
	* [Go](#Go)
* [Magic Bytes](#Magic-Bytes)
* [Манипулирование сериализованными объектами](#Манипулирование-сериализованными-объектами)
	* [изменение атрибута объекта](#изменение-атрибута-объекта)
	* [модификация типа данных](#модификация-типа-данных)
	* [использование функционала приложения](#использование-функционала-приложения)
	* [магические методы](#магические-методы)
	* [передача произвольного объекта](#передача-произвольного-объекта)
* [Точки входа](#Точки-входа)
* [Профит](#Профит)
* [Защита](#Защита)

Deserealization, PHP, Java, Python, C, Go, Server
> Сериализация — это перевод структуры данных или объекта в битовую последовательность или строку определённого формата. При этом формат может быть разным: JSON, XML, YAML или бинарным. В любом случае на выходе получается поток байтов.Так, любой объект из читаемого кода преобразуется в набор байтов. 
>
> Десериализация — это обратный процесс. Из потока байтов восстанавливают копию структуры данных или объекта.
>
> Небезопасная десериализация — это ситуация, когда сайт десериализует данные, которые контролирует пользователь.
>> Чаще всего уязвимость десериализации связана с BAC. Она позволяет хакерам получить несанкционированный доступ к аккаунтам админов и других пользователей. Это как матрёшка: одна уязвимость открывает другую.

* **В некоторых языках программирования сериализацию называют иначе из-за названия библиотек** 
	* Ruby - Marshal
	* Python — pickle.

| Язык | Стандартная / Основная библиотека (родной формат) | Основные библиотеки для межъязыковых форматов |
| :--- | :--- | :--- |
| **Python** | `pickle` | `json`, `pyyaml` (YAML), `xml.etree` |
| **Ruby** | `Marshal` | `json` (гем), `psych` (YAML) |
| **Java** | `java.io.Serializable` | `Jackson` (JSON/XML/YAML), `Gson` (JSON) |
| **C#** | `BinaryFormatter` | `Newtonsoft.Json`, `System.Text.Json` (JSON) |
| **JavaScript** | `JSON` (родной) | `JSON` (де-факто стандарт) |
| **Go** | `encoding/gob` | `encoding/json`, `encoding/xml` |
| **PHP** | `serialize()`/`unserialize()` | `json_encode()`/`json_decode()` |
| **Swift** | `Codable` протокол | `JSONEncoder`/`JSONDecoder`, `PropertyListEncoder`/`PropertyListDecoder` |
| **Kotlin** | `java.io.Serializable` | `kotlinx.serialization`, `Jackson`, `Gson` | 

# Детекция десериализации по языкам программирования

## PHP

| Тип | Паттерн | Пример |
|-----|---------|--------|
| Base64 | `unserialize(base64_decode(` | `unserialize(base64_decode($_POST['data']))` |
| Base64 | `@unserialize(base64_decode(` | `@unserialize(base64_decode($data))` |
| Hex | `unserialize(hex2bin(` | `unserialize(hex2bin($_GET['data']))` |
| Hex | `unserialize(pack('H*',` | `unserialize(pack('H*', $hexData))` |
| Универсальный | `unserialize(` | `unserialize($input)` |

## Python

| Тип | Паттерн | Пример |
|-----|---------|--------|
| Base64 | `pickle.loads(base64.b64decode(` | `pickle.loads(base64.b64decode(data))` |
| Base64 | `marshal.loads(base64.b64decode(` | `marshal.loads(base64.b64decode(encoded))` |
| Base64 | `yaml.load(base64.b64decode(` | `yaml.load(base64.b64decode(data))` |
| Hex | `pickle.loads(bytes.fromhex(` | `pickle.loads(bytes.fromhex(hex_str))` |
| Hex | `codecs.decode(`, `'hex'` + десериализация | `pickle.loads(codecs.decode(hex_str, 'hex'))` |
| Универсальный | `pickle.loads(` | `pickle.loads(serialized)` |
| Универсальный | `yaml.load(` | `yaml.load(input)` |
| Универсальный | `json.loads(` | `json.loads(json_str)` |

## Java

| Тип | Паттерн | Пример |
|-----|---------|--------|
| Base64 | `Base64.getDecoder().decode(` + десериализация | `ois.readObject(Base64.getDecoder().decode(str))` |
| Base64 | `new ObjectInputStream(` + Base64 | `new ObjectInputStream(new ByteArrayInputStream(Base64.decode(base64Str)))` |
| Hex | `Hex.decode(` + десериализация | `ois.readObject(Hex.decode(hexString))` |
| Hex | `DatatypeConverter.parseHexBinary(` | `new ObjectInputStream(new ByteArrayInputStream(DatatypeConverter.parseHexBinary(hex)))` |
| Универсальный | `readObject(` | `objectInputStream.readObject()` |
| Универсальный | `readUnshared(` | `ois.readUnshared()` |

## C#

| Тип | Паттерн | Пример |
|-----|---------|--------|
| Base64 | `Convert.FromBase64String(` + `BinaryFormatter` | `bf.Deserialize(new MemoryStream(Convert.FromBase64String(data)))` |
| Base64 | `System.Convert.FromBase64String(` | `System.Convert.FromBase64String(serialized)` |
| Hex | `StringToByteArray(` (hex) + десериализация | `bf.Deserialize(new MemoryStream(StringToByteArray(hex)))` |
| Hex | `Convert.FromHexString(` | `bf.Deserialize(new MemoryStream(Convert.FromHexString(hexStr)))` |
| Универсальный | `BinaryFormatter.Deserialize(` | `binaryFormatter.Deserialize(stream)` |
| Универсальный | `SoapFormatter.Deserialize(` | `soapFormatter.Deserialize(stream)` |
| Универсальный | `ObjectStateFormatter.Deserialize(` | `formatter.Deserialize(stream)` |

## JavaScript/Node.js

| Тип | Паттерн | Пример |
|-----|---------|--------|
| Base64 | `JSON.parse(atob(` | `JSON.parse(atob(base64String))` |
| Base64 | `Buffer.from(`, `'base64'` + парсинг | `JSON.parse(Buffer.from(data, 'base64'))` |
| Hex | `Buffer.from(`, `'hex'` + парсинг | `JSON.parse(Buffer.from(hexString, 'hex'))` |
| Универсальный | `JSON.parse(` | `JSON.parse(jsonString)` |
| Универсальный | `eval(` | `eval(serializedObj)` |

## Ruby

| Тип | Паттерн | Пример |
|-----|---------|--------|
| Base64 | `Marshal.load(Base64.decode64(` | `Marshal.load(Base64.decode64(encoded))` |
| Hex | `Marshal.load([hex_str].pack('H*'))` | `Marshal.load([hex_str].pack('H*'))` |
| Универсальный | `Marshal.load(` | `Marshal.load(data)` |
| Универсальный | `YAML.load(` | `YAML.load(yaml_data)` |

## Go

| Тип | Паттерн | Пример |
|-----|---------|--------|
| Base64 | `base64.StdEncoding.DecodeString(` + `gob` | `gob.NewDecoder(decoded).Decode(&obj)` |
| Hex | `hex.DecodeString(` + десериализация | `gob.NewDecoder(decodedHex).Decode(&obj)` |


# Magic Bytes

| Object Type | Header (Hex) | Header (Base64) | Описание |
|-------------|--------------|-----------------|----------|
| Java Serialized | `AC ED 00` | `rO0` | Стандартная Java сериализация |
| .NET ViewState | `FF 01` | `/w` | ASP.NET ViewState |
| Python Pickle | `80 04 95` | `gASV` | Python pickle protocol 4 |
| PHP Serialized | `4F 3A` | `Tz` | PHP object serialization |
| JWT Token | `65 79 4A` | `eyJ` | JWT (starts with "eyJ") |
| SAML Response | `50 4B 03 04` | `UEsDBA` | SAML/XML часто в ZIP |
| OAuth Token | `62 65 61 72 65 72` | `bearer` | Bearer token |
| ASP.NET_SessionId | `41 53 50 2E` | `QVNQLg` | ASP.NET Session |
| PHP Session | `5F 5F 53 45 53 53 49 4F 4E` | `X19TRVNTSU9O` | `__SESSION` |
| Ruby on Rails Session | `2D 2D 2D 0A` | `LS0tCg` | Rails session (YAML) |
| Flask Session | `2E` | `Lg` | Flask signed session |
| Express.js Session | `7B 22 63 6F 6F 6B 69 65` | `eyJjb29raWU` | Express session JSON |
| Laravel Cookie | `65 79 4A 70` | `eyJw` | Laravel encrypted cookie |
| Spring Session | `7B 22 40 63 6C 61 73 73` | `eyJAY2xhc3M` | Spring Session JSON |
| XML Data | `3C 3F 78 6D 6C` | `PD94bWw` | XML declaration |
| JSON Data | `7B` / `5B` | `ew` / `W` | JSON object/array |
| Base64 Encoded | Various | Ends with `=` | Base64 padding |
| GZIP Compressed | `1F 8B 08` | `H4sI` | GZIP header |
| ZIP Archive | `50 4B 03 04` | `UEsDBA` | ZIP file |
| PDF Document | `25 50 44 46` | `JVBER` | PDF file |
| Windows PE | `4D 5A` | `TVo` | EXE/DLL file |
| ELF Binary | `7F 45 4C 46` | `f0VMRg` | Linux executable |
| BMP Image | `42 4D` | `Qk` | Bitmap image |
| PNG Image | `89 50 4E 47` | `iVBORw` | PNG image |
| JPEG Image | `FF D8 FF` | `/+3/` | JPEG image |
| GIF Image | `47 49 46 38` | `R0lGOD` | GIF image |
| SQL Dump | `2D 2D 20 53 51 4C` | `LS0gU1FM` | SQL comments |
| CSV Data | `EF BB BF` / text | UTF-8 BOM |
| YAML Config | `2D 2D 2D` | `LS0t` | YAML document start |
| Properties File | `23` | `Iw` | Java properties (# comment) |
| INI File | `5B` | `W` | INI section start [ |
| HTML Page | `3C 21 44 4F 43 54` | `PCFET0NU` | HTML doctype |
| ASPX Page | `3C 25 40 20 50 61 67 65` | `PCVAIHBhZ2U` | ASPX directive |
| PHP Script | `3C 3F 70 68 70` | `PD9waHA` | PHP open tag |
| Python Script | `23 21` | `IyE` | Shebang #! |
| Shell Script | `23 21 2F 62 69 6E` | `IyEvYmlu` | #!/bin shebang |
| Windows Batch | `40 65 63 68 6F 20 6F 66 66` | `QGVjaG8gb2Zm` | @echo off |
| PowerShell | `23 21` / `49 45 58` | `IyE` / `SUVY` | PowerShell shebang/IEX |
| Certificate PEM | `2D 2D 2D 2D 2D 42 45 47 49 4E` | `LS0tLS1CRUdJ` | `-----BEGIN` |
| Private Key | `2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 52 49 56 41 54 45` | `LS0tLS1CRUdJIFBSSVZBVE` | `-----BEGIN PRIVATE` |
| SSH Key | `73 73 68 2D` | `c3NoL` | `ssh-` |
| OpenSSL Encrypted | `53 61 6C 74 65 64 5F` | `U2FsdGVkX` | OpenSSL "Salted_" |
| AES Encrypted | `53 61 6C 74 65 64 5F` | `U2FsdGVkX` | AES with salt |
| DES Encrypted | Various | | DES encrypted data |
| RC4 Encrypted | Random | | RC4 (no specific header) |
| Bitcoin Wallet | `01 42 43 30 45` | `AUJDMGU` | Bitcoin wallet |
| Ethereum Key | `08 02 12 20` | `CAI` | Ethereum private key |
| Docker Image | `FF 4F 4C 49 4D 47` | `/09MSU1H` | Docker legacy |
| Kubernetes Config | `61 70 69 56 65 72 73 69 6F 6E 3A` | `YXBpVmVyc2lvbjo` | `apiVersion:` |
| Docker Compose | `76 65 72 73 69 6F 6E 3A 20 27 33 27` | `dmVyc2lvbjogJzMn` | `version: '3'` |
| Terraform Config | `72 65 73 6F 75 72 63 65 20 22` | `cmVzb3VyY2UgIg` | `resource "` |
| Ansible Vault | `24 41 4E 53 49 42 4C 45 5F 56 41 55 4C 54` | `JEFOU0lCTEVfVkFVTFQ` | `$ANSIBLE_VAULT` |
| AWS Key | `41 4B 49 41` | `QUtJQQ` | `AKIA` AWS access key |
| Google API Key | `41 49 7A 61` | `QUl6Y` | Google API key pattern |
| Slack Token | `78 6F 78 62` | `eG94Y` | Slack token pattern |
| GitHub Token | `67 68 70 5F` | `Z2hwX` | GitHub token `ghp_` |
| Stripe Key | `73 6B 5F 6C 69 76 65` | `c2tfbGl2ZQ` | Stripe `sk_live` |
| Twilio Key | `53 4B` | `U0s` | Twilio `SK` prefix |
| SendGrid Key | `53 47 2E` | `U0cu` | SendGrid `SG.` |
| Mailgun Key | `6B 65 79 2D` | `a2V5L` | Mailgun `key-` |
| Heroku API Key | `68 65 72 6F 6B 75 2D 61 70 69 2D 6B 65 79` | `aGVyb2t1LWFwaS1rZXk` | `heroku-api-key` |

# **Эксплуатация**

## **Манипулирование сериализованными объектами**

### изменение атрибута объекта

1. Поиск сериализованных данных при изучении трафика.  
2. Декодирование (при необходимости).  
3. Определение потенциально значимого атрибута.  
4. Изменение атрибута.  
5. Кодирование (при необходимости).  
6. Отправка модифицированного запроса.

### модификация типа данных
    
1. Поиск сериализованных данных при изучении трафика.  
2. Декодирование (при необходимости).  
3. Определение потенциально значимого атрибута.  
4. Изменение типа атрибута.  
5. Присвоение нового значения атрибуту.  
6. Кодирование (при необходимости).  
7. Отправка модифицированного запроса.

> Если изменяются типы данных в сериализованном объекте, нужно обновить все метки типов и индикаторы длины. Иначе сериализованный объект — нельзя будет десериализовать.

* Для атрибутов типа integer и bool длину значения указывать не нужно.
  
  ```
    i (integer) — число,
    s (string) — строка,
    b (bool) — булево значение.
  ```

**Пример**
```
O:11:"credentials":2:{s:8:"username";s:8:"apushkin";s:8:"password";s:15:"4r1naR0d!onovna";} 
Можно изменить тип атрибута password с string на integer и присвоить ему значение 0. Тогда пароль окажется верным в любом случае, а модифицированные данные будут такими:
O:11:"credentials":2:{s:8:"username";s:8:"apushkin";s:8:"password";i:0;} 
```

> В PHP 8 и более поздних версиях сравнение 0 == "Example string" оценивается как false, поскольку строки больше не преобразуются неявно в 0 во время сравнения. В результате этот эксплойт невозможен в этих версиях PHP.
>> Поведение при сравнении буквенно-цифровой строки, которая начинается с цифры, остается прежним в PHP 8. Таким образом, 5 == "5 чего-то" по-прежнему рассматривается как 5 == 5.

## использование функционала приложения

**Пример:**

* Допустим, аватар пользователя привязан к его профилю. Значит, путь к файлу с фотографией хранится в атрибуте image_location объекта $user.
* Если объект $user воссоздали из сериализованного объекта, злоумышленник может передать объект с модифицированным атрибутом image_location. 
* Если личный кабинет позволяет удалить аватар, пользователь сможет контролировать удаление файлов с сервера.
  
```
Перехватываем запрос и находим в нём сериализованный объект:
O:4:"user":2:{s:8:"username";s:5:"amigo";s:14:"image_location";s:22:"/data/users/amigo/avatar.jpg";} 
Затем модифицируем запрос, меняя путь до файла:
O:4:"user":2:{s:8:"username";s:5:"amigo";s:14:"image_location";s:11:"/etc/passwd";} 
```
Используя функциональность приложения, удаляем свой аватар. После этого файл /etc/passwd удалится с сервера, поэтому на нём будет сложно войти в систему.

## магические методы
  
> магические методы — они вызываются автоматически при возникновении определенного события или сценария. Иногда они обозначаются префиксом или окружением имени метода двойным подчеркиванием.
>> В некоторых языках есть магические методы, которые вызываются в процессе десериализации.

* [PHP](https://thecodersbreakfast.net/index.php?post/2011/05/12/Serialization-and-magic-methods)
* [Python](https://coderpad.io/blog/development/guide-to-python-magic-methods/)
* [Java](https://thecodersbreakfast.net/index.php?post/2011/05/12/Serialization-and-magic-methods)

## передача произвольного объекта
  
1. Изучить все классы.
2. Найти классы, которые содержат магические методы десериализации.
3. Попробовать найти такой класс, который выполняет опасные операции над управляемыми данными.
4. Передать сериализованный объект такого класса, чтобы использовать его магический метод для эксплойта.

## Gadget chains

* **Gadgets** - это фрагмент кода, реализуемый классом приложения, который может быть вызван в процессе десериализации.

> В реальной жизни многие небезопасные уязвимости десериализации можно будет использовать только с помощью цепочек гаджетов. Иногда это может быть простая одно- или двухшаговая цепочка, но для создания атак высокой степени серьезности, скорее всего, потребуется более сложная последовательность инстанциаций объектов и вызовов методов.

* Существует несколько доступных инструментов:
	* [Java](https://github.com/Kaupervud69/WebVuln/blob/main/DeSerealization/Java.md#%D0%98%D0%BD%D1%81%D1%82%D1%80%D1%83%D0%BC%D0%B5%D0%BD%D1%82%D1%8B)
 	* [PHP](https://github.com/Kaupervud69/WebVuln/blob/main/DeSerealization/PHP.md#%D0%98%D0%BD%D1%81%D1%82%D1%80%D1%83%D0%BC%D0%B5%D0%BD%D1%82%D1%8B)

# **Точки входа**
  
* все данные, которые передаются на сайт; (cookie)
* всё, что похоже на сериализованные данные.
* Если есть доступ к исходному коду, искать тут [тык сюда](#Детекция-десериализации-по-языкам-программирования)

# **Профит**

* запустить удалённое выполнение кода,  
* повысить свои привилегии в системе,  
* получить неавторизованный доступ к файлам.

# **Защита**

* Проверка входных данных: валидировать и фильтруй данные до десериализации.
* Использовать безопасные форматы: JSON и XML безопаснее бинарной десериализации.
* Ограничение разрешённых типов: десериализовать только безопасные классы.
* Регистрация классов: явно задавать список типов, которые можно десериализовать.
* Целостность данных: использовать цифровые подписи или хеширование, чтобы гарантировать целостность данных.
* Обновления и патчи: следить за обновлениями используемых библиотек и патчей безопасности.




