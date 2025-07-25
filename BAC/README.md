# **BAC**

> Контроль доступа — это применение ограничений на то, кто или что имеет право выполнять действия или получать доступ к ресурсам.

> Broken Access Control, или просто BAС — это сломанный контроль доступа.

* **Модель безопасности контроля доступа**:

> **Программный контроль доступа**:
> При программном контроле доступа матрица привилегий пользователей хранится в базе данных или аналогичной базе данных, а контроль доступа применяется программно со ссылкой на эту матрицу. Этот подход к контролю доступа может включать роли или группы или отдельных пользователей, коллекции или рабочие процессы процессов и может быть очень детализированным.

> **Дискреционный контроль доступа (DAC)**: 
> При дискреционном контроле доступа доступ к ресурсам или функциям ограничивается на основе пользователей или именованных групп пользователей. Владельцы ресурсов или функций имеют возможность назначать или делегировать права доступа пользователям. Эта модель очень детализирована, и права доступа определяются для отдельного ресурса или функции и пользователя. Следовательно, модель может стать очень сложной для проектирования и управления.

> **Обязательный контроль доступа (MAC)**: 
> Обязательный контроль доступа — это централизованно контролируемая система контроля доступа, в которой доступ субъекта к некоторому объекту (файлу или другому ресурсу) ограничен. Важно отметить, что в отличие от DAC пользователи и владельцы ресурсов не имеют возможности делегировать или изменять права доступа к своим ресурсам. Эта модель часто ассоциируется с военными системами, основанными на допуске.

> **Управление доступом на основе ролей (RBAC)**: 
> При управлении доступом на основе ролей определяются именованные роли, которым назначаются привилегии доступа. Затем пользователям назначаются одна или несколько ролей. RBAC обеспечивает улучшенное управление по сравнению с другими моделями контроля доступа и, при правильном проектировании, достаточную детализацию для обеспечения управляемого контроля доступа в сложных приложениях.

* **BAC возникает, если**:
  * У разработчиков нет чёткого понимания, какие функции и ресурсы доступны.
  * Разработчики доверяют неявным факторам авторизации — например, реализуют контроль доступа на основе URL-адреса или заголовка Referer.
  * Разработчики забывают добавить функции для проверки контроля доступа, когда работают над новой функциональностью.
  * Контроль доступа реализуется на фронтенде, но не реализуется на бэкенде.
  * Система проверяет права один раз в многошаговом процессе.
    
* **Виды**
   * вертикальный — ограничивает доступ на основе роли пользователя в системе,
   * горизонтальный — ограничивает доступ пользователям с одинаковыми привилегиями,
   * контекстно-зависимый — ограничивает доступ в зависимости от состояния приложения.

* **POC**
*	Вертикальный: 
Шаг 1. Выбираем действие, которое доступно привилегированному пользователю, но не доступно обычному. Например, удаление пользователя.
Шаг 2. Попробуем перейти в административную панель. Не получилось, панель доступна только для админов:
Шаг 3. Изучаем, как выглядит этот запрос, в Burp Suite.
Здесь куки session фиксирует сессию пользователя. А куки Admin определяет, является пользователь администратором сайта или нет.
Шаг 4. Меняем значение куки Admin на true и снова отправляем запрос.
Запрос выполнился успешно. Теперь можно посмотреть, как выглядит веб-интерфейс административной панели.
Шаг 5. Отправляем запрос в браузере: нажимаем правой кнопкой мыши на строку запроса и выбираем Request in browser.
Появится ссылка — копируем её и переходим по ней в браузере. Теперь есть доступ к панели администратора:
Шаг 6. Используем целевое действие — удаляем пользователя max.
Сделать это сразу не получится: браузер автоматически подставит прежнее значение куки — Admin=false. Ещё раз измени куки в Burp Suite и отправь запрос повторно.
В итоге аккаунт пользователя max будет удалён.
*	Горизонтальный:
Чтобы обнаружить уязвимость:
Шаг 1. Заходим в личный кабинет. Есть своя учётная запись, и мы знаем, что пароль находится в личном кабинете.
Шаг 2. Изучаем параметры запроса. Здесь, например, в параметрах указано id=andrew . Можно сделать вывод, что доступ в личный кабинет зависит от логина пользователя.
Шаг 3. Проверяем гипотезу: меняем значение id на max . Запрос будет выглядеть так: https://example.com/my-account?id=max.
Шаг 4. Отправляем запрос.
*	Контекстно-зависимый:
Шаг 1. Изучает запрос на подтверждение доставки в Burp Suite:
Тут видно, что в запросе на подтверждения перечислены id товаров. Можно попробовать перехватить запрос и добавить ещё несколько id.
Шаг 2. Перехватывает запрос и добавляет ещё два id:
После этого в заказ добавятся ещё два товара. Магазин доставит их злоумышленнику бесплатно.

* **Профит**
    нарушение работы веб-приложения;
    изменение паролей пользователей;
    удаление пользователей;
    публикация вредоносного или провокационного контента;
    использование любых функций, доступных через админ-панель.
    получить доступ к чужому личному кабинету;
    перевести деньги с чужого аккаунта;
    просматривать чужие чаты или сообщения;
    получить доступ к личной и чувствительной информации пользователя (да-да, все узнают, что ты делал прошлым летом);
    изменить пароль, телефон, email или другие данные другого пользователя — это позволяет полностью перехватить управление аккаунтом;
    разместить пост с вредоносным кодом, ссылкой на фишинговый сайт или оскорблениями через аккаунт другого пользователя.

* **Защита**
    Никогда не полагайся только на случайные числовые id для контроля доступа к объекту. Хакер может их забрутфорсить.
    Следуй принципу наименьших привилегий: запрещай всё по умолчанию. Потом выдавай доступ тем, кому он действительно нужен.
    По возможности используй единый механизм контроля доступа на уровне всего приложения.
    Тщательно проверяй и тестируй средства управления доступом перед релизом. Так ты поймёшь, работают они или нет.
    Реализуй средства управления доступом и на клиентской части приложения, и на серверной.
    После разработки новой функциональности в приложении не будет лишним проверить его от лица пользователей с разным уровнем привилегий. Так ты убедишься, что каждый из них имеет доступ только к разрешенным ресурсам.
