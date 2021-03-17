Примеры работы с библиотекой PKCS#11 для устройств семейства Рутокен ЭЦП,
используя RutokenPkcs11Interop для .NET на настольных платформах, и Xamarin для iOS и Android.

Поддерживаются:
- .NETFramework 4.5 и новее,
- .NETStandard 2.0,
- MonoAndroid 2.3,
- Xamarin.iOS 1.0,
- Xamarin.Mac 2.0.

Примеры содержат каркасы будущих приложений, и демонстрируют:
- использование сертификатов и ключей ГОСТ-2001, ГОСТ-2012 и международных алгоритмов,
- подписание в различных форматах,
- шифрование, расшифрование,
- создание запроса на сертификаты,
- обнаружение устройств,
- и другие аспекты прикладного взаимодействия с устройствами Рутокен.

Перед началом запуска примеров, нужно в менеджере пакетов NuGet установить RutokenPkcs11Interop послежне версии

## Сборка для Andoid
При сборке для Android устойств, дополнительно нужно положить последние версии библиотек rtserviceconnection.aar и pkcs11jna.jar в директорию xamarin/Xamarin.Info/Xamarin.Info.Android/Jars. Их можно взять из нашего [sdk](https://www.rutoken.ru/developers/sdk/) в директориях sdk\mobile\android\libs и sdk\java\samples\lib
