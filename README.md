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

Перед началом запуска примеров, нужно в менеджере пакетов NuGet установить Aktiv.RutokenPkcs11Interop и Pkcs11Interop версии 4.1.1.
С Pkcs11Interop версии 5.0.0 будут проблемы при сборке проекта.
