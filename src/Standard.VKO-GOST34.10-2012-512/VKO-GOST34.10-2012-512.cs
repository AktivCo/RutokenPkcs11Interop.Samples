using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI.MechanismParams;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace Standard.VKO_GOST3410_2012_512
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команд выработки ключа обмена                            *
    * и маскирования сессионного ключа:                                      *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - выполнение аутентификации Пользователя;                             *
    *  - генерация сессионного ключа;                                        *
    *  - генерация UKM;                                                      *
    *  - выработка ключа обмена;                                             *
    *  - маскирование сессионного ключа на выработанном ключе обемена;       *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Пример использует объекты, созданные в памяти Рутокен примером         *
    * CreateGOST34.10-2012-512.                                              *
    *************************************************************************/

    class VKO_GOST3410_2012_512
    {
        // Шаблон для поиска закрытого ключа отправителя
        static readonly List<IObjectAttribute> PrivateKeyAttributes = new List<IObjectAttribute>
        {
            // ID пары
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.Gost512KeyPairId1),
            // Класс - закрытый ключ
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            // Тип ключа - ГОСТ Р 34.10-2012(512)
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410_512)
        };

        // Шаблон для создания ключа обмена
        static readonly List<IObjectAttribute> DerivedKeyAttributes = new List<IObjectAttribute>
        {
            // Метка ключа
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, SampleConstants.DerivedKeyLabel),
            // Класс - секретный ключ
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            // Тип ключа - ГОСТ 28147-89
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint) CKK.CKK_GOST28147),
            // Ключ является объектом сессии
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
            // Ключ может быть изменен после создания
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
            // Ключ недоступен без аутентификации на токене
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
            // Ключ может быть извлечен в зашифрованном виде
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
            // Ключ может быть извлечен в открытом виде
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false)
        };

        // Шаблон сессионного ключа
        static readonly List<IObjectAttribute> SessionKeyAttributes = new List<IObjectAttribute>
        {
            // Метка ключа
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, SampleConstants.WrappedKeyLabel),
            // Класс - секретный ключ
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            // Тип ключа - ГОСТ 28147-89
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint) CKK.CKK_GOST28147),
            // Ключ является объектом сессии
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
            // Ключ может быть изменен после создания
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
            // Ключ недоступен без аутентификации на токене
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
            // Ключ может быть извлечен в зашифрованном виде
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
            // Ключ может быть извлечен в открытом виде
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false)
        };

        /// <summary>
        /// Функция выработки ключа обмена
        /// </summary>
        /// <param name="session">Хэндл сессии</param>
        /// <param name="privateKeyAttributes">Шаблон для поиска закрытого ключа</param>
        /// <param name="ukm">Буфер, содержащий UKM</param>
        /// <param name="derivedKeyHandle">Хэндл выработанного общего ключа</param>
        static void Derive_GostR3410_12_Key(IRutokenSession session,
            List<IObjectAttribute> privateKeyAttributes,
            byte[] ukm, out IObjectHandle derivedKeyHandle)
        {
            // Получить массив хэндлов закрытых ключей
            Console.WriteLine("Getting private key...");
            List<IObjectHandle> privateKeys = session.FindAllObjects(privateKeyAttributes);
            Errors.Check("No private keys found", privateKeys.Count > 0);

            var attributes = new List<CKA>
            {
                CKA.CKA_VALUE
            };

            // Определение параметров механизма наследования ключа
            Console.WriteLine("Deriving key...");
            var deriveMechanismParams =
                Helpers.factories.RutokenMechanismParamsFactory.CreateCkGostR3410_12_DeriveParams(
                    (uint)Extended_CKM.CKM_KDF_GOSTR3411_2012_256, SampleData.PublicKeyData_512, ukm);

            // Определяем механизм наследования ключа
            var deriveMechanism = Helpers.factories.MechanismFactory.Create((uint)Extended_CKM.CKM_GOSTR3410_12_DERIVE, deriveMechanismParams);

            // Наследуем ключ
            derivedKeyHandle = session.DeriveKey(deriveMechanism, privateKeys[0], DerivedKeyAttributes);

            Errors.Check("Invalid derived key handle", derivedKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);

            try
            {
                // Получить и распечатать значение выработанного ключа
                List<IObjectAttribute> derivedKeyValue = session.GetAttributeValue(derivedKeyHandle, attributes);
                Console.WriteLine(" Derived key value:");
                Helpers.PrintByteArray(derivedKeyValue[0].GetValueAsByteArray());
            }
            catch (Pkcs11Exception)
            {
                // Уничтожаем ключ, если произошла ошибка при чтении значения
                session.DestroyObject(derivedKeyHandle);
                throw;
            }
        }

        static void Main(string[] args)
        {
            try
            {
                // Инициализировать библиотеку
                Console.WriteLine("Library initialization");
                using (var pkcs11 = Helpers.factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Helpers.factories, Settings.RutokenEcpDllDefaultPath, AppType.MultiThreaded))
                {
                    // Получить доступный слот
                    Console.WriteLine("Checking tokens available");
                    IRutokenSlot slot = Helpers.GetUsableSlot(pkcs11);

                    // Определение поддерживаемых токеном механизмов
                    Console.WriteLine("Checking mechanisms available");
                    List<CKM> mechanisms = slot.GetMechanismList();
                    Errors.Check(" No mechanisms available", mechanisms.Count > 0);
                    bool isGostR3410_12DeriveSupported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3410_12_DERIVE);
                    bool isGostWrapSupported = mechanisms.Contains((CKM)CKM.CKM_GOST28147_KEY_WRAP);
                    Errors.Check(" CKM_GOSTR3410_12_DERIVE isn`t supported!", isGostR3410_12DeriveSupported);
                    Errors.Check(" CKM_GOST28147_KEY_WRAP isn`t supported!", isGostWrapSupported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (IRutokenSession session = slot.OpenRutokenSession(SessionType.ReadWrite))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        IObjectHandle sessionKeyHandle = null;
                        IObjectHandle derivedKeyHandle = null;

                        try
                        {
                            // Генерация параметра для структуры типа CK_GOSTR3410_12_DERIVE_PARAMS
                            // для выработки общего ключа
                            Console.WriteLine("Preparing data for deriving and wrapping...");
                            byte[] ukm = session.GenerateRandom(SampleConstants.UkmLength);

                            // Генерация значения сессионного ключа
                            byte[] sessionKeyValue = session.GenerateRandom(SampleConstants.Gost28147_KeySize);

                            Console.WriteLine(" IRutokenSession key data is:");
                            Helpers.PrintByteArray(sessionKeyValue);
                            Console.WriteLine("Preparing has been completed successfully");

                            // Выработка ключа обмена
                            Console.WriteLine("Deriving key...");
                            Derive_GostR3410_12_Key(session, PrivateKeyAttributes,
                                ukm, out derivedKeyHandle);
                            Console.WriteLine("Key has been derived successfully");

                            // Маскировать сессионный ключ с помощью выработанного ключа обмена
                            Console.WriteLine("Wrapping key...");
                            Console.WriteLine(" Creating the GOST 28147-89 key to wrap...");
                            // Выработка ключа, который будет замаскирован
                            SessionKeyAttributes.Add(Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, sessionKeyValue));
                            sessionKeyHandle = session.CreateObject(SessionKeyAttributes);

                            // Определение параметров механизма маскирования
                            var wrapMechanismParams = Helpers.factories.MechanismParamsFactory.CreateCkKeyDerivationStringData(ukm);
                            var wrapMechanism = Helpers.factories.MechanismFactory.Create((uint)CKM.CKM_GOST28147_KEY_WRAP, wrapMechanismParams);

                            // Маскирование ключа на ключе обмена
                            byte[] wrappedKey = session.WrapKey(wrapMechanism, derivedKeyHandle, sessionKeyHandle);

                            Console.WriteLine("  Wrapped key data is:");
                            Helpers.PrintByteArray(wrappedKey);
                            Console.WriteLine(" Key has been wrapped successfully");
                        }
                        finally
                        {
                            Console.WriteLine("Destroying keys");
                            // Удаляем сессионный ключ
                            if (sessionKeyHandle != null)
                            {
                                session.DestroyObject(sessionKeyHandle);
                            }

                            // Удаляем наследованные ключи
                            if (derivedKeyHandle != null)
                            {
                                session.DestroyObject(derivedKeyHandle);
                            }

                            // Сбросить права доступа как в случае исключения,
                            // так и в случае успеха.
                            // Сессия закрывается автоматически.
                            session.Logout();
                        }
                    }
                }
            }
            catch (Pkcs11Exception ex)
            {
                Console.WriteLine($"Operation failed [Method: {ex.Method}, RV: {ex.RV}]");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Operation failed [Message: {ex.Message}]");
            }
        }
    }
}
