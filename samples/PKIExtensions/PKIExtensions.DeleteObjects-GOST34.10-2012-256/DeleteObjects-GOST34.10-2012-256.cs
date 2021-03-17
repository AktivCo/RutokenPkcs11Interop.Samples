using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace PKIExtensions.DeleteObjects_GOST3410_2012_256
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен ЭЦП при помощи библиотеки PKCS#11 на языке C#  *
    *------------------------------------------------------------------------*
    * Удаление объектов, созданных предыдущими примерами:                    *
    *  - установление соединения с Рутокен ЭЦП в первом доступном слоте;     *
    *  - выполнение аутентификации Пользователя;                             *
    *  - поиск ключевой пары ГОСТ Р 34.10-2012 с длиной закрытого ключа      *
    *    256 бит и сертификата на Рутокен;                                   *
    *  - удаление найденных объектов;                                        *
    *  - сброс прав доступа Пользователя и закрытие соединения с Рутокен.    *
    *------------------------------------------------------------------------*
    * Пример удаляет объекты, созданные в памяти Рутокен примерами           *
    * PKIExtensions.CreateCSR-PKCS10-GOST34.10-2012-256 и                    *
    * PKIExtensions.ImportCertificate-GOST34.10-2012-256                     *
    *************************************************************************/

    class DeleteObjects_GOST3410_2012_256
    {
        // Шаблон для поиска открытого ключа ГОСТ Р 34.10-2012(256)
        static readonly List<IObjectAttribute> PublicKeyAttributes = new List<IObjectAttribute>
        {
            // Объект открытого ключа
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            // Открытый ключ является объектом токена
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            // Идентификатор искомой пары
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.Gost256KeyPairId1),
            // Тип ключа - ГОСТ Р 34.10-2012(256)
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint) CKK.CKK_GOSTR3410)
        };

        // Шаблон для поиска закрытого ключа ГОСТ Р 34.10-2012(256)
        static readonly List<IObjectAttribute> PrivateKeyAttributes = new List<IObjectAttribute>
        {
            // Объект закрытого ключа
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            // Закрытый ключ является объектом токена
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            // Идентификатор искомой пары
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.Gost256KeyPairId1),
            // Тип ключа - ГОСТ Р 34.10-2012(256)
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint) CKK.CKK_GOSTR3410)
        };

        // Шаблон для поиска сертификата ключа подписи
        static readonly List<IObjectAttribute> CertificateAttributes = new List<IObjectAttribute>
        {
            // Объект сертификата
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
            // Сертификат является объектом токена
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            // Тип сертификата - X.509
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
            // Идентификатор сертификата
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.Gost256KeyPairId1),
            // Категория сертификата - пользовательский
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_CATEGORY, SampleConstants.TokenUserCertificate)
        };

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

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (IRutokenSession session = slot.OpenRutokenSession(SessionType.ReadWrite))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        try
                        {
                            // Удаление объектов
                            Console.WriteLine("Deleting objects...");
                            // Поиск открытых ключей на токене
                            Console.WriteLine(" Getting public keys...");
                            var publicKeys = session.FindAllObjects(PublicKeyAttributes);

                            // Удалить ключи
                            if (publicKeys.Count > 0)
                            {
                                int objectsCounter = 1;
                                foreach (var publicKey in publicKeys)
                                {
                                    Console.WriteLine($"   Object №{objectsCounter} destroyed");
                                    session.DestroyObject(publicKey);
                                    objectsCounter++;
                                }

                                Console.WriteLine("Public keys have been destroyed successfully");
                            }
                            else
                            {
                                Console.WriteLine("No public keys found");
                            }

                            // Поиск закрытых ключей на токене
                            Console.WriteLine(" Getting private keys...");
                            var privateKeys = session.FindAllObjects(PrivateKeyAttributes);

                            // Удалить ключи
                            if (privateKeys.Count > 0)
                            {
                                int objectsCounter = 1;
                                foreach (var privateKey in privateKeys)
                                {
                                    Console.WriteLine($"   Object №{objectsCounter} destroyed");
                                    session.DestroyObject(privateKey);
                                    objectsCounter++;
                                }

                                Console.WriteLine("Private keys have been destroyed successfully");
                            }
                            else
                            {
                                Console.WriteLine("No private keys found");
                            }

                            // Поиск сертификата на токене
                            Console.WriteLine(" Getting certificates...");
                            var certificates = session.FindAllObjects(CertificateAttributes);

                            // Удалить сертификаты
                            if (certificates.Count > 0)
                            {
                                int objectsCounter = 1;
                                foreach (var certificate in certificates)
                                {
                                    Console.WriteLine($"   Object №{objectsCounter} destroyed");
                                    session.DestroyObject(certificate);
                                    objectsCounter++;
                                }

                                Console.WriteLine("Certificates have been destroyed successfully");
                            }
                            else
                            {
                                Console.WriteLine("No certificates found");
                            }


                        }
                        finally
                        {
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
