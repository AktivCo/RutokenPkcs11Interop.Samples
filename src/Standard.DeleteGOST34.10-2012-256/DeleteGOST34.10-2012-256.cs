using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace Standard.DeleteGOST3410_2012_256
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команды удаления объектов PKCS#11:                       *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - выполнение аутентификации Пользователя;                             *
    *  - удаление ключей ГОСТ Р 34.10-2012                                   *
    *    с длиной закрытого ключа 256 бит;                                   *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Пример удаляет все ключевые пары, созданные в CreateGOST34.10-2012-256.*
    *************************************************************************/

    class DeleteGOST3410_2012_256
    {
        // Шаблон для поиска ключевой пары ГОСТ Р 34.10-2012(256)
        // (первая ключевая пара для подписи и выработки общего ключа)
        static readonly List<IObjectAttribute> KeyPair1Attributes = new List<IObjectAttribute>
        {
            // Идентификатор ключевой пары
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.Gost256KeyPairId1),
            // Тип ключа - ГОСТ Р 34.10-2012(256)
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint) CKK.CKK_GOSTR3410)
        };

        // Шаблон для поиска ключевой пары ГОСТ Р 34.10-2012(256)
        // (вторая ключевая пара для подписи и выработки общего ключа)
        static readonly List<IObjectAttribute> KeyPair2Attributes = new List<IObjectAttribute>
        {
            // Идентификатор ключевой пары
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.Gost256KeyPairId2),
            // Тип ключа - ГОСТ Р 34.10-2012(256)
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint) CKK.CKK_GOSTR3410)
        };

        static readonly List<List<IObjectAttribute>> KeyPairsAttributes = new List<List<IObjectAttribute>>
        {
            KeyPair1Attributes,
            KeyPair2Attributes
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
                            // Получить массив хэндлов объектов, соответствующих критериям поиска
                            Console.WriteLine("Getting key pairs...");
                            var foundObjects = new List<IObjectHandle>();
                            foreach (var keyPairAttributes in KeyPairsAttributes)
                            {
                                foundObjects.AddRange(session.FindAllObjects(keyPairAttributes));
                            }

                            // Удалить ключи
                            if (foundObjects.Count > 0)
                            {
                                Console.WriteLine("Destroying objects...");
                                int objectsCounter = 1;
                                foreach (var foundObject in foundObjects)
                                {
                                    Console.WriteLine($"   Object №{objectsCounter}");
                                    session.DestroyObject(foundObject);
                                    objectsCounter++;
                                }

                                Console.WriteLine("Objects have been destroyed successfully");
                            }
                            else
                            {
                                Console.WriteLine("No objects found");
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
