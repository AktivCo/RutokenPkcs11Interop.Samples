using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace DeleteRSA
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
    *  - удаление ключей RSA;                                                *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Пример удаляет все ключевые пары, созданные в CreateRSA.               *
    *************************************************************************/

    class DeleteRSA
    {
        // Шаблон для поиска ключевой пары RSA
        // (Ключевая пара для подписи и шифрования)
        static readonly List<IObjectAttribute> KeyPairAttributes = new List<IObjectAttribute>
        {
            // Идентификатор ключевой пары
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.RsaKeyPairId),
            // Тип ключа - RSA
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA)
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
                            Console.WriteLine("Getting RSA key pair...");
                            List<IObjectHandle> foundObjects = session.FindAllObjects(KeyPairAttributes);

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
