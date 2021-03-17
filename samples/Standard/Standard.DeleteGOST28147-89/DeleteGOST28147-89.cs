using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace DeleteGOST28147_89
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
    *  - удаление ключей ГОСТ 28147-89;                                      *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Пример удаляет все ключи, созданные в CreateGOST28147-89.              *
    *************************************************************************/

    class DeleteGOST28147_89
    {
        // Шаблон для поиска симметричного ключа ГОСТ 28147-89
        static readonly List<IObjectAttribute> SymmetricKeyAttributes = new List<IObjectAttribute>
        {
            // Идентификатор ключа
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.GostSecretKeyId),
            // Тип ключа - ГОСТ 28147-89
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint) CKK.CKK_GOST28147)
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
                            Console.WriteLine("Getting secret keys...");
                            List<IObjectHandle> foundObjects = session.FindAllObjects(SymmetricKeyAttributes);

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
