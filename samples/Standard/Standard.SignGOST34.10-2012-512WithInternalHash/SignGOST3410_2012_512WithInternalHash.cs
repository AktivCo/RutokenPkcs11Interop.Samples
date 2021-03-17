using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace Standard.SignGOST3410_2012_512WithInternalHash
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команд вычисления/проверки ЭП на ключах                  *
    * ГОСТ Р 34.10-2012 для длины ключа 512 бит:                             *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - выполнение аутентификации Пользователя;                             *
    *  - внутреннее хэширование и подпись сообщения                          *
    *    на демонстрационном ключе;                                          *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Пример использует объекты, созданные в памяти Рутокен примером         *
    * CreateGOST34.10-2012-512.                                              *
    *************************************************************************/

    class SignGOST3410_2012_512WithInternalHash
    {
        // Шаблон для поиска закрытого ключа для цифровой подписи
        static readonly List<IObjectAttribute> PrivateKeyAttributes = new List<IObjectAttribute>
        {
            // ID пары
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.Gost512KeyPairId1),
            // Класс - закрытый ключ
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)
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

                    // Определение поддерживаемых токеном механизмов
                    Console.WriteLine("Checking mechanisms available");
                    List<CKM> mechanisms = slot.GetMechanismList();
                    Errors.Check(" No mechanisms available", mechanisms.Count > 0);
                    bool isGostR3410w3411_512Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3410_WITH_GOSTR3411_12_512);
                    Errors.Check(" CKM_GOSTR3410_WITH_GOSTR3411_12_512 isn`t supported!", isGostR3410w3411_512Supported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (IRutokenSession session = slot.OpenRutokenSession(SessionType.ReadWrite))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        try
                        {
                            // Получить приватный ключ для генерации подписи
                            Console.WriteLine("Getting signing key...");
                            List<IObjectHandle> privateKeys = session.FindAllObjects(PrivateKeyAttributes);
                            Errors.Check("No private keys found", privateKeys.Count > 0);

                            // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2012(512)
                            var signMechanism = Helpers.factories.MechanismFactory.Create((uint)Extended_CKM.CKM_GOSTR3410_WITH_GOSTR3411_12_512);

                            // Подписать данные
                            Console.WriteLine("Signing data...");
                            byte[] signature = session.Sign(signMechanism, privateKeys[0], SampleData.Digest_Gost3411_SourceData);

                            // Распечатать буфер, содержащий подпись
                            Console.WriteLine(" Signature buffer is:");
                            Helpers.PrintByteArray(signature);
                            Console.WriteLine("Data has been signed successfully");
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
