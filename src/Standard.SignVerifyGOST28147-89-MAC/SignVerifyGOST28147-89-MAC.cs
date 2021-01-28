using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace Standard.SignVerifyGOST28147_89_MAC
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команд выработки имитовставки на ключе ГОСТ 28147-89:    *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - выполнение аутентификации Пользователя;                             *
    *  - выработка имитовставки для сообщения на демонстрационном ключе;     *
    *  - проверка имитовставки на демонстрационном ключе;                    *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Пример использует объекты, созданные в памяти Рутокен примером         *
    * CreateGOST28147-89.                                                    *
    *************************************************************************/

    class SignVerifyGOST28147_89_MAC
    {
        // Шаблон для поиска симметричного ключа ГОСТ 28147-89
        static readonly List<IObjectAttribute> SymmetricKeyAttributes = new List<IObjectAttribute>
        {
            // Идентификатор ключа
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            // Класс - секретный ключ
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

                    // Определение поддерживаемых токеном механизмов
                    Console.WriteLine("Checking mechanisms available");
                    List<CKM> mechanisms = slot.GetMechanismList();
                    Errors.Check(" No mechanisms available", mechanisms.Count > 0);
                    bool isGost28147MACSupported = mechanisms.Contains((CKM)CKM.CKM_GOST28147_MAC);
                    Errors.Check(" CKM_GOST28147_MAC isn`t supported!", isGost28147MACSupported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (IRutokenSession session = slot.OpenRutokenSession(SessionType.ReadWrite))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        try
                        {
                            // Получить ключ для выработки имитовставки
                            Console.WriteLine("Getting MAC key...");
                            List<IObjectHandle> keys = session.FindAllObjects(SymmetricKeyAttributes);
                            Errors.Check("No keys found", keys.Count > 0);

                            // Инициализация операции выработки имитовставки
                            var hmacMechanism = Helpers.factories.MechanismFactory.Create((uint)CKM.CKM_GOST28147_MAC);

                            // Выработать имитовставку
                            Console.WriteLine("Signing data...");
                            byte[] signature = session.Sign(hmacMechanism, keys[0], SampleData.Digest_Gost3411_SourceData);

                            // Распечатать буфер, содержащий имитовставку
                            Console.WriteLine(" MAC buffer is:");
                            Helpers.PrintByteArray(signature);
                            Console.WriteLine("MAC has been computed successfully");

                            // Проверка имитовставки
                            Console.WriteLine("Verifying MAC...");
                            bool isSignatureValid;
                            session.Verify(hmacMechanism, keys[0], SampleData.Digest_Gost3411_SourceData, signature, out isSignatureValid);

                            if (isSignatureValid)
                                Console.WriteLine("Verifying has been completed successfully");
                            else
                                throw new InvalidOperationException("Invalid signature");
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
