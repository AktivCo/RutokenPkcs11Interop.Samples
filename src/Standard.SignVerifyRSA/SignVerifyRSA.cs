using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace SignVerifyRSA
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команд вычисления/проверки ЭЦП на ключах RSA:            *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - выполнение аутентификации Пользователя на Рутокен;                  *
    *  - подпись сообщения на демонстрационном ключе;                        *
    *  - проверка подписи на демонстрационном ключе;                         *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Пример использует объекты, созданные в памяти Рутокен примером         *
    * CreateRSA.                                                             *
    *************************************************************************/

    class SignVerifyRSA
    {
        // Шаблон для поиска открытого ключа RSA
        static readonly List<IObjectAttribute> PublicKeyAttributes = new List<IObjectAttribute>
        {
            // ID пары
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.RsaKeyPairId),
            // Класс - открытый ключ
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
        };

        // Шаблон для поиска закрытого ключа RSA
        static readonly List<IObjectAttribute> PrivateKeyAttributes = new List<IObjectAttribute>
        {
            // ID пары
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.RsaKeyPairId),
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
                    bool isRsaSupported = mechanisms.Contains(CKM.CKM_RSA_PKCS);
                    bool isSha1Supported = mechanisms.Contains(CKM.CKM_SHA_1);
                    Errors.Check(" CKM_RSA_PKCS isn`t supported!", isRsaSupported);
                    Errors.Check(" CKM_SHA_1 isn`t supported!", isSha1Supported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (IRutokenSession session = slot.OpenRutokenSession(SessionType.ReadWrite))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        try
                        {
                            // Получить данные для вычисления подписи
                            byte[] sourceData = SampleData.Digest_Gost3411_SourceData;

                            // Получить приватный ключ для генерации подписи
                            Console.WriteLine("Getting private key...");
                            List<IObjectHandle> privateKeys = session.FindAllObjects(PrivateKeyAttributes);
                            Errors.Check("No private keys found", privateKeys.Count > 0);

                            // Инициализировать операцию хэширования
                            var mechanism = Helpers.factories.MechanismFactory.Create(CKM.CKM_SHA_1);

                            // Вычислить хэш-код данных
                            Console.WriteLine("Hashing data...");
                            byte[] hash = session.Digest(mechanism, sourceData);

                            // Распечатать буфер, содержащий хэш-код
                            Console.WriteLine(" Hashed buffer is:");
                            Helpers.PrintByteArray(hash);
                            Console.WriteLine("Hashing has been completed successfully");

                            // Инициализация операции подписи данных по алгоритму RSA
                            var signMechanism = Helpers.factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);

                            // Подписать данные
                            Console.WriteLine("Signing data...");
                            byte[] signature = session.Sign(signMechanism, privateKeys[0], hash);

                            // Распечатать буфер, содержащий подпись
                            Console.WriteLine(" Signature buffer is:");
                            Helpers.PrintByteArray(signature);
                            Console.WriteLine("Data has been signed successfully");

                            // Получить публичный ключ для проверки подписи
                            Console.WriteLine("Getting public key...");
                            List<IObjectHandle> publicKeys = session.FindAllObjects(PublicKeyAttributes);
                            Errors.Check("No public keys found", publicKeys.Count > 0);

                            // Проверка подписи для данных
                            Console.WriteLine("Verifying data...");
                            bool isSignatureValid = false;
                            session.Verify(signMechanism, publicKeys[0], hash, signature, out isSignatureValid);

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
