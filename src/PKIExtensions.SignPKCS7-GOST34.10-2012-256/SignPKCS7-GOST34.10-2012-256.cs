using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace PKIExtensions.SignPKCS7_GOST3410_2012_256
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен ЭЦП при помощи библиотеки PKCS#11 на языке C#  *
    *------------------------------------------------------------------------*
    * Использование команды подписи данных ключевой парой ГОСТ Р 34.10-2012  *
    * с длиной закрытого ключа 256 бит в формате PKCS#7:                     *
    *  - установление соединения с Рутокен ЭЦП в первом доступном слоте;     *
    *  - выполнение аутентификации Пользователя;                             *
    *  - поиск закрытого ключа ГОСТ Р 34.10-2012 (256 бит) и сертификата     *
    *    на Рутокен;                                                         *
    *  - подпись данных в формате PKCS#7;                                    *
    *  - сброс прав доступа Пользователя и закрытие соединения с Рутокен.    *
    *------------------------------------------------------------------------*
    * Пример использует объекты, созданные в памяти Рутокен примерами        *
    * PKIExtensions.CreateCSR-PKCS10-GOST34.10-2012-256 и                    *
    * PKIExtensions.ImportCertificate-GOST34.10-2012-256                     *
    *************************************************************************/

    class SignPKCS7_GOST3410_2012_256
    {
        // Шаблон для поиска закрытого ключа ГОСТ Р 34.10-2012 (256 бит)
        static readonly List<IObjectAttribute> PrivateKeyAttributes = new List<IObjectAttribute>
        {
            // Объект закрытого ключа
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            // Закрытый ключ является объектом токена
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            // Идентификатор искомой пары
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.Gost256KeyPairId1),
       };

        // Шаблон для поиска сертификата ключа подписи
        static readonly List<IObjectAttribute> CertificateAttributes = new List<IObjectAttribute>
        {
            // Объект сертификата
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
            // Сертификат является объектом токена
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            // Идентификатор сертификата
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.Gost256KeyPairId1),
            // Тип сертификата - X.509
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
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
                            // Формирование подписи
                            Console.WriteLine("Signing...");

                            // Поиск закрытого ключа на токене
                            Console.WriteLine(" Getting private key...");
                            List<IObjectHandle> privateKeys = session.FindAllObjects(PrivateKeyAttributes);
                            Errors.Check("No private keys found", privateKeys.Count > 0);

                            // Поиск сертификата на токене
                            Console.WriteLine(" Getting certificate...");
                            List<IObjectHandle> certificates = session.FindAllObjects(CertificateAttributes);
                            Errors.Check("No certificates found", certificates.Count > 0);

                            // Подпись данных
                            byte[] signature = session.PKCS7Sign(SampleData.PKCS7_SignDataBytes,
                                certificates[0], privateKeys[0], null, SampleConstants.UseHardwareHash);

                            // Для преобразования строки в массив байт
                            // можно воспользоваться следующим закомментированным примером
                            // с использованием метода ConvertUtils.Utf8StringToBytes
                            //byte[] signature = session.PKCS7Sign(ConvertUtils.Utf8StringToBytes(SampleData.PKCS7_SignData),
                            //        certificates[0], privateKeys[0], null, SampleConstants.UseHardwareHash);

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
