using System;
using System.IO;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace PKIExtensions.VerifyPKCS7Detached
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен ЭЦП при помощи библиотеки PKCS#11 на языке C#  *
    *------------------------------------------------------------------------*
    * Использование команды проверки подписанных данных ключевой парой       *
    * ГОСТ Р 34.10-2001 в формате PKCS#7:                                    *
    *  - установление соединения с Рутокен ЭЦП в первом доступном слоте;     *
    *  - выполнение аутентификации Пользователя;                             *
    *  - проверка подписанного сообщения в формате PKCS#7, которое не хранит *
    *    исходные данные;                                                    *
    *  - сброс прав доступа Пользователя и закрытие соединения с Рутокен.    *
    *                                                                        *
    * На данный момент функции C_EX_PKCS7VerifyInit, C_EX_PKCS7VerifyUpdate  *
    * и C_EX_PKCS7VerifyFinal поддерживают только алгоритм ГОСТ Р 34.10-2001 *
    *------------------------------------------------------------------------*
    * Пример использует объекты, созданные в памяти примерами                *
    * PKIExtensions.ImportCertificate-GOST34.10-2001 и                       *
    * PKIExtensions.SignPKCS7Detached-GOST34.10-2001                         *
    * (положить в папку с exe-файлом signature.bin).                         *
    * Также необходимо предоставить сертификат УЦ                            *
    * (положить в папку с exe-файлом CA_cert.cer), в котором был выписан     *
    * сертификат в примере PKIExtensions.ImportCertificate-GOST34.10-2001    *
    * в der кодировке                                                        *
    *************************************************************************/

    class VerifyPKCS7Detached
    {
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
                            Console.WriteLine("Reading CA certificate...");
                            var CACertificate = File.ReadAllBytes("CA_cert.cer");

                            Console.WriteLine("Reading CMS...");
                            var cms = File.ReadAllBytes("signature.bin");

                            // Проверка подписи
                            Console.WriteLine("Verifying...");
                            using (var inputStream = new MemoryStream(SampleData.PKCS7_SignDataBytes))
                            {
                                var result = session.PKCS7Verify(cms, inputStream,
                                    new CkVendorX509Store(new[] { CACertificate }), VendorCrlMode.OptionalClrCheck, 0);

                                if (result.IsValid)
                                {
                                    Console.WriteLine(" Signer certificate's data is:");
                                    foreach (var certificate in result.Certificates)
                                    {
                                        Helpers.PrintByteArray(certificate);
                                    }

                                    Console.WriteLine("Verifying has been completed successfully");
                                }
                                else
                                    throw new InvalidOperationException("Invalid signature");
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
