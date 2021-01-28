using System;
using System.Collections.Generic;
using System.Linq;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace PKIExtensions.GetCertificateInfo_GOST3410_2001
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен ЭЦП при помощи библиотеки PKCS#11 на языке C#  *
    *------------------------------------------------------------------------*
    * Использование команды получения информации о сертификате на токене:    *
    *  - установление соединения с Рутокен ЭЦП в первом доступном слоте;     *
    *  - выполнение аутентификации Пользователя;                             *
    *  - получение информации об импортированном на Рутокен сертификате;     *
    *  - сброс прав доступа Пользователя и закрытие соединения с Рутокен.    *
    *------------------------------------------------------------------------*
    * Примеру необходимо наличие сертификата на токене (например, после      *
    * PKIExtensions.ImportCertificate-GOST34.10-2001).                       *
    *************************************************************************/

    class GetCertificateInfo_GOST3410_2001
    {
        // Шаблон для поиска сертификата
        static readonly List<IObjectAttribute> CertificateAttributes = new List<IObjectAttribute>
        {
            // Объект сертификата
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
            // Сертификат является объектом токена
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            // Сертификат доступен без аутентификации
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
            // Тип сертификата - X.509
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
            // Идентификатор сертификата, должен совпадать с CKA_ID соответствующей ключевой пары
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.GostKeyPairId1),
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
                            // Получение информации о сертификате
                            Console.WriteLine("Getting information...");
                            Console.WriteLine(" Getting certificates...");

                            // Получить массив хэндлов сертификатов
                            var certificates = session.FindAllObjects(CertificateAttributes);
                            Errors.Check(" Certificates not found", certificates != null);
                            Errors.Check(" Certificates not found", certificates.Any());

                            // Получение информации о сертификате
                            string certificateInfo = session.GetCertificateInfoText(certificates[0]);
                            Errors.Check(" Certificate info not found", !string.IsNullOrEmpty(certificateInfo));

                            // Распечатать буфер, содержащий информацию о сертификате
                            Console.WriteLine(certificateInfo);

                            Console.WriteLine("Information has been acquired successfully");
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
