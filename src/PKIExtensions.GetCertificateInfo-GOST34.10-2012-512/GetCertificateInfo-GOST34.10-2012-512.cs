﻿using System;
using System.Collections.Generic;
using System.Linq;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Samples.Common;

namespace PKIExtensions.GetCertificateInfo_GOST3410_2012_512
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
    * PKIExtensions.ImportCertificate-GOST34.10-2012-512).                   *
    *************************************************************************/

    class GetCertificateInfo_GOST3410_2012_512
    {
        // Шаблон для поиска сертификата
        static readonly List<ObjectAttribute> CertificateAttributes = new List<ObjectAttribute>
        {
            // Объект сертификата
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
            // Сертификат является объектом токена
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            // Сертификат доступен без аутентификации
            new ObjectAttribute(CKA.CKA_PRIVATE, false),
            // Тип сертификата - X.509
            new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
            // Идентификатор сертификата, должен совпадать с CKA_ID соответствующей ключевой пары
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost512KeyPairId1),
            // Категория сертификата - пользовательский
            new ObjectAttribute(CKA.CKA_CERTIFICATE_CATEGORY, SampleConstants.TokenUserCertificate)
        };

        static void Main(string[] args)
        {
            try
            {
                // Инициализировать библиотеку
                Console.WriteLine("Library initialization");
                using (var pkcs11 = new Pkcs11(Settings.RutokenEcpDllDefaultPath, Settings.OsLockingDefault))
                {
                    // Получить доступный слот
                    Console.WriteLine("Checking tokens available");
                    Slot slot = Helpers.GetUsableSlot(pkcs11);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
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
