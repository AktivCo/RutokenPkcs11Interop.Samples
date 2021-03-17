using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace PKIExtensions.CreateCSR_PKCS10_GOST3410_2012_512
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен ЭЦП при помощи библиотеки PKCS#11 на языке C#  *
    *------------------------------------------------------------------------*
    * Использование команды создания запроса на сертификат ключа подписи для *
    * ключевой пары ГОСТ Р 34.10-2012 с длиной закрытого ключа 512 бит:      *
    *  - установление соединения с Рутокен ЭЦП в первом доступном слоте;     *
    *  - выполнение аутентификации Пользователя;                             *
    *  - генерация ключевой пары ГОСТ 34.10-2012(512) на Рутокен;            *
    *  - создание подписанного запроса на сертификат для сгенерированной     *
    *    ключевой пары и его вывод;                                          *
    *  - сброс прав доступа Пользователя и закрытие соединения с Рутокен.    *
    *------------------------------------------------------------------------*
    * Созданные примером объекты используются также и в других примерах      *
    * работы с библиотекой PKCS#11.                                          *
    *************************************************************************/

    class CreateCSR_PKCS10_GOST3410_2012_512
    {
        // Шаблон для создания открытого ключа ГОСТ Р 34.10-2012 (512 бит)
        static readonly List<IObjectAttribute> PublicKeyAttributes = new List<IObjectAttribute>
        {
            // Объект открытого ключа
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            // Метка ключа
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, SampleConstants.Gost512PublicKeyLabel1),
            // Идентификатор ключевой пары #1 (должен совпадать у открытого и закрытого ключей)
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.Gost512KeyPairId1),
            // Тип ключа
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410_512),
            // Открытый ключ является объектом токена
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            // Ключ доступен без аутентификации
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
            // Параметры алгоритма ГОСТ Р 34.10-2012(512)
            Helpers.factories.ObjectAttributeFactory.Create((uint) CKA.CKA_GOSTR3410_PARAMS, SampleConstants.GostR3410_512_Parameters),
            // Параметры алгоритма ГОСТ Р 34.11-2012 (512 бит). Использование этих параметров явно задает
	        // требование на генерацию ГОСТ Р 34.10-2012 (512 бит)
            Helpers.factories.ObjectAttributeFactory.Create((uint) CKA.CKA_GOSTR3411_PARAMS, SampleConstants.GostR3411_512_Parameters)
        };

        // Шаблон для создания закрытого ключа ГОСТ Р 34.10-2012 (512 бит)
        static readonly List<IObjectAttribute> PrivateKeyAttributes = new List<IObjectAttribute>
        {
            // Объект закрытого ключа
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            // Метка ключа
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, SampleConstants.Gost512PrivateKeyLabel1),
            // Идентификатор ключевой пары #1 (должен совпадать у открытого и закрытого ключей)
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, SampleConstants.Gost512KeyPairId1),
            // Тип ключа
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410_512),
            // Открытый ключ является объектом токена
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            // Ключ доступен без аутентификации
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
            // Ключ поддерживает выработку общих ключей (VKO)
            Helpers.factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, true),
            // Параметры алгоритма ГОСТ Р 34.10-2012 (512 бит)
            Helpers.factories.ObjectAttributeFactory.Create((uint) CKA.CKA_GOSTR3410_PARAMS, SampleConstants.GostR3410_512_Parameters),
            // Параметры алгоритма ГОСТ Р 34.11-2012 (512 бит). Использование этих параметров явно задает
	        // требование на генерацию ГОСТ Р 34.10-2012 (512 бит)
            Helpers.factories.ObjectAttributeFactory.Create((uint) CKA.CKA_GOSTR3411_PARAMS, SampleConstants.GostR3411_512_Parameters)
        };

        // Список полей DN (Distinguished Name)
        static readonly string[] Dn =
        {
            "CN",                        // Тип поля CN (Common Name)
            "UTF8String:Иванов",         // Значение
            "C",                         // C (Country)
            "RU",
            "2.5.4.5",                   // SN (Serial Number)
            "12312312312",
            "1.2.840.113549.1.9.1",      // E (E-mail)
            "ivanov@mail.ru",
            "ST",                        // ST (State or province)
            "UTF8String:Москва",
            "O",                         // O (Organization)
            "CompanyName",
            "OU",                        // OU (Organizational Unit)
            "Devel",
            "L",                         // L (Locality)
            "Moscow"
        };

        // Список дополнительных полей
        static readonly string[] Exts =
        {
            "keyUsage",                                                               // Использование ключа
            "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment",
            "extendedKeyUsage",                                                       // Дополнительное использование
            "1.2.643.2.2.34.6,1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4",
            "2.5.29.14",                                                              // Идентификатор ключа субъекта (SKI)
            "ASN1:FORMAT:HEX,OCTETSTRING:FE117B93CEC6B5065E1613E155D3A9CA597C0F81",
            "2.5.29.17",                                                              // Дополнительное имя (пример с кодированием в виде DER)
            "DER:30:0F:81:0D:65:78:61:6d:70:6c:65:40:79:61:2E:72:75",
            "2.5.29.32",                                                              // Политики сертификата (кодирование в виде DER с пометкой "critical")
            "critical,DER:30:0A:30:08:06:06:2A:85:03:64:71:01",
            "1.2.643.100.111",                                                        // Средства электронной подписи владельца
            "ASN1:UTF8String:СКЗИ \\\"Рутокен ЭЦП 2.0\\\""
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
                    bool isGostR3410_2012_512Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3410_512_KEY_PAIR_GEN);
                    bool isGostR3411_12_512_Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3411_12_512);
                    Errors.Check(" CKM_GOSTR3410_512_KEY_PAIR_GEN isn`t supported!", isGostR3410_2012_512Supported);
                    Errors.Check(" CKM_GOSTR3411_12_512 isn`t supported!", isGostR3411_12_512_Supported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (IRutokenSession session = slot.OpenRutokenSession(SessionType.ReadWrite))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        try
                        {
                            // Создать запрос на сертификат
                            Console.WriteLine("Creating CSR...");

                            // Генерация ключевой пары на токене
                            // Определить механизм генерации ключа
                            Console.WriteLine("Generating GOST R 34.10-2012(512) exchange key pairs...");
                            var mechanism = Helpers.factories.MechanismFactory.Create((uint)Extended_CKM.CKM_GOSTR3410_512_KEY_PAIR_GEN);

                            IObjectHandle publicKeyHandle;
                            IObjectHandle privateKeyHandle;
                            session.GenerateKeyPair(mechanism, PublicKeyAttributes, PrivateKeyAttributes, out publicKeyHandle, out privateKeyHandle);
                            Errors.Check("Invalid public key handle", publicKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
                            Errors.Check("Invalid private key handle", privateKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);

                            // Создание запроса на сертификат
                            string csr = session.CreateCSR(publicKeyHandle, Dn, privateKeyHandle, null, Exts);
                            Errors.Check("Invalid csr", csr != null);
                            Errors.Check("Invalid csr length", csr.Length > 0);

                            // Распечатать буфер в кодировке Base64
                            Console.WriteLine(csr);
                            Console.WriteLine("Creating has been completed successfully.");
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
