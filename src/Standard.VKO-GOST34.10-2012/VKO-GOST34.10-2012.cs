﻿using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI.MechanismParams;
using RutokenPkcs11Interop.Samples.Common;

namespace VKO_GOST3410_2012
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2017, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команд выработки общего ключа, шифрования одного ключа   *
    * другим:                                                                *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - выполнение аутентификации Пользователя;                             *
    *  - выработка общего ключа на первой стороне;                           *
    *  - маскирование ключа на выработанном общем ключе;                     *
    *  - выработка общего ключа на второй стороне;                           *
    *  - демаскирование ключа на выработанном общем ключе;                   *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Пример использует объекты, созданные в памяти Рутокен примером         *
    * CreateGOST34.10-2012.                                                  *
    *************************************************************************/

    class VKO_GOST3410_2012
    {
        // Шаблон для поиска закрытого ключа отправителя
        static readonly List<ObjectAttribute> SenderPrivateKeyAttributes = new List<ObjectAttribute>
        {
            // ID пары
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost512KeyPairId1),
            // Класс - закрытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            // Тип ключа - ГОСТ Р 34.10-2012(512)
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410_512)
        };

        // Шаблон для поиска закрытого ключа получателя
        static readonly List<ObjectAttribute> RecipientPrivateKeyAttributes = new List<ObjectAttribute>
        {
            // ID пары
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost512KeyPairId2),
            // Класс - закрытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            // Тип ключа - ГОСТ Р 34.10-2012(512)
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410_512)
        };

        // Шаблон для поиска открытого ключа отправителя
        static readonly List<ObjectAttribute> SenderPublicKeyAttributes = new List<ObjectAttribute>
        {
            // ID пары
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost512KeyPairId1),
            // Класс - открытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            // Тип ключа - ГОСТ Р 34.10-2012(512)
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410_512)
        };

        // Шаблон для поиска открытого ключа получателя
        static readonly List<ObjectAttribute> RecipientPublicKeyAttributes = new List<ObjectAttribute>
        {
            // ID пары
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost512KeyPairId2),
            // Класс - открытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            // Тип ключа - ГОСТ Р 34.10-2012(512)
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410_512)
        };

        // Шаблон для создания ключа обмена
        static readonly List<ObjectAttribute> DerivedKeyAttributes = new List<ObjectAttribute>
        {
            // Метка ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.DerivedKeyLabel),
            // Класс - секретный ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            // Тип ключа - ГОСТ 28147-89
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOST28147),
            // Ключ является объектом сессии
            new ObjectAttribute(CKA.CKA_TOKEN, false),
            // Ключ может быть изменен после создания
            new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
            // Ключ недоступен без аутентификации на токене
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            // Ключ может быть извлечен в зашифрованном виде
            new ObjectAttribute(CKA.CKA_EXTRACTABLE, true),
            // Ключ может быть извлечен в открытом виде
            new ObjectAttribute(CKA.CKA_SENSITIVE, false)
        };

        // Шаблон маскируемого ключа
        static readonly List<ObjectAttribute> SessionKeyAttributes = new List<ObjectAttribute>
        {
            // Метка ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.WrappedKeyLabel),
            // Класс - секретный ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            // Тип ключа - ГОСТ 28147-89
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOST28147),
            // Ключ является объектом сессии
            new ObjectAttribute(CKA.CKA_TOKEN, false),
            // Ключ может быть изменен после создания
            new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
            // Ключ недоступен без аутентификации на токене
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            // Ключ может быть извлечен в зашифрованном виде
            new ObjectAttribute(CKA.CKA_EXTRACTABLE, true),
            // Ключ может быть извлечен в открытом виде
            new ObjectAttribute(CKA.CKA_SENSITIVE, false)
        };

        // Шаблон демаскированного ключа
        static readonly List<ObjectAttribute> UnwrappedKeyAttributes = new List<ObjectAttribute>
        {
            // Метка ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.UnwrappedKeyLabel),
            // Класс - секретный ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            // Тип ключа - ГОСТ 28147-89
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOST28147),
            // Ключ является объектом сессии
            new ObjectAttribute(CKA.CKA_TOKEN, false),
            // Ключ может быть изменен после создания
            new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
            // Ключ доступен без аутентификации на токене
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            // Ключ может быть извлечен в зашифрованном виде
            new ObjectAttribute(CKA.CKA_EXTRACTABLE, true),
            // Ключ может быть извлечен в открытом виде
            new ObjectAttribute(CKA.CKA_SENSITIVE, false)
        };

        /// <summary>
        /// Функция выработки ключа обмена
        /// </summary>
        /// <param name="session">Хэндл сессии</param>
        /// <param name="privateKeyAttributes">Шаблон для поиска закрытого ключа</param>
        /// <param name="publicKeyAttributes">Шаблон для поиска открытого ключа</param>
        /// <param name="ukm">Буфер, содержащий UKM</param>
        /// <param name="derivedKeyHandle">Хэндл выработанного общего ключа</param>
        public static void Derive_GostR3410_12_Key(Session session,
            List<ObjectAttribute> privateKeyAttributes,
            List<ObjectAttribute> publicKeyAttributes,
            byte[] ukm, out ObjectHandle derivedKeyHandle)
        {
            // Получить массив хэндлов закрытых ключей
            Console.WriteLine("Getting private key...");
            List<ObjectHandle> privateKeys = session.FindAllObjects(privateKeyAttributes);
            Errors.Check("No private keys found", privateKeys.Count > 0);

            // Получить массив хэндлов открытых ключей
            Console.WriteLine("Getting public key...");
            List<ObjectHandle> publicKeys = session.FindAllObjects(publicKeyAttributes);
            Errors.Check("No public keys found", publicKeys.Count > 0);

            // Получаем значение открытого ключа
            Console.WriteLine("Getting public key value...");
            var attributes = new List<CKA>
            {
                CKA.CKA_VALUE
            };
            List<ObjectAttribute> publicKeyValue = session.GetAttributeValue(publicKeys[0], attributes);

            // Определение параметров механизма наследования ключа
            Console.WriteLine("Deriving key...");
            var deriveMechanismParams =
                new CkGostR3410_12_DeriveParams(
                    (uint) Extended_CKM.CKM_KDF_GOSTR3411_2012_256, publicKeyValue[0].GetValueAsByteArray(), ukm);

            // Определяем механизм наследования ключа
            var deriveMechanism = new Mechanism((uint) Extended_CKM.CKM_GOSTR3410_12_DERIVE, deriveMechanismParams);

            // Наследуем ключ
            derivedKeyHandle = session.DeriveKey(deriveMechanism, privateKeys[0], DerivedKeyAttributes);

            Errors.Check("Invalid derived key handle", derivedKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);

            try
            {
                // Получить и распечатать значение выработанного ключа
                List<ObjectAttribute> derivedKeyValue = session.GetAttributeValue(derivedKeyHandle, attributes);
                Console.WriteLine(" Derived key value:");
                Helpers.PrintByteArray(derivedKeyValue[0].GetValueAsByteArray());
            }
            catch (Pkcs11Exception)
            {
                // Уничтожаем ключ, если произошла ошибка при чтении значения
                session.DestroyObject(derivedKeyHandle);
                throw;
            }
        }

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

                    // Определение поддерживаемых токеном механизмов
                    Console.WriteLine("Checking mechanisms available");
                    List<CKM> mechanisms = slot.GetMechanismList();
                    Errors.Check(" No mechanisms available", mechanisms.Count > 0);
                    bool isGostR3410_12DeriveSupported = mechanisms.Contains((CKM) Extended_CKM.CKM_GOSTR3410_12_DERIVE);
                    bool isGostWrapSupported = mechanisms.Contains((CKM) Extended_CKM.CKM_GOST28147_KEY_WRAP);
                    Errors.Check(" CKM_GOSTR3410_12_DERIVE isn`t supported!", isGostR3410_12DeriveSupported);
                    Errors.Check(" CKM_GOST28147_KEY_WRAP isn`t supported!", isGostWrapSupported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        ObjectHandle sessionKeyHandle = null;
                        ObjectHandle senderDerivedKeyHandle = null;
                        ObjectHandle recipientDerivedKeyHandle = null;
                        ObjectHandle unwrappedKeyHandle = null;

                        try
                        {
                            // Генерация параметра для структуры типа CK_GOSTR3410_DERIVE_PARAMS
                            // для выработки общего ключа
                            Console.WriteLine("Preparing data for deriving and wrapping...");
                            byte[] ukm = session.GenerateRandom(SampleConstants.UkmLength);

                            // Генерация значения сессионного ключа
                            byte[] sessionKeyValue = session.GenerateRandom(SampleConstants.Gost28147_KeySize);

                            Console.WriteLine(" Session key data is:");
                            Helpers.PrintByteArray(sessionKeyValue);
                            Console.WriteLine("Preparing has been completed successfully");

                            // Выработка общего ключа на стороне отправителя
                            Console.WriteLine("Deriving key on the sender's side...");
                            Derive_GostR3410_12_Key(session,
                                SenderPrivateKeyAttributes, RecipientPublicKeyAttributes,
                                ukm, out senderDerivedKeyHandle);
                            Console.WriteLine("Key has been derived successfully");

                            // Маскировать сессионный ключ с помощью общего выработанного ключа
                            // на стороне отправителя
                            Console.WriteLine("Wrapping key...");
                            Console.WriteLine(" Creating the GOST 28147-89 key to wrap...");
                            // Выработка ключа, который будет замаскирован
                            SessionKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VALUE, sessionKeyValue));
                            sessionKeyHandle = session.CreateObject(SessionKeyAttributes);

                            // Определение параметров механизма маскирования
                            var wrapMechanismParams = new CkKeyDerivationStringData(ukm);
                            var wrapMechanism = new Mechanism((uint)Extended_CKM.CKM_GOST28147_KEY_WRAP, wrapMechanismParams);

                            // Маскирование ключа на общем ключе, выработанном на стороне отправителя
                            byte[] wrappedKey = session.WrapKey(wrapMechanism, senderDerivedKeyHandle, sessionKeyHandle);

                            Console.WriteLine("  Wrapped key data is:");
                            Helpers.PrintByteArray(wrappedKey);
                            Console.WriteLine(" Key has been wrapped successfully");

                            // Выработка общего ключа на стороне получателя
                            Console.WriteLine("Deriving key on the sender's side...");
                            Derive_GostR3410_12_Key(session,
                                RecipientPrivateKeyAttributes, SenderPublicKeyAttributes,
                                ukm, out recipientDerivedKeyHandle);
                            Console.WriteLine("Key has been derived successfully");

                            // Демаскирование сессионного ключа с помощью общего выработанного
                            // ключа на стороне получателя
                            Console.WriteLine("Unwrapping key...");
                            unwrappedKeyHandle =
                                session.UnwrapKey(wrapMechanism, recipientDerivedKeyHandle, wrappedKey, UnwrappedKeyAttributes);

                            // Сравнение ключа
                            // Получаем публичный ключ по его Id
                            var attributes = new List<CKA>
                            {
                                CKA.CKA_VALUE
                            };
                            List<ObjectAttribute> unwrappedKeyValueAttribute =
                                session.GetAttributeValue(unwrappedKeyHandle, attributes);
                            byte[] unwrappedKeyValue = unwrappedKeyValueAttribute[0].GetValueAsByteArray();

                            Console.WriteLine(" Unwrapped key data is:");
                            Helpers.PrintByteArray(unwrappedKeyValue);
                            Console.WriteLine("Unwrapping has been completed successfully");

                            bool equal = (Convert.ToBase64String(sessionKeyValue) ==
                                          Convert.ToBase64String(unwrappedKeyValue));
                            Errors.Check("Session and unwrapped keys are not equal!", equal);

                            Console.WriteLine("Session and unwrapped keys are equal");
                        }
                        finally
                        {
                            Console.WriteLine("Destroying keys");
                            // Удаляем сессионный ключ
                            if (sessionKeyHandle != null)
                            {
                                session.DestroyObject(sessionKeyHandle);
                            }

                            // Удаляем наследованные ключи
                            if (senderDerivedKeyHandle != null)
                            {
                                session.DestroyObject(senderDerivedKeyHandle);
                            }
                            if (recipientDerivedKeyHandle != null)
                            {
                                session.DestroyObject(recipientDerivedKeyHandle);
                            }

                            // Удаляем размаскированный ключ
                            if (unwrappedKeyHandle != null)
                            {
                                session.DestroyObject(unwrappedKeyHandle);
                            }

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
