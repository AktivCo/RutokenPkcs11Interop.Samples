using System;
using System.Collections.Generic;
using System.IO;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace EncDecGOST28147_89_Stream
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команд шифрования/расшифрования на ключе ГОСТ 28147-89:  *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - выполнение аутентификации Пользователя;                             *
    *  - шифрование сообщения на демонстрационном ключе (итеративно);        *
    *  - расшифрование зашифрованного сообщения на демонстрационном ключе;   *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Пример использует объекты, созданные в памяти Рутокен примером         *
    * CreateGOST28147-89.                                                    *
    *************************************************************************/

    class EncDecGOST28147_89_Stream
    {
        //  Шаблон для поиска симметричного ключа ГОСТ 28147-89
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

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (IRutokenSession session = slot.OpenRutokenSession(SessionType.ReadWrite))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        try
                        {
                            // Получить данные для шифрования
                            byte[] sourceData = SampleData.Encrypt_Gost28147_89_SourceData;

                            // Получить ключ для шифрования
                            Console.WriteLine("Getting secret key...");
                            List<IObjectHandle> keys = session.FindAllObjects(SymmetricKeyAttributes);
                            Errors.Check("No keys found", keys.Count > 0);

                            // Инициализировать операцию шифрования
                            var mechanism = Helpers.factories.MechanismFactory.Create((uint)CKM.CKM_GOST28147);

                            // Зашифровать данные
                            Console.WriteLine("Encrypting...");
                            byte[] encryptedData = null;
                            using (MemoryStream inputStream = new MemoryStream(sourceData), outputStream = new MemoryStream())
                            {
                                session.Encrypt(mechanism, keys[0], inputStream, outputStream, 8);
                                encryptedData = outputStream.ToArray();
                            }

                            // Распечатать буфер, содержащий зашифрованные данные
                            Console.WriteLine(" Encrypting buffer is:");
                            Helpers.PrintByteArray(encryptedData);
                            Console.WriteLine("Encryption has been completed successfully");

                            // Расшифровать данные
                            Console.WriteLine("Decrypting...");
                            byte[] decryptedData = null;
                            using (MemoryStream inputStream = new MemoryStream(encryptedData), outputStream = new MemoryStream())
                            {
                                session.Decrypt(mechanism, keys[0], inputStream, outputStream, 8);
                                decryptedData = outputStream.ToArray();
                            }

                            // Распечатать буфер, содержащий расшифрованные данные
                            Console.WriteLine(" Decrypted buffer is:");
                            Helpers.PrintByteArray(decryptedData);
                            Console.WriteLine("Decryption has been completed successfully");

                            // Сравнить исходные данные с расшифрованными
                            bool encryptionState = (Convert.ToBase64String(sourceData) ==
                                                    Convert.ToBase64String(decryptedData));
                            Errors.Check("Source data and decrypted data are not equal", encryptionState);

                            Console.WriteLine("Source data and decrypted data are equal");
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
