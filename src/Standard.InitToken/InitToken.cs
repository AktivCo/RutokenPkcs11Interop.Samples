using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace InitToken
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команд инициализации Рутокен:                            *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - инициализация токена;                                               *
    *  - выполнение аутентификации Администратора;                           *
    *  - инициализация PIN-кода Пользователя;                                *
    *  - сброс прав доступа Администратора и закрытие соединения с Рутокен.  *
    *------------------------------------------------------------------------*
    * Данный пример является самодостаточным.                                *
    *************************************************************************/

    class InitToken
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

                    // Инициализировать токен
                    Console.WriteLine("Token initialization");
                    slot.InitToken(SampleConstants.SecurityOfficerPin, SampleConstants.TokenStdLabel);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (IRutokenSession session = slot.OpenRutokenSession(SessionType.ReadWrite))
                    {
                        // Выполнить аутентификацию Администратора
                        Console.WriteLine("SO authentication");
                        session.Login(CKU.CKU_SO, SampleConstants.SecurityOfficerPin);

                        try
                        {
                            // Инициализировать PIN-код Пользователя
                            Console.WriteLine("User PIN initialization");
                            session.InitPin(SampleConstants.NormalUserPin);

                            Console.WriteLine("Initialization has been completed successfully");
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
