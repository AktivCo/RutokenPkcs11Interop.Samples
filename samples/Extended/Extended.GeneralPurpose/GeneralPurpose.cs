using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace Extended.GeneralPurpose
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Пример использования функций расширения компании "Актив"               *
    * стандарта PKCS#11:                                                     *
    *  - установление соединения с Rutoken в первом доступном слоте;         *
    *  - выполнение инициализации токена;                                    *
    *  - блокирование PIN-кода Пользователя;                                 *
    *  - разблокирование PIN-кода Пользователя;                              *
    *  - задание новой метки токена;                                         *
    *  - вывод информации о токене.                                          *
    *------------------------------------------------------------------------*
    * Данный пример является самодостаточным.                                *
    *************************************************************************/

    class GeneralPurpose
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

                    // Получить расширенную информацию о подключенном токене
                    Console.WriteLine("Getting extended token information...");
                    ITokenInfoExtended tokenInfo = slot.GetTokenInfoExtended();

                    // Определить класс токена
                    var isRutokenS = (tokenInfo.TokenClass == RutokenClass.S);

                    Console.WriteLine("Extended token information has been got successfully");

                    Console.WriteLine("Extended initializing token...");
                    var rutokenInitParam = Helpers.factories.RutokenInitParamFactory.Create(SampleConstants.SecurityOfficerPin, SampleConstants.NewUserPin,
                        SampleConstants.TokenStdLabel,
                        new List<RutokenFlag> { RutokenFlag.AdminChangeUserPin, RutokenFlag.UserChangeUserPin }, isRutokenS ? (uint)1 : 6, isRutokenS ? (uint)1 : 6,
                        SampleConstants.MaxAdminRetryCount, SampleConstants.MaxUserRetryCount, smMode: 0);
                    slot.InitTokenExtended(SampleConstants.SecurityOfficerPin, rutokenInitParam);
                    Console.WriteLine("Token has been initialized successfully");

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (IRutokenSession session = slot.OpenRutokenSession(SessionType.ReadWrite))
                    {
                        Console.WriteLine("Extended PIN function test...");
                        // Пробуем заблокировать PIN-код Пользователя
                        Console.WriteLine(" Locking user PIN...");
                        // Ввод неправильного PIN-кода Пользователя до блокировки PIN-кода
                        for (var i = 0; i < (SampleConstants.MaxUserRetryCount + 1); i++)
                        {
                            try
                            {
                                Console.WriteLine($"Login with wrong user PIN: {i}");
                                session.Login(CKU.CKU_USER, SampleConstants.WrongUserPin);
                            }
                            catch (Pkcs11Exception ex)
                            {
                                if (ex.RV != CKR.CKR_PIN_INCORRECT && ex.RV != CKR.CKR_PIN_LOCKED)
                                {
                                    throw;
                                }

                                switch (ex.RV)
                                {
                                    case CKR.CKR_PIN_INCORRECT:
                                        Console.WriteLine(" -> Wrong PIN");
                                        break;
                                    case CKR.CKR_PIN_LOCKED:
                                        Console.WriteLine(" -> PIN Locked");
                                        break;
                                }
                            }
                        }
                        // Пробуем разблокировать PIN-код Пользователя
                        Console.WriteLine(" Unlocking user PIN...");

                        // Выполнить аутентификацию администратора
                        session.Login(CKU.CKU_SO, SampleConstants.SecurityOfficerPin);

                        try
                        {
                            // Разблокировать PIN-код Пользователя
                            session.UnblockUserPIN();
                        }
                        finally
                        {
                            // Завершение сессии администратора
                            session.Logout();
                        }

                        Console.WriteLine("Extended PIN function test has been completed successfully");

                        Console.WriteLine("Work with token name...");

                        // Аутентификация пользователя
                        session.Login(CKU.CKU_USER, SampleConstants.NewUserPin);

                        try
                        {
                            //Изменить метку токена на "длинную"
                            Console.WriteLine($" Set long token name: {SampleConstants.TokenLongLabel}");
                            session.SetTokenName(SampleConstants.TokenLongLabel);

                            // Получение метки токена
                            string tokenLabel = session.GetTokenLabel();
                            Console.WriteLine(" Reading token name...");
                            Console.WriteLine($" Token name: {tokenLabel}");

                            Console.WriteLine("Work with token name has been completed successfully");

                            // Вывести расширенную информацию о токене
                            Console.WriteLine("Extended information:");
                            Console.Write(" Token type: ");
                            switch (tokenInfo.TokenType)
                            {
                                case RutokenType.ECP:
                                    Console.WriteLine("(Rutoken ECP)");
                                    break;
                                case RutokenType.LITE:
                                    Console.WriteLine("(Rutoken Lite)");
                                    break;
                                case RutokenType.RUTOKEN:
                                    Console.WriteLine("(Rutoken S)");
                                    break;
                                case RutokenType.PINPAD_FAMILY:
                                    Console.WriteLine("(Rutoken PINPad)");
                                    break;
                                default:
                                    Console.WriteLine("Unknown token type: " + tokenInfo.TokenType);
                                    break;
                            }
                            Console.WriteLine(" Protocol number: 0x{0:X}", tokenInfo.ProtocolNumber);
                            Console.WriteLine(" Microcode number: 0x{0:X}", tokenInfo.MicrocodeNumber);
                            Console.WriteLine(" Order number: 0x{0:X}", tokenInfo.OrderNumber);
                            Console.WriteLine(" Flags: 0x{0:X}", tokenInfo.Flags);
                            Console.WriteLine(" Max admin PIN length: 0x{0:X}", tokenInfo.MaxAdminPinLen);
                            Console.WriteLine(" Min admin PIN length: 0x{0:X}", tokenInfo.MinAdminPinLen);
                            Console.WriteLine(" Max user PIN length: 0x{0:X}", tokenInfo.MaxUserPinLen);
                            Console.WriteLine(" Min user PIN length: 0x{0:X}", tokenInfo.MinUserPinLen);
                            Console.WriteLine(" Max admin retry counter: 0x{0:X}", tokenInfo.MaxAdminRetryCount);
                            Console.WriteLine(" Admin retry counter: 0x{0:X}", tokenInfo.AdminRetryCountLeft);
                            Console.WriteLine(" Max user retry counter: 0x{0:X}", tokenInfo.MaxUserRetryCount);
                            Console.WriteLine(" User retry counter: 0x{0:X}", tokenInfo.UserRetryCountLeft);
                            Console.WriteLine(" Serial number: {0}", tokenInfo.SerialNumber);
                            Console.WriteLine(" Total memory: 0x{0:X}", tokenInfo.TotalMemory);
                            Console.WriteLine(" Free memory: 0x{0:X}", tokenInfo.FreeMemory);
                            Console.WriteLine(" ATR: {0}", tokenInfo.ATR);
                            Console.WriteLine(" Token class: {0}", tokenInfo.TokenClass);
                            Console.WriteLine(" Battery voltage (Bluetooth): 0x{0:X}", tokenInfo.BatteryVoltage);
                            Console.WriteLine(" BodyColor (Bluetooth): {0}", tokenInfo.BodyColor);
                            Console.WriteLine(" Firmware checksum:  0x{0:X}", tokenInfo.FirmwareChecksum);

                            Console.WriteLine("Extended info test has been completed successfully");

                            // Установить PIN-код Пользователя по умолчанию
                            Console.WriteLine("Changing user PIN to default...");
                            session.SetPin(SampleConstants.NewUserPin, SampleConstants.NormalUserPin);
                            Console.WriteLine("User PIN has been changed to default successfully");
                        }
                        finally
                        {
                            // Завершение сессии пользователя
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
