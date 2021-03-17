using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace Info
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команд получения информации о доступных слотах           *
    * и токенах:                                                             *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - получение информации о библиотеке PKCS#11;                          *
    *  - получение информации о доступных слотах;                            *
    *  - получение информации о подключенных токенах;                        *
    *  - получение информации о поддерживаемых механизмах.                   *
    *------------------------------------------------------------------------*
    * Данный пример является самодостаточным.                                *
    *************************************************************************/

    class Info
    {
        static void Main(string[] args)
        {
            try
            {
                // Инициализировать библиотеку
                Console.WriteLine("Library initialization");
                using (var pkcs11 = Helpers.factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Helpers.factories, Settings.RutokenEcpDllDefaultPath, AppType.MultiThreaded))
                {
                    // Получить информацию о библиотеке
                    Console.WriteLine("Getting library info");
                    ILibraryInfo libraryInfo = pkcs11.GetInfo();
                    Console.WriteLine("Printing library info:");
                    Console.WriteLine(" PKCS#11 version: {0}", libraryInfo.CryptokiVersion);
                    Console.WriteLine(" Manufacturer: {0}", libraryInfo.ManufacturerId);
                    Console.WriteLine(" Flags: 0x{0:X}", libraryInfo.Flags);
                    Console.WriteLine(" Library description: {0}", libraryInfo.LibraryDescription);
                    Console.WriteLine();

                    // Получить слоты
                    Console.WriteLine("Checking slots available");
                    List<IRutokenSlot> slots = pkcs11.GetRutokenSlotList(SlotsType.WithTokenPresent);
                    // Проверить, что слоты найдены
                    if (slots == null)
                        throw new NullReferenceException("No available slots");
                    // Проверить, что число слотов больше 0
                    if (slots.Count <= 0)
                        throw new InvalidOperationException("No available slots");

                    // Распечатать информацию:
                    //        - о слотах;
                    //        - о подключенных токенах;
                    //        - о поддерживаемых механизмах.
                    foreach (var slot in slots)
                    {
                        ISlotInfo slotInfo = slot.GetSlotInfo();

                        // Распечатать информацию о слоте
                        Console.WriteLine("Printing slot info:");
                        Console.WriteLine(" IRutokenSlot description: {0}", slotInfo.SlotDescription);
                        Console.WriteLine(" Manufacturer: {0}", slotInfo.ManufacturerId);
                        Console.WriteLine(" Flags: 0x{0:X}", slotInfo.SlotFlags.Flags);
                        Console.WriteLine(" Hardware version: {0}", slotInfo.HardwareVersion);
                        Console.WriteLine(" Firmware version: {0}", slotInfo.FirmwareVersion);
                        Console.WriteLine();

                        if (slotInfo.SlotFlags.TokenPresent)
                        {
                            // Получить информацию о токене
                            ITokenInfo tokenInfo = slot.GetTokenInfo();

                            // Распечатать информацию о токене
                            Console.WriteLine("Printing token info:");
                            Console.WriteLine(" Label: {0}", tokenInfo.Label);
                            Console.WriteLine(" Manufacturer: {0}", tokenInfo.ManufacturerId);
                            Console.WriteLine(" Token model: {0}", tokenInfo.Model);
                            Console.WriteLine(" Token #: {0}", tokenInfo.SerialNumber);
                            Console.WriteLine(" Flags: 0x{0:X}", tokenInfo.TokenFlags.Flags);
                            Console.WriteLine(" Max session count: {0}", tokenInfo.MaxSessionCount);
                            Console.WriteLine(" Current session count: {0}", tokenInfo.SessionCount);
                            Console.WriteLine(" Max RW session count: {0}", tokenInfo.MaxRwSessionCount);
                            Console.WriteLine(" Current RW session count: {0}", tokenInfo.RwSessionCount);
                            Console.WriteLine(" Max PIN length: {0}", tokenInfo.MaxPinLen);
                            Console.WriteLine(" Min PIN length: {0}", tokenInfo.MinPinLen);
                            Console.WriteLine(" Total public memory: {0}", tokenInfo.TotalPublicMemory);
                            Console.WriteLine(" Free public memory: {0}", tokenInfo.FreePublicMemory);
                            Console.WriteLine(" Total private memory: {0}", tokenInfo.TotalPrivateMemory);
                            Console.WriteLine(" Free private memory: {0}", tokenInfo.FreePrivateMemory);
                            Console.WriteLine(" Hardware version: {0}", tokenInfo.HardwareVersion);
                            Console.WriteLine(" Firmware version: {0}", tokenInfo.FirmwareVersion);
                            Console.WriteLine(" Timer #: {0}", tokenInfo.UtcTime);
                            Console.WriteLine();

                            // Получить список поддерживаемых токеном механизмов
                            Console.WriteLine("Checking mechanisms available");
                            List<CKM> mechanisms = slot.GetMechanismList();
                            Errors.Check("No mechanisms available", mechanisms.Count > 0);

                            foreach (var mechanism in mechanisms)
                            {
                                IMechanismInfo mechanismInfo = slot.GetMechanismInfo(mechanism);
                                Console.WriteLine("Printing mechanism info:");
                                if (Enum.IsDefined(typeof(Extended_CKM), (Extended_CKM)mechanismInfo.Mechanism))
                                {
                                    Console.WriteLine(" IMechanism type: {0}", (Extended_CKM)mechanismInfo.Mechanism);
                                }
                                else
                                {
                                    Console.WriteLine(" IMechanism type: {0}", mechanismInfo.Mechanism);
                                }
                                Console.WriteLine(" Min key size: {0}", mechanismInfo.MinKeySize);
                                Console.WriteLine(" Max key size: {0}", mechanismInfo.MaxKeySize);
                                Console.WriteLine(" IMechanism flags: 0x{0:X}", mechanismInfo.MechanismFlags.Flags);
                                Console.WriteLine();
                            }
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
