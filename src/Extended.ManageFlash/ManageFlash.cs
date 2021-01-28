using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Samples.Common;

namespace Extended.ManageFlash
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен ЭЦП Flash при помощи библиотеки PKCS#11        *
    * на языке C#                                                            *
    *------------------------------------------------------------------------*
    * Использование команд управления памятью Рутокен Flash:                 *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - создание локального PIN-кода Рутокен;                               *
    *  - получение объема флеш-памяти Рутокен;                               *
    *  - создание разделов флеш-памяти Рутокен;                              *
    *  - получение информации о разделах флеш-памяти Рутокен;                *
    *  - изменение атрибутов разделов флеш-памяти Рутокен;                   *
    *  - закрытие соединения с Рутокен.                                      *
    *------------------------------------------------------------------------*
    * Данный пример является самодостаточным.                                *
    *************************************************************************/

    class ManageFlash
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
                    var tokenInfo = slot.GetTokenInfoExtended();

                    // Определить наличие флеш-памяти у токена
                    var isFlashMemoryAvailable = tokenInfo.Flags & (uint)RutokenFlag.HasFlashDrive;
                    Errors.Check("Checking flash availability", Convert.ToBoolean(isFlashMemoryAvailable));

                    // Создать локальный PIN-код токена с ID = 0x03
                    Console.WriteLine("Setting local PINs...");

                    // Создание локальных PIN-кодов
                    // (создание успешно только в случае их отсутствия)

                    // Создание локального PIN-кода токена с ID = 0x03
                    slot.SetLocalPIN(SampleConstants.NormalUserPin, SampleConstants.LocalPin, SampleConstants.LocalPinId1);

                    // Создание локального PIN-кода токена с ID = 0x1E
                    slot.SetLocalPIN(SampleConstants.NormalUserPin, SampleConstants.LocalPin, SampleConstants.LocalPinId2);

                    Console.WriteLine("Local PINs have been set successfully");

                    // Демонстрация работы с флеш-памятью
                    Console.WriteLine("Working with flash memory...");

                    // Получить объем флеш-памяти
                    ulong driveSize = slot.GetDriveSize();
                    Console.WriteLine($" Flash drive capacity: {driveSize} Mb.");

                    // Полное удаление информации с флеш-памяти с последующим созданием
                    // разделов в соответствии с переданными параметрами
                    ulong volumeRwSize = driveSize / 2;
                    ulong volumeRoSize = driveSize / 4;
                    ulong volumeHiSize = driveSize / 8;
                    ulong volumeCdSize = driveSize - volumeRwSize - volumeRoSize - volumeHiSize;

                    var initParams = new List<IVolumeFormatInfoExtended>()
                    {
                        Helpers.factories.VolumeFormatInfoExtendedFactory.Create(volumeRwSize, FlashAccessMode.Readwrite, CKU.CKU_USER, 0),
                        Helpers.factories.VolumeFormatInfoExtendedFactory.Create(volumeRoSize, FlashAccessMode.Readonly, CKU.CKU_SO, 0),
                        Helpers.factories.VolumeFormatInfoExtendedFactory.Create(volumeHiSize, FlashAccessMode.Hidden, (CKU)SampleConstants.LocalPinId1, 0),
                        Helpers.factories.VolumeFormatInfoExtendedFactory.Create(volumeCdSize, FlashAccessMode.Cdrom, (CKU)SampleConstants.LocalPinId2, 0),
                    };

                    Console.WriteLine(" Formatting drive...");
                    slot.FormatDrive(CKU.CKU_SO, SampleConstants.SecurityOfficerPin, initParams);

                    // Получение информации о разделах флеш-памяти
                    Console.WriteLine(" Getting volumes info...");
                    var volumesInfo = slot.GetVolumesInfo();
                    foreach (var volumeInfo in volumesInfo)
                    {
                        Console.WriteLine(" Printing volume info:");
                        Console.WriteLine($"  Volume id: {volumeInfo.VolumeId}");
                        Console.WriteLine($"  Volume size: {volumeInfo.VolumeSize} Mb");
                        Console.WriteLine($"  Access mode: {volumeInfo.AccessMode}");
                        Console.WriteLine($"  Volume owner: {volumeInfo.VolumeOwner}");
                        Console.WriteLine($"  Flags: {volumeInfo.Flags}");
                    }

                    // Изменить атрибут доступа раздела флеш-памяти на постоянной основе
                    // (до следующего изменения атрибутов)
                    Console.WriteLine(" Permanent changing volume attributes...");
                    uint volumeRo = 2;
                    slot.ChangeVolumeAttributes(CKU.CKU_SO, SampleConstants.SecurityOfficerPin,
                        volumeRo, FlashAccessMode.Readwrite, permanent: true);

                    // Временно изменить атрибут доступа к разделу флеш-памяти
                    // (до первого извлечения устройства или следующего изменения атрибутов)
                    Console.WriteLine(" Temporary changing volume attributes...");
                    uint volumeRw = 1;
                    slot.ChangeVolumeAttributes(CKU.CKU_USER, SampleConstants.NormalUserPin,
                        volumeRw, FlashAccessMode.Hidden, permanent: false);
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
