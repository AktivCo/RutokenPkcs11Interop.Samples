using System;
using System.Threading;
using System.Collections.Generic;
using System.Collections.ObjectModel;

using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.Common;

using Xamarin.Forms;

namespace Xamarin.Info
{
    public class Feature
    {
        public Feature(string name, string description)
        {
            Name = name;
            Description = description;
        }

        public string Name { get; set; }
        public string Description { get; set; }
    }

    // TODO: Go to MVVM
    public partial class MainPage : ContentPage
    {
        public MainPage()
        {
            InitializeComponent();
        }

        private ObservableCollection<Feature> features;
        public ObservableCollection<Feature> Features
        {
            get => features;
            set
            {
                features = value;
                OnPropertyChanged(nameof(Features));
            }
        }

        private bool WaitingForToken(IRutokenPkcs11Library pkcs11, ref bool stopFlag)
        {
            for (; ; )
            {
                bool eventOccured = false;
                ulong slotId = 0;
                pkcs11.WaitForSlotEvent(WaitType.NonBlocking, out eventOccured, out slotId);
                if (eventOccured)
                    return true;

                if (stopFlag)
                    return false;

                Thread.Sleep(500);
            }

        }

        private async void Button_OnClicked(object sender, EventArgs e)
        {
#if __IOS__
            string token_type = await DisplayActionSheet("Использовать:", "Cancel", null, "NFC Рутокен", "BT Рутокен");
            bool use_nfc = token_type == "NFC Рутокен";
#else
            bool use_nfc = false;
#endif

            try
            {
                bool stopFlag = false;
                if (use_nfc)
                {
#if __IOS__
                    Action<string> callback = x => { Console.WriteLine(x); stopFlag = true; };
                    iOS.startNFC(callback);
#endif
                }

                Features = new ObservableCollection<Feature>();
                RutokenPkcs11InteropFactories factories = new RutokenPkcs11InteropFactories();

                // Инициализировать библиотеку
                using (var pkcs11 = factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(factories, Settings.RutokenEcpDllDefaultPath, AppType.MultiThreaded))
                {
                    // Получить информацию о библиотеке
                    var libraryInfo = pkcs11.GetInfo();

                    Features.Add(new Feature("PKCS#11 version", libraryInfo.CryptokiVersion));
                    Features.Add(new Feature("Library manufacturer", libraryInfo.ManufacturerId));
                    Features.Add(new Feature("Library description", libraryInfo.LibraryDescription));

                    if (use_nfc)
                        WaitingForToken(pkcs11, ref stopFlag);

                    // Получить слоты
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
                        var slotInfo = slot.GetSlotInfo();

                        // Распечатать информацию о слоте
                        Features.Add(new Feature("Slot description", slotInfo.SlotDescription));
                        Features.Add(new Feature("Slot manufacturer", slotInfo.ManufacturerId));
                        Features.Add(new Feature("Slot hardware version", slotInfo.HardwareVersion));
                        Features.Add(new Feature("Slot firmware version", slotInfo.FirmwareVersion));

                        if (slotInfo.SlotFlags.TokenPresent)
                        {
                            // Получить информацию о токене
                            var tokenInfo = slot.GetTokenInfo();

                            // Распечатать информацию о токене
                            Features.Add(new Feature("Token Label", tokenInfo.Label));
                            Features.Add(new Feature("Token manufacturer", tokenInfo.ManufacturerId));
                            Features.Add(new Feature("Token model", tokenInfo.Model));
                            Features.Add(new Feature("Token #", tokenInfo.SerialNumber));
                            Features.Add(new Feature("Token hardware version", tokenInfo.HardwareVersion));
                            Features.Add(new Feature("Token firmware version", tokenInfo.FirmwareVersion));

                            // Получить список поддерживаемых токеном механизмов
                            var mechanisms = slot.GetMechanismList();
                            if (mechanisms.Count == 0)
                            {
                                throw new InvalidOperationException("No mechanism available");
                            };

                            foreach (var mechanism in mechanisms)
                            {
                                var mechanismInfo = slot.GetMechanismInfo(mechanism);
                                Features.Add(new Feature("Mechanism type", mechanismInfo.Mechanism.ToString()));
                            }
                        }
                    }
                }
            }
            catch (Pkcs11Exception ex)
            {
                DisplayAlert("Error", $"Operation failed [Method: {ex.Method}, RV: {ex.RV}]", "OK");
            }
            catch (Exception ex)
            {
                DisplayAlert("Error", $"Operation failed [Message: {ex.Message}]", "OK");
            }
            finally
            {
                if (use_nfc)
                {
#if __IOS__
                    App.platformSpecificFunctions.stopNFC();
#endif
                }
            }
        }
    }
}
