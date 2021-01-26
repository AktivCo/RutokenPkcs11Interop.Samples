using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using RutokenPkcs11Interop.Common;
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

        private void WaitingForToken(Pkcs11 pkcs11)
        {
            for (; ; )
            {
                List<Slot> slots = pkcs11.GetSlotList(SlotsType.WithTokenPresent);
            }

        }

        private async void Button_OnClicked(object sender, EventArgs e)
        {
            bool use_nfc = false;
            try
            {
                string token_type = await DisplayActionSheet("Использовать:", "Cancel", null, "NFC Рутокен", "BT Рутокен");

                use_nfc = token_type == "NFC Рутокен";
                if (use_nfc)
                {
                    Action<string> callback = x => Console.WriteLine(x);
                    App.platformSpecificFunctions.startNFC(callback); // needed only for iOs. On Android do nothing
                }
                Features = new ObservableCollection<Feature>();

                // Инициализировать библиотеку
                using (var pkcs11 = new Pkcs11(Settings.RutokenEcpDllDefaultPath, AppType.MultiThreaded))
                {
                    // Получить информацию о библиотеке
                    var libraryInfo = pkcs11.GetInfo();

                    Features.Add(new Feature("PKCS#11 version", libraryInfo.CryptokiVersion));
                    Features.Add(new Feature("Library manufacturer", libraryInfo.ManufacturerId));
                    Features.Add(new Feature("Library description", libraryInfo.LibraryDescription));

                    if (use_nfc)
                    {
                        WaitingForToken(pkcs11);
                    }

                    // Получить слоты
                    List<Slot> slots = pkcs11.GetSlotList(SlotsType.WithTokenPresent);
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
                    App.platformSpecificFunctions.stopNFC(); // needed only for iOs. On Android do nothing
                }
            }
        }
    }
}
