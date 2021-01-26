using System;
namespace Xamarin.Info.Droid
{
    public class AndroidFunctions : IPlatformSpecificFunctions
    {
        public void startNFC(Action<string> callback) { }
        public void stopNFC() { }
    }
}
