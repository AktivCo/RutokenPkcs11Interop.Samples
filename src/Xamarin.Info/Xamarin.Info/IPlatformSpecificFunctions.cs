using System;

namespace Xamarin.Info
{
    public interface IPlatformSpecificFunctions
    {
        void startNFC(Action<string> callback);
        void stopNFC();
    }
}