using System;

namespace Xamarin.Info
{
    public interface IPlatformSpecificFunctions
    {
        void startNFC();
        void stopNFC();
    }
}