using System;

namespace Net.RutokenPkcs11Interop.Samples.Common
{
    public static class Errors
    {
        public static void Check(string errorMessage, bool condition)
        {
            if (!condition)
                throw new InvalidOperationException(errorMessage);
        }
    }
}
