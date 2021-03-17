using System;
using System.Runtime.InteropServices;
using Foundation;
using ObjCRuntime;

namespace Xamarin.Info.iOS
{
    public class NfcFunctions
    {
        // Declare the signature of the method that users would have to provide
        public delegate void startNFCCallback(IntPtr error);

        // Declare the signature of the method that the block will call
        private delegate void startNFCCallbackProxy(IntPtr block, IntPtr error);

        static startNFCCallbackProxy static_handler = TrampolineHandler;

        // Our trampoline method must be registered for reverse-callback with Mono
        // it takes one extra parameter than the signature, which is the pointer
        // to the block that was originally passed.
        [MonoPInvokeCallback(typeof(startNFCCallbackProxy))]
        private static void TrampolineHandler(IntPtr block, IntPtr error)
        {
            // Find the delegate for the block and call it
            var callback = BlockLiteral.GetTarget<startNFCCallback>(block);
            if (callback != null)
                callback(error);
        }

        private class NativeLibrary
        {
            [DllImport("__Internal")]
            public static extern void startNFC(ref BlockLiteral block);

            [DllImport("__Internal")]
            public static extern int stopNFC();
        }


        static BlockLiteral block = new BlockLiteral();

        [BindingImpl(BindingImplOptions.Optimizable)]
        public void startNFC(Action<string> callback)
        {
            startNFCCallback internalCallback = ptr => {
                NSError error = (NSError) Runtime.GetNSObject(ptr);
                callback(error.LocalizedDescription);
            };

            block.SetupBlockUnsafe(static_handler, internalCallback);

            try
            {
                NativeLibrary.startNFC(ref block);
            }
            catch (Exception ex)
            {
                Console.Write("Error", $"Operation failed [Message: {ex.Message}]", "OK");
                block.CleanupBlock();
            }
        }

        public void stopNFC()
        {
            NativeLibrary.stopNFC();
            block.CleanupBlock();
        }
    }
}