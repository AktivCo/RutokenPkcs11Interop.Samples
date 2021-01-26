using System;
using System.Runtime.InteropServices;
using Foundation;
using ObjCRuntime;

namespace Xamarin.Info.iOS
{
    public class iOsFunctions : IPlatformSpecificFunctions
    {
        // Declare the signature of the method that users would have to provide
        public delegate void startNFCCallback(ref NSError nserror);

        // Declare the signature of the method that the block will call
        private delegate void startNFCCallbackProxy(IntPtr blockLiteral, ref NSError nserror);

        // Static variable that points to our trampoline method
        private static readonly startNFCCallbackProxy static_handler = TrampolineHandler;

        // Our trampoline method must be registered for reverse-callback with Mono
        // it takes one extra parameter than the signature, which is the pointer
        // to the block that was originally passed.
        [MonoPInvokeCallback(typeof(startNFCCallbackProxy))]
        private static void TrampolineHandler(IntPtr block, ref NSError error)
        {
            // Find the delegate for the block and call it
            var callback = BlockLiteral.GetTarget<startNFCCallback>(block);
            if (callback != null)
                callback(ref error);
        }

        private class NativeLibrary
        {
            [DllImport("__Internal")]
            public static extern void startNFC(ref BlockLiteral block);

            [DllImport("__Internal")]
            public static extern int stopNFC();
        }

        public void startNFC(Action<string> callback)
        {
            startNFCCallback internalCallback = (ref NSError x) => Console.WriteLine(x);
            BlockLiteral block = new BlockLiteral();
            block.SetupBlock(static_handler, internalCallback);
            try
            {
                NativeLibrary.startNFC(ref block) ;
            }
            catch (Exception ex)
            {
                Console.Write("Error", $"Operation failed [Message: {ex.Message}]", "OK");
            }
            finally
            {
                block.CleanupBlock();
            }
        }

        public void stopNFC()
        {
            NativeLibrary.stopNFC();
        }
    }
}