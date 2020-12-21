using System;
using System.Runtime.InteropServices;
using Foundation;
using ObjCRuntime;

namespace Xamarin.Info.iOS
{
    public class iOsFunctions : IPlatformSpecificFunctions
    {
        // Declare the signature of the method that users would have to provide
        public delegate void startNFCCallback(IntPtr nserror);

        // Declare the signature of the method that the block will call
        private delegate void startNFCCallbackProxy(IntPtr blockLiteral, IntPtr nserror);
        // Static variable that points to our trampoline method
        private static readonly startNFCCallbackProxy static_handler = TrampolineHandler;

        // Our trampoline method must be registered for reverse-callback with Mono
        // it takes one extra parameter than the signature, which is the pointer
        // to the block that was originally passed.
        [MonoPInvokeCallback(typeof(startNFCCallbackProxy))]
        private static void TrampolineHandler(IntPtr block, IntPtr nserror)
        {
            // Find the delegate for the block and call it
            var callback = BlockLiteral.GetTarget<startNFCCallback>(block);
            if (callback != null)
                callback(nserror);
        }

        public class NativeLibrary
        {
            [DllImport("__Internal")]
            public static extern void startNFC(BlockLiteral block);

            [DllImport("__Internal")]
            public static extern int stopNFC();
        }

        public static void printNSError(IntPtr ptr)
        {
            Console.WriteLine(Runtime.GetNSObject<NSError>(ptr));
        }

        public void startNFC()
        {
            startNFCCallback callback = x => Console.WriteLine(Runtime.GetNSObject<NSError>(x)); ;
            BlockLiteral block = new BlockLiteral();
            block.SetupBlock(static_handler, callback);
            try
            {
                NativeLibrary.startNFC(block);
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