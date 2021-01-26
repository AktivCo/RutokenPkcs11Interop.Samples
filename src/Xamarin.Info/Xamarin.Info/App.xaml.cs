using System;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;

[assembly: XamlCompilation(XamlCompilationOptions.Compile)]
namespace Xamarin.Info
{
    public partial class App : Application
    {
        public static IPlatformSpecificFunctions platformSpecificFunctions { get; set; }

        public App(IPlatformSpecificFunctions funcs)
        {
            InitializeComponent();

            platformSpecificFunctions = funcs;

            MainPage = new MainPage();
        }

        protected override void OnStart()
        {
            // Handle when your app starts
        }

        protected override void OnSleep()
        {
            // Handle when your app sleeps
        }

        protected override void OnResume()
        {
            // Handle when your app resumes
        }
    }
}
