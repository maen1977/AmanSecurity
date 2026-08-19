using MaenShield.Infrastructure;
using System;
using System.IO;
using System.Threading;
using System.Windows.Forms;

namespace MaenShield.App
{
    internal static class Program
    {
        internal const int AppVersionCode = 2;
        internal const string AppVersionName = "1.1.9-windows";

        [STAThread]
        private static void Main(string[] args)
        {
            var root = AppDomain.CurrentDomain.BaseDirectory;
            if (args != null && Array.Exists(args, x => string.Equals(x, "--update-only", StringComparison.OrdinalIgnoreCase)))
            {
                var service = new CloudUpdateService(root, AppVersionCode, CloudUpdateService.DefaultBaseUrl);
                service.UpdateAsync(CancellationToken.None).GetAwaiter().GetResult();
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm(root, AppVersionCode, AppVersionName));
        }
    }
}
