using System;
using System.Diagnostics;

namespace MaenShield.Infrastructure
{
    public static class WindowsUpdateScheduler
    {
        public const string TaskName = "Maen Shield\\Daily Intelligence Update";

        public static bool InstallDaily(string executablePath, string startTimeLocal)
        {
            if (string.IsNullOrWhiteSpace(executablePath)) throw new ArgumentException("Executable path is required.", "executablePath");
            var command = "schtasks.exe";
            var arguments = "/Create /SC DAILY /TN \"" + TaskName + "\" /TR \"\\\"" + executablePath + "\\\" --update-only\" /ST " + (startTimeLocal ?? "03:17") + " /F /RL LIMITED";
            return Run(command, arguments) == 0;
        }

        public static bool Remove()
        {
            return Run("schtasks.exe", "/Delete /TN \"" + TaskName + "\" /F") == 0;
        }

        private static int Run(string fileName, string arguments)
        {
            try
            {
                using (var process = Process.Start(new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                }))
                {
                    process.WaitForExit(15000);
                    return process.HasExited ? process.ExitCode : -1;
                }
            }
            catch { return -1; }
        }
    }
}
