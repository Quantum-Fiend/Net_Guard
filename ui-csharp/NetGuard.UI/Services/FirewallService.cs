using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace NetGuard.UI.Services
{
    public class FirewallService
    {
        public async Task<bool> BlockIpAddressAsync(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress)) return false;

            try
            {
                // Use netsh to add a block rule
                string ruleName = $"NetGuard Block {ipAddress}";
                string arguments = $"advfirewall firewall add rule name=\"{ruleName}\" dir=in action=block remoteip={ipAddress}";

                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = arguments,
                    Verb = "runas", // Request admin privileges if not already present (application manifest should handle this though)
                    UseShellExecute = true,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                // Since we are running as Admin (requirement), this should pass through without prompt if app is Admin.
                // However, UseShellExecute=true + runas might prompt if not.
                // If the main app is already admin, we can likely use UseShellExecute=false.
                // Let's try to run it directly.

                // Refined PSI for embedded execution
                var psiDirect = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                };

                using (var process = Process.Start(psiDirect))
                {
                    await process.WaitForExitAsync();
                    return process.ExitCode == 0;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
