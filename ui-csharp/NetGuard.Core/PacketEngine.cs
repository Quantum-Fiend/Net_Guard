using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace NetGuard.Core
{
    public class PacketEngine : IDisposable
    {
        private bool _isInitialized;
        private CancellationTokenSource _pollingCts;
        
        public event EventHandler<MarshaledAlert> AlertReceived;
        public event EventHandler<MarshaledStats> StatsUpdated;

        public bool IsRunning => _isInitialized && NativeMethods.NetGuard_IsRunning() != 0;

        public void Initialize()
        {
            if (_isInitialized) return;

            int result = NativeMethods.NetGuard_Initialize();
            if (result != 0) // NETGUARD_OK is 0
            {
                throw new Exception($"Failed to initialize NetGuard engine. Error code: {result}");
            }

            _isInitialized = true;
            StartPolling();
        }

        public void StartCapture(string deviceName, string filter = "")
        {
            CheckInitialized();
            int result = NativeMethods.NetGuard_StartCapture(deviceName, filter);
            if (result != 0)
            {
                throw new Exception($"Failed to start capture. Error code: {result}");
            }
        }

        public void StopCapture()
        {
            CheckInitialized();
            NativeMethods.NetGuard_StopCapture();
        }

        public void StartPcap(string filepath)
        {
            CheckInitialized();
            NativeMethods.NetGuard_StartPcap(filepath);
        }

        public void StopPcap()
        {
            CheckInitialized();
            NativeMethods.NetGuard_StopPcap();
        }

        public void EnablePortScanDetection(bool enabled)
        {
            CheckInitialized();
            NativeMethods.NetGuard_SetPromiscuous(enabled ? 1 : 0);
        }

        public void LoadRules(string rulesPath)
        {
            CheckInitialized();
            int result = NativeMethods.NetGuard_LoadRules(rulesPath);
            if (result != 0)
            {
                throw new Exception("Failed to load rules.");
            }
        }

        public List<MarshaledDevice> GetDevices()
        {
            var devices = new MarshaledDevice[16]; // Fixed size for now
            int count = NativeMethods.NetGuard_GetDevices(devices, devices.Length);
            
            var result = new List<MarshaledDevice>();
            if (count > 0)
            {
                for (int i = 0; i < count; i++)
                {
                    result.Add(devices[i]);
                }
            }
            return result;
        }

        private void StartPolling()
        {
            _pollingCts = new CancellationTokenSource();
            Task.Run(async () =>
            {
                while (!_pollingCts.Token.IsCancellationRequested)
                {
                    if (IsRunning)
                    {
                        PollAlerts();
                        PollStats();
                    }
                    await Task.Delay(500, _pollingCts.Token);
                }
            });
        }

        private void PollAlerts()
        {
            try
            {
                int pending = NativeMethods.NetGuard_GetPendingAlertCount();
                for (int i = 0; i < pending; i++)
                {
                    var alert = new MarshaledAlert();
                    if (NativeMethods.NetGuard_GetNextAlert(ref alert) != 0)
                    {
                        AlertReceived?.Invoke(this, alert);
                    }
                }
            }
            catch
            {
                // Suppress polling errors
            }
        }

        private void PollStats()
        {
            try
            {
                var stats = new MarshaledStats();
                if (NativeMethods.NetGuard_GetStatistics(ref stats) == 0)
                {
                    StatsUpdated?.Invoke(this, stats);
                }
            }
            catch
            {
                // Suppress polling errors
            }
        }

        private void CheckInitialized()
        {
            if (!_isInitialized) throw new InvalidOperationException("Engine not initialized");
        }

        public void Dispose()
        {
            _pollingCts?.Cancel();
            if (_isInitialized)
            {
                NativeMethods.NetGuard_Shutdown();
                _isInitialized = false;
            }
        }
    }
}
