using Microsoft.Data.Sqlite;
using NetGuard.Core;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace NetGuard.UI.Services
{
    public class AlertRepository
    {
        private readonly DatabaseService _dbService;

        public AlertRepository(DatabaseService dbService)
        {
            _dbService = dbService;
        }

        public async Task AddAlertAsync(MarshaledAlert alert, string srcIpStr, string dstIpStr)
        {
            using (var connection = _dbService.GetConnection())
            {
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT INTO Alerts (
                        Timestamp, Severity, AttackType, SrcIp, DstIp, 
                        SrcPort, DstPort, Protocol, Description, RuleName, Confidence
                    ) VALUES (
                        $ts, $sev, $type, $sip, $dip, 
                        $sport, $dport, $proto, $desc, $rule, $conf
                    )
                ";

                command.Parameters.AddWithValue("$ts", (long)alert.Timestamp);
                command.Parameters.AddWithValue("$sev", alert.Severity);
                command.Parameters.AddWithValue("$type", alert.AttackType);
                command.Parameters.AddWithValue("$sip", srcIpStr);
                command.Parameters.AddWithValue("$dip", dstIpStr);
                command.Parameters.AddWithValue("$sport", alert.SrcPort);
                command.Parameters.AddWithValue("$dport", alert.DstPort);
                command.Parameters.AddWithValue("$proto", alert.Protocol.ToString()); // Simplified
                command.Parameters.AddWithValue("$desc", alert.Description ?? "");
                command.Parameters.AddWithValue("$rule", alert.RuleName ?? "");
                command.Parameters.AddWithValue("$conf", alert.Confidence);

                await command.ExecuteNonQueryAsync();
            }
        }

        public async Task<List<Dictionary<string, object>>> GetRecentAlertsAsync(int limit = 100)
        {
            var results = new List<Dictionary<string, object>>();
            using (var connection = _dbService.GetConnection())
            {
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT * FROM Alerts ORDER BY Timestamp DESC LIMIT $limit
                ";
                command.Parameters.AddWithValue("$limit", limit);

                using (var reader = await command.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        var row = new Dictionary<string, object>();
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            row[reader.GetName(i)] = reader.GetValue(i);
                        }
                        results.Add(row);
                    }
                }
            }
            return results;
        }

        public async Task<List<MarshaledAlert>> GetAllAlertsAsync()
        {
            var results = new List<MarshaledAlert>();
            using (var connection = _dbService.GetConnection())
            {
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM Alerts ORDER BY Timestamp DESC";

                using (var reader = await command.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        var alert = new MarshaledAlert
                        {
                            // Simplified reconstruction
                            Timestamp = (ulong)reader.GetInt64(1),
                            Severity = reader.GetInt32(2),
                            AttackType = reader.GetInt32(3),
                            // IPs stored as strings, but struct needs uints. 
                            // For CSV export we might just want the raw data or a DTO. 
                            // Let's rely on the VM to format strictly for CSV, 
                            // but here we return a DTO or just use the Dictionary approach for flexibility.
                        };
                        // actually, let's just return List<AlertViewModel> friendly structures or similar
                        // For simplicity, let's just return the raw reader data as a list of strong typed objects
                        // customized for export.
                    }
                }
            }
            return results;
        }

        public async Task<List<AlertExportDto>> GetAlertsForExportAsync()
        {
            var results = new List<AlertExportDto>();
            using (var connection = _dbService.GetConnection())
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT Timestamp, Severity, AttackType, SrcIp, DstIp, SrcPort, DstPort, Protocol, Description, RuleName FROM Alerts ORDER BY Timestamp DESC";
                
                using (var reader = await command.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        results.Add(new AlertExportDto
                        {
                            Timestamp = reader.GetInt64(0),
                            Severity = reader.GetInt32(1),
                            AttackType = reader.GetInt32(2),
                            SrcIp = reader.GetString(3),
                            DstIp = reader.GetString(4),
                            SrcPort = reader.GetInt32(5),
                            DstPort = reader.GetInt32(6),
                            Protocol = reader.GetString(7),
                            Description = reader.IsDBNull(8) ? "" : reader.GetString(8),
                            RuleName = reader.IsDBNull(9) ? "" : reader.GetString(9)
                        });
                    }
                }
            }
            return results;
        }
    }

    public class AlertExportDto
    {
        public long Timestamp { get; set; }
        public int Severity { get; set; }
        public int AttackType { get; set; }
        public string SrcIp { get; set; }
        public string DstIp { get; set; }
        public int SrcPort { get; set; }
        public int DstPort { get; set; }
        public string Protocol { get; set; }
        public string Description { get; set; }
        public string RuleName { get; set; }
    }
}
