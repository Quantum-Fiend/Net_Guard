using Microsoft.Data.Sqlite;
using System;
using System.IO;

namespace NetGuard.UI.Services
{
    public class DatabaseService
    {
        private const string DbName = "netguard_data.db";
        private readonly string _connectionString;

        public DatabaseService()
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string folder = Path.Combine(appData, "NetGuard");
            Directory.CreateDirectory(folder);
            string dbPath = Path.Combine(folder, DbName);
            
            _connectionString = $"Data Source={dbPath}";
            
            InitializeDatabase();
        }

        private void InitializeDatabase()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    CREATE TABLE IF NOT EXISTS Alerts (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        Timestamp INTEGER NOT NULL,
                        Severity INTEGER NOT NULL,
                        AttackType INTEGER NOT NULL,
                        SrcIp TEXT NOT NULL,
                        DstIp TEXT NOT NULL,
                        SrcPort INTEGER NOT NULL,
                        DstPort INTEGER NOT NULL,
                        Protocol TEXT NOT NULL,
                        Description TEXT,
                        RuleName TEXT,
                        Confidence REAL
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON Alerts(Timestamp);
                    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON Alerts(Severity);
                ";
                command.ExecuteNonQuery();
            }
        }

        public SqliteConnection GetConnection()
        {
            return new SqliteConnection(_connectionString);
        }
    }
}
