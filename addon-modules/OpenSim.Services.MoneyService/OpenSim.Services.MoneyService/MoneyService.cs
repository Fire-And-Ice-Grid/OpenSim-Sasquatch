/*
 * Copyright (c) Contributors, http://opensimulator.org/, http://www.nsl.tuis.ac.jp/
 * See CONTRIBUTORS.TXT for a full list of copyright holders.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *	 * Neither the name of the OpenSim Project nor the
 *	   names of its contributors may be used to endorse or promote products
 *	   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE DEVELOPERS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

using System;
using System.IO;
using System.Collections.Generic;
using System.Net.Security;
using System.Reflection;
using System.Timers;
using OpenSim.Framework.Servers.HttpServer;
using Nini.Config;
using log4net;
using OpenSim.Services.Base;
using OpenSim.Framework.Console;

using NSL.Certificate.Tools;
using OpenSim.Framework;


/// <summary>
/// OpenSim Server MoneyServer
/// </summary>
namespace OpenSim.Services.MoneyService
{
    /// <summary>
    /// class MoneyServerBase : BaseOpenSimServer, IMoneyService
    /// Manni internal class
    /// </summary>
    internal class MoneyService : ServiceBase, IMoneyService
    {
        private static readonly ILog m_log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        private string connectionString = string.Empty;
        private uint m_moneyServerPort = 8008;         // 8008 is default server port

        private string m_version = "";
        private string m_certFilename = "";
        private string m_certPassword = "";
        private string m_cacertFilename = "";
        private string m_clcrlFilename = "";
        private bool m_checkClientCert = false;

        private int DEAD_TIME = 120;
        private int MAX_DB_CONNECTION = 10;

        private MoneyXmlRpcModule m_moneyXmlRpcModule;
        private MoneyDBService m_moneyDBService;

        private readonly NSLCertificateVerify m_certVerify = new NSLCertificateVerify(); // for Client Certificate

        private Dictionary<string, string> m_sessionDic = new Dictionary<string, string>();
        private Dictionary<string, string> m_secureSessionDic = new Dictionary<string, string>();
        private Dictionary<string, string> m_webSessionDic = new Dictionary<string, string>();

        private static bool m_Initialized;

        public NSLCertificateVerify CertVerify => m_certVerify;

        protected string m_ConfigName = "MoneyService";

        public MoneyService(IConfigSource config)
            : this(config, "MoneyService")
        {
        }

        public MoneyService(IConfigSource config, string configName) : base(config)
        {
            var databaseConfig = config.Configs["DatabaseService"];
            if (databaseConfig == null)
                throw new Exception("No " + m_ConfigName + " database configuration");

            MAX_DB_CONNECTION = databaseConfig.GetInt("MaxConnection", MAX_DB_CONNECTION);
            connectionString = databaseConfig.GetString("ConnectionString");
            
            if (string.IsNullOrEmpty(connectionString))
            {
                var sqlserver = databaseConfig.GetString("hostname", "localhost");
                var database = databaseConfig.GetString("database", "OpenSim");
                var username = databaseConfig.GetString("username", "root");
                var password = databaseConfig.GetString("password", "password");
                var pooling = databaseConfig.GetString("pooling", "false");
                var port = databaseConfig.GetString("port", "3306");

                connectionString = "Server=" + sqlserver + ";Port=" + port + ";Database=" + database + ";User ID=" +
                                                username + ";Password=" + password + ";Pooling=" + pooling + ";";
            }

            if (string.IsNullOrEmpty(connectionString))
            {
                m_log.Info("[MONEY SERVER]: No " + m_ConfigName + " database connection string specified");
                return;
            }

            var moneyConfig = config.Configs[m_ConfigName];
            if (moneyConfig == null)
            {
                m_log.Info("[MONEY SERVER]: No " + m_ConfigName + " configuration");
                return;
            }

            // [MoneyServer]
            if (moneyConfig.GetBoolean("Enabled", false) == false)
            {
                m_log.Info("[MONEY SERVER]: Not enabled");
                return;
            }

            m_version = moneyConfig.GetString("Version", m_version);
            DEAD_TIME = moneyConfig.GetInt("ExpiredTime", DEAD_TIME);
            //            m_moneyServerPort = (uint)m_server_config.GetInt("ServerPort", (int)m_moneyServerPort);

            m_checkClientCert = false;
            
            ////
            //// [Certificate]
            //m_cert_config = moneyConfig.m_config.Configs["Certificate"];
            //    if (m_cert_config == null)
            //    {
            //        m_log.Info("[MONEY SERVER]: [Certificate] section is not found. Using [MoneyServer] section instead");
            //        m_cert_config = m_server_config;
            //    }

            //    // HTTPS Server Cert (Server Mode)
            //    m_certFilename = m_cert_config.GetString("ServerCertFilename", m_certFilename);
            //    m_certPassword = m_cert_config.GetString("ServerCertPassword", m_certPassword);
            //    if (m_certFilename != "")
            //    {
            //        m_log.Info("[MONEY SERVER]: ReadIniConfig: Execute HTTPS comunication. Cert file is " + m_certFilename);
            //    }

            //    // Client Certificate
            //    m_checkClientCert = m_cert_config.GetBoolean("CheckClientCert", m_checkClientCert);
            //    m_cacertFilename = m_cert_config.GetString("CACertFilename", m_cacertFilename);
            //    m_clcrlFilename = m_cert_config.GetString("ClientCrlFilename", m_clcrlFilename);
            //    //
            //    if (m_checkClientCert && m_cacertFilename != "")
            //    {
            //        CertVerify.SetPrivateCA(m_cacertFilename);
            //        m_log.Info("[MONEY SERVER]: ReadIniConfig: Execute Authentication of Clients. CA  file is " + m_cacertFilename);
            //    }
            //    else
            //    {
            //        m_checkClientCert = false;
            //    }

            if (m_checkClientCert && m_clcrlFilename != "")
            {
                CertVerify.SetPrivateCRL(m_clcrlFilename);
                m_log.Info("[MONEY SERVER]: ReadIniConfig: Execute Authentication of Clients. CRL file is " + m_clcrlFilename);
            }

            if (!m_Initialized)
            {
                m_Initialized = true;

                //MainConsole.Instance.Commands.AddCommand("fs", false,
                //        "show assets", "show assets", "Show asset stats",
                //        HandleShowAssets);
                //MainConsole.Instance.Commands.AddCommand("fs", false,
                //        "show digest", "show digest <ID>", "Show asset digest",
                //        HandleShowDigest);
                //MainConsole.Instance.Commands.AddCommand("fs", false,
                //        "delete asset", "delete asset <ID>",
                //        "Delete asset from database",
                //        HandleDeleteAsset);
                //MainConsole.Instance.Commands.AddCommand("fs", false,
                //        "import", "import <conn> <table> [<start> <count>]",
                //        "Import legacy assets",
                //        HandleImportAssets);
                //MainConsole.Instance.Commands.AddCommand("fs", false,
                //        "force import", "force import <conn> <table> [<start> <count>]",
                //        "Import legacy assets, overwriting current content",
                //        HandleImportAssets);
            }

            m_log.Info("[MONEY SERVER]: Connecting to Money Storage Server");

            m_moneyDBService = new MoneyDBService();
            m_moneyDBService.Initialise(connectionString, MAX_DB_CONNECTION);

            m_moneyXmlRpcModule = new MoneyXmlRpcModule();
            m_moneyXmlRpcModule.Initialise(m_version, m_moneyDBService, this);
            m_moneyXmlRpcModule.PostInitialise();
        }


        /// <summary>
        /// Check the transactions table, set expired transaction state to failed
        /// </summary>
        private void CheckTransaction(object sender, ElapsedEventArgs e)
        {
            long ticksToEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks;
            int unixEpochTime = (int)((DateTime.UtcNow.Ticks - ticksToEpoch) / 10000000);
            int deadTime = unixEpochTime - DEAD_TIME;
            m_moneyDBService.SetTransExpired(deadTime);
        }


        /// <summary>
        /// Is Check Client Cert
        /// </summary>
        public bool IsCheckClientCert()
        {
            return m_checkClientCert;
        }


        /// <summary>
        /// Get Server Config
        /// </summary>
        public IConfig GetServerConfig()
        {
            return m_server_config;
        }


        /// <summary>
        /// Get Cert Config
        /// </summary>
        public IConfig GetCertConfig()
        {
            return m_cert_config;
        }

        /// <summary>
        /// Get Session Dic
        /// </summary>
        public Dictionary<string, string> GetSessionDic()
        {
            return m_sessionDic;
        }

        /// <summary>
        /// Get Secure Session Dic
        /// </summary>
        public Dictionary<string, string> GetSecureSessionDic()
        {
            return m_secureSessionDic;
        }


        /// <summary>
        /// Get Web Session Dic
        /// </summary>
        public Dictionary<string, string> GetWebSessionDic()
        {
            return m_webSessionDic;
        }

    }
}
