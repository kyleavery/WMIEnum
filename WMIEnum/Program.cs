using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace WMIEnum
{
    class Program
    {
        public static void Usage()
        {
            Console.WriteLine("\r\nWMIEnum - Local and Remote System Enumeration using WMI\r\n");

            Console.WriteLine(" Commands:");
            Console.WriteLine(
                "  basicinfo - Hostname and domain.\r\n" +
                "  procs - Running processes.\r\n" +
                "  services - All services, state, start mode, and service path.\r\n" +
                "  drives - Local and remote system drives.\r\n" +
                "  nics - Active NICs, IP address, and gateway.\r\n" +
                "  av - AV products that write to root\\SecurityCenter2, whether they are enabled, and if they are updated.\r\n" +
                "  dir - Directory contents.\r\n" +
                "  cat - File contents.\r\n" +
                "  find - Location of file on disk.\r\n");

            Console.WriteLine(" Arguments:");
            Console.WriteLine(
                "  /target - IP address or hostname of the machine you would like to query. Leave blank for local enum.\r\n" +
                "  /user - Username for target machine. Leave blank for local enum.\r\n" +
                "  /pass - Password for target machine. Leave blank for local enum.\r\n" +
                "  /domain - Domain of target machine. Leave blank for local enum.\r\n" +
                "  /dir - Directory for dir command.\r\n" +
                "  /file - Filename for cat and file clist.\r\n" +
                "  /proto - Protocol to use (WinRM or DCOM). Default is WinRM.\r\n" +
                "  /ssl - Encrypt the traffic (true or false). Only applicable if using WinRM. Default is true.\r\n");

            Console.WriteLine(" Examples:");
            Console.WriteLine(
                "  WMIEnum.exe procs\r\n" +
                "  WMIEnum.exe av /target:HOST /domain:DOMAIN /user:USERNAME /pass:PASSWORD /ssl:FALSE\r\n" +
                "  WMIEnum.exe find /file:NAME.TXT /target:HOST /domain:DOMAIN /user:USERNAME /pass:PASSWORD");
        }
        static CimSession CreateSession(string target, string user, string pass, string domain, string proto, bool ssl)
        {
            if (target == "." || target == "127.0.0.1" || target == "localhost")
            {
                Console.WriteLine("Querying localhost");
                return CimSession.Create(target);
            }
            else
            {
                Console.WriteLine("Querying " + target);
                SecureString secpass = new SecureString();
                foreach (char c in pass) { secpass.AppendChar(c); }
                CimCredential Credentials = new CimCredential(PasswordAuthenticationMechanism.Default, domain, user, secpass);

                if (proto == "dcom")
                {
                    var dcomOptions = new DComSessionOptions();
                    dcomOptions.AddDestinationCredentials(Credentials);
                    return CimSession.Create(target, dcomOptions);
                }
                else
                {
                    var wsmanOptions = new WSManSessionOptions();
                    wsmanOptions.AddDestinationCredentials(Credentials);
                    wsmanOptions.UseSsl = ssl;
                    return CimSession.Create(target, wsmanOptions);
                }
            }
        }

        static void ListBasicInfo(CimSession session)
        {
            var query = session.QueryInstances(@"root\cimv2", "WQL", "SELECT * FROM Win32_ComputerSystem");
            foreach (CimInstance item in query)
            {
                Console.Write("Hostname: {0} Domain: {1} ",
                item.CimInstanceProperties["Name"].Value,
                item.CimInstanceProperties["Domain"].Value);
            }

            query = session.QueryInstances(@"root\cimv2", "WQL", "SELECT * FROM Win32_OperatingSystem");
            foreach (CimInstance item in query)
            {
                Console.WriteLine("Version: {0}", item.CimInstanceProperties["Version"].Value);
            }
        }
        static void ListRunningProcesses(CimSession session)
        {
            var query = session.QueryInstances(@"root\cimv2", "WQL", "SELECT * FROM Win32_Process");
            Console.WriteLine("{0,-10} {1,-10} {3,-20} {2,4:1}", "PID", "PPID", "Name", "Owner");
            foreach (CimInstance item in query)
            {
                Console.WriteLine("{0,-10} {1,-10} {3,-20} {2,5:1}",
                    item.CimInstanceProperties["ProcessID"].Value,
                    item.CimInstanceProperties["ParentProcessID"].Value,
                    item.CimInstanceProperties["Name"].Value,
                    session.InvokeMethod(item, "GetOwner", null).OutParameters["User"].Value);
            }
        }
        static void ListRunningServices(CimSession session)
        {
            var query = session.QueryInstances(@"root\cimv2", "WQL", "SELECT * FROM Win32_Service");
            Console.WriteLine("{0,-50} {1,-10} {2,-10} {3,-10}", "Name", "State", "Mode", "Path");
            foreach (CimInstance item in query)
            {
                Console.WriteLine("{0,-50} {1,-10} {2,-10} {3,-10}",
                    item.CimInstanceProperties["Name"].Value,
                    item.CimInstanceProperties["State"].Value,
                    item.CimInstanceProperties["StartMode"].Value,
                    item.CimInstanceProperties["Pathname"].Value);
            }
        }
        static void ListSystemDrives(CimSession session)
        {
            var query = session.QueryInstances(@"root\cimv2", "WQL", "SELECT * FROM Win32_LogicalDisk");
            foreach (CimInstance item in query)
            {
                Console.WriteLine("{0} {1}{2}",
                    item.CimInstanceProperties["DeviceId"].Value,
                    item.CimInstanceProperties["VolumeName"].Value,
                    item.CimInstanceProperties["ProviderName"].Value);
            }
        }
        static void ListActiveNICs(CimSession session)
        {
            var query = session.QueryInstances(@"root\cimv2", "WQL", "SELECT * FROM Win32_NetworkadApterConfiguration");
            foreach (CimInstance item in query)
            {
                string[] ipaddrs = (string[])(item.CimInstanceProperties["IPAddress"].Value);
                if (ipaddrs != null)
                {
                    Console.WriteLine("{0}:\n IP: {1}\n GW: {2}",
                    item.CimInstanceProperties["ServiceName"].Value,
                    ipaddrs[0],
                    ((string[])item.CimInstanceProperties["DefaultIPGateway"].Value)[0]);
                }
            }
        }
        static void ListAntiVirus(CimSession session)
        {
            // https://social.msdn.microsoft.com/Forums/en-US/6501b87e-dda4-4838-93c3-244daa355d7c/wmisecuritycenter2-productstate
            var avEnabled = new Dictionary<int, string>() {
                {11, "Enabled"},
                {10, "Enabled"},
                {01, "Disabled"},
                {00, "Disabled"}
            };
            var avUpdated = new Dictionary<int, string>() {
                {00, "up to date"},
                {10, "out of date"}
            };
            string hexState = "";

            var query = session.QueryInstances(@"root\SecurityCenter", "WQL", "SELECT * FROM AntiVirusProduct");
            foreach (CimInstance item in query)
            {
                Console.Write("{0}: ", item.CimInstanceProperties["displayName"].Value);
                hexState = (Convert.ToInt32((item.CimInstanceProperties["productState"].Value).ToString())).ToString("X");
                Console.WriteLine(avEnabled[Int16.Parse(hexState.Substring(1, 2))] + " and " + avUpdated[Int16.Parse(hexState.Substring(3, 2))]);
            }
            query = session.QueryInstances(@"root\SecurityCenter2", "WQL", "SELECT * FROM AntiVirusProduct");
            foreach (CimInstance item in query)
            {
                Console.Write("{0}: ", item.CimInstanceProperties["displayName"].Value);
                hexState = (Convert.ToInt32((item.CimInstanceProperties["productState"].Value).ToString())).ToString("X");
                Console.WriteLine(avEnabled[Int16.Parse(hexState.Substring(1, 2))] + " and " + avUpdated[Int16.Parse(hexState.Substring(3, 2))]);
            }
        }
        static void ListFiles(CimSession session, string dir)
        {
            dir = dir.Replace(@"\", @"\\");
            if (!dir.EndsWith(@"\\"))
            {
                dir += @"\\";
            }
            var query = session.QueryInstances(@"root\cimv2", "WQL", "SELECT * FROM cim_logicalfile WHERE Drive='" + dir.Substring(0, 2) + "' AND Path='" + dir.Substring(2) + "'");
            foreach (CimInstance item in query)
            {
                Console.WriteLine("{0}", item.CimInstanceProperties["Name"].Value);
            }  
        }
        static void ReadFile(CimSession session, string file)
        {
            // https://twitter.com/mattifestation/status/1220713684756049921
            CimInstance baseInstance = new CimInstance("PS_ModuleFile");
            baseInstance.CimInstanceProperties.Add(CimProperty.Create("InstanceID", file, CimFlags.Key));
            CimInstance modifiedInstance = session.GetInstance("ROOT/Microsoft/Windows/Powershellv3", baseInstance);

            System.Byte[] fileBytes = (byte[])modifiedInstance.CimInstanceProperties["FileData"].Value;
            Console.WriteLine(Encoding.UTF8.GetString(fileBytes, 0, fileBytes.Length));
        }
        static void FindFile(CimSession session, string file)
        {
            int i = file.LastIndexOf(".");
            string filter = "";
            if (i < 0)
            {
                filter = "Filename='" + file + "'";
            }
            else
            {
                filter = "Extension='" + file.Substring(i + 1) + "' AND Filename LIKE '" + file.Substring(0, i) + "'";
            }
            var query = session.QueryInstances(@"root\cimv2", "WQL", "SELECT * FROM Cim_DataFile WHERE " + filter);
            foreach (CimInstance item in query)
            {
                Console.WriteLine("{0}", item.CimInstanceProperties["name"].Value);
            }
        }

        static void Main(string[] args)
        {
            try
            {
                if (args.Length < 1)
                {
                    Usage();
                    return;
                }
                Dictionary<string, string> arguments = new Dictionary<string, string>();
                foreach (string a in args)
                {
                    int i = a.IndexOf(":");
                    if (i > 0)
                        arguments[a.Substring(1, i - 1)] = a.Substring(i + 1);
                }
                string target = arguments.ContainsKey("target") ? arguments["target"] : ".";
                if (arguments.ContainsKey("target") && !(arguments.ContainsKey("user") && arguments.ContainsKey("pass")))
                {
                    Usage();
                    return;
                }

                string orEmpty(string key) => arguments.ContainsKey(key) ? arguments[key] : "";

                CimSession session = CreateSession(target,
                    orEmpty("user"),
                    orEmpty("pass"),
                    orEmpty("domain"),
                    orEmpty("proto").ToLower() != "dcom" ? "winrm" : "dcom",
                    orEmpty("ssl").ToLower() != "false");

                CommandList clist = new CommandList();
                clist.CreateCommand(ListBasicInfo, "basic", "basicinfo", "info");
                clist.CreateCommand(ListRunningProcesses, "proc", "process", "processes", "procs");
                clist.CreateCommand(ListRunningServices, "service", "services", "svc", "svcs");
                clist.CreateCommand(ListSystemDrives, "drive", "drives", "share", "shares");
                clist.CreateCommand(ListActiveNICs, "nic", "nics");
                clist.CreateCommand(ListAntiVirus, "av", "antivirus");

                Action<CimSession> AddOption(string val, string flag, Action<CimSession, string> action)
                {
                    if (val == "")
                    {
                        return sess =>
                        {
                            Console.WriteLine("You have to specify /" + flag + ":NAME");
                        };
                    }
                    else
                    {
                        return sess =>
                        {
                            action(sess, val);
                        };
                    }
                }
                string dir = orEmpty("dir");
                clist.CreateCommand(AddOption(dir, "dir", ListFiles), "ls", "dir");
                string file = orEmpty("file");
                clist.CreateCommand(AddOption(file, "file", ReadFile), "read", "cat", "type");
                clist.CreateCommand(AddOption(file, "file", FindFile), "find", "locate");

                clist.RunCommand(args[0], session);
            }
            catch (Exception e)
            {
                Console.WriteLine("{0}", e.Message);
            }
        }
    }
}
