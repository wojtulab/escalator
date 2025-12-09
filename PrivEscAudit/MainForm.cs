using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Windows.Forms;
using Microsoft.Win32;

namespace PrivEscAudit
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();
        }

        private void btnScan_Click(object sender, EventArgs e)
        {
            txtOutput.Clear();
            lblStatus.Text = "Skanowanie w toku... / Scanning...";
            Application.DoEvents(); // Simple way to keep UI responsive

            try
            {
                var results = new List<AuditResult>();
                var currentUser = WindowsIdentity.GetCurrent();

                txtOutput.AppendText($"Uruchomiono jako użytkownik: {currentUser.Name}\n");
                txtOutput.AppendText("Rozpoczynanie audytu...\n\n");

                // Audit Services
                results.AddRange(AuditServices(currentUser));

                // Audit AlwaysInstallElevated
                results.AddRange(AuditAlwaysInstallElevated());

                // Sort results by probability (Descending)
                var sortedResults = results.OrderByDescending(r => r.ProbabilityScore).ToList();

                if (sortedResults.Count == 0)
                {
                    txtOutput.AppendText("Nie znaleziono oczywistych podatności.");
                }
                else
                {
                    txtOutput.AppendText($"Znaleziono {sortedResults.Count} potencjalnych wektorów:\n\n");
                    foreach (var res in sortedResults)
                    {
                        txtOutput.SelectionFont = new System.Drawing.Font(txtOutput.Font, System.Drawing.FontStyle.Bold);
                        txtOutput.AppendText($"[{res.ProbabilityScore}%] {res.Title}\n");

                        txtOutput.SelectionFont = new System.Drawing.Font(txtOutput.Font, System.Drawing.FontStyle.Regular);
                        txtOutput.AppendText($"{res.Description}\n");

                        txtOutput.SelectionColor = System.Drawing.Color.Blue;
                        txtOutput.AppendText("Proponowana komenda (Cmd as Admin/System):\n");
                        txtOutput.AppendText(res.Command + "\n");
                        txtOutput.SelectionColor = txtOutput.ForeColor;

                        txtOutput.AppendText(new string('-', 50) + "\n\n");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Błąd krytyczny: " + ex.Message);
            }
            finally
            {
                lblStatus.Text = "Audyt zakończony.";
            }
        }

        private List<AuditResult> AuditServices(WindowsIdentity currentUser)
        {
            var list = new List<AuditResult>();
            ServiceController[] services;
            try
            {
                services = ServiceController.GetServices();
            }
            catch
            {
                return list;
            }

            foreach (var service in services)
            {
                try
                {
                    string regPath = $@"SYSTEM\CurrentControlSet\Services\{service.ServiceName}";
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(regPath))
                    {
                        if (key == null) continue;

                        object startVal = key.GetValue("Start");
                        if (startVal == null) continue;
                        int startType = (int)startVal;
                        if (startType != 2 && startType != 3) continue; // Only Auto or Demand

                        string imagePath = key.GetValue("ImagePath") as string;
                        if (string.IsNullOrEmpty(imagePath)) continue;

                        string binaryPath = ExtractPath(imagePath);
                        string fullBinaryPath = binaryPath;
                        try { fullBinaryPath = Environment.ExpandEnvironmentVariables(binaryPath); } catch { }

                        // Check 1: File Permissions
                        if (File.Exists(fullBinaryPath))
                        {
                            if (CheckFilePermissions(fullBinaryPath, currentUser))
                            {
                                list.Add(new AuditResult
                                {
                                    Title = $"Service Binary Writable: {service.ServiceName}",
                                    Description = $"Użytkownik ma prawa do zapisu pliku binarnego usługi: {fullBinaryPath}",
                                    Command = $"cmd /c copy /Y C:\\Windows\\System32\\cmd.exe \"{fullBinaryPath}\" & sc start {service.ServiceName}",
                                    ProbabilityScore = 80
                                });
                            }

                            // Check 2: Folder Permissions (DLL Hijacking)
                            try
                            {
                                string folderPath = Path.GetDirectoryName(fullBinaryPath);
                                if (!string.IsNullOrEmpty(folderPath) && Directory.Exists(folderPath))
                                {
                                    if (CheckFolderPermissions(folderPath, currentUser))
                                    {
                                        list.Add(new AuditResult
                                        {
                                            Title = $"Service Folder Writable: {service.ServiceName}",
                                            Description = $"Użytkownik ma prawa do zapisu w folderze usługi: {folderPath}. Możliwy DLL Hijacking.",
                                            Command = $"echo [DLL_PAYLOAD] > \"{folderPath}\\hijack.dll\" & sc stop {service.ServiceName} & sc start {service.ServiceName}",
                                            ProbabilityScore = 50
                                        });
                                    }
                                }
                            }
                            catch { }
                        }

                        // Check 3: Registry Permissions
                        if (CheckRegistryPermissions(key, currentUser))
                        {
                            list.Add(new AuditResult
                            {
                                Title = $"Service Configuration Writable: {service.ServiceName}",
                                Description = "Użytkownik ma prawa zapisu w kluczu rejestru usługi (możliwa zmiana binpath).",
                                Command = $"sc config {service.ServiceName} binpath= \"cmd.exe /k start cmd.exe\" & sc stop {service.ServiceName} & sc start {service.ServiceName}",
                                ProbabilityScore = 70
                            });
                        }
                    }
                }
                catch { }
            }
            return list;
        }

        private List<AuditResult> AuditAlwaysInstallElevated()
        {
            var list = new List<AuditResult>();
            bool hkcu = CheckAlwaysInstallElevatedKey(Registry.CurrentUser, @"Software\Policies\Microsoft\Windows\Installer");
            bool hklm = CheckAlwaysInstallElevatedKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows\Installer");

            if (hkcu || hklm)
            {
                list.Add(new AuditResult
                {
                    Title = "AlwaysInstallElevated Enabled",
                    Description = "Polityka AlwaysInstallElevated jest włączona w rejestrze. Każdy plik MSI uruchomi się jako SYSTEM.",
                    Command = "msiexec /quiet /qn /i C:\\Temp\\malicious.msi",
                    ProbabilityScore = 90
                });
            }
            return list;
        }

        // Helpers
        static bool CheckAlwaysInstallElevatedKey(RegistryKey root, string subkey)
        {
            try
            {
                using (var key = root.OpenSubKey(subkey))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("AlwaysInstallElevated");
                        if (val != null && val is int intVal && intVal == 1) return true;
                    }
                }
            }
            catch { }
            return false;
        }

        static string ExtractPath(string imagePath)
        {
            if (string.IsNullOrEmpty(imagePath)) return "";
            if (imagePath.StartsWith("\""))
            {
                int nextQuote = imagePath.IndexOf('"', 1);
                if (nextQuote > 1) return imagePath.Substring(1, nextQuote - 1);
            }
            string path = imagePath;
            int dashIndex = imagePath.IndexOf(" -");
            if (dashIndex > 0) path = path.Substring(0, dashIndex);
            int slashIndex = path.IndexOf(" /");
            if (slashIndex > 0) path = path.Substring(0, slashIndex);
            return path.Trim();
        }

        static bool CheckFilePermissions(string path, WindowsIdentity currentUser)
        {
            try
            {
                FileSecurity fSecurity = File.GetAccessControl(path);
                return HasWriteAccess(fSecurity, currentUser);
            }
            catch { return false; }
        }

        static bool CheckFolderPermissions(string path, WindowsIdentity currentUser)
        {
            try
            {
                DirectorySecurity dSecurity = Directory.GetAccessControl(path);
                return HasWriteAccess(dSecurity, currentUser);
            }
            catch { return false; }
        }

        static bool CheckRegistryPermissions(RegistryKey key, WindowsIdentity currentUser)
        {
            try
            {
                RegistrySecurity rSecurity = key.GetAccessControl();
                return HasWriteAccess(rSecurity, currentUser);
            }
            catch { return false; }
        }

        static bool HasWriteAccess(CommonObjectSecurity security, WindowsIdentity identity)
        {
            if (security == null) return false;
            AuthorizationRuleCollection rules;
            try { rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)); } catch { return false; }

            var userSids = new HashSet<SecurityIdentifier>();
            if (identity.User != null) userSids.Add(identity.User);
            if (identity.Groups != null)
            {
                foreach (var group in identity.Groups)
                {
                    if (group is SecurityIdentifier sid) userSids.Add(sid);
                }
            }

            bool allowWrite = false;
            bool denyWrite = false;

            foreach (AuthorizationRule rule in rules)
            {
                if (rule is FileSystemAccessRule fsRule)
                {
                    if (userSids.Contains(fsRule.IdentityReference))
                    {
                        var rights = fsRule.FileSystemRights;
                        bool isWrite = (rights & FileSystemRights.WriteData) != 0 ||
                                       (rights & FileSystemRights.AppendData) != 0 ||
                                       (rights & FileSystemRights.Modify) != 0 ||
                                       (rights & FileSystemRights.FullControl) != 0;
                        if (isWrite)
                        {
                            if (fsRule.AccessControlType == AccessControlType.Allow) allowWrite = true;
                            else if (fsRule.AccessControlType == AccessControlType.Deny) denyWrite = true;
                        }
                    }
                }
                else if (rule is RegistryAccessRule regRule)
                {
                    if (userSids.Contains(regRule.IdentityReference))
                    {
                        var rights = regRule.RegistryRights;
                        bool isWrite = (rights & RegistryRights.SetValue) != 0 ||
                                       (rights & RegistryRights.WriteKey) != 0 ||
                                       (rights & RegistryRights.FullControl) != 0;
                        if (isWrite)
                        {
                            if (regRule.AccessControlType == AccessControlType.Allow) allowWrite = true;
                            else if (regRule.AccessControlType == AccessControlType.Deny) denyWrite = true;
                        }
                    }
                }
            }
            return allowWrite && !denyWrite;
        }
    }
}
