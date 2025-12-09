using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;

namespace PrivEscAudit
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== Narzędzie Audytu Eskalacji Uprawnień Windows (PrivEsc Audit) ===");
            try
            {
                string userName = WindowsIdentity.GetCurrent().Name;
                Console.WriteLine("Uruchomiono jako użytkownik: " + userName);
            }
            catch
            {
                Console.WriteLine("Nie można pobrać tożsamości bieżącego użytkownika.");
            }
            Console.WriteLine("====================================================================\n");

            try
            {
                AuditServices();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Błąd podczas audytu usług: {ex.Message}");
            }

            try
            {
                AuditAlwaysInstallElevated();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Błąd podczas audytu AlwaysInstallElevated: {ex.Message}");
            }

            Console.WriteLine("\nAudyt zakończony.");
        }

        static void AuditServices()
        {
            Console.WriteLine("--- Sprawdzanie błędnych konfiguracji usług ---");

            ServiceController[] services;
            try
            {
                services = ServiceController.GetServices();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Nie można pobrać listy usług: " + ex.Message);
                return;
            }

            var currentUser = WindowsIdentity.GetCurrent();
            var vulnerableFound = false;

            foreach (var service in services)
            {
                try
                {
                    // Ścieżka rejestru: HKLM\SYSTEM\CurrentControlSet\Services\ServiceName
                    string regPath = $@"SYSTEM\CurrentControlSet\Services\{service.ServiceName}";
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(regPath))
                    {
                        if (key == null) continue;

                        object startVal = key.GetValue("Start");
                        if (startVal == null) continue;

                        int startType = (int)startVal;
                        // 2 = Auto, 3 = Demand
                        if (startType != 2 && startType != 3) continue;

                        string imagePath = key.GetValue("ImagePath") as string;
                        if (string.IsNullOrEmpty(imagePath)) continue;

                        // Parsowanie ścieżki do pliku wykonywalnego
                        string binaryPath = ExtractPath(imagePath);
                        string fullBinaryPath = binaryPath;

                        // Próba normalizacji ścieżki, jeśli jest względna lub zawiera zmienne środowiskowe
                        try { fullBinaryPath = Environment.ExpandEnvironmentVariables(binaryPath); } catch {}

                        if (!File.Exists(fullBinaryPath))
                        {
                             // Plik może nie istnieć lub być systemowy (np. sterowniki w System32 bez pełnej ścieżki)
                             // Jeśli nie możemy zweryfikować pliku, pomijamy sprawdzenie uprawnień pliku
                        }

                        // Sprawdzenie uprawnień do pliku
                        bool fileVuln = false;
                        if (File.Exists(fullBinaryPath))
                        {
                            fileVuln = CheckFilePermissions(fullBinaryPath, currentUser);
                        }

                        // Sprawdzenie uprawnień do klucza rejestru (proxy dla konfiguracji usługi)
                        bool regVuln = CheckRegistryPermissions(key, currentUser);

                        // Sprawdzenie uprawnień do folderu (tylko jeśli wykryliśmy usługę, sprawdzamy też jej folder)
                        // Ale prompt prosi o listowanie folderów podatnych na zapis.
                        // Możemy to zrobić przy okazji sprawdzania usługi.
                        bool folderVuln = false;
                        string folderPath = "";
                        if (File.Exists(fullBinaryPath))
                        {
                            try
                            {
                                folderPath = Path.GetDirectoryName(fullBinaryPath);
                                if (!string.IsNullOrEmpty(folderPath) && Directory.Exists(folderPath))
                                {
                                    folderVuln = CheckFolderPermissions(folderPath, currentUser);
                                }
                            }
                            catch {}
                        }

                        if (fileVuln || regVuln || folderVuln)
                        {
                            vulnerableFound = true;
                            Console.WriteLine($"[!] Znaleziono potencjalną podatność w usłudze: {service.ServiceName}");
                            Console.WriteLine($"    Nazwa wyświetlana: {service.DisplayName}");
                            Console.WriteLine($"    Ścieżka binarna: {imagePath}"); // Oryginalna ścieżka z rejestru
                            Console.WriteLine($"    Typ uruchamiania: {(startType == 2 ? "Auto (Automatyczny)" : "Demand (Ręczny)")}");

                            if (fileVuln)
                            {
                                Console.WriteLine("    [PODATNOŚĆ] Użytkownik ma uprawnienia do ZAPISU/MODYFIKACJI pliku binarnego.");
                                Console.WriteLine("    Proponowany wektor wykorzystania (Exploit):");
                                Console.WriteLine($"      cmd /c copy /Y C:\\Temp\\malicious.exe \"{fullBinaryPath}\"");
                                Console.WriteLine("    Naprawa (Fix):");
                                Console.WriteLine($"      icacls \"{fullBinaryPath}\" /remove \"{currentUser.Name}\"");
                            }

                            if (regVuln)
                            {
                                Console.WriteLine("    [PODATNOŚĆ] Użytkownik ma uprawnienia do ZAPISU w kluczu rejestru usługi (Zmiana konfiguracji).");
                                Console.WriteLine("    Proponowany wektor wykorzystania (Exploit):");
                                Console.WriteLine($"      sc config \"{service.ServiceName}\" binpath= \"C:\\Temp\\malicious.exe\"");
                            }

                            if (folderVuln)
                            {
                                Console.WriteLine($"    [PODATNOŚĆ] Użytkownik ma uprawnienia do ZAPISU w folderze: {folderPath}");
                                Console.WriteLine("    Możliwość: DLL Hijacking lub podmiana pliku.");
                                Console.WriteLine("    Proponowany wektor wykorzystania (Exploit):");
                                Console.WriteLine($"      cmd /c copy /Y C:\\Temp\\malicious.dll \"{folderPath}\\hijack.dll\"");
                            }

                            Console.WriteLine();
                        }
                    }
                }
                catch (System.Security.SecurityException)
                {
                    // Brak dostępu - ignorujemy
                    continue;
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }
                catch
                {
                    // Inne błędy ignorujemy, by kontynuować audyt
                }
            }

            if (!vulnerableFound)
            {
                Console.WriteLine("Nie znaleziono oczywistych podatności w konfiguracji usług.");
            }
        }

        static void AuditAlwaysInstallElevated()
        {
            Console.WriteLine("\n--- Sprawdzanie AlwaysInstallElevated ---");
            bool hkcu = CheckAlwaysInstallElevatedKey(Registry.CurrentUser, @"Software\Policies\Microsoft\Windows\Installer");
            bool hklm = CheckAlwaysInstallElevatedKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows\Installer");

            if (hkcu || hklm)
            {
                Console.WriteLine("[!] Wykryto włączone AlwaysInstallElevated!");
                if (hkcu) Console.WriteLine("    Znaleziono w HKEY_CURRENT_USER (HKCU)");
                if (hklm) Console.WriteLine("    Znaleziono w HKEY_LOCAL_MACHINE (HKLM)");

                Console.WriteLine("    Proponowany wektor wykorzystania (Exploit):");
                Console.WriteLine("      msiexec /quiet /qn /i C:\\Temp\\malicious.msi");
            }
            else
            {
                Console.WriteLine("Opcja AlwaysInstallElevated nie jest włączona.");
            }
        }

        static bool CheckAlwaysInstallElevatedKey(RegistryKey root, string subkey)
        {
            try
            {
                using (var key = root.OpenSubKey(subkey))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("AlwaysInstallElevated");
                        if (val != null && val is int intVal && intVal == 1)
                        {
                            return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        static string ExtractPath(string imagePath)
        {
            if (string.IsNullOrEmpty(imagePath)) return "";

            // Jeśli ścieżka w cudzysłowie
            if (imagePath.StartsWith("\""))
            {
                int nextQuote = imagePath.IndexOf('"', 1);
                if (nextQuote > 1)
                {
                    return imagePath.Substring(1, nextQuote - 1);
                }
            }

            // Jeśli bez cudzysłowu, bierzemy do pierwszego parametru (uproszczenie)
            // Zakładamy, że parametry zaczynają się od spacji i myślnika/slasha
            // To prosta heurystyka, może nie działać idealnie dla folderów ze spacjami bez cudzysłowu

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
            catch
            {
                return false;
            }
        }

        static bool CheckFolderPermissions(string path, WindowsIdentity currentUser)
        {
             try
            {
                DirectorySecurity dSecurity = Directory.GetAccessControl(path);
                return HasWriteAccess(dSecurity, currentUser);
            }
            catch
            {
                return false;
            }
        }

        static bool CheckRegistryPermissions(RegistryKey key, WindowsIdentity currentUser)
        {
            try
            {
                RegistrySecurity rSecurity = key.GetAccessControl();
                return HasWriteAccess(rSecurity, currentUser);
            }
            catch
            {
                return false;
            }
        }

        static bool HasWriteAccess(ObjectSecurity security, WindowsIdentity identity)
        {
            if (security == null) return false;

            AuthorizationRuleCollection rules;
            try
            {
                rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
            }
            catch { return false; }

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
                        // Sprawdzamy uprawnienia dające możliwość modyfikacji
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
