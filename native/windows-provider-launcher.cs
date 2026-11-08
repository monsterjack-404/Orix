using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Web.Script.Serialization;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace OrixWindowsSandbox {
  public static class Launcher {
    sealed class ProviderTeardownIncompleteException : Exception {
      public ProviderTeardownIncompleteException(Exception inner)
        : base("ORIX_WINDOWS_TEARDOWN_UNVERIFIED: provider process termination could not be confirmed; AppContainer cleanup was skipped", inner) { }
    }

    public static int Main(string[] args) {
      string root = null;
      string profileName = null;
      bool profileCreated = false;
      try {
        if (args == null || args.Length != 2 || (args[0] != "run" && args[0] != "cleanup"))
          throw new ArgumentException("Expected mode and config path");
        JavaScriptSerializer serializer = new JavaScriptSerializer();
        Dictionary<string, object> config =
          serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(args[1]));
        root = Convert.ToString(config["sandboxRoot"]);
        profileName = Convert.ToString(config["profileName"]);
        string logPath = Convert.ToString(config["logPath"]);
        Environment.SetEnvironmentVariable("ORIX_WINDOWS_LOG", logPath);
        if (args[0] == "cleanup") {
          Cleanup(root, profileName);
          return 0;
        }
        string executable = Convert.ToString(config["executable"]);
        string cwd = Convert.ToString(config["cwd"]);
        IEnumerable rawArgs = (IEnumerable)config["args"];
        string[] providerArgs = rawArgs.Cast<object>().Select(item => Convert.ToString(item)).ToArray();
        Dictionary<string, object> rawEnvironment = (Dictionary<string, object>)config["environment"];
        Dictionary<string, string> providerEnvironment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (KeyValuePair<string, object> item in rawEnvironment)
          providerEnvironment[item.Key] = Convert.ToString(item.Value);
        int exitCode = 125;
        try {
          exitCode = Run(executable, providerArgs, cwd, root, profileName, providerEnvironment, out profileCreated);
        } catch (ProviderTeardownIncompleteException error) {
          // Never remove profile ACLs or redirected scratch while any provider
          // process may still be alive. Leave recovery to an explicit operator.
          Console.Error.WriteLine("ORIX_WINDOWS_ISOLATION_ERROR=" + error.Message);
          return 125;
        } catch (Exception error) {
          Console.Error.WriteLine("ORIX_WINDOWS_ISOLATION_ERROR=" + error.Message);
        }
        if (profileCreated) {
          try {
            Cleanup(root, profileName);
          } catch (Exception cleanupError) {
            Console.Error.WriteLine("ORIX_WINDOWS_CLEANUP_ERROR=" + cleanupError.Message);
            return 125;
          }
        }
        return exitCode;
      } catch (Exception error) {
        Console.Error.WriteLine("ORIX_WINDOWS_ISOLATION_ERROR=" + error.Message);
        bool explicitCleanup = args != null && args.Length > 0 && args[0] == "cleanup";
        if (!explicitCleanup && profileCreated && !String.IsNullOrEmpty(root) && !String.IsNullOrEmpty(profileName)) {
          try { Cleanup(root, profileName); }
          catch (Exception cleanupError) {
            Console.Error.WriteLine("ORIX_WINDOWS_CLEANUP_ERROR=" + cleanupError.Message);
          }
        }
        return 125;
      }
    }

    const uint CREATE_SUSPENDED = 0x00000004;
    const uint CREATE_NEW_CONSOLE = 0x00000010;
    const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    const uint STARTF_USESHOWWINDOW = 0x00000001;
    const short SW_HIDE = 0;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const uint STARTF_USESTDHANDLES = 0x00000100;
    const uint DUPLICATE_SAME_ACCESS = 0x00000002;
    const uint FILE_READ_ATTRIBUTES = 0x00000080;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint FILE_SHARE_WRITE = 0x00000002;
    const uint FILE_SHARE_DELETE = 0x00000004;
    const uint OPEN_EXISTING = 3;
    const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
    const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
    const uint PROCESS_CREATION_CHILD_PROCESS_OVERRIDE = 0x00000002;
    const uint JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    const uint JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x00000001;
    const uint JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x00000004;
    const int JobObjectExtendedLimitInformation = 9;
    const int JobObjectCpuRateControlInformation = 15;
    const int TokenIsAppContainer = 29;
    const int TokenPrivileges = 3;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    static readonly IntPtr PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = new IntPtr(0x00020009);
    static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = new IntPtr(0x00020002);
    static readonly IntPtr PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY = new IntPtr(0x0002000E);
    static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    const int MAX_ROOTFS_TREE_DEPTH = 64;
    const int MAX_ROOTFS_TREE_ENTRIES = 100000;
    const int MAX_CLEANUP_TREE_DEPTH = 256;
    const int MAX_CLEANUP_TREE_ENTRIES = 100000;

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_CAPABILITIES {
      public IntPtr AppContainerSid;
      public IntPtr Capabilities;
      public uint CapabilityCount;
      public uint Reserved;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
      public uint cb;
      public string lpReserved;
      public string lpDesktop;
      public string lpTitle;
      public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
      public short wShowWindow;
      public short cbReserved2;
      public IntPtr lpReserved2;
      public IntPtr hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFOEX {
      public STARTUPINFO StartupInfo;
      public IntPtr lpAttributeList;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
      public IntPtr hProcess, hThread;
      public uint dwProcessId, dwThreadId;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct FILETIME_DATA {
      public uint LowDateTime;
      public uint HighDateTime;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct LUID {
      public uint LowPart;
      public int HighPart;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES {
      public LUID Luid;
      public uint Attributes;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct BY_HANDLE_FILE_INFORMATION {
      public uint FileAttributes;
      public FILETIME_DATA CreationTime;
      public FILETIME_DATA LastAccessTime;
      public FILETIME_DATA LastWriteTime;
      public uint VolumeSerialNumber;
      public uint FileSizeHigh;
      public uint FileSizeLow;
      public uint NumberOfLinks;
      public uint FileIndexHigh;
      public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
      public long PerProcessUserTimeLimit;
      public long PerJobUserTimeLimit;
      public uint LimitFlags;
      public UIntPtr MinimumWorkingSetSize;
      public UIntPtr MaximumWorkingSetSize;
      public uint ActiveProcessLimit;
      public UIntPtr Affinity;
      public uint PriorityClass;
      public uint SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IO_COUNTERS {
      public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
      public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
      public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
      public IO_COUNTERS IoInfo;
      public UIntPtr ProcessMemoryLimit;
      public UIntPtr JobMemoryLimit;
      public UIntPtr PeakProcessMemoryUsed;
      public UIntPtr PeakJobMemoryUsed;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
      public uint ControlFlags;
      public uint CpuRate;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    static extern int CreateAppContainerProfile(string name, string displayName, string description,
      IntPtr capabilities, uint capabilityCount, out IntPtr appContainerSid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr appContainerSid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    static extern int DeleteAppContainerProfile(string name);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr FreeSid(IntPtr sid);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode,
      IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(IntPtr file, out BY_HANDLE_FILE_INFORMATION information);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetSystemDirectoryW(StringBuilder buffer, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess,
      out IntPtr targetHandle, uint desiredAccess, bool inheritHandle, uint options);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute,
      IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessW(string applicationName, StringBuilder commandLine,
      IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
      IntPtr environment, string currentDirectory, ref STARTUPINFOEX startupInfo,
      out PROCESS_INFORMATION processInformation);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int tokenInformationClass, IntPtr information,
      int informationLength, out int returnLength);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool LookupPrivilegeValueW(string systemName, string name, out LUID luid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetProcessMitigationPolicy(IntPtr process, int policy, out uint buffer, UIntPtr length);

    static void Log(string message) {
      try {
        string logPath = Environment.GetEnvironmentVariable("ORIX_WINDOWS_LOG");
        if (!String.IsNullOrEmpty(logPath))
          File.AppendAllText(logPath, DateTime.UtcNow.ToString("o") + " " + message + Environment.NewLine);
        Console.Error.WriteLine("ORIX_WINDOWS_TRACE=" + message);
      } catch { }
    }

    static Exception Win32(string operation) {
      return new Win32Exception(Marshal.GetLastWin32Error(), operation);
    }

    static bool HasEnabledPrivilege(IntPtr token, string privilegeName) {
      LUID expected;
      if (!LookupPrivilegeValueW(null, privilegeName, out expected))
        throw Win32("Resolve " + privilegeName);
      int required = 0;
      GetTokenInformation(token, TokenPrivileges, IntPtr.Zero, 0, out required);
      if (required < sizeof(uint) || required > 65536)
        throw new InvalidOperationException("Windows returned an invalid token-privilege buffer size");
      IntPtr buffer = Marshal.AllocHGlobal(required);
      try {
        int returned;
        if (!GetTokenInformation(token, TokenPrivileges, buffer, required, out returned))
          throw Win32("Read provider token privileges");
        int count = Marshal.ReadInt32(buffer);
        int entrySize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
        if (count < 0 || count > 1024 || sizeof(uint) + (long)count * entrySize > returned)
          throw new InvalidOperationException("Windows returned a malformed token-privilege list");
        for (int index = 0; index < count; index++) {
          IntPtr entry = IntPtr.Add(buffer, sizeof(uint) + index * entrySize);
          LUID_AND_ATTRIBUTES item = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(entry, typeof(LUID_AND_ATTRIBUTES));
          if (item.Luid.LowPart == expected.LowPart && item.Luid.HighPart == expected.HighPart)
            return (item.Attributes & SE_PRIVILEGE_ENABLED) != 0;
        }
        return false;
      } finally {
        Marshal.FreeHGlobal(buffer);
      }
    }

    static void LogProcessChildPolicy(IntPtr process, string label) {
      uint flags;
      if (GetProcessMitigationPolicy(process, 13, out flags, new UIntPtr((uint)sizeof(uint))))
        Log(label + "=0x" + flags.ToString("X8"));
      else
        Log(label + "_UNAVAILABLE=" + Marshal.GetLastWin32Error());
    }

    // Duplicate stdio handles for the child; never mutate the host's original
    // handle-table entries while preparing CreateProcess.
    static IntPtr DuplicateStandardHandle(IntPtr sourceHandle, string label, IList<IntPtr> ownedHandles) {
      if (sourceHandle == IntPtr.Zero || sourceHandle == INVALID_HANDLE_VALUE)
        throw new InvalidOperationException("The host " + label + " standard handle is unavailable");
      IntPtr duplicate;
      IntPtr process = GetCurrentProcess();
      if (!DuplicateHandle(process, sourceHandle, process, out duplicate, 0, true, DUPLICATE_SAME_ACCESS))
        throw Win32("Duplicate host " + label + " standard handle");
      if (duplicate == IntPtr.Zero || duplicate == INVALID_HANDLE_VALUE)
        throw new InvalidOperationException("Windows returned an invalid duplicate for the " + label + " standard handle");
      ownedHandles.Add(duplicate);
      return duplicate;
    }

    static IntPtr CreateProfile(string name) {
      IntPtr sid;
      int hr = CreateAppContainerProfile(name, "ORIX Provider Sandbox", "Isolated ORIX static provider", IntPtr.Zero, 0, out sid);
      if (hr == 0) return sid;
      if (unchecked((uint)hr) == 0x800700B7) {
        hr = DeriveAppContainerSidFromAppContainerName(name, out sid);
        if (hr == 0) return sid;
      }
      Marshal.ThrowExceptionForHR(hr);
      throw new InvalidOperationException("Could not create or derive the AppContainer SID");
    }

    // NTFS hard links are multiple names for one file object. Granting the
    // AppContainer SID read access through an in-root name would also change
    // the shared file ACL seen by every name, potentially widening access to
    // an out-of-rootfs path. Inspect the open file handle and fail closed unless
    // the regular file has exactly one link.
    static void ValidateSingleLinkFile(string path) {
      IntPtr handle = CreateFileW(path, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
      if (handle == IntPtr.Zero || handle == INVALID_HANDLE_VALUE)
        throw Win32("Open rootfs file for hard-link inspection");
      try {
        BY_HANDLE_FILE_INFORMATION information;
        if (!GetFileInformationByHandle(handle, out information))
          throw Win32("Read rootfs file hard-link metadata");
        if ((information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
          throw new InvalidOperationException("ORIX_WINDOWS_ROOTFS_UNTRUSTED: reparse-point file changed during hard-link inspection: " + path);
        if (information.NumberOfLinks != 1)
          throw new InvalidOperationException("ORIX_WINDOWS_ROOTFS_UNTRUSTED: hard-linked files are not allowed in the provider rootfs: " +
            path + " (linkCount=" + information.NumberOfLinks + ")");
      } finally {
        CloseHandle(handle);
      }
    }

    static void ValidateTree(string path, SecurityIdentifier serviceSid) {
      int entriesSeen = 0;
      ValidateTree(path, serviceSid, 0, ref entriesSeen);
    }

    static void ValidateTree(string path, SecurityIdentifier serviceSid, int depth, ref int entriesSeen) {
      if (depth > MAX_ROOTFS_TREE_DEPTH)
        throw new InvalidOperationException("ORIX_WINDOWS_ROOTFS_UNTRUSTED: provider rootfs exceeds the maximum directory depth");
      if (++entriesSeen > MAX_ROOTFS_TREE_ENTRIES)
        throw new InvalidOperationException("ORIX_WINDOWS_ROOTFS_UNTRUSTED: provider rootfs exceeds the maximum entry count");
      FileAttributes attributes = File.GetAttributes(path);
      if ((attributes & FileAttributes.ReparsePoint) != 0)
        throw new InvalidOperationException("ORIX_WINDOWS_ROOTFS_UNTRUSTED: reparse points are not allowed in the provider rootfs: " + path);
      bool directory = (attributes & FileAttributes.Directory) != 0;
      if (!directory) ValidateSingleLinkFile(path);
      FileSystemSecurity security = directory
        ? (FileSystemSecurity)Directory.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access)
        : (FileSystemSecurity)File.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access);
      SecurityIdentifier owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
      if (!IsTrustedRootPrincipal(owner, serviceSid))
        throw new InvalidOperationException("ORIX_WINDOWS_ROOTFS_UNTRUSTED: rootfs entry has an untrusted owner: " + path);

      FileSystemRights writeMask = FileSystemRights.Write |
        FileSystemRights.Delete |
        FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership;
      AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
      foreach (FileSystemAccessRule rule in rules) {
        if (rule.AccessControlType != AccessControlType.Allow) continue;
        SecurityIdentifier principal = rule.IdentityReference as SecurityIdentifier;
        if (principal == null || IsTrustedRootPrincipal(principal, serviceSid)) continue;
        if ((rule.FileSystemRights & writeMask) != 0)
          throw new InvalidOperationException("ORIX_WINDOWS_ROOTFS_UNTRUSTED: an untrusted principal has write-capable access to rootfs entry " +
            path + " (" + principal.Value + "; rights=" + rule.FileSystemRights + ")");
      }

      if (directory) {
        foreach (string child in Directory.EnumerateFileSystemEntries(path))
          ValidateTree(child, serviceSid, depth + 1, ref entriesSeen);
      }
    }

    static bool IsTrustedRootPrincipal(SecurityIdentifier sid, SecurityIdentifier serviceSid) {
      // The service identity may own the rootfs. System, local Administrators,
      // and Windows TrustedInstaller are trusted host principals.
      return sid.Equals(serviceSid) ||
        sid.Value == "S-1-5-18" ||
        sid.Value == "S-1-5-32-544" ||
        sid.Value == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" ||
        sid.Value == "S-1-3-0"; // CREATOR OWNER is an inheritable placeholder.
    }

    static void ValidateRootTrust(string root) {
      string fullRoot = Path.GetFullPath(root);
      string volumeRoot = Path.GetPathRoot(fullRoot);
      if (String.Equals(fullRoot.TrimEnd('\\', '/'), volumeRoot.TrimEnd('\\', '/'),
        StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException("ORIX_WINDOWS_ROOTFS_UNTRUSTED: filesystem root cannot be used as a provider rootfs");

      SecurityIdentifier serviceSid = WindowsIdentity.GetCurrent().User;
      // On the rootfs itself, reject every write-capable grant. On parent
      // directories, reject rights that can delete/replace the rootfs or let an
      // untrusted principal take ownership/change the ACL. Ordinary create-file
      // or create-directory rights on a parent cannot modify an existing child;
      // any inherited grant that reaches the rootfs is checked at the rootfs.
      FileSystemRights rootfsWriteMask = FileSystemRights.Write |
        FileSystemRights.Delete |
        FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership;
      FileSystemRights ancestorDestructiveMask = FileSystemRights.Delete |
        FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership;
      // DELETE on the volume-root object itself cannot remove or rename the
      // volume root. Do not confuse it with DELETE_CHILD, which is represented
      // by DeleteSubdirectoriesAndFiles and can delete the rootfs beneath it.
      // Keep ACL/ownership mutation forbidden because inherited ACE changes
      // can affect descendants on filesystems that propagate inherited ACLs.
      FileSystemRights volumeRootDestructiveMask = FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership;

      for (DirectoryInfo current = new DirectoryInfo(fullRoot); current != null; current = current.Parent) {
        FileAttributes attributes = File.GetAttributes(current.FullName);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
          throw new InvalidOperationException("ORIX_WINDOWS_ROOTFS_UNTRUSTED: reparse-point ancestor is not allowed: " + current.FullName);

        DirectorySecurity security = Directory.GetAccessControl(current.FullName,
          AccessControlSections.Owner | AccessControlSections.Access);
        SecurityIdentifier owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
        if (!IsTrustedRootPrincipal(owner, serviceSid))
          throw new InvalidOperationException("ORIX_WINDOWS_ROOTFS_UNTRUSTED: rootfs path component has an untrusted owner: " + current.FullName);

        // The volume root cannot itself be renamed, but DELETE_CHILD (the
        // DeleteSubdirectoriesAndFiles right) on it can still delete or replace
        // the rootfs directory beneath it. Hosted Windows images may expose
        // ordinary create/write rights to Authenticated Users, so apply only
        // the destructive ancestor mask at the volume root.
        bool volumeRootComponent = String.Equals(current.FullName.TrimEnd('\\', '/'),
          volumeRoot.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase);
        if (current.Parent == null && !volumeRootComponent) continue;

        AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules) {
          if (rule.AccessControlType != AccessControlType.Allow) continue;
          SecurityIdentifier principal = rule.IdentityReference as SecurityIdentifier;
          if (principal == null || IsTrustedRootPrincipal(principal, serviceSid)) continue;
          bool rootfsComponent = String.Equals(current.FullName, fullRoot,
            StringComparison.OrdinalIgnoreCase);
          FileSystemRights deniedRights = rootfsComponent
            ? rootfsWriteMask
            : volumeRootComponent ? volumeRootDestructiveMask : ancestorDestructiveMask;
          if ((rule.FileSystemRights & deniedRights) != 0)
            throw new InvalidOperationException("ORIX_WINDOWS_ROOTFS_UNTRUSTED: an untrusted principal has unsafe access to " +
              current.FullName + " (" + principal.Value + "; rights=" + rule.FileSystemRights +
              "; inheritance=" + rule.InheritanceFlags + "; rootfs=" + rootfsComponent + ")");
        }
      }
    }

    // ALL APPLICATION PACKAGES is a built-in AppContainer token group. If
    // an ancestor already grants that group traverse/read-execute, adding a
    // per-profile ACE would be redundant and may require WRITE_DAC on protected
    // Windows directories (for example Program Files). Respect deny ACEs and
    // add a narrow per-profile FILE_TRAVERSE rule only when the existing DACL
    // does not already provide traversal to AppContainer tokens.
    static bool HasAppContainerTraversalGrant(DirectorySecurity security, SecurityIdentifier sid) {
      SecurityIdentifier allApplicationPackages = new SecurityIdentifier("S-1-15-2-1");
      SecurityIdentifier allRestrictedApplicationPackages = new SecurityIdentifier("S-1-15-2-2");
      AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
      bool allowed = false;
      foreach (FileSystemAccessRule rule in rules) {
        SecurityIdentifier principal = rule.IdentityReference as SecurityIdentifier;
        if (principal == null) continue;
        bool applies = principal.Equals(sid) ||
          principal.Equals(allApplicationPackages) ||
          principal.Equals(allRestrictedApplicationPackages);
        if (!applies || (rule.FileSystemRights & FileSystemRights.Traverse) == 0) continue;
        if (rule.AccessControlType == AccessControlType.Deny) return false;
        if (rule.AccessControlType == AccessControlType.Allow) allowed = true;
      }
      return allowed;
    }

    // A child process opened by an AppContainer must resolve the executable path
    // using the AppContainer token. Grant only FILE_TRAVERSE on each trusted
    // ancestor that does not already provide it to AppContainer token groups;
    // do not grant directory listing or file-read access outside rootfs.
    // These per-profile ACEs are removed after the provider Job Object is empty.
    static void GrantAncestorTraversal(string root, SecurityIdentifier sid) {
      string fullRoot = Path.GetFullPath(root);
      SecurityIdentifier serviceSid = WindowsIdentity.GetCurrent().User;
      DirectoryInfo current = Directory.GetParent(fullRoot);
      while (current != null) {
        FileAttributes attributes = File.GetAttributes(current.FullName);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
          throw new InvalidOperationException("ORIX_WINDOWS_ROOTFS_UNTRUSTED: reparse-point ancestor appeared before traversal grant: " + current.FullName);
        DirectorySecurity security = Directory.GetAccessControl(current.FullName,
          AccessControlSections.Owner | AccessControlSections.Access);
        SecurityIdentifier owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
        if (HasAppContainerTraversalGrant(security, sid)) {
          Log("RUN:ANCESTOR_TRAVERSE_INHERITED:" + current.FullName);
        } else if (!owner.Equals(serviceSid)) {
          // Never attempt to rewrite DACLs on OS/admin-owned ancestors such as
          // Program Files. The AppContainer receives a profile-specific traverse
          // ACE only on the service-owned directory it created. Windows' normal
          // ancestor traversal semantics are left intact; CreateProcess under
          // the actual AppContainer token is the fail-closed access check.
          Log("RUN:ANCESTOR_TRAVERSE_OS_MANAGED:" + current.FullName);
        } else {
          security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.Traverse, AccessControlType.Allow));
          Directory.SetAccessControl(current.FullName, security);
          Log("RUN:ANCESTOR_TRAVERSE_GRANTED:" + current.FullName);
        }
        current = current.Parent;
      }
    }

    // Only rewrite an ancestor DACL when this invocation actually inserted an
    // explicit ACE for its unique AppContainer SID. This avoids needless writes
    // to protected inherited-only ancestors and preserves unrelated ACEs.
    static void PurgeAncestorTraversal(string root, SecurityIdentifier sid) {
      string fullRoot = Path.GetFullPath(root);
      DirectoryInfo current = Directory.GetParent(fullRoot);
      while (current != null) {
        FileAttributes attributes = File.GetAttributes(current.FullName);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
          throw new InvalidOperationException("ORIX_WINDOWS_CLEANUP_REPARSE_POINT: refusing to purge ancestor traversal through reparse point: " + current.FullName);
        DirectorySecurity security = Directory.GetAccessControl(current.FullName, AccessControlSections.Access);
        AuthorizationRuleCollection rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier));
        bool hasExplicitProfileRule = rules.Cast<FileSystemAccessRule>().Any(rule =>
          rule.IdentityReference.Equals(sid) && !rule.IsInherited);
        if (hasExplicitProfileRule) {
          security.PurgeAccessRules(sid);
          Directory.SetAccessControl(current.FullName, security);
          Log("CLEANUP:ANCESTOR_TRAVERSE_REMOVED:" + current.FullName);
        } else {
          Log("CLEANUP:ANCESTOR_TRAVERSE_UNCHANGED:" + current.FullName);
        }
        current = current.Parent;
      }
    }

    static void GrantTree(string path, SecurityIdentifier sid, FileSystemRights rights, bool root) {
      int entriesSeen = 0;
      GrantTree(path, sid, rights, root, 0, ref entriesSeen);
    }

    static void GrantTree(string path, SecurityIdentifier sid, FileSystemRights rights, bool root, int depth, ref int entriesSeen) {
      if (depth > MAX_ROOTFS_TREE_DEPTH)
        throw new InvalidOperationException("ORIX_WINDOWS_ROOTFS_UNTRUSTED: provider rootfs exceeds the maximum directory depth while applying its AppContainer ACL");
      if (++entriesSeen > MAX_ROOTFS_TREE_ENTRIES)
        throw new InvalidOperationException("ORIX_WINDOWS_ROOTFS_UNTRUSTED: provider rootfs exceeds the maximum entry count while applying its AppContainer ACL");
      FileAttributes attributes = File.GetAttributes(path);
      if ((attributes & FileAttributes.ReparsePoint) != 0)
        throw new InvalidOperationException("Reparse points are not allowed in the provider rootfs: " + path);
      bool directory = (attributes & FileAttributes.Directory) != 0;
      if (directory) {
        DirectorySecurity security = Directory.GetAccessControl(path, AccessControlSections.Access);
        security.AddAccessRule(new FileSystemAccessRule(sid, rights,
          InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
          PropagationFlags.None, AccessControlType.Allow));
        Directory.SetAccessControl(path, security);
        foreach (string child in Directory.EnumerateFileSystemEntries(path))
          GrantTree(child, sid, rights, false, depth + 1, ref entriesSeen);
      } else {
        FileSecurity security = File.GetAccessControl(path, AccessControlSections.Access);
        security.AddAccessRule(new FileSystemAccessRule(sid, rights, AccessControlType.Allow));
        File.SetAccessControl(path, security);
      }
    }

    static List<KeyValuePair<string, FileAttributes>> CollectCleanupTree(string path, string reparseError) {
      var collected = new List<KeyValuePair<string, FileAttributes>>();
      var pending = new Stack<KeyValuePair<string, int>>();
      pending.Push(new KeyValuePair<string, int>(path, 0));
      while (pending.Count > 0) {
        KeyValuePair<string, int> item = pending.Pop();
        FileAttributes attributes;
        try { attributes = File.GetAttributes(item.Key); }
        catch (FileNotFoundException) { continue; }
        catch (DirectoryNotFoundException) { continue; }
        if (item.Value > MAX_CLEANUP_TREE_DEPTH)
          throw new InvalidOperationException("ORIX_WINDOWS_CLEANUP_LIMIT: cleanup tree exceeds the maximum directory depth");
        if (collected.Count >= MAX_CLEANUP_TREE_ENTRIES)
          throw new InvalidOperationException("ORIX_WINDOWS_CLEANUP_LIMIT: cleanup tree exceeds the maximum entry count");
        if ((attributes & FileAttributes.ReparsePoint) != 0)
          throw new InvalidOperationException(reparseError + item.Key);
        collected.Add(new KeyValuePair<string, FileAttributes>(item.Key, attributes));
        if ((attributes & FileAttributes.Directory) != 0) {
          foreach (string child in Directory.EnumerateFileSystemEntries(item.Key))
            pending.Push(new KeyValuePair<string, int>(child, item.Value + 1));
        }
      }
      return collected;
    }

    // Preflight the complete tree before mutating any ACL. The iterative walk
    // is bounded and cannot overflow the native stack on provider-controlled
    // directory depth. Children are processed before parents during cleanup.
    static void PurgeTree(string path, SecurityIdentifier sid) {
      List<KeyValuePair<string, FileAttributes>> entries = CollectCleanupTree(
        path, "ORIX_WINDOWS_CLEANUP_REPARSE_POINT: refusing to traverse cleanup path: ");
      for (int index = entries.Count - 1; index >= 0; index--) {
        string entryPath = entries[index].Key;
        if ((entries[index].Value & FileAttributes.Directory) != 0) {
          DirectorySecurity security = Directory.GetAccessControl(entryPath, AccessControlSections.Access);
          security.PurgeAccessRules(sid);
          Directory.SetAccessControl(entryPath, security);
        } else {
          FileSecurity security = File.GetAccessControl(entryPath, AccessControlSections.Access);
          security.PurgeAccessRules(sid);
          File.SetAccessControl(entryPath, security);
        }
      }
    }

    // Remove only the per-profile AppContainer temp tree. Preflight the entire
    // subtree and delete children before parents without recursive calls.
    static void DeleteTreeNoReparse(string path) {
      List<KeyValuePair<string, FileAttributes>> entries = CollectCleanupTree(
        path, "ORIX_WINDOWS_CLEANUP_REPARSE_POINT: refusing to clean an AppContainer temp reparse point: ");
      for (int index = entries.Count - 1; index >= 0; index--) {
        string entryPath = entries[index].Key;
        FileAttributes attributes = entries[index].Value;
        if ((attributes & FileAttributes.ReadOnly) != 0)
          File.SetAttributes(entryPath, attributes & ~FileAttributes.ReadOnly);
        if ((attributes & FileAttributes.Directory) != 0)
          Directory.Delete(entryPath, false);
        else
          File.Delete(entryPath);
      }
    }

    static string Quote(string value) {
      if (value.Length > 0 && value.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0) return value;
      StringBuilder output = new StringBuilder();
      output.Append('"');
      int slashes = 0;
      foreach (char ch in value) {
        if (ch == '\\') { slashes++; continue; }
        if (ch == '"') {
          output.Append('\\', slashes * 2 + 1);
          output.Append('"');
          slashes = 0;
          continue;
        }
        output.Append('\\', slashes);
        slashes = 0;
        output.Append(ch);
      }
      output.Append('\\', slashes * 2);
      output.Append('"');
      return output.ToString();
    }

    static IntPtr BuildEnvironment(IDictionary environment) {
      SortedDictionary<string, string> values = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
      foreach (DictionaryEntry item in environment) values[(string)item.Key] = Convert.ToString(item.Value);
      string block = String.Join("\0", values.Select(pair => pair.Key + "=" + pair.Value)) + "\0\0";
      byte[] bytes = Encoding.Unicode.GetBytes(block);
      IntPtr pointer = Marshal.AllocHGlobal(bytes.Length);
      Marshal.Copy(bytes, 0, pointer, bytes.Length);
      return pointer;
    }

    static string TrustedSystemDirectory() {
      // Do not resolve security-sensitive Windows utilities from inherited
      // SystemRoot/WINDIR environment variables. Ask the OS for its system
      // directory directly, then use only an absolute path beneath it.
      StringBuilder buffer = new StringBuilder(32768);
      uint length = GetSystemDirectoryW(buffer, (uint)buffer.Capacity);
      if (length == 0 || length >= (uint)buffer.Capacity)
        throw Win32("Resolve trusted Windows system directory");
      string directory = Path.GetFullPath(buffer.ToString());
      if (!Path.IsPathRooted(directory))
        throw new InvalidOperationException("Windows returned a non-absolute system directory");
      return directory;
    }

    static void SetIntegrityLevel(string path, string level) {
      string icacls = Path.Combine(TrustedSystemDirectory(), "icacls.exe");
      FileAttributes attributes = File.GetAttributes(icacls);
      if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        throw new InvalidOperationException("Trusted icacls utility is not a regular system file");
      ProcessStartInfo start = new ProcessStartInfo();
      start.FileName = icacls;
      start.Arguments = Quote(path) + " /setintegritylevel (OI)(CI)" + level;
      start.UseShellExecute = false;
      start.CreateNoWindow = true;
      start.RedirectStandardOutput = true;
      start.RedirectStandardError = true;
      using (Process process = Process.Start(start)) {
        StringBuilder output = new StringBuilder();
        StringBuilder error = new StringBuilder();
        process.OutputDataReceived += (sender, eventArgs) => {
          if (eventArgs.Data != null && output.Length < 8192)
            output.AppendLine(eventArgs.Data.Substring(0, Math.Min(eventArgs.Data.Length, 8192 - output.Length)));
        };
        process.ErrorDataReceived += (sender, eventArgs) => {
          if (eventArgs.Data != null && error.Length < 8192)
            error.AppendLine(eventArgs.Data.Substring(0, Math.Min(eventArgs.Data.Length, 8192 - error.Length)));
        };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        if (!process.WaitForExit(10000)) {
          // Do not begin AppContainer/profile cleanup while icacls may still be
          // changing the scratch ACL. Kill and synchronously observe process exit.
          try { process.Kill(); } catch { /* it may have exited between timeout and Kill */ }
          process.WaitForExit();
          throw new TimeoutException("icacls integrity-label operation timed out");
        }
        // The parameterless wait also drains completion of asynchronous output
        // handlers on .NET Framework before the process object is disposed.
        process.WaitForExit();
        if (process.ExitCode != 0)
          throw new InvalidOperationException("Could not set " + level + " integrity on scratch directory: " +
            error.ToString() + output.ToString());
      }
    }

    static string PrepareScratch(string root, IntPtr sid, string profileName, IDictionary environment) {
      string temp = Path.Combine(root, "tmp");
      if (!Directory.Exists(temp)) throw new DirectoryNotFoundException("sandbox_root/tmp is required for provider scratch writes");
      DirectorySecurity security = Directory.GetAccessControl(temp, AccessControlSections.Access);
      SecurityIdentifier identity = new SecurityIdentifier(sid);
      security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.Modify,
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
        PropagationFlags.None, AccessControlType.Allow));
      Directory.SetAccessControl(temp, security);
      SetIntegrityLevel(temp, "L");

      // AppContainer redirects Win32 temporary-file APIs into a package-specific
      // AC\\Temp directory beneath TEMP. Provision only that private redirected
      // path and grant the package SID the same bounded scratch permissions.
      string appContainerTemp = Path.Combine(temp, "Packages", profileName.ToLowerInvariant(), "AC", "Temp");
      Directory.CreateDirectory(appContainerTemp);
      DirectorySecurity redirectedSecurity = Directory.GetAccessControl(appContainerTemp, AccessControlSections.Access);
      redirectedSecurity.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.Modify,
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
        PropagationFlags.None, AccessControlType.Allow));
      Directory.SetAccessControl(appContainerTemp, redirectedSecurity);
      SetIntegrityLevel(appContainerTemp, "L");

      environment["TEMP"] = temp;
      environment["TMP"] = temp;
      environment["HOME"] = temp;
      environment["USERPROFILE"] = temp;
      environment["LOCALAPPDATA"] = temp;
      environment["APPDATA"] = temp;
      return temp;
    }

    static void ConfigureJob(IntPtr job) {
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
      limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_JOB_MEMORY;
      limits.BasicLimitInformation.ActiveProcessLimit = 64;
      limits.JobMemoryLimit = new UIntPtr(512UL * 1024UL * 1024UL);
      IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
      try {
        Marshal.StructureToPtr(limits, buffer, false);
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, buffer,
          (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)))) throw Win32("Set job memory/process limits");
      } finally { Marshal.FreeHGlobal(buffer); }

      JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu = new JOBOBJECT_CPU_RATE_CONTROL_INFORMATION();
      cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
      cpu.CpuRate = 5000;
      buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(JOBOBJECT_CPU_RATE_CONTROL_INFORMATION)));
      try {
        Marshal.StructureToPtr(cpu, buffer, false);
        if (!SetInformationJobObject(job, JobObjectCpuRateControlInformation, buffer,
          (uint)Marshal.SizeOf(typeof(JOBOBJECT_CPU_RATE_CONTROL_INFORMATION)))) throw Win32("Set job CPU hard cap");
      } finally { Marshal.FreeHGlobal(buffer); }
    }

    static void TerminateAndWaitForProvider(IntPtr job, bool processAssignedToJob, IntPtr processHandle) {
      if (processAssignedToJob && job != IntPtr.Zero) {
        uint jobWait = WaitForSingleObject(job, 0);
        if (jobWait != 0) {
          if (!TerminateJobObject(job, 1)) {
            jobWait = WaitForSingleObject(job, 0);
            if (jobWait != 0) throw Win32("Terminate provider Job Object");
          }
        }
        jobWait = WaitForSingleObject(job, 5000);
        if (jobWait != 0) throw new TimeoutException("Provider Job Object did not become empty after termination (wait=" + jobWait + ")");
        Log("RUN:TEARDOWN_CONFIRMED_JOB_EMPTY");
        return;
      }

      uint processWait = WaitForSingleObject(processHandle, 0);
      if (processWait != 0) {
        if (!TerminateProcess(processHandle, 1)) {
          processWait = WaitForSingleObject(processHandle, 0);
          if (processWait != 0) throw Win32("Terminate provider process outside Job Object");
        }
      }
      processWait = WaitForSingleObject(processHandle, 5000);
      if (processWait != 0) throw new TimeoutException("Provider process did not exit after termination (wait=" + processWait + ")");
      Log("RUN:TEARDOWN_CONFIRMED_PROCESS_EXITED");
    }

    public static int Run(string executable, string[] arguments, string cwd, string root,
      string profileName, IDictionary environment, out bool profileCreated) {
      profileCreated = false;
      IntPtr sid = IntPtr.Zero, job = IntPtr.Zero, attributeList = IntPtr.Zero;
      IntPtr securityCaps = IntPtr.Zero, handleList = IntPtr.Zero, childProcessPolicy = IntPtr.Zero, environmentBlock = IntPtr.Zero;
      IntPtr token = IntPtr.Zero, tokenInfo = IntPtr.Zero;
      PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
      List<IntPtr> inheritedStandardHandles = new List<IntPtr>();
      bool processCreated = false;
      bool processAssignedToJob = false;
      try {
        Log("RUN:BEGIN");
        if (!Directory.Exists(root) || !Directory.Exists(cwd))
          throw new DirectoryNotFoundException("Provider rootfs or working directory is missing");
        ValidateRootTrust(root);
        ValidateTree(root, WindowsIdentity.GetCurrent().User);
        sid = CreateProfile(profileName);
        profileCreated = true;
        Log("RUN:PROFILE_CREATED");
        SecurityIdentifier identity = new SecurityIdentifier(sid);
        GrantTree(root, identity, FileSystemRights.ReadAndExecute, true);
        Log("RUN:ROOT_ACL_GRANTED");
        PrepareScratch(root, sid, profileName, environment);
        Log("RUN:PRIVATE_TEMP_READY");

        job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw Win32("Create provider Job Object");
        ConfigureJob(job);
        Log("RUN:JOB_LIMITS_CONFIGURED");

        SECURITY_CAPABILITIES capabilities = new SECURITY_CAPABILITIES();
        capabilities.AppContainerSid = sid;
        securityCaps = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SECURITY_CAPABILITIES)));
        Marshal.StructureToPtr(capabilities, securityCaps, false);

        // Duplicate stdio handles as inheritable child-only handles. The
        // original helper handles remain untouched.
        IntPtr stdin = DuplicateStandardHandle(GetStdHandle(-10), "stdin", inheritedStandardHandles);
        IntPtr stdout = DuplicateStandardHandle(GetStdHandle(-11), "stdout", inheritedStandardHandles);
        IntPtr stderr = DuplicateStandardHandle(GetStdHandle(-12), "stderr", inheritedStandardHandles);
        handleList = Marshal.AllocHGlobal(IntPtr.Size * inheritedStandardHandles.Count);
        for (int index = 0; index < inheritedStandardHandles.Count; index++)
          Marshal.WriteIntPtr(handleList, IntPtr.Size * index, inheritedStandardHandles[index]);

        // AppContainer child creation may be restricted by the inherited process policy.
        // The trusted, non-AppContainer launcher explicitly permits descendants, but does
        // not relax the AppContainer token or Job Object: descendants inherit both and
        // cannot break away from this job because no breakaway limit is enabled.
        childProcessPolicy = Marshal.AllocHGlobal(sizeof(uint));
        Marshal.WriteInt32(childProcessPolicy, unchecked((int)PROCESS_CREATION_CHILD_PROCESS_OVERRIDE));

        IntPtr attributeSize = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 3, 0, ref attributeSize);
        attributeList = Marshal.AllocHGlobal(attributeSize);
        if (!InitializeProcThreadAttributeList(attributeList, 3, 0, ref attributeSize)) throw Win32("Initialize process attribute list");
        if (!UpdateProcThreadAttribute(attributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
          securityCaps, (IntPtr)Marshal.SizeOf(typeof(SECURITY_CAPABILITIES)), IntPtr.Zero, IntPtr.Zero))
          throw Win32("Attach AppContainer security capabilities");
        if (!UpdateProcThreadAttribute(attributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
          handleList, (IntPtr)(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero))
          throw Win32("Restrict inherited handles");
        if (!UpdateProcThreadAttribute(attributeList, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
          childProcessPolicy, (IntPtr)sizeof(uint), IntPtr.Zero, IntPtr.Zero))
          throw Win32("Allow Job-contained AppContainer descendants");

        STARTUPINFOEX startup = new STARTUPINFOEX();
        startup.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOEX));
        // Console-based AppContainer runtimes need a real console host for nested
        // CreateProcess calls. Give the provider a fresh, hidden console rather than
        // inheriting a host's possibly isolated console context. Keep lpDesktop null:
        // no private desktop/window-station is created or selected by ORIX.
        startup.StartupInfo.lpDesktop = null;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        startup.StartupInfo.wShowWindow = SW_HIDE;
        startup.StartupInfo.hStdInput = stdin;
        startup.StartupInfo.hStdOutput = stdout;
        startup.StartupInfo.hStdError = stderr;
        startup.lpAttributeList = attributeList;

        string commandLine = Quote(executable) + (arguments.Length == 0 ? "" : " " + String.Join(" ", arguments.Select(Quote)));
        environmentBlock = BuildEnvironment(environment);
        if (!CreateProcessW(executable, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, true,
          CREATE_SUSPENDED | CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
          environmentBlock, cwd, ref startup, out processInfo)) throw Win32("Create AppContainer provider process");
        processCreated = true;
        Log("RUN:PROCESS_CREATED_SUSPENDED");
        if (!AssignProcessToJobObject(job, processInfo.hProcess)) throw Win32("Assign provider to Job Object");
        processAssignedToJob = true;
        Log("RUN:PROCESS_ASSIGNED_TO_JOB");

        if (!OpenProcessToken(processInfo.hProcess, 0x0008, out token)) throw Win32("Open provider process token");
        tokenInfo = Marshal.AllocHGlobal(sizeof(int));
        int returned;
        if (!GetTokenInformation(token, TokenIsAppContainer, tokenInfo, sizeof(int), out returned)) throw Win32("Verify AppContainer token");
        if (Marshal.ReadInt32(tokenInfo) != 1) throw new InvalidOperationException("Windows did not create the provider inside an AppContainer");

        LogProcessChildPolicy(GetCurrentProcess(), "RUN:HELPER_CHILD_PROCESS_POLICY_FLAGS");
        LogProcessChildPolicy(processInfo.hProcess, "RUN:PROVIDER_CHILD_PROCESS_POLICY_FLAGS");
        bool bypassTraverseEnabled = HasEnabledPrivilege(token, "SeChangeNotifyPrivilege");
        Log("RUN:PROVIDER_SE_CHANGE_NOTIFY_ENABLED=" + (bypassTraverseEnabled ? "1" : "0"));
        if (bypassTraverseEnabled) {
          // Windows grants SeChangeNotifyPrivilege by default. An enabled
          // AppContainer token privilege bypasses per-component FILE_TRAVERSE
          // checks, so do not rewrite protected host ancestors such as
          // Program Files merely to add redundant per-profile ACEs.
          Log("RUN:ANCESTOR_TRAVERSE_BYPASS_PRIVILEGE");
        } else {
          // Some hardened hosts remove this privilege. In that case explicit
          // traverse grants are required; failure to update a protected
          // ancestor remains fail-closed.
          GrantAncestorTraversal(root, identity);
          Log("RUN:ANCESTOR_TRAVERSE_READY");
        }

        Console.Error.WriteLine("ORIX_WINDOWS_APPCONTAINER=1;JOB_CPU_RATE=5000;JOB_MEMORY=536870912;JOB_ACTIVE_PROCESSES=64");
        Console.Error.WriteLine("ORIX_WINDOWS_CHILD_PROCESS_POLICY=OVERRIDE_JOB_CONTAINED");
        Console.Error.WriteLine("ORIX_WINDOWS_CONSOLE=NEW_HIDDEN;DESKTOP=INHERITED");
        Log("RUN:APP_CONTAINER_VERIFIED");
        if (ResumeThread(processInfo.hThread) == 0xFFFFFFFF) throw Win32("Resume AppContainer provider");
        Log("RUN:PROCESS_RESUMED");
        if (WaitForSingleObject(processInfo.hProcess, 0xFFFFFFFF) != 0) throw Win32("Wait for AppContainer provider");
        Log("RUN:PROCESS_EXITED");
        uint exitCode;
        if (!GetExitCodeProcess(processInfo.hProcess, out exitCode)) throw Win32("Read provider exit code");

        // The provider's descendants stay in the job. Terminate any that outlive the main process.
        uint jobWait = WaitForSingleObject(job, 100);
        if (jobWait == 258) {
          if (!TerminateJobObject(job, exitCode)) throw Win32("Terminate remaining provider descendants");
          jobWait = WaitForSingleObject(job, 5000);
        }
        if (jobWait != 0) throw new TimeoutException("Provider Job Object did not become empty");
        Log("RUN:JOB_EMPTY");
        return unchecked((int)exitCode);
      } finally {
        Exception teardownFailure = null;
        if (processCreated && processInfo.hProcess != IntPtr.Zero) {
          try {
            // Termination APIs are asynchronous. Do not return to Main (where
            // AppContainer ACL/scratch cleanup occurs) until the job is empty
            // or the direct suspended process is signaled.
            TerminateAndWaitForProvider(job, processAssignedToJob, processInfo.hProcess);
          } catch (Exception error) {
            teardownFailure = error;
            Log("RUN:TEARDOWN_INCOMPLETE:" + error.Message);
            Console.Error.WriteLine("ORIX_WINDOWS_TEARDOWN_UNVERIFIED=" + error.Message);
          }
        }
        if (tokenInfo != IntPtr.Zero) Marshal.FreeHGlobal(tokenInfo);
        if (token != IntPtr.Zero) CloseHandle(token);
        if (processInfo.hThread != IntPtr.Zero) CloseHandle(processInfo.hThread);
        if (processInfo.hProcess != IntPtr.Zero) CloseHandle(processInfo.hProcess);
        foreach (IntPtr inheritedHandle in inheritedStandardHandles) {
          if (inheritedHandle != IntPtr.Zero && inheritedHandle != INVALID_HANDLE_VALUE)
            CloseHandle(inheritedHandle);
        }
        if (job != IntPtr.Zero) CloseHandle(job);
        if (attributeList != IntPtr.Zero) DeleteProcThreadAttributeList(attributeList);
        if (securityCaps != IntPtr.Zero) Marshal.FreeHGlobal(securityCaps);
        if (childProcessPolicy != IntPtr.Zero) Marshal.FreeHGlobal(childProcessPolicy);
        if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
        if (environmentBlock != IntPtr.Zero) Marshal.FreeHGlobal(environmentBlock);
        if (sid != IntPtr.Zero) FreeSid(sid);
        if (teardownFailure != null) throw new ProviderTeardownIncompleteException(teardownFailure);
      }
    }

    public static void Cleanup(string root, string profileName) {
      IntPtr sid = IntPtr.Zero;
      try {
        Console.Error.WriteLine("ORIX_CLEANUP:BEGIN");
        Log("CLEANUP:BEGIN");
        int hr = DeriveAppContainerSidFromAppContainerName(profileName, out sid);
        // A failed SID lookup is not evidence that the profile is absent.
        // The API documents E_INVALIDARG as a failure; treating every HRESULT
        // as a successful no-op would hide invalid input and genuine cleanup
        // failures. DeleteAppContainerProfile itself is idempotent for absence.
        if (hr != 0) Marshal.ThrowExceptionForHR(hr);
        Console.Error.WriteLine("ORIX_CLEANUP:SID_DERIVED");
        Log("CLEANUP:SID_DERIVED");
        SecurityIdentifier identity = new SecurityIdentifier(sid);
        if (Directory.Exists(root)) PurgeTree(root, identity);
        string scratch = Path.Combine(root, "tmp");
        // AppContainer's Win32 temp redirection is profile-specific. Remove its
        // files and low-integrity directory after the provider job is empty so
        // temporary artifacts cannot leak into later runs.
        string packageScratch = Path.Combine(scratch, "Packages", profileName.ToLowerInvariant());
        DeleteTreeNoReparse(packageScratch);
        string packagesRoot = Path.Combine(scratch, "Packages");
        if (Directory.Exists(packagesRoot) && !Directory.EnumerateFileSystemEntries(packagesRoot).Any())
          Directory.Delete(packagesRoot, false);
        if (Directory.Exists(scratch)) SetIntegrityLevel(scratch, "M");
        PurgeAncestorTraversal(root, identity);
        Console.Error.WriteLine("ORIX_CLEANUP:ANCESTOR_TRAVERSE_PURGED");
        Log("CLEANUP:ANCESTOR_TRAVERSE_PURGED");
        Console.Error.WriteLine("ORIX_CLEANUP:ROOT_ACL_PURGED");
        Log("CLEANUP:ROOT_ACL_PURGED");
        int deleteResult = DeleteAppContainerProfile(profileName);
        Console.Error.WriteLine("ORIX_CLEANUP:PROFILE_DELETE_HR:" + deleteResult);
        Log("CLEANUP:PROFILE_DELETE_HR:" + deleteResult);
        if (deleteResult != 0 && unchecked((uint)deleteResult) != 0x80070002)
          Marshal.ThrowExceptionForHR(deleteResult);
      } finally {
        if (sid != IntPtr.Zero) FreeSid(sid);
        Log("CLEANUP:SID_FREED");
      }
    }
  }
}
