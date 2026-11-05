using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace OrixWindowsSandbox {
  public static class Launcher {
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const uint STARTF_USESTDHANDLES = 0x00000100;
    const uint HANDLE_FLAG_INHERIT = 0x00000001;
    const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
    const uint JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    const uint JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x00000001;
    const uint JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x00000004;
    const int JobObjectExtendedLimitInformation = 9;
    const int JobObjectCpuRateControlInformation = 15;
    const int TokenIsAppContainer = 29;
    static readonly IntPtr PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = new IntPtr(0x00020009);
    static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = new IntPtr(0x00020002);
    static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

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
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    static extern int GetAppContainerFolderPath(IntPtr appContainerSid, out IntPtr path);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr FreeSid(IntPtr sid);

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
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
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

    static Exception Win32(string operation) {
      return new Win32Exception(Marshal.GetLastWin32Error(), operation);
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

    static void ValidateTree(string path) {
      FileAttributes attributes = File.GetAttributes(path);
      if ((attributes & FileAttributes.ReparsePoint) != 0)
        throw new InvalidOperationException("Reparse points are not allowed in the provider rootfs: " + path);
      if ((attributes & FileAttributes.Directory) != 0) {
        foreach (string child in Directory.EnumerateFileSystemEntries(path)) ValidateTree(child);
      }
    }

    static void GrantTree(string path, SecurityIdentifier sid, FileSystemRights rights, bool root) {
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
        foreach (string child in Directory.EnumerateFileSystemEntries(path)) GrantTree(child, sid, rights, false);
      } else {
        FileSecurity security = File.GetAccessControl(path, AccessControlSections.Access);
        security.AddAccessRule(new FileSystemAccessRule(sid, rights, AccessControlType.Allow));
        File.SetAccessControl(path, security);
      }
    }

    static void DeleteTreeNoFollow(string path) {
      if (!File.Exists(path) && !Directory.Exists(path)) return;
      FileAttributes attributes = File.GetAttributes(path);
      bool directory = (attributes & FileAttributes.Directory) != 0;
      bool reparse = (attributes & FileAttributes.ReparsePoint) != 0;
      if (directory && !reparse) {
        foreach (string child in Directory.EnumerateFileSystemEntries(path)) DeleteTreeNoFollow(child);
        Directory.Delete(path, false);
      } else if (directory) {
        Directory.Delete(path, false);
      } else {
        File.Delete(path);
      }
    }

    static void PurgeTree(string path, SecurityIdentifier sid) {
      if (!File.Exists(path) && !Directory.Exists(path)) return;
      FileAttributes attributes = File.GetAttributes(path);
      if ((attributes & FileAttributes.ReparsePoint) != 0) return;
      bool directory = (attributes & FileAttributes.Directory) != 0;
      if (directory) {
        foreach (string child in Directory.EnumerateFileSystemEntries(path)) PurgeTree(child, sid);
        DirectorySecurity security = Directory.GetAccessControl(path, AccessControlSections.Access);
        security.PurgeAccessRules(sid);
        Directory.SetAccessControl(path, security);
      } else {
        FileSecurity security = File.GetAccessControl(path, AccessControlSections.Access);
        security.PurgeAccessRules(sid);
        File.SetAccessControl(path, security);
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

    static string CreatePrivateTemp(IntPtr sid, IDictionary environment) {
      IntPtr pathPointer = IntPtr.Zero;
      int hr = GetAppContainerFolderPath(sid, out pathPointer);
      if (hr != 0) Marshal.ThrowExceptionForHR(hr);
      string appFolder;
      try { appFolder = Marshal.PtrToStringUni(pathPointer); }
      finally { if (pathPointer != IntPtr.Zero) Marshal.FreeCoTaskMem(pathPointer); }
      if (String.IsNullOrEmpty(appFolder)) throw new InvalidOperationException("Windows returned an empty AppContainer data path");
      string temp = Path.Combine(appFolder, "Temp");
      Directory.CreateDirectory(temp);
      environment["TEMP"] = temp;
      environment["TMP"] = temp;
      environment["HOME"] = appFolder;
      environment["USERPROFILE"] = appFolder;
      environment["LOCALAPPDATA"] = appFolder;
      environment["APPDATA"] = appFolder;
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

    public static int Run(string executable, string[] arguments, string cwd, string root,
      string profileName, IDictionary environment) {
      IntPtr sid = IntPtr.Zero, job = IntPtr.Zero, attributeList = IntPtr.Zero;
      IntPtr securityCaps = IntPtr.Zero, handleList = IntPtr.Zero, environmentBlock = IntPtr.Zero;
      IntPtr token = IntPtr.Zero, tokenInfo = IntPtr.Zero;
      PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
      bool processCreated = false;
      try {
        if (!Directory.Exists(root) || !Directory.Exists(cwd))
          throw new DirectoryNotFoundException("Provider rootfs or working directory is missing");
        ValidateTree(root);
        sid = CreateProfile(profileName);
        SecurityIdentifier identity = new SecurityIdentifier(sid);
        GrantTree(root, identity, FileSystemRights.ReadAndExecute, true);
        CreatePrivateTemp(sid, environment);

        job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw Win32("Create provider Job Object");
        ConfigureJob(job);

        SECURITY_CAPABILITIES capabilities = new SECURITY_CAPABILITIES();
        capabilities.AppContainerSid = sid;
        securityCaps = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SECURITY_CAPABILITIES)));
        Marshal.StructureToPtr(capabilities, securityCaps, false);

        IntPtr stdin = GetStdHandle(-10), stdout = GetStdHandle(-11), stderr = GetStdHandle(-12);
        foreach (IntPtr handle in new IntPtr[] { stdin, stdout, stderr }) {
          if (handle != IntPtr.Zero && handle != INVALID_HANDLE_VALUE)
            SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        }
        handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
        Marshal.WriteIntPtr(handleList, 0, stdin);
        Marshal.WriteIntPtr(handleList, IntPtr.Size, stdout);
        Marshal.WriteIntPtr(handleList, IntPtr.Size * 2, stderr);

        IntPtr attributeSize = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref attributeSize);
        attributeList = Marshal.AllocHGlobal(attributeSize);
        if (!InitializeProcThreadAttributeList(attributeList, 2, 0, ref attributeSize)) throw Win32("Initialize process attribute list");
        if (!UpdateProcThreadAttribute(attributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
          securityCaps, (IntPtr)Marshal.SizeOf(typeof(SECURITY_CAPABILITIES)), IntPtr.Zero, IntPtr.Zero))
          throw Win32("Attach AppContainer security capabilities");
        if (!UpdateProcThreadAttribute(attributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
          handleList, (IntPtr)(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero))
          throw Win32("Restrict inherited handles");

        STARTUPINFOEX startup = new STARTUPINFOEX();
        startup.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOEX));
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = stdin;
        startup.StartupInfo.hStdOutput = stdout;
        startup.StartupInfo.hStdError = stderr;
        startup.lpAttributeList = attributeList;

        string commandLine = Quote(executable) + (arguments.Length == 0 ? "" : " " + String.Join(" ", arguments.Select(Quote)));
        environmentBlock = BuildEnvironment(environment);
        if (!CreateProcessW(executable, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, true,
          CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
          environmentBlock, cwd, ref startup, out processInfo)) throw Win32("Create AppContainer provider process");
        processCreated = true;
        if (!AssignProcessToJobObject(job, processInfo.hProcess)) throw Win32("Assign provider to Job Object");

        if (!OpenProcessToken(processInfo.hProcess, 0x0008, out token)) throw Win32("Open provider process token");
        tokenInfo = Marshal.AllocHGlobal(sizeof(int));
        int returned;
        if (!GetTokenInformation(token, TokenIsAppContainer, tokenInfo, sizeof(int), out returned)) throw Win32("Verify AppContainer token");
        if (Marshal.ReadInt32(tokenInfo) != 1) throw new InvalidOperationException("Windows did not create the provider inside an AppContainer");

        Console.Error.WriteLine("ORIX_WINDOWS_APPCONTAINER=1;JOB_CPU_RATE=5000;JOB_MEMORY=536870912;JOB_ACTIVE_PROCESSES=64");
        if (ResumeThread(processInfo.hThread) == 0xFFFFFFFF) throw Win32("Resume AppContainer provider");
        if (WaitForSingleObject(processInfo.hProcess, 0xFFFFFFFF) != 0) throw Win32("Wait for AppContainer provider");
        uint exitCode;
        if (!GetExitCodeProcess(processInfo.hProcess, out exitCode)) throw Win32("Read provider exit code");

        // The provider's descendants stay in the job. Terminate any that outlive the main process.
        uint jobWait = WaitForSingleObject(job, 100);
        if (jobWait == 258) {
          if (!TerminateJobObject(job, exitCode)) throw Win32("Terminate remaining provider descendants");
          jobWait = WaitForSingleObject(job, 5000);
        }
        if (jobWait != 0) throw new TimeoutException("Provider Job Object did not become empty");
        return unchecked((int)exitCode);
      } finally {
        if (processCreated && processInfo.hProcess != IntPtr.Zero) {
          if (job != IntPtr.Zero) TerminateJobObject(job, 1);
          TerminateProcess(processInfo.hProcess, 1);
        }
        if (tokenInfo != IntPtr.Zero) Marshal.FreeHGlobal(tokenInfo);
        if (token != IntPtr.Zero) CloseHandle(token);
        if (processInfo.hThread != IntPtr.Zero) CloseHandle(processInfo.hThread);
        if (processInfo.hProcess != IntPtr.Zero) CloseHandle(processInfo.hProcess);
        if (job != IntPtr.Zero) CloseHandle(job);
        if (attributeList != IntPtr.Zero) DeleteProcThreadAttributeList(attributeList);
        if (securityCaps != IntPtr.Zero) Marshal.FreeHGlobal(securityCaps);
        if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
        if (environmentBlock != IntPtr.Zero) Marshal.FreeHGlobal(environmentBlock);
        if (sid != IntPtr.Zero) FreeSid(sid);
      }
    }

    public static void Cleanup(string root, string profileName) {
      IntPtr sid = IntPtr.Zero;
      try {
        Console.Error.WriteLine("ORIX_CLEANUP:BEGIN");
        int hr = DeriveAppContainerSidFromAppContainerName(profileName, out sid);
        if (hr != 0) { Console.Error.WriteLine("ORIX_CLEANUP:NO_PROFILE:" + hr); return; }
        Console.Error.WriteLine("ORIX_CLEANUP:SID_DERIVED");
        SecurityIdentifier identity = new SecurityIdentifier(sid);
        if (Directory.Exists(root)) PurgeTree(root, identity);
        Console.Error.WriteLine("ORIX_CLEANUP:ROOT_ACL_PURGED");
        IntPtr appPathPointer = IntPtr.Zero;
        int pathResult = GetAppContainerFolderPath(sid, out appPathPointer);
        if (pathResult == 0 && appPathPointer != IntPtr.Zero) {
          string appFolder;
          try { appFolder = Marshal.PtrToStringUni(appPathPointer); }
          finally { Marshal.FreeCoTaskMem(appPathPointer); }
          if (!String.IsNullOrEmpty(appFolder) && Directory.Exists(appFolder))
            DeleteTreeNoFollow(appFolder);
        }
        Console.Error.WriteLine("ORIX_CLEANUP:APP_FOLDER_PURGED");
        int deleteResult = DeleteAppContainerProfile(profileName);
        Console.Error.WriteLine("ORIX_CLEANUP:PROFILE_DELETED");
        if (deleteResult != 0 && unchecked((uint)deleteResult) != 0x80070002)
          Marshal.ThrowExceptionForHR(deleteResult);
      } finally {
        if (sid != IntPtr.Zero) FreeSid(sid);
      }
    }
  }
}
