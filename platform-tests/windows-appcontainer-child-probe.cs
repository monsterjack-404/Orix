using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;

namespace OrixWindowsSandbox.Tests {
  internal static class AppContainerChildProbe {
    private static int Main(string[] args) {
      if (args == null || args.Length != 2)
        return 64;

      string mode = args[0];
      string markerPath = args[1];
      if (String.IsNullOrWhiteSpace(markerPath) || !Path.IsPathRooted(markerPath))
        return 64;

      if (String.Equals(mode, "child", StringComparison.Ordinal)) {
        int sequence = 0;
        while (true) {
          File.WriteAllText(markerPath, (++sequence).ToString());
          Thread.Sleep(20);
        }
      }

      if (!String.Equals(mode, "parent", StringComparison.Ordinal))
        return 64;

      // This test intentionally uses the Windows/.NET process API, not Node's
      // bundled libuv. It verifies that an AppContainer process can create a
      // descendant which remains inside the same non-breakaway Job Object.
      string executable = Assembly.GetExecutingAssembly().Location;
      ProcessStartInfo start = new ProcessStartInfo();
      start.FileName = executable;
      start.Arguments = "child \\"" + markerPath + "\\\"";
      start.WorkingDirectory = Environment.CurrentDirectory;
      start.UseShellExecute = false;
      start.CreateNoWindow = true;
      start.WindowStyle = ProcessWindowStyle.Hidden;

      Process child = null;
      try {
        child = Process.Start(start);
        if (child == null)
          return 70;

        DateTime deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline) {
          if (File.Exists(markerPath)) {
            Console.Out.Write("provider-descendant-started");
            Console.Out.Flush();
            return 0;
          }
          if (child.HasExited)
            return 71;
          Thread.Sleep(20);
        }
        return 72;
      } catch (Exception error) {
        Console.Error.WriteLine("native descendant launch failed: " + error.GetType().Name + ":" + error.Message);
        return 73;
      }
      // The outer ORIX native launcher owns and terminates the provider Job
      // Object after this leader exits; never detach or kill the child here.
    }


  }
}
