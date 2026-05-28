// Managed shim for the `burnwall` .NET global tool.
//
// A .NET tool must have a managed entry point, but burnwall itself is a native
// Rust binary. This shim is that entry point: at runtime it picks the native
// binary matching the current OS/architecture (RID) from the binaries bundled
// in the package, makes it executable, runs it with the same arguments, and
// returns its exit code. It does no work of its own.

using System.Diagnostics;
using System.Runtime.InteropServices;

static string CurrentRid()
{
    string os =
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "win" :
        RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "osx" :
        RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" :
        throw new PlatformNotSupportedException("burnwall: unsupported operating system");

    string arch = RuntimeInformation.ProcessArchitecture switch
    {
        Architecture.X64 => "x64",
        Architecture.Arm64 => "arm64",
        var other => throw new PlatformNotSupportedException(
            $"burnwall: unsupported architecture {other}"),
    };

    return $"{os}-{arch}";
}

string rid = CurrentRid();
bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
string exeName = isWindows ? "burnwall.exe" : "burnwall";
string nativePath = Path.Combine(AppContext.BaseDirectory, "native", rid, exeName);

if (!File.Exists(nativePath))
{
    Console.Error.WriteLine(
        $"burnwall: no bundled binary for this platform ({rid}). Expected at: {nativePath}");
    return 70; // EX_SOFTWARE
}

if (!isWindows)
{
    // Files unpacked from a NuGet package do not keep the executable bit.
    try
    {
        File.SetUnixFileMode(
            nativePath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
            UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
    }
    catch
    {
        // Best effort: if it is already executable this will be a no-op.
    }
}

var startInfo = new ProcessStartInfo(nativePath) { UseShellExecute = false };
foreach (string arg in args)
{
    startInfo.ArgumentList.Add(arg);
}

using var process = Process.Start(startInfo);
if (process is null)
{
    Console.Error.WriteLine($"burnwall: failed to launch {nativePath}");
    return 70;
}

process.WaitForExit();
return process.ExitCode;
