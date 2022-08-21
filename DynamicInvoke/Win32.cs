// Author: Ryan Cobb (@cobbr_io), The Wover (@TheRealWover)

using System;
using System.Runtime.InteropServices;

namespace DInvoke.DynamicInvoke
{
    public static class Win32
    {
        public static IntPtr OpenProcess(Data.Win32.Kernel32.ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId)
        {
            object[] funcargs =
            {
                dwDesiredAccess, bInheritHandle, dwProcessId
            };

            return (IntPtr)Generic.DynamicAPIInvoke(@"kernel32.dll", @"OpenProcess",
                typeof(Delegates.OpenProcess), ref funcargs);
        }

        public static IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            ref IntPtr lpThreadId)
        {
            object[] funcargs =
            {
                hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId
            };

            IntPtr retValue = (IntPtr)Generic.DynamicAPIInvoke(@"kernel32.dll", @"CreateRemoteThread",
                typeof(Delegates.CreateRemoteThread), ref funcargs);
            lpThreadId = (IntPtr)funcargs[6];

            return retValue;
        }
        public static bool IsWow64Process(IntPtr hProcess, ref bool lpSystemInfo)
        {
            object[] funcargs =
            {
                hProcess, lpSystemInfo
            };

            bool retVal = (bool)Generic.DynamicAPIInvoke(@"kernel32.dll", @"IsWow64Process", typeof(Delegates.IsWow64Process), ref funcargs);

            lpSystemInfo = (bool) funcargs[1];
            return retVal;
        }

        public static class Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr CreateRemoteThread(IntPtr hProcess,
                IntPtr lpThreadAttributes,
                uint dwStackSize,
                IntPtr lpStartAddress,
                IntPtr lpParameter,
                uint dwCreationFlags,
                out IntPtr lpThreadId);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate IntPtr OpenProcess(
                Data.Win32.Kernel32.ProcessAccessFlags dwDesiredAccess,
                bool bInheritHandle,
                UInt32 dwProcessId
            );

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool IsWow64Process(
                IntPtr hProcess, ref bool lpSystemInfo
            );
        }
    }
}
