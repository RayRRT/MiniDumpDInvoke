using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

using Data = DInvoke.Data;
using Utilities = DInvoke.Utilities;
using DynamicInvoke = DInvoke.DynamicInvoke;

namespace DInvoke.ManualMap
{
    public class Overload
    {
        public static string FindDecoyModule(long MinSize, bool LegitSigned = true)
        {
            string SystemDirectoryPath = Environment.GetEnvironmentVariable("WINDIR") + Path.DirectorySeparatorChar + "System32";
            List<string> files = new List<string>(Directory.GetFiles(SystemDirectoryPath, "*.dll"));
            foreach (ProcessModule Module in Process.GetCurrentProcess().Modules)
            {
                if (files.Any(s => s.Equals(Module.FileName, StringComparison.OrdinalIgnoreCase)))
                {
                    files.RemoveAt(files.FindIndex(x => x.Equals(Module.FileName, StringComparison.OrdinalIgnoreCase)));
                }
            }

            Random r = new Random();
            List<int> candidates = new List<int>();
            while (candidates.Count != files.Count)
            {
                int rInt = r.Next(0, files.Count);
                string currentCandidate = files[rInt];
                if (candidates.Contains(rInt) == false &&
                    new FileInfo(currentCandidate).Length >= MinSize)
                {
                    if (LegitSigned == true)
                    {
                        if (Utilities.Utilities.FileHasValidSignature(currentCandidate) == true)
                            return currentCandidate;
                        else
                            candidates.Add(rInt);
                    }
                    else
                        return currentCandidate;
                }
                candidates.Add(rInt);
            }
            return string.Empty;
        }
        public static Data.PE.PE_MANUAL_MAP OverloadModule(string PayloadPath, string DecoyModulePath = null, bool LegitSigned = true)
        {
            if (!File.Exists(PayloadPath))
            {
                throw new InvalidOperationException("");
            }
            byte[] Payload = File.ReadAllBytes(PayloadPath);

            return OverloadModule(Payload, DecoyModulePath, LegitSigned);
        }
        public static Data.PE.PE_MANUAL_MAP OverloadModule(byte[] Payload, string DecoyModulePath = null, bool LegitSigned = true)
        {
            if (!string.IsNullOrEmpty(DecoyModulePath))
            {
                if (!File.Exists(DecoyModulePath))
                {
                    throw new InvalidOperationException("");
                }
                byte[] DecoyFileBytes = File.ReadAllBytes(DecoyModulePath);
                if (DecoyFileBytes.Length < Payload.Length)
                {
                    throw new InvalidOperationException("");
                }
            }
            else
            {
                DecoyModulePath = FindDecoyModule(Payload.Length);
                if (string.IsNullOrEmpty(DecoyModulePath))
                {
                    throw new InvalidOperationException("");
                }
            }
            Data.PE.PE_MANUAL_MAP DecoyMetaData = Map.MapModuleFromDisk(DecoyModulePath);
            IntPtr RegionSize = DecoyMetaData.PEINFO.Is32Bit ? (IntPtr)DecoyMetaData.PEINFO.OptHeader32.SizeOfImage : (IntPtr)DecoyMetaData.PEINFO.OptHeader64.SizeOfImage;
            DynamicInvoke.Native.NtProtectVirtualMemory((IntPtr)(-1), ref DecoyMetaData.ModuleBase, ref RegionSize, Data.Win32.WinNT.PAGE_READWRITE);
            DynamicInvoke.Native.RtlZeroMemory(DecoyMetaData.ModuleBase, (int)RegionSize);
            Data.PE.PE_MANUAL_MAP OverloadedModuleMetaData = Map.MapModuleToMemory(Payload, DecoyMetaData.ModuleBase);
            OverloadedModuleMetaData.DecoyModule = DecoyModulePath;

            return OverloadedModuleMetaData;
        }
    }
}
