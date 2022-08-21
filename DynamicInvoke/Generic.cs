// Author: Ryan Cobb (@cobbr_io)

using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using ManualMap = DInvoke.ManualMap;

namespace DInvoke.DynamicInvoke
{
    public class Generic
    {
        public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
        {
            IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
            return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
        }
        public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
        {
            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
            return funcDelegate.DynamicInvoke(Parameters);
        }
        public static IntPtr LoadModuleFromDisk(string DLLPath)
        {
            Data.Native.UNICODE_STRING uModuleName = new Data.Native.UNICODE_STRING();
            Native.RtlInitUnicodeString(ref uModuleName, DLLPath);

            IntPtr hModule = IntPtr.Zero;
            Data.Native.NTSTATUS CallResult = Native.LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
            if (CallResult != Data.Native.NTSTATUS.Success || hModule == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            return hModule;
        }
        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero && CanLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(DLLName);
                if (hModule == IntPtr.Zero)
                {
                    throw new FileNotFoundException(DLLName + ",");
                }
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ",");
            }

            return GetExportAddress(hModule, FunctionName);
        }
        public static IntPtr GetLibraryAddress(string DLLName, short Ordinal, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero && CanLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(DLLName);
                if (hModule == IntPtr.Zero)
                {
                    throw new FileNotFoundException(DLLName + ", ");
                }
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", ");
            }

            return GetExportAddress(hModule, Ordinal);
        }
        public static IntPtr GetLibraryAddress(string DLLName, string FunctionHash, long Key, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero && CanLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(DLLName);
                if (hModule == IntPtr.Zero)
                {
                    throw new FileNotFoundException(DLLName + ", ");
                }
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", ");
            }

            return GetExportAddress(hModule, FunctionHash, Key);
        }
        public static IntPtr GetLoadedModuleAddress(string DLLName)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {
                    return Mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }
        public static IntPtr GetPebLdrModuleEntry(string DLLName)
        {
            Data.Native.PROCESS_BASIC_INFORMATION pbi = Native.NtQueryInformationProcessBasicInformation((IntPtr)(-1));
            bool Is32Bit = false;
            UInt32 LdrDataOffset = 0;
            UInt32 InLoadOrderModuleListOffset = 0;
            if (IntPtr.Size == 4)
            {
                Is32Bit = true;
                LdrDataOffset = 0xc;
                InLoadOrderModuleListOffset = 0xC;
            }
            else
            {
                LdrDataOffset = 0x18;
                InLoadOrderModuleListOffset = 0x10;
            }
            IntPtr PEB_LDR_DATA = Marshal.ReadIntPtr((IntPtr)((UInt64)pbi.PebBaseAddress + LdrDataOffset));
            IntPtr pInLoadOrderModuleList = (IntPtr)((UInt64)PEB_LDR_DATA + InLoadOrderModuleListOffset);
            Data.Native.LIST_ENTRY le = (Data.Native.LIST_ENTRY)Marshal.PtrToStructure(pInLoadOrderModuleList, typeof(Data.Native.LIST_ENTRY));
            IntPtr flink = le.Flink;
            IntPtr hModule = IntPtr.Zero;
            Data.PE.LDR_DATA_TABLE_ENTRY dte = (Data.PE.LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(Data.PE.LDR_DATA_TABLE_ENTRY));
            while (dte.InLoadOrderLinks.Flink != le.Blink)
            {
                if (Marshal.PtrToStringUni(dte.FullDllName.Buffer).EndsWith(DLLName, StringComparison.OrdinalIgnoreCase))
                {
                    hModule = dte.DllBase;
                }
                flink = dte.InLoadOrderLinks.Flink;
                dte = (Data.PE.LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(Data.PE.LDR_DATA_TABLE_ENTRY));
            }

            return hModule;
        }
        public static string GetAPIHash(string APIName, long Key)
        {
            byte[] data = Encoding.UTF8.GetBytes(APIName.ToLower());
            byte[] kbytes = BitConverter.GetBytes(Key);

            using (HMACMD5 hmac = new HMACMD5(kbytes))
            {
                byte[] bHash = hmac.ComputeHash(data);
                return BitConverter.ToString(bHash).Replace("-", "");
            }
        }
        public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                throw new InvalidOperationException("");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                throw new MissingMethodException(ExportName + ",");
            }
            return FunctionPtr;
        }
        public static IntPtr GetExportAddress(IntPtr ModuleBase, short Ordinal)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));
                for (int i = 0; i < NumberOfNames; i++)
                {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    if (FunctionOrdinal == Ordinal)
                    {
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                throw new InvalidOperationException("");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                throw new MissingMethodException(Ordinal + ", ");
            }
            return FunctionPtr;
        }
        public static IntPtr GetExportAddress(IntPtr ModuleBase, string FunctionHash, long Key)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (GetAPIHash(FunctionName, Key).Equals(FunctionHash, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                throw new InvalidOperationException("");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                throw new MissingMethodException(FunctionHash + ", ");
            }
            return FunctionPtr;
        }
        public static IntPtr GetNativeExportAddress(IntPtr ModuleBase, string ExportName)
        {
            Data.Native.ANSI_STRING aFunc = new Data.Native.ANSI_STRING
            {
                Length = (ushort)ExportName.Length,
                MaximumLength = (ushort)(ExportName.Length + 2),
                Buffer = Marshal.StringToCoTaskMemAnsi(ExportName)
            };

            IntPtr pAFunc = Marshal.AllocHGlobal(Marshal.SizeOf(aFunc));
            Marshal.StructureToPtr(aFunc, pAFunc, true);

            IntPtr pFuncAddr = IntPtr.Zero;
            Native.LdrGetProcedureAddress(ModuleBase, pAFunc, IntPtr.Zero, ref pFuncAddr);

            Marshal.FreeHGlobal(pAFunc);

            return pFuncAddr;
        }
        public static IntPtr GetNativeExportAddress(IntPtr ModuleBase, short Ordinal)
        {
            IntPtr pFuncAddr = IntPtr.Zero;
            IntPtr pOrd = (IntPtr)Ordinal;

            Native.LdrGetProcedureAddress(ModuleBase, IntPtr.Zero, pOrd, ref pFuncAddr);

            return pFuncAddr;
        }
        public static Data.PE.PE_META_DATA GetPeMetaData(IntPtr pModule)
        {
            Data.PE.PE_META_DATA PeMetaData = new Data.PE.PE_META_DATA();
            try
            {
                UInt32 e_lfanew = (UInt32)Marshal.ReadInt32((IntPtr)((UInt64)pModule + 0x3c));
                PeMetaData.Pe = (UInt32)Marshal.ReadInt32((IntPtr)((UInt64)pModule + e_lfanew));
                if (PeMetaData.Pe != 0x4550)
                {
                    throw new InvalidOperationException("");
                }
                PeMetaData.ImageFileHeader = (Data.PE.IMAGE_FILE_HEADER)Marshal.PtrToStructure((IntPtr)((UInt64)pModule + e_lfanew + 0x4), typeof(Data.PE.IMAGE_FILE_HEADER));
                IntPtr OptHeader = (IntPtr)((UInt64)pModule + e_lfanew + 0x18);
                UInt16 PEArch = (UInt16)Marshal.ReadInt16(OptHeader);
                if (PEArch == 0x010b)
                {
                    PeMetaData.Is32Bit = true;
                    PeMetaData.OptHeader32 = (Data.PE.IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(OptHeader, typeof(Data.PE.IMAGE_OPTIONAL_HEADER32));
                }
                else if (PEArch == 0x020b)
                {
                    PeMetaData.Is32Bit = false;
                    PeMetaData.OptHeader64 = (Data.PE.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(OptHeader, typeof(Data.PE.IMAGE_OPTIONAL_HEADER64));
                } else
                {
                    throw new InvalidOperationException("");
                }
                Data.PE.IMAGE_SECTION_HEADER[] SectionArray = new Data.PE.IMAGE_SECTION_HEADER[PeMetaData.ImageFileHeader.NumberOfSections];
                for (int i = 0; i < PeMetaData.ImageFileHeader.NumberOfSections; i++)
                {
                    IntPtr SectionPtr = (IntPtr)((UInt64)OptHeader + PeMetaData.ImageFileHeader.SizeOfOptionalHeader + (UInt32)(i * 0x28));
                    SectionArray[i] = (Data.PE.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(SectionPtr, typeof(Data.PE.IMAGE_SECTION_HEADER));
                }
                PeMetaData.Sections = SectionArray;
            }
            catch
            {
                throw new InvalidOperationException("");
            }
            return PeMetaData;
        }
        public static Dictionary<string, string> GetApiSetMapping()
        {
            Data.Native.PROCESS_BASIC_INFORMATION pbi = Native.NtQueryInformationProcessBasicInformation((IntPtr)(-1));
            UInt32 ApiSetMapOffset = IntPtr.Size == 4 ? (UInt32)0x38 : 0x68;
            Dictionary<string, string> ApiSetDict = new Dictionary<string, string>();

            IntPtr pApiSetNamespace = Marshal.ReadIntPtr((IntPtr)((UInt64)pbi.PebBaseAddress + ApiSetMapOffset));
            Data.PE.ApiSetNamespace Namespace = (Data.PE.ApiSetNamespace)Marshal.PtrToStructure(pApiSetNamespace, typeof(Data.PE.ApiSetNamespace));
            for (var i = 0; i < Namespace.Count; i++)
            {
                Data.PE.ApiSetNamespaceEntry SetEntry = new Data.PE.ApiSetNamespaceEntry();
                SetEntry = (Data.PE.ApiSetNamespaceEntry)Marshal.PtrToStructure((IntPtr)((UInt64)pApiSetNamespace + (UInt64)Namespace.EntryOffset + (UInt64)(i * Marshal.SizeOf(SetEntry))), typeof(Data.PE.ApiSetNamespaceEntry));
                string ApiSetEntryName = Marshal.PtrToStringUni((IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetEntry.NameOffset), SetEntry.NameLength/2) + ".dll";

                Data.PE.ApiSetValueEntry SetValue = new Data.PE.ApiSetValueEntry();
                SetValue = (Data.PE.ApiSetValueEntry)Marshal.PtrToStructure((IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetEntry.ValueOffset), typeof(Data.PE.ApiSetValueEntry));
                string ApiSetValue = string.Empty;
                if (SetValue.ValueCount != 0)
                {
                    ApiSetValue = Marshal.PtrToStringUni((IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetValue.ValueOffset), SetValue.ValueCount/2);
                }
                ApiSetDict.Add(ApiSetEntryName, ApiSetValue);
            }
            return ApiSetDict;
        }
        public static void CallMappedPEModule(Data.PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            IntPtr hRemoteThread = IntPtr.Zero;
            IntPtr lpStartAddress = PEINFO.Is32Bit ? (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader32.AddressOfEntryPoint) :
                                                     (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader64.AddressOfEntryPoint);

            Native.NtCreateThreadEx(
                ref hRemoteThread,
                Data.Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL,
                IntPtr.Zero, (IntPtr)(-1),
                lpStartAddress, IntPtr.Zero,
                false, 0, 0, 0, IntPtr.Zero
            );
        }
        public static void CallMappedDLLModule(Data.PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            IntPtr lpEntryPoint = PEINFO.Is32Bit ? (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader32.AddressOfEntryPoint) :
                                                   (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader64.AddressOfEntryPoint);

            Data.PE.DllMain fDllMain = (Data.PE.DllMain)Marshal.GetDelegateForFunctionPointer(lpEntryPoint, typeof(Data.PE.DllMain));
            bool CallRes = fDllMain(ModuleMemoryBase, Data.PE.DLL_PROCESS_ATTACH, IntPtr.Zero);
            if (!CallRes)
            {
                throw new InvalidOperationException("");
            }
        }
        public static object CallMappedDLLModuleExport(Data.PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase, string ExportName, Type FunctionDelegateType, object[] Parameters, bool CallEntry = true)
        {
            if (CallEntry)
            {
                CallMappedDLLModule(PEINFO, ModuleMemoryBase);
            }
            IntPtr pFunc = GetExportAddress(ModuleMemoryBase, ExportName);
            return DynamicFunctionInvoke(pFunc, FunctionDelegateType, ref Parameters);
        }
        public static IntPtr GetSyscallStub(string FunctionName)
        {
            bool isWOW64 = Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            ProcessModule NativeModule = null;
            string NtdllPath = string.Empty;
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                {
                    NtdllPath = Mod.FileName;
                }

            }

            foreach (ProcessModule _ in Process.GetCurrentProcess().Modules)
            {
                if (_.FileName.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                {
                    NativeModule = _;
                    NtdllPath = NativeModule.FileName;
                }
            }
            IntPtr pModule = ManualMap.Map.AllocateFileToMemory(NtdllPath);
            Data.PE.PE_META_DATA PEINFO = GetPeMetaData(pModule);
            IntPtr BaseAddress = IntPtr.Zero;
            IntPtr RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;
            UInt32 SizeOfHeaders = PEINFO.Is32Bit ? PEINFO.OptHeader32.SizeOfHeaders : PEINFO.OptHeader64.SizeOfHeaders;

            IntPtr pImage = Native.NtAllocateVirtualMemory(
                (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
                Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                Data.Win32.WinNT.PAGE_READWRITE
            );
            UInt32 BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, SizeOfHeaders);
            foreach (Data.PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                IntPtr pVirtualSectionBase = (IntPtr)((UInt64)pImage + ish.VirtualAddress);
                IntPtr pRawSectionBase = (IntPtr)((UInt64)pModule + ish.PointerToRawData);
                BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
                if (BytesWritten != ish.SizeOfRawData)
                {
                    throw new InvalidOperationException("");
                }
            }
            IntPtr pFunc = GetExportAddress(pImage, FunctionName);
            if (pFunc == IntPtr.Zero)
            {
                throw new InvalidOperationException("");
            }
            BaseAddress = IntPtr.Zero;
            RegionSize = (IntPtr)0x50;
            IntPtr pCallStub = Native.NtAllocateVirtualMemory(
                (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
                Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                Data.Win32.WinNT.PAGE_READWRITE
            );
            BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pCallStub, pFunc, 0x50);
            if (BytesWritten != 0x50)
            {
                throw new InvalidOperationException("");
            }
            if (IntPtr.Size == 4 && isWOW64)
            {
                string w64 = "Wow" + "64" + "Tran" + "si" + "tion";
                IntPtr pNativeWow64Transition = GetExportAddress(NativeModule.BaseAddress, w64);
                byte bRetValue = Marshal.ReadByte(pCallStub, 13);
                Marshal.WriteByte(pCallStub, 5, 0xff);
                Marshal.WriteByte(pCallStub, 6, 0x15);
                Marshal.WriteInt32(pCallStub, 7, pNativeWow64Transition.ToInt32());
                Marshal.WriteByte(pCallStub, 11, 0xc2);
                Marshal.WriteByte(pCallStub, 12, bRetValue);
                Marshal.WriteByte(pCallStub, 13, 0x00);
                Marshal.WriteByte(pCallStub, 14, 0x90);
                Marshal.WriteByte(pCallStub, 15, 0x90);
            }
            Native.NtProtectVirtualMemory((IntPtr)(-1), ref pCallStub, ref RegionSize, Data.Win32.WinNT.PAGE_EXECUTE_READ);
            Marshal.FreeHGlobal(pModule);
            RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;

            Native.NtFreeVirtualMemory((IntPtr)(-1), ref pImage, ref RegionSize, Data.Win32.Kernel32.MEM_RELEASE);

            return pCallStub;
        }
    }
}