using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;


namespace DInvoke.ManualMap
{
    public class Map
    {
        public static Data.PE.PE_MANUAL_MAP MapModuleFromDisk(string DLLPath)
        {
            if (!File.Exists(DLLPath))
            {
                throw new InvalidOperationException("Filepath not found.");
            }
            Data.Native.UNICODE_STRING ObjectName = new Data.Native.UNICODE_STRING();
            DynamicInvoke.Native.RtlInitUnicodeString(ref ObjectName, (@"\??\" + DLLPath));
            IntPtr pObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(ObjectName));
            Marshal.StructureToPtr(ObjectName, pObjectName, true);

            Data.Native.OBJECT_ATTRIBUTES objectAttributes = new Data.Native.OBJECT_ATTRIBUTES();
            objectAttributes.Length = Marshal.SizeOf(objectAttributes);
            objectAttributes.ObjectName = pObjectName;
            objectAttributes.Attributes = 0x40;

            Data.Native.IO_STATUS_BLOCK ioStatusBlock = new Data.Native.IO_STATUS_BLOCK();

            IntPtr hFile = IntPtr.Zero;
            DynamicInvoke.Native.NtOpenFile(
                ref hFile,
                Data.Win32.Kernel32.FileAccessFlags.FILE_READ_DATA |
                Data.Win32.Kernel32.FileAccessFlags.FILE_EXECUTE |
                Data.Win32.Kernel32.FileAccessFlags.FILE_READ_ATTRIBUTES |
                Data.Win32.Kernel32.FileAccessFlags.SYNCHRONIZE,
                ref objectAttributes, ref ioStatusBlock,
                Data.Win32.Kernel32.FileShareFlags.FILE_SHARE_READ |
                Data.Win32.Kernel32.FileShareFlags.FILE_SHARE_DELETE,
                Data.Win32.Kernel32.FileOpenFlags.FILE_SYNCHRONOUS_IO_NONALERT |
                Data.Win32.Kernel32.FileOpenFlags.FILE_NON_DIRECTORY_FILE
            );
            IntPtr hSection = IntPtr.Zero;
            ulong MaxSize = 0;
            Data.Native.NTSTATUS ret = DynamicInvoke.Native.NtCreateSection(
                ref hSection,
                (UInt32)Data.Win32.WinNT.ACCESS_MASK.SECTION_ALL_ACCESS,
                IntPtr.Zero,
                ref MaxSize,
                Data.Win32.WinNT.PAGE_READONLY,
                Data.Win32.WinNT.SEC_IMAGE,
                hFile
            );
            IntPtr pBaseAddress = IntPtr.Zero;
            DynamicInvoke.Native.NtMapViewOfSection(
                hSection, (IntPtr)(-1), ref pBaseAddress,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                ref MaxSize, 0x2, 0x0,
                Data.Win32.WinNT.PAGE_READWRITE
            );
            Data.PE.PE_MANUAL_MAP SecMapObject = new Data.PE.PE_MANUAL_MAP
            {
                PEINFO = DynamicInvoke.Generic.GetPeMetaData(pBaseAddress),
                ModuleBase = pBaseAddress
            };

            return SecMapObject;
        }
        public static IntPtr AllocateFileToMemory(string FilePath)
        {
            if (!File.Exists(FilePath))
            {
                throw new InvalidOperationException("no");
            }

            byte[] bFile = File.ReadAllBytes(FilePath);
            return AllocateBytesToMemory(bFile);
        }
        public static IntPtr AllocateBytesToMemory(byte[] FileByteArray)
        {
            IntPtr pFile = Marshal.AllocHGlobal(FileByteArray.Length);
            Marshal.Copy(FileByteArray, 0, pFile, FileByteArray.Length);
            return pFile;
        }
        public static void RelocateModule(Data.PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            Data.PE.IMAGE_DATA_DIRECTORY idd = PEINFO.Is32Bit ? PEINFO.OptHeader32.BaseRelocationTable : PEINFO.OptHeader64.BaseRelocationTable;
            Int64 ImageDelta = PEINFO.Is32Bit ? (Int64)((UInt64)ModuleMemoryBase - PEINFO.OptHeader32.ImageBase) :
                                                (Int64)((UInt64)ModuleMemoryBase - PEINFO.OptHeader64.ImageBase);
            IntPtr pRelocTable = (IntPtr)((UInt64)ModuleMemoryBase + idd.VirtualAddress);
            Int32 nextRelocTableBlock = -1;
            while (nextRelocTableBlock != 0)
            {
                Data.PE.IMAGE_BASE_RELOCATION ibr = new Data.PE.IMAGE_BASE_RELOCATION();
                ibr = (Data.PE.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(pRelocTable, typeof(Data.PE.IMAGE_BASE_RELOCATION));

                Int64 RelocCount = ((ibr.SizeOfBlock - Marshal.SizeOf(ibr)) / 2);
                for (int i = 0; i < RelocCount; i++)
                {
                    IntPtr pRelocEntry = (IntPtr)((UInt64)pRelocTable + (UInt64)Marshal.SizeOf(ibr) + (UInt64)(i * 2));
                    UInt16 RelocValue = (UInt16)Marshal.ReadInt16(pRelocEntry);
                    UInt16 RelocType = (UInt16)(RelocValue >> 12);
                    UInt16 RelocPatch = (UInt16)(RelocValue & 0xfff);
                    if (RelocType != 0)
                    {
                        try
                        {
                            IntPtr pPatch = (IntPtr)((UInt64)ModuleMemoryBase + ibr.VirtualAdress + RelocPatch);
                            if (RelocType == 0x3)
                            {
                                Int32 OriginalPtr = Marshal.ReadInt32(pPatch);
                                Marshal.WriteInt32(pPatch, (OriginalPtr + (Int32)ImageDelta));
                            }
                            else
                            {
                                Int64 OriginalPtr = Marshal.ReadInt64(pPatch);
                                Marshal.WriteInt64(pPatch, (OriginalPtr + ImageDelta));
                            }
                        }
                        catch
                        {
                            throw new InvalidOperationException("Memory access violation.");
                        }
                    }
                }
                pRelocTable = (IntPtr)((UInt64)pRelocTable + ibr.SizeOfBlock);
                nextRelocTableBlock = Marshal.ReadInt32(pRelocTable);
            }
        }
        public static void RewriteModuleIAT(Data.PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            Data.PE.IMAGE_DATA_DIRECTORY idd = PEINFO.Is32Bit ? PEINFO.OptHeader32.ImportTable : PEINFO.OptHeader64.ImportTable;
            if (idd.VirtualAddress == 0)
            {
                return;
            }
            IntPtr pImportTable = (IntPtr)((UInt64)ModuleMemoryBase + idd.VirtualAddress);
            Data.Native.OSVERSIONINFOEX OSVersion = new Data.Native.OSVERSIONINFOEX();
            DynamicInvoke.Native.RtlGetVersion(ref OSVersion);
            Dictionary<string, string> ApiSetDict = new Dictionary<string, string>();
            if (OSVersion.MajorVersion >= 10)
            {
                ApiSetDict = DynamicInvoke.Generic.GetApiSetMapping();
            }
            int counter = 0;
            Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR iid = new Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR();
            iid = (Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                (IntPtr)((UInt64)pImportTable + (uint)(Marshal.SizeOf(iid) * counter)),
                typeof(Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)
            );
            while (iid.Name != 0)
            {
                string DllName = string.Empty;
                try
                {
                    DllName = Marshal.PtrToStringAnsi((IntPtr)((UInt64)ModuleMemoryBase + iid.Name));
                }
                catch { }
                if (DllName == string.Empty)
                {
                    throw new InvalidOperationException("no");
                }
                else
                {
                    if (OSVersion.MajorVersion >= 10 && (DllName.StartsWith("api-") || DllName.StartsWith("ext-")) &&
                        ApiSetDict.ContainsKey(DllName) && ApiSetDict[DllName].Length > 0)
                    {
                        DllName = ApiSetDict[DllName];
                    }
                    IntPtr hModule = DynamicInvoke.Generic.GetLoadedModuleAddress(DllName);
                    if (hModule == IntPtr.Zero)
                    {
                        hModule = DynamicInvoke.Generic.LoadModuleFromDisk(DllName);
                        if (hModule == IntPtr.Zero)
                        {
                            throw new FileNotFoundException(DllName + ", no");
                        }
                    }
                    if (PEINFO.Is32Bit)
                    {
                        Data.PE.IMAGE_THUNK_DATA32 oft_itd = new Data.PE.IMAGE_THUNK_DATA32();
                        for (int i = 0; true; i++)
                        {
                            oft_itd = (Data.PE.IMAGE_THUNK_DATA32)Marshal.PtrToStructure((IntPtr)((UInt64)ModuleMemoryBase + iid.OriginalFirstThunk + (UInt32)(i * (sizeof(UInt32)))), typeof(Data.PE.IMAGE_THUNK_DATA32));
                            IntPtr ft_itd = (IntPtr)((UInt64)ModuleMemoryBase + iid.FirstThunk + (UInt64)(i * (sizeof(UInt32))));
                            if (oft_itd.AddressOfData == 0)
                            {
                                break;
                            }

                            if (oft_itd.AddressOfData < 0x80000000)
                            {
                                IntPtr pImpByName = (IntPtr)((UInt64)ModuleMemoryBase + oft_itd.AddressOfData + sizeof(UInt16));
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = DynamicInvoke.Generic.GetNativeExportAddress(hModule, Marshal.PtrToStringAnsi(pImpByName));
                                Marshal.WriteInt32(ft_itd, pFunc.ToInt32());
                            }
                            else
                            {
                                ulong fOrdinal = oft_itd.AddressOfData & 0xFFFF;
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = DynamicInvoke.Generic.GetNativeExportAddress(hModule, (short)fOrdinal);
                                Marshal.WriteInt32(ft_itd, pFunc.ToInt32());
                            }
                        }
                    }
                    else
                    {
                        Data.PE.IMAGE_THUNK_DATA64 oft_itd = new Data.PE.IMAGE_THUNK_DATA64();
                        for (int i = 0; true; i++)
                        {
                            oft_itd = (Data.PE.IMAGE_THUNK_DATA64)Marshal.PtrToStructure((IntPtr)((UInt64)ModuleMemoryBase + iid.OriginalFirstThunk + (UInt64)(i * (sizeof(UInt64)))), typeof(Data.PE.IMAGE_THUNK_DATA64));
                            IntPtr ft_itd = (IntPtr)((UInt64)ModuleMemoryBase + iid.FirstThunk + (UInt64)(i * (sizeof(UInt64))));
                            if (oft_itd.AddressOfData == 0)
                            {
                                break;
                            }

                            if (oft_itd.AddressOfData < 0x8000000000000000)
                            {
                                IntPtr pImpByName = (IntPtr)((UInt64)ModuleMemoryBase + oft_itd.AddressOfData + sizeof(UInt16));
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = DynamicInvoke.Generic.GetNativeExportAddress(hModule, Marshal.PtrToStringAnsi(pImpByName));
                                Marshal.WriteInt64(ft_itd, pFunc.ToInt64());
                            }
                            else
                            {
                                ulong fOrdinal = oft_itd.AddressOfData & 0xFFFF;
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = DynamicInvoke.Generic.GetNativeExportAddress(hModule, (short)fOrdinal);
                                Marshal.WriteInt64(ft_itd, pFunc.ToInt64());
                            }
                        }
                    }
                    counter++;
                    iid = (Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                        (IntPtr)((UInt64)pImportTable + (uint)(Marshal.SizeOf(iid) * counter)),
                        typeof(Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)
                    );
                }
            }
        }
        public static void SetModuleSectionPermissions(Data.PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            IntPtr BaseOfCode = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.BaseOfCode : (IntPtr)PEINFO.OptHeader64.BaseOfCode;
            DynamicInvoke.Native.NtProtectVirtualMemory((IntPtr)(-1), ref ModuleMemoryBase, ref BaseOfCode, Data.Win32.WinNT.PAGE_READONLY);
            foreach (Data.PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                bool isRead = (ish.Characteristics & Data.PE.DataSectionFlags.MEM_READ) != 0;
                bool isWrite = (ish.Characteristics & Data.PE.DataSectionFlags.MEM_WRITE) != 0;
                bool isExecute = (ish.Characteristics & Data.PE.DataSectionFlags.MEM_EXECUTE) != 0;
                uint flNewProtect = 0;
                if (isRead & !isWrite & !isExecute)
                {
                    flNewProtect = Data.Win32.WinNT.PAGE_READONLY;
                }
                else if (isRead & isWrite & !isExecute)
                {
                    flNewProtect = Data.Win32.WinNT.PAGE_READWRITE;
                }
                else if (isRead & isWrite & isExecute)
                {
                    flNewProtect = Data.Win32.WinNT.PAGE_EXECUTE_READWRITE;
                }
                else if (isRead & !isWrite & isExecute)
                {
                    flNewProtect = Data.Win32.WinNT.PAGE_EXECUTE_READ;
                }
                else if (!isRead & !isWrite & isExecute)
                {
                    flNewProtect = Data.Win32.WinNT.PAGE_EXECUTE;
                }
                else
                {
                    throw new InvalidOperationException("Unknown section flag, " + ish.Characteristics);
                }
                IntPtr pVirtualSectionBase = (IntPtr)((UInt64)ModuleMemoryBase + ish.VirtualAddress);
                IntPtr ProtectSize = (IntPtr)ish.VirtualSize;
                DynamicInvoke.Native.NtProtectVirtualMemory((IntPtr)(-1), ref pVirtualSectionBase, ref ProtectSize, flNewProtect);
            }
        }
        public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(string ModulePath)
        {
            IntPtr pModule = AllocateFileToMemory(ModulePath);
            return MapModuleToMemory(pModule);
        }
        public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(byte[] Module)
        {
            IntPtr pModule = AllocateBytesToMemory(Module);
            return MapModuleToMemory(pModule);
        }
        public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(byte[] Module, IntPtr pImage)
        {
            IntPtr pModule = AllocateBytesToMemory(Module);

            return MapModuleToMemory(pModule, pImage);
        }
        public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(IntPtr pModule)
        {
            Data.PE.PE_META_DATA PEINFO = DynamicInvoke.Generic.GetPeMetaData(pModule);
            if ((PEINFO.Is32Bit && IntPtr.Size == 8) || (!PEINFO.Is32Bit && IntPtr.Size == 4))
            {
                Marshal.FreeHGlobal(pModule);
                throw new InvalidOperationException("The module architecture does not match the process architecture.");
            }
            IntPtr BaseAddress = IntPtr.Zero;
            IntPtr RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;
            IntPtr pImage = DynamicInvoke.Native.NtAllocateVirtualMemory(
                (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
                Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                Data.Win32.WinNT.PAGE_READWRITE
            );
            return MapModuleToMemory(pModule, pImage, PEINFO);
        }
        public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(IntPtr pModule, IntPtr pImage)
        {
            Data.PE.PE_META_DATA PEINFO = DynamicInvoke.Generic.GetPeMetaData(pModule);
            return MapModuleToMemory(pModule, pImage, PEINFO);
        }
        public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(IntPtr pModule, IntPtr pImage, Data.PE.PE_META_DATA PEINFO)
        {
            if ((PEINFO.Is32Bit && IntPtr.Size == 8) || (!PEINFO.Is32Bit && IntPtr.Size == 4))
            {
                Marshal.FreeHGlobal(pModule);
                throw new InvalidOperationException("The module architecture does not match the process architecture.");
            }
            UInt32 SizeOfHeaders = PEINFO.Is32Bit ? PEINFO.OptHeader32.SizeOfHeaders : PEINFO.OptHeader64.SizeOfHeaders;
            UInt32 BytesWritten = DynamicInvoke.Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, SizeOfHeaders);
            foreach (Data.PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                IntPtr pVirtualSectionBase = (IntPtr)((UInt64)pImage + ish.VirtualAddress);
                IntPtr pRawSectionBase = (IntPtr)((UInt64)pModule + ish.PointerToRawData);
                BytesWritten = DynamicInvoke.Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
                if (BytesWritten != ish.SizeOfRawData)
                {
                    throw new InvalidOperationException("fail to write to memory.");
                }
            }
            RelocateModule(PEINFO, pImage);
            RewriteModuleIAT(PEINFO, pImage);
            SetModuleSectionPermissions(PEINFO, pImage);
            Marshal.FreeHGlobal(pModule);
            Data.PE.PE_MANUAL_MAP ManMapObject = new Data.PE.PE_MANUAL_MAP
            {
                ModuleBase = pImage,
                PEINFO = PEINFO
            };

            return ManMapObject;
        }
        public static void FreeModule(Data.PE.PE_MANUAL_MAP PEMapped)
        {
            if (!string.IsNullOrEmpty(PEMapped.DecoyModule))
            {
                DynamicInvoke.Native.NtUnmapViewOfSection((IntPtr)(-1), PEMapped.ModuleBase);
            }
            else
            {
                Data.PE.PE_META_DATA PEINFO = PEMapped.PEINFO;
                IntPtr size = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;
                IntPtr pModule = PEMapped.ModuleBase;

                DynamicInvoke.Native.NtFreeVirtualMemory((IntPtr)(-1), ref pModule, ref size, Data.Win32.Kernel32.MEM_RELEASE);
            }
        }
    }
}
