/*
	MIT License
	Copyright (c) 2021 Kento Oki
	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:
	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/

#include "main.h"

#pragma warning(disable: 4047)
#pragma warning(disable: 4100)

NTSTATUS LookupProcessIdByProcessName(
	_In_ PCWSTR ProcessName,
	_Out_ PHANDLE UniqueProcessId)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PVOID Buffer;
	UNICODE_STRING ProcessNameUs;

	*UniqueProcessId = 0;

	Buffer = ExAllocatePool(NonPagedPool, 1024 * 1024);

	if (!Buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	PSYSTEM_PROCESS_INFORMATION ProcessInformation = 
		(PSYSTEM_PROCESS_INFORMATION)(Buffer);

	ntStatus = ZwQuerySystemInformation(
		SystemProcessInformation, ProcessInformation, 1024 * 1024, NULL);

	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePool(Buffer);
		return ntStatus;
	}

	RtlInitUnicodeString(&ProcessNameUs, ProcessName);

	for (;;)
	{
		if (RtlEqualUnicodeString(&ProcessInformation->ImageName, &ProcessNameUs, TRUE) == TRUE)
		{
			*UniqueProcessId = ProcessInformation->UniqueProcessId;

			ExFreePool(Buffer);
			return STATUS_SUCCESS;
		}
		else if (ProcessInformation->NextEntryOffset)
		{
			ProcessInformation = (PSYSTEM_PROCESS_INFORMATION)(
				(PUCHAR)ProcessInformation + ProcessInformation->NextEntryOffset);
		}
		else
		{
			break;
		}
	}

	ExFreePool(Buffer);

	return STATUS_NOT_FOUND;
}

NTSTATUS CopyProcessVirtualMemory(
	_In_ PEPROCESS Process,
	_Inout_ PVOID Destination,
	_Inout_ PVOID Source,
	_In_ SIZE_T Size)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	KAPC_STATE ApcState;

	// 1. Attach to the process
	//    Sets specified process's PML4 to the CR3
	KeStackAttachProcess((PRKPROCESS)Process, &ApcState);

	__try
	{
		// 2. Copy specified user-process's virtua memory to 
		//    the kernel's buffer
		RtlCopyMemory(Destination, Source, Size);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("[*] Exception occured: %lX\n", GetExceptionCode());
		ntStatus = STATUS_UNSUCCESSFUL;
	}

	// 3. Detach from the process
	//    Restores previous APC state to the current thread
	KeUnstackDetachProcess(&ApcState);

	return ntStatus;
}

NTSTATUS CopyProcessVirtualMemory2(
	_In_ PEPROCESS Process,
	_Inout_ PVOID Destination,
	_Inout_ PVOID Source,
	_In_ SIZE_T Size)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	KAPC_STATE ApcState;
	PHYSICAL_ADDRESS SourcePhysicalAddress;
	PVOID MappedIoSpace;
	PVOID MappedKva;
	PMDL Mdl;
	BOOLEAN ShouldUseSourceAsUserVa;

	ShouldUseSourceAsUserVa = Source <= MmHighestUserAddress ? TRUE : FALSE;

	// 1. Attach to the process
	//    Sets specified process's PML4 to the CR3
	KeStackAttachProcess((PRKPROCESS)Process, &ApcState);

	// 2. Get the physical address corresponding to the user virtual memory
	SourcePhysicalAddress = MmGetPhysicalAddress(
		ShouldUseSourceAsUserVa == TRUE ? Source : Destination);

	// 3. Detach from the process
	//    Restores previous APC state to the current thread
	KeUnstackDetachProcess(&ApcState);

	if (!SourcePhysicalAddress.QuadPart)
	{
		return STATUS_INVALID_ADDRESS;
	}

	DbgPrint("[+] Source Physical Address: 0x%llX\n", SourcePhysicalAddress.QuadPart);

	// 4. Map an IO space for MDL
	MappedIoSpace = MmMapIoSpace(SourcePhysicalAddress, Size, MmNonCached);

	if (!MappedIoSpace)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	DbgPrint("[+] Physical Address 0x%llX is mapped to IO space 0x%p\n", 
		SourcePhysicalAddress, MappedIoSpace);

	// 5. Allocate MDL
	Mdl = IoAllocateMdl(MappedIoSpace, (ULONG)Size, FALSE, FALSE, NULL);

	if (!Mdl)
	{
		DbgPrint("[!] Failed to allocate MDL\n");
		MmUnmapIoSpace(MappedIoSpace, Size);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	// 6. Build MDL for non-paged pool
	MmBuildMdlForNonPagedPool(Mdl);

	// 7. Map to the KVA
	MappedKva = MmMapLockedPagesSpecifyCache(
		Mdl,
		KernelMode,
		MmNonCached,
		NULL,
		FALSE,
		NormalPagePriority);

	if (!MappedKva)
	{
		DbgPrint("[!] Failed to map physical pages\n");
		MmUnmapIoSpace(MappedIoSpace, Size);
		IoFreeMdl(Mdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	DbgPrint("[+] Mapped to KVA 0x%p\n", MappedKva);

	// 8. copy memory
	RtlCopyMemory(
		ShouldUseSourceAsUserVa == TRUE ? Destination : MappedKva,
		ShouldUseSourceAsUserVa == TRUE ? MappedKva : Destination,
		Size);

	MmUnmapIoSpace(MappedIoSpace, Size);
	MmUnmapLockedPages(MappedKva, Mdl);
	IoFreeMdl(Mdl);

	return ntStatus;
}

NTSTATUS DispatchDriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS ntStatus = STATUS_SUCCESS;
	HANDLE TargetProcessId;
	PEPROCESS Process;
	PVOID ProcessSectionBase;
	USHORT PEMZ = NULL;

	DbgPrint("[~] Looking for process \"notepad.exe\"");

	if (!NT_SUCCESS(ntStatus = LookupProcessIdByProcessName(L"notepad.exe", &TargetProcessId)))
	{
		DbgPrint("[!] Failed to lookup process id\n");
		return ntStatus;
	}

	// Possible overflow but ignore for this case
	DbgPrint("[+] Target ProcessId: %d\n", TargetProcessId);

	if (!NT_SUCCESS(ntStatus = PsLookupProcessByProcessId(TargetProcessId, &Process)))
	{
		DbgPrint("[!] Failed to lookup process\n");
		return ntStatus;
	}

	// SectionBase should contain 0x5A4D (MZ) at start for valid PE
	ProcessSectionBase = PsGetProcessSectionBaseAddress(Process);

	DbgPrint("[+] PEPROCESS @ 0x%p\n", Process);
	DbgPrint("[+] ProcessSectionBase: 0x%p\n", ProcessSectionBase);

	if (!NT_SUCCESS(ntStatus = CopyProcessVirtualMemory(
		Process, &PEMZ, ProcessSectionBase, sizeof(USHORT))))
	{
		DbgPrint("[!] Failed to copy process memory (1)\n");
		return ntStatus;
	}

	DbgPrint("[+] Success (1): 0x%04X\n", PEMZ);

	// Zero out the memory in order to perform again
	RtlZeroMemory(&PEMZ, sizeof(PEMZ));

	if (!NT_SUCCESS(ntStatus = CopyProcessVirtualMemory2(
		Process, &PEMZ, ProcessSectionBase, sizeof(USHORT))))
	{
		DbgPrint("[!] Failed to copy process memory (2)\n");
		return ntStatus;
	}

	DbgPrint("[+] Success (2): 0x%04X\n", PEMZ);

	return ntStatus;
}

VOID
DriverUnload(
	IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	return;
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	DriverObject->DriverUnload = DriverUnload;

	ntStatus = DispatchDriverEntry(DriverObject, RegistryPath);

	return ntStatus;
}