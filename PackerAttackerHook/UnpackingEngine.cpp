#include "UnpackingEngine.h"
#include "Memory.h"
#include "Logger.h"
#include "DebugStackTracer.h"

#include <fstream>
#include <sstream>
#include <assert.h>
#include <algorithm>
#include <ntstatus.h>

void loopme()
{
	__asm
	{
		start:
			nop
			nop
			nop
			jmp start
	}
}

UnpackingEngine* UnpackingEngine::instance = NULL;

bool _regionTracking= true;

UnpackingEngine::UnpackingEngine(void)
{
    this->hooks = new HookingEngine();
    this->lock = new SyncLock();
    this->hooksReady = false;
    this->inAllocationHook = false;
    this->bypassHooks = false;
	this->nestedHook= false;
	Logger::getInstance();
}


UnpackingEngine::~UnpackingEngine(void)
{
    delete this->hooks;
    delete this->lock;
}

void UnpackingEngine::initialize()
{
    auto sg = this->lock->enterWithScopeGuard();

    this->processID = GetCurrentProcessId();

    /* init logger */
    char logName[MAX_PATH];
    sprintf_s<MAX_PATH>(logName, "C:\\dumps\\[%d]_packer_attacker.log", this->processID);
    Logger::getInstance()->initialize(logName);

    Logger::getInstance()->write(LOG_INFO, "Starting hooking process...");

    /* get the current DEP state, then make sure DEP is on */
    DWORD depFlags;
    BOOL depCantChange;
    GetProcessDEPPolicy(GetCurrentProcess(), &depFlags, &depCantChange);
    this->simulateDisabledDEP = (depFlags & PROCESS_DEP_ENABLE) != PROCESS_DEP_ENABLE;

    if (this->simulateDisabledDEP && depCantChange)
         Logger::getInstance()->write(LOG_ERROR, "Cannot enable DEP for this process!");
    else
        SetProcessDEPPolicy(PROCESS_DEP_ENABLE);

    /* place hooks and track PE section */
    HOOK_GET_ORIG(this, "ntdll.dll", NtProtectVirtualMemory);
    HOOK_GET_ORIG(this, "ntdll.dll", NtWriteVirtualMemory);
    HOOK_GET_ORIG(this, "ntdll.dll", NtCreateThread);
    HOOK_GET_ORIG(this, "ntdll.dll", NtMapViewOfSection);
    HOOK_GET_ORIG(this, "ntdll.dll", NtResumeThread);
    HOOK_GET_ORIG(this, "ntdll.dll", NtDelayExecution);
    HOOK_GET_ORIG(this, "ntdll.dll", NtAllocateVirtualMemory);
	HOOK_GET_ORIG(this, "ntdll.dll", NtFreeVirtualMemory);
    HOOK_GET_ORIG(this, "Kernel32.dll", CreateProcessInternalW);

	Logger::getInstance()->write(LOG_INFO, "Finding original function addresses...");
	Logger::getInstance()->write(LOG_INFO, "NtProtectVirtualMemory= %08x", this->origNtProtectVirtualMemory);
	Logger::getInstance()->write(LOG_INFO, "NtWriteVirtualMemory= %08x", this->origNtWriteVirtualMemory);
	Logger::getInstance()->write(LOG_INFO, "NtCreateThread= %08x", this->origNtCreateThread);
	Logger::getInstance()->write(LOG_INFO, "NtMapViewOfSection= %08x", this->origNtMapViewOfSection);
	Logger::getInstance()->write(LOG_INFO, "NtResumeThread= %08x", this->origNtResumeThread);
	Logger::getInstance()->write(LOG_INFO, "NtDelayExecution= %08x", this->origNtDelayExecution);
	Logger::getInstance()->write(LOG_INFO, "NtAllocateVirtualMemory= %08x", this->origNtAllocateVirtualMemory);
	Logger::getInstance()->write(LOG_INFO, "NtFreeVirtualMemory= %08x", this->origNtFreeVirtualMemory);
	Logger::getInstance()->write(LOG_INFO, "CreateProcessInternalW= %08x", this->origCreateProcessInternalW);
    Logger::getInstance()->write(LOG_INFO, "Finished finding original function addresses... DONE");

    this->startTrackingPEMemoryBlocks();

    Logger::getInstance()->write(LOG_INFO, "Tracking PE memory blocks... DONE");

    this->hooks->doTransaction([=](){
        this->hooks->placeShallowExceptionHandlerHook(&UnpackingEngine::_onShallowException);
        this->hooks->placeDeepExceptionHandlerHook(&UnpackingEngine::_onDeepException);

		HOOK_SET(this, this->hooks, NtProtectVirtualMemory);
        HOOK_SET(this, this->hooks, NtMapViewOfSection);
        HOOK_SET(this, this->hooks, NtAllocateVirtualMemory);
		HOOK_SET(this, this->hooks, NtFreeVirtualMemory);

        HOOK_SET(this, this->hooks, NtWriteVirtualMemory);
        HOOK_SET(this, this->hooks, NtCreateThread);
        HOOK_SET(this, this->hooks, NtResumeThread);
        HOOK_SET(this, this->hooks, NtDelayExecution);
        HOOK_SET(this, this->hooks, CreateProcessInternalW);
    });

    Logger::getInstance()->write(LOG_INFO, "Placing hooks... DONE");
    Logger::getInstance()->write(LOG_INFO, "Hooks ready!");

    hooksReady = true;
}

void UnpackingEngine::uninitialize()
{
    auto sg = this->lock->enterWithScopeGuard();

    this->dumpRemoteMemoryBlocks();
    Logger::getInstance()->uninitialize();
}

void UnpackingEngine::startTrackingPEMemoryBlocks()
{
    auto mainModule = (BYTE*)GetModuleHandle(NULL);
    assert(mainModule);

    auto dosHeader = MakePointer<IMAGE_DOS_HEADER*, BYTE*>(mainModule, 0);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    auto ntHeaders = MakePointer<IMAGE_NT_HEADERS*, BYTE*>(mainModule, dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return;

    auto baseOfCode = MakePointer<DWORD, HMODULE>((HMODULE)mainModule, ntHeaders->OptionalHeader.BaseOfCode);
    auto baseOfData = MakePointer<DWORD, HMODULE>((HMODULE)mainModule, ntHeaders->OptionalHeader.BaseOfData);
    auto entryPoint = MakePointer<DWORD, HMODULE>((HMODULE)mainModule, ntHeaders->OptionalHeader.AddressOfEntryPoint);

    Logger::getInstance()->write(LOG_INFO, "PE HEADER SAYS\n\tModule: 0x%08x\n\tCode: 0x%08x\n\tData: 0x%08x\n\tEP: 0x%08x", mainModule, baseOfCode, baseOfData, entryPoint);
 

    bool eipAlreadyIgnored = false;
    auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++)
    {
        DWORD destination = MakePointer<DWORD, HMODULE>((HMODULE)mainModule, sectionHeader->VirtualAddress);
        DWORD size = sectionHeader->SizeOfRawData;
        if (size <= 0)
        {
            auto nextSection = sectionHeader; nextSection++;
            size = nextSection->VirtualAddress - sectionHeader->VirtualAddress;
        }

        PESections.push_back(std::make_pair(destination, destination + size));

		Logger::getInstance()->write(LOG_INFO, "PE section %s at 0x%08x to 0x%08x (char: 0x%08x)", sectionHeader->Name, destination, destination+size, sectionHeader->Characteristics);

		#ifdef NEW_TRACKER
        if (!CHECK_FLAG(sectionHeader->Characteristics, CHARACTERISTIC_WRITEABLE)) // || CHECK_FLAG(sectionHeader->Characteristics, CHARACTERISTIC_EXECUTABLE))
            continue; /* skip un-writeable sections */
		#else
        if (!CHECK_FLAG(sectionHeader->Characteristics, CHARACTERISTIC_WRITEABLE))
            continue; /* skip un-writeable sections */

        if (!CHECK_FLAG(sectionHeader->Characteristics, CHARACTERISTIC_EXECUTABLE))
            continue; /* skip non-executable sections */
		#endif



        ULONG oldProtection;
        auto ret = this->origNtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&destination, (PULONG)&size, PAGE_EXECUTE_READ, &oldProtection);
        if (ret != 0)
        {
            Logger::getInstance()->write(LOG_ERROR, "Failed to remove write bits from %s at 0x%08x (char: 0x%08x). GetLastError() == %d |  RET == 0x%08x", sectionHeader->Name, destination, sectionHeader->Characteristics, GetLastError(), ret);
            continue; /* failed to remove write privs ;( */
        }

		#ifdef NEW_TRACKER
		this->blocksInProcess.startTrackingBlock(destination, size, oldProtection);
		#else
		this->writeablePEBlocks.startTracking(destination, size, oldProtection);
		#endif
        

        Logger::getInstance()->write(LOG_INFO, "Placed hook on PE section %s at 0x%08x to 0x%08x (char: 0x%08x)", sectionHeader->Name, destination, destination+size, sectionHeader->Characteristics);
    }

}

bool UnpackingEngine::isPEMemory(DWORD address)
{
    for (unsigned int i = 0; i < this->PESections.size(); i++)
        if (address >= this->PESections[i].first && address <= this->PESections[i].second)
            return true;
    return false;
}

void UnpackingEngine::startTrackingRemoteMemoryBlock(DWORD pid, DWORD baseAddress, DWORD size, unsigned char* data)
{
    if (this->remoteMemoryBlocks.find(pid) == this->remoteMemoryBlocks.end())
        this->remoteMemoryBlocks[pid] = MemoryBlockTracker<TrackedCopiedMemoryBlock>();

    TrackedCopiedMemoryBlock add(baseAddress, size, data);
    this->remoteMemoryBlocks[pid].startTracking(add);
}

void UnpackingEngine::dumpRemoteMemoryBlocks()
{
    for (auto mIT = this->remoteMemoryBlocks.begin(); mIT != this->remoteMemoryBlocks.end(); mIT++)
    {
        auto PID = mIT->first;
        auto blocks = mIT->second;
        for (auto IT = blocks.trackedMemoryBlocks.begin(); IT != blocks.trackedMemoryBlocks.end(); IT++)
        {
            if (IT->size < 50)
                continue;

            char fileName[MAX_PATH];
            sprintf(fileName, "C:\\dumps\\[%d]_%d_0x%08x_to_0x%08x.WPM.DMP", PID, GetTickCount(), IT->startAddress, IT->endAddress);
            this->dumpMemoryBlock(fileName, IT->buffer.size(), (const unsigned char*)IT->buffer.data());
        }
    }
}

void UnpackingEngine::dumpMemoryBlock(TrackedMemoryBlockV2 block, DWORD ep)
{
    wchar_t fileName[MAX_PATH];
    swprintf(fileName, L"C:\\dumps\\[%d]_%d_0x%08x_to_0x%08x_EP_0x%08x_IDX_%d.DMP", this->processID, GetTickCount(), block.startAddress, block.endAddress, ep, ep - block.startAddress);

    this->dumpMemoryBlockW(fileName, block.size, (const unsigned char*)block.startAddress);
}

void UnpackingEngine::dumpMemoryBlock(TrackedMemoryBlock block, DWORD ep)
{
    wchar_t fileName[MAX_PATH];
    swprintf(fileName, L"C:\\dumps\\[%d]_%d_0x%08x_to_0x%08x_EP_0x%08x_IDX_%d.DMP", this->processID, GetTickCount(), block.startAddress, block.endAddress, ep, ep - block.startAddress);

    this->dumpMemoryBlockW(fileName, block.size, (const unsigned char*)block.startAddress);
}

void UnpackingEngine::dumpMemoryRegion(DWORD ep)
{
	char fileName[MAX_PATH];

	Logger::getInstance()->write(LOG_INFO, "ep= 0x%08x\n", ep);

	auto it= this->trackedregions.findTrackedRegion(ep);
	if (it == this->trackedregions.nullMarkerRegion())
		return;

	Logger::getInstance()->write(LOG_INFO, "StartAddress= 0x%08x, EndAddress= 0x%08x, Size= 0x%08x, removed= %d\n", it->startAddress, it->endAddress, it->size, it->removed);

	if ( *(const unsigned char*)it->startAddress == 'M' && *(((const unsigned char*)it->startAddress) + 1) == 'Z' )
		sprintf(fileName, "C:\\dumps\\[%d]_%d_0x%08x_to_0x%08x_EP_0x%08x_IDX_%d.exe_", this->processID, GetTickCount(), it->startAddress, it->endAddress, ep, ep - it->startAddress);
	else
		sprintf(fileName, "C:\\dumps\\[%d]_%d_0x%08x_to_0x%08x_EP_0x%08x_IDX_%d.RDMP", this->processID, GetTickCount(), it->startAddress, it->endAddress, ep, ep - it->startAddress);

	Logger::getInstance()->write(LOG_INFO, "Filename= %s\n", fileName);

	this->dumpMemoryBlock(fileName, it->size, (const unsigned char*)it->startAddress);
}

void UnpackingEngine::dumpMemoryBlock(char* fileName, DWORD size, const unsigned char* data)
{
	Logger::getInstance()->write(LOG_INFO, "Filename(Multibyte)= %s\n", fileName);

    std::fstream file(fileName, std::ios::out | std::ios::binary);
    if (file.is_open())
    {
		if ( ((unsigned int)data & 0xFFF) == 0 ){
			MEMORY_BASIC_INFORMATION mbi;
			Logger::getInstance()->write(LOG_INFO, "Falling in PAGE boundary\n");
			
			while (size){
				memset(&mbi, 0, sizeof(MEMORY_BASIC_INFORMATION));
				auto val= VirtualQuery(data, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
				if (val != 0){

					Logger::getInstance()->write(LOG_INFO, "mbi.BaseAddress= %x\n", mbi.BaseAddress);
					Logger::getInstance()->write(LOG_INFO, "mbi.AllocationBase= %x\n", mbi.AllocationBase);
					Logger::getInstance()->write(LOG_INFO, "mbi.AllocationProtect= %x\n", mbi.AllocationProtect);
					Logger::getInstance()->write(LOG_INFO, "mbi.RegionSize= %x\n", mbi.RegionSize);
					Logger::getInstance()->write(LOG_INFO, "mbi.State= %x\n", mbi.State);
					Logger::getInstance()->write(LOG_INFO, "mbi.Protect= %x\n", mbi.Protect);
					Logger::getInstance()->write(LOG_INFO, "mbi.Type= %x\n", mbi.Type);

					if (mbi.State == MEM_COMMIT){
						unsigned int correctRegionSize= mbi.RegionSize - ((unsigned char*)mbi.BaseAddress - data);
						if (size <= correctRegionSize){
							file.write((const char*)&data[0], size);
							size= 0;
							data+= size;
						} else {
							file.write((const char*)&data[0], correctRegionSize);
							size-= correctRegionSize;
							data+= correctRegionSize;
						}
					} else {
						Logger::getInstance()->write(LOG_INFO, "Saw a PAGE with no MEM_COMMIT\n");
						break;
					}
				} else {
					Logger::getInstance()->write(LOG_INFO, "Failed in VirtualQuery= %x\n", val);
					break;
				}
			}

		} else {
			Logger::getInstance()->write(LOG_INFO, "Not falling in PAGE boundary\n");
			// Need to rewritten
			for (int i = 0; i < size; i++)
				file.write((const char*)&data[i], 1);
		}
        file.close();
    }
    else
        Logger::getInstance()->write(LOG_ERROR, "Failed to create dump file with name '%s'!", fileName);
}

void UnpackingEngine::dumpMemoryBlockW(wchar_t* fileName, DWORD size, const unsigned char* data)
{
	Logger::getInstance()->write(LOG_INFO, "Start dumping.\n");

    std::fstream file(fileName, std::ios::out | std::ios::binary);
    if (file.is_open())
    {
        for (int i = 0; i < size; i++)
            file.write((const char*)&data[i], 1);
        file.close();
    }
    else
        Logger::getInstance()->write(LOG_ERROR, "Failed to create dump file with name '%s'!", fileName);
	Logger::getInstance()->write(LOG_INFO, "Stop dumping.\n");
}

bool UnpackingEngine::isSelfProcess(HANDLE process)
{
    return (process == 0 || process == INVALID_HANDLE_VALUE || GetProcessId(process) == this->processID);
}

DWORD UnpackingEngine::getProcessIdIfRemote(HANDLE process)
{
     if (process == 0 && process == INVALID_HANDLE_VALUE)
         return 0;
     
     DWORD pid = GetProcessId(process);
     return (pid == this->processID) ? 0 : pid;
}

#ifndef NEW_TRACKER
ULONG UnpackingEngine::processMemoryBlockFromHook(const char* source, DWORD address, DWORD size, ULONG newProtection, ULONG oldProtection, bool considerOldProtection)
{
    PVOID _address = (PVOID)address;
    DWORD _size = size;
    ULONG _oldProtection = oldProtection;

#ifdef NEW_TRACKER
	auto it = this->blocksInProcess.findTracked(address, size);
    if (it != this->blocksInProcess.nullMarker())
#else
    auto it = this->writeablePEBlocks.findTracked(address, size);
    if (it != this->writeablePEBlocks.nullMarker())
#endif
    {
        /* this is a PE section that we're currently tracking, let's make sure it stays that way */
        if (IS_WRITEABLE_PROT(newProtection))
        {
            this->origNtProtectVirtualMemory(GetCurrentProcess(), &_address, &_size, REMOVE_WRITEABLE_PROT(newProtection), &_oldProtection);
            Logger::getInstance()->write(LOG_INFO, "[%s] Persisting hook on PE section at 0x%08x - 0x%08x", source, address, address + size);
        }
        else
            Logger::getInstance()->write(LOG_INFO, "[%s] Block detected as writeable PE block, no need to persist hook 0x%08x - 0x%08x", source, address, address + size);
    }
    else if (considerOldProtection && 
            IS_WRITEABLE_PROT(newProtection) &&
            !IS_WRITEABLE_PROT(oldProtection) &&
            this->isPEMemory(address)) // newly writeable pe section
    {
        /* this is a PE section being set to writeable, track it */
        this->origNtProtectVirtualMemory(GetCurrentProcess(), &_address, &_size, REMOVE_WRITEABLE_PROT(newProtection), &_oldProtection);
		#ifdef NEW_TRACKER
		this->blocksInProcess.startTracking(address, size, newProtection);
		#else
		this->writeablePEBlocks.startTracking(address, size, newProtection);
		#endif
        
        Logger::getInstance()->write(LOG_INFO, "[%s] Placed write hook on PE section at 0x%08x - 0x%08x", source, address, address + size);
    }
    else if (IS_EXECUTABLE_PROT(newProtection))
    {
        /* page was set to executable, track the page and remove executable rights */
		#ifdef NEW_TRACKER
		if (!this->blocksInProcess.isTracked(address, size))
        {
            this->blocksInProcess.startTracking(address, size, (DWORD)newProtection);
		#else
		if (!this->blacklistedBlocks.isTracked(address, size))
        {
            this->executableBlocks.startTracking(address, size, (DWORD)newProtection);
		#endif
            this->origNtProtectVirtualMemory(GetCurrentProcess(), &_address, &_size, REMOVE_EXECUTABLE_PROT(newProtection), &_oldProtection);
            Logger::getInstance()->write(LOG_INFO, "[%s] Placed execution hook on 0x%08x - 0x%08x", source, address, address + size);
        }
        else
            Logger::getInstance()->write(LOG_WARN, "[%s] Failed to place execution hook on BLACKLISTED BLOCK 0x%08x - 0x%08x", source, address, address + size);
    }
    else
    {
		#ifdef NEW_TRACKER
		auto it = this->blocksInProcess.findTracked(address, size);
        if (it == this->blocksInProcess.nullMarker())
		#else
		auto it = this->executableBlocks.findTracked(address, size);
        if (it == this->executableBlocks.nullMarker())
		#endif
            Logger::getInstance()->write(LOG_INFO, "[%s] No need to hook block 0x%08x - 0x%08x", source, address, address + size);
    }

    return _oldProtection;
}

#else
ULONG UnpackingEngine::processMemoryBlockFromHook(const char* source, DWORD address, DWORD size, ULONG newProtection, ULONG oldProtection, bool considerOldProtection)
{
    PVOID _address = (PVOID)address;
    DWORD _size = size;
    ULONG _oldProtection= 0;

	if(IS_WRITEABLE_PROT(newProtection) && IS_EXECUTABLE_PROT(newProtection)){
		this->origNtProtectVirtualMemory(GetCurrentProcess(), &_address, &_size, REMOVE_EXECUTABLE_PROT(REMOVE_WRITEABLE_PROT(newProtection)), &_oldProtection);
		Logger::getInstance()->write(LOG_INFO, "[%s] Placed write/exeucte hook on block at 0x%08x - 0x%08x", source, address, address + size);
	} else if (IS_WRITEABLE_PROT(newProtection)) {
		this->origNtProtectVirtualMemory(GetCurrentProcess(), &_address, &_size, REMOVE_WRITEABLE_PROT(newProtection), &_oldProtection);
		Logger::getInstance()->write(LOG_INFO, "[%s] Placed write hook on block at 0x%08x - 0x%08x", source, address, address + size);
	} else if (IS_EXECUTABLE_PROT(newProtection)){
		this->origNtProtectVirtualMemory(GetCurrentProcess(), &_address, &_size, REMOVE_EXECUTABLE_PROT(newProtection), &_oldProtection);
		Logger::getInstance()->write(LOG_INFO, "[%s] Placed execution hook on 0x%08x - 0x%08x", source, address, address + size);
	} else {
		Logger::getInstance()->write(LOG_INFO, "[%s] No need to hook block 0x%08x - 0x%08x", source, address, address + size);
    }

	
	auto it = this->blocksInProcess.findTrackedBlock(address, size);
	if (it != this->blocksInProcess.nullMarkerBlock()){
		// Already tracked one and we must have already manipulated the bits.
		_oldProtection= it->neededProtection;
		this->blocksInProcess.startTrackingBlock(address, size, newProtection);
	} else {
		// Untracked block.
		if(IS_WRITEABLE_PROT(newProtection) || IS_EXECUTABLE_PROT(newProtection)){
			// With WRITE and/or EXEC bit set.
			this->blocksInProcess.startTrackingBlock(address, size, newProtection);
			_oldProtection= oldProtection;
		}
	}

	return _oldProtection;

#if 0
	auto it = this->blocksInProcess.findTracked(address, size);
    if (it != this->blocksInProcess.nullMarker())
    {
        /* this is a PE section that we're currently tracking, let's make sure it stays that way */
        if (IS_WRITEABLE_PROT(newProtection))
        {
            this->origNtProtectVirtualMemory(GetCurrentProcess(), &_address, &_size, REMOVE_WRITEABLE_PROT(newProtection), &_oldProtection);
            Logger::getInstance()->write(LOG_INFO, "[%s] Persisting hook on PE section at 0x%08x - 0x%08x", source, address, address + size);
        }
        else
            Logger::getInstance()->write(LOG_INFO, "[%s] Block detected as writeable PE block, no need to persist hook 0x%08x - 0x%08x", source, address, address + size);
    }
    else if (considerOldProtection && 
            IS_WRITEABLE_PROT(newProtection) &&
            !IS_WRITEABLE_PROT(oldProtection) &&
            this->isPEMemory(address)) // newly writeable pe section
    {
        /* this is a PE section being set to writeable, track it */
        this->origNtProtectVirtualMemory(GetCurrentProcess(), &_address, &_size, REMOVE_WRITEABLE_PROT(newProtection), &_oldProtection);
		#ifdef NEW_TRACKER
		this->blocksInProcess.startTracking(address, size, newProtection);
		#else
		this->writeablePEBlocks.startTracking(address, size, newProtection);
		#endif
        
        Logger::getInstance()->write(LOG_INFO, "[%s] Placed write hook on PE section at 0x%08x - 0x%08x", source, address, address + size);
    }
    else if (IS_EXECUTABLE_PROT(newProtection))
    {
        /* page was set to executable, track the page and remove executable rights */
		#ifdef NEW_TRACKER
		if (!this->blocksInProcess.isTracked(address, size))
        {
            this->blocksInProcess.startTracking(address, size, (DWORD)newProtection);
		#else
		if (!this->blacklistedBlocks.isTracked(address, size))
        {
            this->executableBlocks.startTracking(address, size, (DWORD)newProtection);
		#endif
            this->origNtProtectVirtualMemory(GetCurrentProcess(), &_address, &_size, REMOVE_EXECUTABLE_PROT(newProtection), &_oldProtection);
            Logger::getInstance()->write(LOG_INFO, "[%s] Placed execution hook on 0x%08x - 0x%08x", source, address, address + size);
        }
        else
            Logger::getInstance()->write(LOG_WARN, "[%s] Failed to place execution hook on BLACKLISTED BLOCK 0x%08x - 0x%08x", source, address, address + size);
    }
    else
    {
		#ifdef NEW_TRACKER
		auto it = this->blocksInProcess.findTracked(address, size);
        if (it == this->blocksInProcess.nullMarker())
		#else
		auto it = this->executableBlocks.findTracked(address, size);
        if (it == this->executableBlocks.nullMarker())
		#endif
            Logger::getInstance()->write(LOG_INFO, "[%s] No need to hook block 0x%08x - 0x%08x", source, address, address + size);
    }

    return _oldProtection;
#endif
}
#endif

/*
#define PAGE_NOACCESS          0x01     // winnt
#define PAGE_READONLY          0x02     // winnt
#define PAGE_READWRITE         0x04     // winnt
#define PAGE_WRITECOPY         0x08     // winnt
#define PAGE_EXECUTE           0x10     // winnt
#define PAGE_EXECUTE_READ      0x20     // winnt
#define PAGE_EXECUTE_READWRITE 0x40     // winnt
#define PAGE_EXECUTE_WRITECOPY 0x80     // winnt
#define PAGE_GUARD            0x100     // winnt
#define PAGE_NOCACHE          0x200     // winnt
*/

std::string UnpackingEngine::retProtectionString(ULONG protectionbits)
{
	std::string protectionstring;
	protectionstring.reserve(64);

	if(protectionbits & PAGE_NOACCESS){
		protectionstring.append("PAGE_NOACCESS");
		protectionbits &= (~PAGE_NOACCESS);
	}
	if(protectionbits & PAGE_READONLY){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_READONLY");
		protectionbits &= (~PAGE_READONLY);
	}
	if(protectionbits & PAGE_READWRITE){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_READWRITE");
		protectionbits &= (~PAGE_READWRITE);
	}
	if(protectionbits & PAGE_WRITECOPY){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_WRITECOPY");
		protectionbits &= (~PAGE_WRITECOPY);
	}
	if(protectionbits & PAGE_EXECUTE){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_EXECUTE");
		protectionbits &= (~PAGE_EXECUTE);
	}
	if(protectionbits & PAGE_EXECUTE_READ){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_EXECUTE_READ");
		protectionbits &= (~PAGE_EXECUTE_READ);
	}
	if(protectionbits & PAGE_EXECUTE_READWRITE){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_EXECUTE_READWRITE");
		protectionbits &= (~PAGE_EXECUTE_READWRITE);
	}
	if(protectionbits & PAGE_EXECUTE_WRITECOPY){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_EXECUTE_WRITECOPY");
		protectionbits &= (~PAGE_EXECUTE_WRITECOPY);
	}
	if(protectionbits & PAGE_GUARD){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_GUARD");
		protectionbits &= (~PAGE_GUARD);
	}
	if(protectionbits & PAGE_NOCACHE){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_NOCACHE");
		protectionbits &= (~PAGE_NOCACHE);
	}
	if(protectionbits & MEM_COMMIT){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("MEM_COMMIT");
		protectionbits &= (~MEM_COMMIT);
	}
	if(protectionbits & MEM_RELEASE){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("MEM_RELEASE");
		protectionbits &= (~MEM_RELEASE);
	}
	if(protectionbits & MEM_DECOMMIT){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("MEM_DECOMMIT");
		protectionbits &= (~MEM_DECOMMIT);
	}

	if(protectionbits){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("FIXMEEEEEE");
	}
	return protectionstring;
}


/* This function needs to rewritten to handle all types of blocks. */
bool UnpackingEngine::FreetheseBlocks(PVOID baseAddress, ULONG numberOfBytes)
{

	this->blocksInProcess.stopTrackingBlock((DWORD) baseAddress, numberOfBytes);
	return true;

	ULONG freedCount= 0;

	while(freedCount != numberOfBytes){
		#ifdef NEW_TRACKER
		auto it = this->blocksInProcess.findTrackedBlock((DWORD)baseAddress, 1);
		if (it != this->blocksInProcess.nullMarkerBlock()){
		#else
		auto it = this->executableBlocks.findTracked((DWORD)baseAddress, 1);
		if (it != this->executableBlocks.nullMarker()){
		#endif
			Logger::getInstance()->write(LOG_INFO, "It's a tracked block. StartAddress= 0x%08x, EndAddress= 0x%08x, Size= 0x%08x, protection= %d\n", it->startAddress, it->endAddress, it->size, it->neededProtection);
			if ((DWORD)baseAddress == it->startAddress && numberOfBytes <= it->size){
				// Free is within the current region.
				it->startAddress += numberOfBytes;
				it->size -= numberOfBytes;
				
				freedCount += numberOfBytes;
			} else {
				if ((DWORD)baseAddress == it->startAddress && numberOfBytes > it->size){
					it->removed= true;
					baseAddress= (PVOID)(it->endAddress + 1);
					freedCount += (it->size);
				}
			}
		} else {
			break;
		}

		/* FIXME
		
		auto it = this->writeablePEBlocks.findTracked((DWORD)baseAddress, 1);
		if (it != this->writeablePEBlocks.nullMarker()){
			Logger::getInstance()->write(LOG_INFO, "It's a tracked block. StartAddress= 0x%08x, EndAddress= 0x%08x, Size= 0x%08x, protection= %d\n", it->startAddress, it->endAddress, it->size, it->neededProtection);
			if ((DWORD)baseAddress == it->startAddress && numberOfBytes <= it->size){
				// Free is within the current region.
				it->startAddress += numberOfBytes;
				it->size -= numberOfBytes;
				
				freedCount += numberOfBytes;
			} else {
			}
		}*/

		#ifdef NEW_TRACKER
		if (it == this->blocksInProcess.nullMarkerBlock())
			break;
		#else
		if (it == this->executableBlocks.nullMarker())
			break;
		#endif


		//break;
	}

	this->blocksInProcess.removeRemovedBlocks();
	return true;
}




NTSTATUS UnpackingEngine::onNtProtectVirtualMemory(HANDLE process, PVOID* baseAddress, PULONG numberOfBytes, ULONG newProtection, PULONG OldProtection)
{
    /* do original protection */
    ULONG _oldProtection= 0;

	/* we do not want to re-process this if we did in NtAllocate hook, as it sometimes calls NtProtect 
    if (this->inAllocationHook)
        return this->origNtProtectVirtualMemory(process, baseAddress, numberOfBytes, newProtection, OldProtection); */

	if(this->hooksReady)
		Logger::getInstance()->write(LOG_INFO, "PRE-NtProtectVirtualMemory(TargetPID %d, Address= 0x%08x, Size= 0x%08x, NewProtection= 0x%08x(%s))\n", GetProcessId(process), (DWORD)*baseAddress, (DWORD)*numberOfBytes, newProtection, retProtectionString(newProtection).c_str());

    NTSTATUS ret = this->origNtProtectVirtualMemory(process, baseAddress, numberOfBytes, newProtection, &_oldProtection);
	if (ret == STATUS_SUCCESS && this->isSelfProcess(process))
		this->trackedregions.startTrackingRegion((DWORD)*baseAddress, (DWORD)*numberOfBytes);

    if (OldProtection)
        *OldProtection = _oldProtection;

	/*if ((DWORD)*baseAddress == 0x75721000){
		loopme();
	}*/

    if (ret == 0 && this->hooksReady && this->isSelfProcess(process))
    {
		Logger::getInstance()->write(LOG_INFO, "PST-NtProtectVirtualMemory(TargetPID %d, Address= 0x%08x, Size= 0x%08x, NewProtection= 0x%08x(%s), OldProtection= 0x%08x(%s))\n", GetProcessId(process), (DWORD)*baseAddress, (DWORD)*numberOfBytes, newProtection, retProtectionString(newProtection).c_str(), *OldProtection, retProtectionString(*OldProtection).c_str());
        _oldProtection = this->processMemoryBlockFromHook("onNtProtectVirtualMemory", (DWORD)*baseAddress, (DWORD)*numberOfBytes, newProtection, *OldProtection, true);
        if (OldProtection)
            *OldProtection = _oldProtection;
    }

	
    return ret;
}

NTSTATUS UnpackingEngine::onNtWriteVirtualMemory(HANDLE process, PVOID baseAddress, PVOID buffer, ULONG numberOfBytes, PULONG numberOfBytesWritten)
{
    if (this->hooksReady)
        Logger::getInstance()->write(LOG_INFO, "PRE-NtWriteVirtualMemory(TargetPID %d, Address 0x%08x, Count 0x%08x)\n", GetProcessId(process), baseAddress, numberOfBytes);

    auto ret = this->origNtWriteVirtualMemory(process, baseAddress, buffer, numberOfBytes, numberOfBytesWritten);

    if (this->hooksReady)
        Logger::getInstance()->write(LOG_INFO, "PST-NtWriteVirtualMemory(TargetPID %d, Address 0x%08x, Count 0x%08x) RET: 0x%08x\n", GetProcessId(process), baseAddress, (numberOfBytesWritten) ? *numberOfBytesWritten : numberOfBytes, ret);

    if (ret == 0 && this->hooksReady)
    {
        DWORD targetPID = this->getProcessIdIfRemote(process);
        if (targetPID)
            this->startTrackingRemoteMemoryBlock(targetPID, (DWORD)baseAddress, (DWORD)numberOfBytes, (unsigned char*)buffer);
    }

    return ret;
}

BOOL WINAPI UnpackingEngine::onCreateProcessInternalW(
    HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken)
{
    auto ret = origCreateProcessInternalW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);

    if ((dwCreationFlags & CREATE_SUSPENDED) != CREATE_SUSPENDED)
    {
        /* the process wasnt initially suspended, so we can inject right away */
        Logger::getInstance()->write(LOG_INFO, "Propogating into process %d from CreateProcessInternalW() hook.\n", lpProcessInformation->dwProcessId);
        hooks->injectIntoProcess(lpProcessInformation->hProcess, L"PackerAttackerHook.dll");
        Logger::getInstance()->write(LOG_INFO, "Propogation into process %d from CreateProcessInternalW() hook COMPLETE!\n", lpProcessInformation->dwProcessId);

        if (ResumeThread(lpProcessInformation->hThread) == -1)
            Logger::getInstance()->write(LOG_ERROR, "Failed to resume process! Thread %d\n", lpProcessInformation->dwThreadId);
    }
    else
    {
        /* the process was created as suspended, track the thread and only inject once it is resumed */
        this->suspendedThreads[lpProcessInformation->dwThreadId] = lpProcessInformation->dwProcessId;
    }

    return ret;
}

NTSTATUS WINAPI UnpackingEngine::onNtCreateThread(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
{
    if (this->hooksReady)
        Logger::getInstance()->write(LOG_INFO, "NtCreateThread(TargetPID %d, Entry 0x%08x)\n", GetProcessId(ProcessHandle), ThreadContext->Eip);

    if (this->hooksReady)
    {
        if (this->isSelfProcess(ProcessHandle))
        {
            /* the thread is in this process, check if it is starting on a tracked executable block */

			#ifdef NEW_TRACKER
			auto it = this->blocksInProcess.findTrackedBlock(ThreadContext->Eip, 1);
			if (it != this->blocksInProcess.nullMarkerBlock())
			#else
			auto it = this->executableBlocks.findTracked(ThreadContext->Eip, 1);
            if (it != this->executableBlocks.nullMarker())
			#endif
            {
                /* it's an executable block being tracked */
                /* set the block back to executable */
                ULONG _oldProtection;
                auto ret = this->origNtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&it->startAddress, (PULONG)&it->size, (DWORD)it->neededProtection, &_oldProtection);
                if (ret == 0)
                {
                    /* dump the motherfucker and stop tracking it */
					#ifdef NEW_TRACKER
					this->blocksInProcess.startTrackingBlock(*it);
					#else
					this->blacklistedBlocks.startTracking(*it);
					#endif

                    
                    this->dumpMemoryBlock(*it, ThreadContext->Eip);

					#ifdef NEW_TRACKER
					this->blocksInProcess.stopTrackingBlock(*it);
					#else
					this->executableBlocks.stopTracking(it);
					#endif
                }
            }
        }
    }

    return this->origNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
}

NTSTATUS WINAPI UnpackingEngine::onNtMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, ULONG CommitSize,
    PLARGE_INTEGER SectionOffset, PULONG ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect)
{
	Logger::getInstance()->write(LOG_INFO, "PRE-NtMapViewOfSection(TargetPID %d, Address 0x%08x, Size 0x%08x)\n", GetProcessId(ProcessHandle), (DWORD)*BaseAddress, (DWORD)*ViewSize);

    if (this->hooksReady)
        Logger::getInstance()->write(LOG_INFO, "PRE-NtMapViewOfSection(TargetPID %d, Address 0x%08x, Size 0x%08x)\n", GetProcessId(ProcessHandle), (DWORD)*BaseAddress, (DWORD)*ViewSize);

    auto ret = this->origNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
                                            SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);

    if (this->hooksReady)
        Logger::getInstance()->write(LOG_INFO, "PST-NtMapViewOfSection(TargetPID %d, Address is 0x%08x, Size 0x%08x, Protect 0x%08x) RET: 0x%08x\n", GetProcessId(ProcessHandle), (DWORD)*BaseAddress, (DWORD)*ViewSize, Protect, ret);

    if (ret == 0 && this->hooksReady)
    {
        DWORD targetPID = this->getProcessIdIfRemote(ProcessHandle);
        if (targetPID)
        {
            //TODO: clean this up, there's no reason we have to allocate a buffer and use an RPM() call.
            DWORD bytesRead;
            unsigned char* buffer = new unsigned char[(DWORD)*ViewSize];
            if (ReadProcessMemory(ProcessHandle, *BaseAddress, &buffer[0], (DWORD)*ViewSize, &bytesRead) && bytesRead > 0)
            {
                char fileName[MAX_PATH];
                sprintf(fileName, "C:\\dumps\\[%d]_%d_0x%08x_to_0x%08x.MVOS.DMP", targetPID, GetTickCount(), (DWORD)*BaseAddress, (DWORD)*BaseAddress + (DWORD)*ViewSize);

                this->dumpMemoryBlock(fileName, bytesRead, (const unsigned char*)buffer);
            }
            else
                Logger::getInstance()->write(LOG_ERROR, "Failed to ReadProcessMemory() from NtMapViewOfSection() hook! (Address is 0x%08x, Size is 0x%08x) (PID is %d)\n", (DWORD)*BaseAddress, (DWORD)*ViewSize, GetProcessId(ProcessHandle));

            delete [] buffer;
        }
    }

    return ret;
}

NTSTATUS WINAPI UnpackingEngine::onNtResumeThread(HANDLE thread, PULONG suspendCount)
{
    auto threadId = GetThreadId(thread);
    if (this->suspendedThreads.find(threadId) != this->suspendedThreads.end())
    {
        auto targetPID = suspendedThreads[threadId];
        Logger::getInstance()->write(LOG_INFO, "Propogating into process %d from NtResumeThread() hook.\n", targetPID);

        auto targetHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, targetPID);
        if (targetHandle == INVALID_HANDLE_VALUE)
            Logger::getInstance()->write(LOG_ERROR, "FAILED to open process %d from NtResumeThread() hook!\n", targetPID);
        else
        {
            hooks->injectIntoProcess(targetHandle, L"PackerAttackerHook.dll");
            Logger::getInstance()->write(LOG_INFO, "Propogation into process %d from NtResumeThread() hook COMPLETE!\n", targetPID);
        }

    }

    return this->origNtResumeThread(thread, suspendCount);
}

NTSTATUS WINAPI UnpackingEngine::onNtDelayExecution(BOOLEAN alertable, PLARGE_INTEGER time)
{
    Logger::getInstance()->write(LOG_INFO, "Sleep call detected (Low part: 0x%08x, High part: 0x%08x).", time->LowPart, time->HighPart);

	if (time->HighPart == 0x80000000 && time->LowPart == 0){
		Logger::getInstance()->write(LOG_ERROR, "Infinite sleep. Fixing it.");
		time->HighPart= 0;
	}

	time->HighPart= 0;
	time->LowPart= 0; //0x3B9ACA00; 
	Logger::getInstance()->write(LOG_INFO, "Fixed sleep (Low part: 0x%08x, High part: 0x%08x).", time->LowPart, time->HighPart);

    return this->origNtDelayExecution(alertable, time);
}

NTSTATUS WINAPI UnpackingEngine::onNtFreeVirtualMemory(HANDLE process, PVOID* baseAddress, PULONG RegionSize, ULONG FreeType)
{
	Logger::getInstance()->write(LOG_INFO, "PRE-NtFreeVirtualMemory: TargetPID %d, Address 0x%08x, RegionSize 0x%08x, FreeType 0x%08x(%s)", GetProcessId(process), (DWORD)*baseAddress, (DWORD)*RegionSize, FreeType, retProtectionString(FreeType));
	auto ret= this->origNtFreeVirtualMemory(process, baseAddress, RegionSize, FreeType);
	Logger::getInstance()->write(LOG_INFO, "PST-NtFreeVirtualMemory: TargetPID %d, Address 0x%08x, RegionSize 0x%08x, FreeType 0x%08x(%s)", GetProcessId(process), (DWORD)*baseAddress, (DWORD)*RegionSize, FreeType, retProtectionString(FreeType));
	
	if (ret == STATUS_SUCCESS && this->hooksReady && this->isSelfProcess(process)){
		FreetheseBlocks(*baseAddress, *RegionSize);
        this->trackedregions.stopTrackingRegion((DWORD)*baseAddress, (DWORD)*RegionSize);
	}
	return ret;
}

NTSTATUS WINAPI UnpackingEngine::onNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect)
{
    if (this->inAllocationHook)
        return this->origNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

    this->inAllocationHook = true;

	/*if (*BaseAddress == 0x00000000 && Protect == PAGE_EXECUTE_READWRITE){ // Debug
		   loopme();
	}*/

    if (this->hooksReady)
		Logger::getInstance()->write(LOG_INFO, "PRE-NtAllocateVirtualMemory(TargetPID %d, Address 0x%08x, Size 0x%08x, Protection 0x%08x(%s))\n", GetProcessId(ProcessHandle), (DWORD)*BaseAddress, (DWORD)*RegionSize, Protect, retProtectionString(Protect).c_str());

    auto ret = this->origNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

    if (this->hooksReady)
		Logger::getInstance()->write(LOG_INFO, "PST-NtAllocateVirtualMemory(TargetPID %d, Address 0x%08x, Count 0x%08x, Protection 0x%08x(%s)) RET: 0x%08x\n", GetProcessId(ProcessHandle), (DWORD)*BaseAddress, (RegionSize) ? *RegionSize : 0, Protect, retProtectionString(Protect).c_str(), ret);

    if (ret == STATUS_SUCCESS && this->hooksReady && this->isSelfProcess(ProcessHandle)){
		this->processMemoryBlockFromHook("onNtAllocateVirtualMemory", (DWORD)*BaseAddress, (DWORD)*RegionSize, Protect, NULL, false);
		this->trackedregions.startTrackingRegion((DWORD)*BaseAddress, (DWORD)*RegionSize);
	}
	
    this->inAllocationHook = false;

	Logger::getInstance()->write(LOG_INFO, "Finished NtAllocateVirtualMemory");

    return ret;
}

long UnpackingEngine::onShallowException(PEXCEPTION_POINTERS info)
{
    // ref: https://msdn.microsoft.com/en-us/library/windows/desktop/aa363082(v=vs.85).aspx
    if (info->ExceptionRecord->ExceptionCode != STATUS_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH; /* only worried about access violations */

    if (info->ExceptionRecord->NumberParameters != 2)
        return EXCEPTION_CONTINUE_SEARCH; /* should have 2 params */

    bool isWriteException = (info->ExceptionRecord->ExceptionInformation[0] != 8);
    DWORD exceptionAddress = info->ExceptionRecord->ExceptionInformation[1];//(DWORD)info->ExceptionRecord->ExceptionAddress;

	Logger::getInstance()->write(LOG_INFO, "Got an Exception!");

    if (isWriteException) /* monitor writes to tracked PE sections */
    {
        auto sg = this->lock->enterWithScopeGuard();

		auto it = this->blocksInProcess.findTrackedBlock(exceptionAddress, 1);
		if (it == this->blocksInProcess.nullMarkerBlock())
        {
            Logger::getInstance()->write(LOG_WARN, "STATUS_ACCESS_VIOLATION write on 0x%08x not treated as hook!", exceptionAddress);
            return EXCEPTION_CONTINUE_SEARCH; /* we're not tracking the page */
        }

        /* set the section back to writeable */
        ULONG _oldProtection;
        auto ret = this->origNtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&it->startAddress, (PULONG)&it->size, PAGE_READWRITE, &_oldProtection);
        if (ret != 0)
        {
            Logger::getInstance()->write(LOG_ERROR, "Failed to removed write hook on 0x%08x!", exceptionAddress);
            return EXCEPTION_CONTINUE_SEARCH; /* couldn't set page back to regular protection, wtf? */
        }

        Logger::getInstance()->write(LOG_INFO, "STATUS_ACCESS_VIOLATION write on 0x%08x triggered write hook!", exceptionAddress);

        /* writing to the section should work now */
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else /* monitor executes to tracked executable blocks */
    {
        auto sg = this->lock->enterWithScopeGuard();

		auto it = this->blocksInProcess.findTrackedBlock(exceptionAddress, 1);
		if (it == this->blocksInProcess.nullMarkerBlock())
        {
            /* this isn't memory we've hooked, so this is an unrelated DEP exception.
            If the process didn't initially have DEP enabled, we should fix the protection so it can execute.
            If the process did initially have DEP enabled, we should let it crash as normal */
            if (this->simulateDisabledDEP)
            {
                ULONG _oldProtection;
                DWORD _address = exceptionAddress;
                ULONG _size = 1;
                auto ret = this->origNtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&_address, (PULONG)&_size, PAGE_EXECUTE_READWRITE, &_oldProtection);
                Logger::getInstance()->write(LOG_INFO, "STATUS_ACCESS_VIOLATION execute on 0x%08x (NOT A HOOK). Simulating DEP-lessness from 0x%08x to 0x%08x.", exceptionAddress, _address, _address + _size);

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                Logger::getInstance()->write(LOG_INFO, "STATUS_ACCESS_VIOLATION execute on 0x%08x (NOT A HOOK). No need to simulate DEP-lessness.", exceptionAddress);
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }

        /* it's an executable block being tracked */
        /* set the block back to executable */
        ULONG _oldProtection;
		Logger::getInstance()->write(LOG_INFO, "Trying to remove execute hook on 0x%08x, 0x%08x, 0x%08x, 0x%08x!", exceptionAddress, it->startAddress, it->size, (DWORD)it->neededProtection);
        auto ret = this->origNtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&it->startAddress, (PULONG)&it->size, it->neededProtection, &_oldProtection); // FIX: Need more analysis on why we dont see some NtProtectVirtualMemory
        if (ret != 0)
        {
            Logger::getInstance()->write(LOG_ERROR, "Failed to removed execute hook on 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x!", exceptionAddress, it->startAddress, it->size, (DWORD)it->neededProtection, _oldProtection, ret);
            return EXCEPTION_CONTINUE_SEARCH; /* couldn't set page back to executable, wtf? */
        }

        this->dumpMemoryBlock(*it, exceptionAddress); //Hideme
		this->dumpMemoryRegion(exceptionAddress);

        Logger::getInstance()->write(LOG_INFO, "STATUS_ACCESS_VIOLATION execute on 0x%08x triggered execute hook!", exceptionAddress);

        /* execution should work now */
        return EXCEPTION_CONTINUE_EXECUTION;
    }
}


long UnpackingEngine::onDeepException(PEXCEPTION_POINTERS info)
{
    const char* exceptionDesc = "unknown";
    if (info->ExceptionRecord->ExceptionCode == STATUS_WAIT_0)                          exceptionDesc = "STATUS_WAIT_0";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_ABANDONED_WAIT_0)           exceptionDesc = "STATUS_ABANDONED_WAIT_0";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_USER_APC)                   exceptionDesc = "STATUS_USER_APC";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_TIMEOUT)                    exceptionDesc = "STATUS_TIMEOUT";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_PENDING)                    exceptionDesc = "STATUS_PENDING";
    else if (info->ExceptionRecord->ExceptionCode == DBG_EXCEPTION_HANDLED)             exceptionDesc = "DBG_EXCEPTION_HANDLED";
    else if (info->ExceptionRecord->ExceptionCode == DBG_CONTINUE)                      exceptionDesc = "DBG_CONTINUE";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_SEGMENT_NOTIFICATION)       exceptionDesc = "STATUS_SEGMENT_NOTIFICATION";
    else if (info->ExceptionRecord->ExceptionCode == DBG_TERMINATE_THREAD)              exceptionDesc = "DBG_TERMINATE_THREAD";
    else if (info->ExceptionRecord->ExceptionCode == DBG_TERMINATE_PROCESS)             exceptionDesc = "DBG_TERMINATE_PROCESS";
    else if (info->ExceptionRecord->ExceptionCode == DBG_CONTROL_C)                     exceptionDesc = "DBG_CONTROL_C";
    else if (info->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C)              exceptionDesc = "DBG_PRINTEXCEPTION_C";
    else if (info->ExceptionRecord->ExceptionCode == DBG_RIPEXCEPTION)                  exceptionDesc = "DBG_RIPEXCEPTION";
    else if (info->ExceptionRecord->ExceptionCode == DBG_CONTROL_BREAK)                 exceptionDesc = "DBG_CONTROL_BREAK";
    else if (info->ExceptionRecord->ExceptionCode == DBG_COMMAND_EXCEPTION)             exceptionDesc = "DBG_COMMAND_EXCEPTION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)       exceptionDesc = "STATUS_GUARD_PAGE_VIOLATION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_DATATYPE_MISALIGNMENT)      exceptionDesc = "STATUS_DATATYPE_MISALIGNMENT";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)                 exceptionDesc = "STATUS_BREAKPOINT";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)                exceptionDesc = "STATUS_SINGLE_STEP";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_LONGJUMP)                   exceptionDesc = "STATUS_LONGJUMP";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_UNWIND_CONSOLIDATE)         exceptionDesc = "STATUS_UNWIND_CONSOLIDATE";
    else if (info->ExceptionRecord->ExceptionCode == DBG_EXCEPTION_NOT_HANDLED)         exceptionDesc = "DBG_EXCEPTION_NOT_HANDLED";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)           exceptionDesc = "STATUS_ACCESS_VIOLATION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_IN_PAGE_ERROR)              exceptionDesc = "STATUS_IN_PAGE_ERROR";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_INVALID_HANDLE)             exceptionDesc = "STATUS_INVALID_HANDLE";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_INVALID_PARAMETER)          exceptionDesc = "STATUS_INVALID_PARAMETER";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_NO_MEMORY)                  exceptionDesc = "STATUS_NO_MEMORY";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION)        exceptionDesc = "STATUS_ILLEGAL_INSTRUCTION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_NONCONTINUABLE_EXCEPTION)   exceptionDesc = "STATUS_NONCONTINUABLE_EXCEPTION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_INVALID_DISPOSITION)        exceptionDesc = "STATUS_INVALID_DISPOSITION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_ARRAY_BOUNDS_EXCEEDED)      exceptionDesc = "STATUS_ARRAY_BOUNDS_EXCEEDED";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_DENORMAL_OPERAND)     exceptionDesc = "STATUS_FLOAT_DENORMAL_OPERAND";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_DIVIDE_BY_ZERO)       exceptionDesc = "STATUS_FLOAT_DIVIDE_BY_ZERO";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_INEXACT_RESULT)       exceptionDesc = "STATUS_FLOAT_INEXACT_RESULT";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_INVALID_OPERATION)    exceptionDesc = "STATUS_FLOAT_INVALID_OPERATION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_OVERFLOW)             exceptionDesc = "STATUS_FLOAT_OVERFLOW";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_STACK_CHECK)          exceptionDesc = "STATUS_FLOAT_STACK_CHECK";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_UNDERFLOW)            exceptionDesc = "STATUS_FLOAT_UNDERFLOW";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_INTEGER_DIVIDE_BY_ZERO)     exceptionDesc = "STATUS_INTEGER_DIVIDE_BY_ZERO";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_INTEGER_OVERFLOW)           exceptionDesc = "STATUS_INTEGER_OVERFLOW";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION)     exceptionDesc = "STATUS_PRIVILEGED_INSTRUCTION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_STACK_OVERFLOW)             exceptionDesc = "STATUS_STACK_OVERFLOW";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_DLL_NOT_FOUND)              exceptionDesc = "STATUS_DLL_NOT_FOUND";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_ORDINAL_NOT_FOUND)          exceptionDesc = "STATUS_ORDINAL_NOT_FOUND";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_ENTRYPOINT_NOT_FOUND)       exceptionDesc = "STATUS_ENTRYPOINT_NOT_FOUND";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_CONTROL_C_EXIT)             exceptionDesc = "STATUS_CONTROL_C_EXIT";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_DLL_INIT_FAILED)            exceptionDesc = "STATUS_DLL_INIT_FAILED";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_MULTIPLE_FAULTS)      exceptionDesc = "STATUS_FLOAT_MULTIPLE_FAULTS";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_MULTIPLE_TRAPS)       exceptionDesc = "STATUS_FLOAT_MULTIPLE_TRAPS";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_REG_NAT_CONSUMPTION)        exceptionDesc = "STATUS_REG_NAT_CONSUMPTION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_STACK_BUFFER_OVERRUN)       exceptionDesc = "STATUS_STACK_BUFFER_OVERRUN";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_INVALID_CRUNTIME_PARAMETER) exceptionDesc = "STATUS_INVALID_CRUNTIME_PARAMETER";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_ASSERTION_FAILURE)          exceptionDesc = "STATUS_ASSERTION_FAILURE";


    auto sg = this->lock->enterWithScopeGuard();
    this->ignoreHooks(true);

    Logger::getInstance()->write(LOG_ERROR, "POSSIBLE CRASH DETECTED!");
    Logger::getInstance()->write(LOG_APPENDLINE, "\t%s at 0x%08x", exceptionDesc, info->ExceptionRecord->ExceptionAddress);
    Logger::getInstance()->write(LOG_APPENDLINE, "\t%s", exceptionDesc);
    Logger::getInstance()->write(LOG_APPENDLINE, "Exception Params: %d", info->ExceptionRecord->NumberParameters);
    for (unsigned int i = 0; i < info->ExceptionRecord->NumberParameters; i++)
        Logger::getInstance()->write(LOG_APPENDLINE, "\t\tParam #%d: 0x%08x", i, info->ExceptionRecord->ExceptionInformation[i]);
    Logger::getInstance()->write(LOG_APPENDLINE, "\tEAX: 0x%08x", info->ContextRecord->Eax);
    Logger::getInstance()->write(LOG_APPENDLINE, "\tEBP: 0x%08x", info->ContextRecord->Ebp);
    Logger::getInstance()->write(LOG_APPENDLINE, "\tEBX: 0x%08x", info->ContextRecord->Ebx);
    Logger::getInstance()->write(LOG_APPENDLINE, "\tECX: 0x%08x", info->ContextRecord->Ecx);
    Logger::getInstance()->write(LOG_APPENDLINE, "\tEDI: 0x%08x", info->ContextRecord->Edi);
    Logger::getInstance()->write(LOG_APPENDLINE, "\tEDX: 0x%08x", info->ContextRecord->Edx);
    Logger::getInstance()->write(LOG_APPENDLINE, "\tESI: 0x%08x", info->ContextRecord->Esi);
    Logger::getInstance()->write(LOG_APPENDLINE, "\tESP: 0x%08x", info->ContextRecord->Esp);
    Logger::getInstance()->write(LOG_APPENDLINE, "\tEIP: 0x%08x", info->ContextRecord->Eip);
    Logger::getInstance()->write(LOG_APPENDLINE, "\tEFLAGS: 0x%08x", info->ContextRecord->EFlags);

	//loopme();

    DebugStackTracer stackTracer(
        [=](std::string line) -> void
        {
            bool ignore =
                    (line.find("ERROR:") != std::string::npos) ||
					(line.find("SymType:") != std::string::npos)||
					(line.find("SymInit:") != std::string::npos)||
					(line.find("OS-Version:") != std::string::npos);

            auto replaceString = [=](std::string& text, const std::string key, const std::string value) -> void
            {
	            if (value.find(key) != std::string::npos)
		            return;
	            for (std::string::size_type keyStart = text.find(key); keyStart != std::string::npos; keyStart = text.find(key))
		            text.replace(keyStart, key.size(), value);
            };

        	if (!ignore)
            {
                replaceString(line, ": (filename not available)", "");
		        replaceString(line, ": (function-name not available)", "");
                Logger::getInstance()->write(LOG_APPENDLINE, "\t\t%s", line.c_str());
            }
        }
    );

    Logger::getInstance()->write(LOG_APPENDLINE, "\tStack Trace:");
    stackTracer.ShowCallstack(GetCurrentThread(), info->ContextRecord);
    this->ignoreHooks(false);


    return EXCEPTION_CONTINUE_SEARCH;
}