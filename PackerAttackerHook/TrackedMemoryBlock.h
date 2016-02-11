#pragma once
#include <Windows.h>
#include <list>
#include <vector>
#include <algorithm>
#include "Logger.h"

struct TrackedMemoryBlock
{
    DWORD startAddress, endAddress, size;
    DWORD neededProtection;

    TrackedMemoryBlock(DWORD _startAddress, DWORD _size, DWORD _neededProtection = NULL)
    {
        this->startAddress = _startAddress;
        this->endAddress = _startAddress + _size - 1;
        this->size = _size;
        this->neededProtection = _neededProtection;
    }

    bool overlapsWith(TrackedMemoryBlock right, bool oneSided = false)
    {
        if (!oneSided)
            if (right.overlapsWith(*this, true))
                return true;
        return (right.startAddress >= this->startAddress && right.startAddress <= this->endAddress);
    }

    virtual void mergeWith(TrackedMemoryBlock right)
    {
        DWORD protectionTemp = right.neededProtection;
        if (this->overlapsWith(right, true))
        {
            this->endAddress = right.endAddress;
            this->size = this->endAddress - this->startAddress;
        }
        else if (right.overlapsWith(*this, true))
        {
            TrackedMemoryBlock temp(right);
            temp.mergeWith(*this);

            this->startAddress = temp.startAddress;
            this->endAddress = temp.endAddress;
            this->size = temp.size;
        }
        else
            return;

        this->neededProtection = protectionTemp;
    }
};


struct TrackedCopiedMemoryBlock : public TrackedMemoryBlock
{
    std::vector<unsigned char> buffer;
    TrackedCopiedMemoryBlock(DWORD _startAddress, DWORD _size, unsigned char* _buffer)
        : TrackedMemoryBlock(_startAddress, _size, PAGE_NOACCESS)
    {
        this->buffer.reserve(size);
        for (unsigned int i = 0; i < size; i++)
            this->buffer.push_back(_buffer[i]);
    }

    virtual void mergeWith(TrackedCopiedMemoryBlock right)
    {
        DWORD protectionTemp = right.neededProtection;
        if (this->overlapsWith(right, true))
        {
            /* we need to copy on top of existing bytes */
            unsigned int startIndex = right.startAddress - this->startAddress;
            unsigned int oI = startIndex; //overwrite index
            unsigned int cI = 0; //copy index

            /* copy over existing data */
            for (; oI < this->size; oI++, cI++)
                this->buffer[oI] = right.buffer[cI];

            /* copy over trailing data */
            for (; cI < right.size; cI++, oI++)
            {
                assert(oI <= this->buffer.size());
                if (oI == this->buffer.size())
                    this->buffer.push_back(right.buffer[cI]);
                else
                    this->buffer[oI] = right.buffer[cI];
            }

            this->endAddress = right.endAddress;
            this->size = this->endAddress - this->startAddress;
        }
        else if (right.overlapsWith(*this, true))
        {
            TrackedCopiedMemoryBlock temp(right);
            temp.mergeWith(*this);

            this->startAddress = temp.startAddress;
            this->endAddress = temp.endAddress;
            this->size = temp.size;
            this->buffer = temp.buffer;
        }
        else
            return;

        this->neededProtection = protectionTemp;
    }
};

template<typename TrackType>
struct MemoryBlockTracker
{
    std::list<TrackType> trackedMemoryBlocks;

    typename std::list<TrackType>::iterator nullMarker()
    {
        return this->trackedMemoryBlocks.end();
    }
    typename std::list<TrackType>::iterator findTracked(DWORD address, DWORD size)
    {
        return findTracked(TrackType(address, size));
    }
    typename std::list<TrackType>::iterator findTracked(TrackType check)
    {
        for (auto it = this->trackedMemoryBlocks.begin(); it != this->trackedMemoryBlocks.end(); it++)
            if (it->overlapsWith(check))
                return it;

        return this->trackedMemoryBlocks.end();
    }
    bool isTracked(DWORD address, DWORD size)
    {
        return isTracked(TrackType(address, size));
    }
    bool isTracked(TrackedMemoryBlock check)
    {
        return findTracked(check) != this->nullMarker();
    }
    void startTracking(DWORD address, DWORD size, DWORD protection)
    {
        startTracking(TrackType(address, size, protection));
    }
    void startTracking(TrackType right)
    {
		Logger::getInstance()->write(LOG_INFO, "StartAddress= 0x%08x, EndAddress= 0x%08x, Size= 0x%08x, neededProtection= %d\n", right.startAddress, right.endAddress, right.size, right.neededProtection);
        auto it = this->findTracked(right);
        if (it != this->nullMarker())
            it->mergeWith(right);
        else
            this->trackedMemoryBlocks.push_back(right);

		for (auto it = this->trackedMemoryBlocks.begin(); it != this->trackedMemoryBlocks.end(); it++){
			Logger::getInstance()->write(LOG_INFO, "Block: StartAddress= 0x%08x, EndAddress= 0x%08x, Size= 0x%08x, neededProtection= %d\n", it->startAddress, it->endAddress, it->size, it->neededProtection);
		}
    }

    void stopTracking(DWORD address, DWORD size)
    {
        this->stopTracking(this->findTracked(address, size));
    }
    void stopTracking(typename std::list<TrackType>::iterator it)
    {
        assert(it != this->trackedMemoryBlocks.end());

        this->trackedMemoryBlocks.erase(it);
    }
};


class MemoryRegionTracker
{
	struct _RegionInfo{
		DWORD startAddress, endAddress, size;
		bool removed;
		_RegionInfo(DWORD _startAddress, DWORD _size)
		{
			startAddress= _startAddress;
			endAddress= _startAddress + (_size - 1);
			size= _size;
			removed= false;
		}
	};

	void printTrackingInfo()
	{
		auto it = trackedMemoryRegion.begin();
        for (; it != trackedMemoryRegion.end(); it++){
			Logger::getInstance()->write(LOG_INFO, "StartAddress= 0x%08x, EndAddress= 0x%08x, Size= 0x%08x, removed= %d\n", it->startAddress, it->endAddress, it->size, it->removed);
		}
	}

public:

	std::list<_RegionInfo>::iterator nullMarker()
    {
        return this->trackedMemoryRegion.end();
    }

	std::list<_RegionInfo>::iterator findTrackedRegion(DWORD oeip)
    {
        for (auto it = this->trackedMemoryRegion.begin(); it != this->trackedMemoryRegion.end(); ++it){
			//Logger::getInstance()->write(LOG_INFO, "Before IF condition - StartAddress= 0x%08x, EndAddress= 0x%08x, Size= 0x%08x, removed= %d\n", it->startAddress, it->endAddress, it->size, it->removed);
			if (it->startAddress <= oeip && oeip <= it->endAddress){
				//Logger::getInstance()->write(LOG_INFO, "Inside IF. StartAddress= 0x%08x, EndAddress= 0x%08x, Size= 0x%08x, removed= %d\n", it->startAddress, it->endAddress, it->size, it->removed);
                return it;
			}/* else {
				Logger::getInstance()->write(LOG_INFO, "Else part.\n");
			}*/
		}

        return this->trackedMemoryRegion.end();
    }

	void stopTrackingRegion(DWORD r_startaddress, DWORD r_size)
	{
		Logger::getInstance()->write(LOG_INFO, "r_startaddress= 0x%08x, r_size= 0x%08x\n", r_startaddress, r_size);
		printTrackingInfo();

		//DWORD _relased_size= 0;

		auto it = trackedMemoryRegion.begin();
        for (; r_size !=0 && it != trackedMemoryRegion.end(); it++){
			if (it->startAddress <= r_startaddress && r_startaddress <= it->endAddress){
				
				if (r_size !=0 && r_startaddress - it->startAddress > 0){
					// We need to split this.
					Logger::getInstance()->write(LOG_INFO, "Released block is starting from middle of another existing block StartAddress= 0x%08x, EndAddress= 0x%08x, Size= 0x%08x\n", it->startAddress, it->endAddress, it->size);
					trackedMemoryRegion.push_back(_RegionInfo(it->startAddress, r_startaddress - it->startAddress));
					it->startAddress= r_startaddress;
					it->size= (r_startaddress - it->startAddress) + 1;
				}

				if (r_size !=0 && r_startaddress == it->startAddress && r_size < it->size) {
					Logger::getInstance()->write(LOG_INFO, "Released block is ending in another existing block StartAddress= 0x%08x, EndAddress= 0x%08x, Size= 0x%08x\n", it->startAddress, it->endAddress, it->size);
					trackedMemoryRegion.push_back(_RegionInfo(it->startAddress + r_size, it->size - r_size ));
					r_size= 0;
					it->removed= 1;
					r_startaddress= it->endAddress + 1;
				}

				if (r_size !=0 && r_startaddress == it->startAddress && r_size >= it->size){
					r_size-= it->size;
					r_startaddress= it->endAddress + 1;
					it->removed= 1;
				}
			}
		}

		trackedMemoryRegion.remove_if([](const _RegionInfo & o) { return o.removed; });
		trackedMemoryRegion.sort([](const _RegionInfo & a, const _RegionInfo & b) { return a.startAddress < b.startAddress; }); // sort it based on the startaddress
		printTrackingInfo();
	}

    void startTrackingRegion(DWORD new_startaddress, DWORD new_size)
    {
		//return;
		Logger::getInstance()->write(LOG_INFO, "new_startaddress= 0x%08x, new_size= 0x%08x\nBefore tracking this.\n", new_startaddress, new_size);
		printTrackingInfo();

		// Merge overlapping regions.
		auto it = trackedMemoryRegion.begin();
        for (; it != trackedMemoryRegion.end(); it++){
			if (it->startAddress <= new_startaddress && new_startaddress <= it->endAddress){
				auto new_endaddress= new_startaddress + (new_size - 1);
				Logger::getInstance()->write(LOG_INFO, "Overlapping region. StartAddress= 0x%08x, EndAddress= 0x%08x, Size= 0x%08x\n", it->startAddress, it->endAddress, it->size);
				if (new_endaddress > it->endAddress){
					// Go past the current region.

					//Fixed this region
					it->size += (new_endaddress - it->endAddress);
					it->endAddress= it->startAddress + it->size;

					auto nx = std::next(it, 1);
					while (nx != trackedMemoryRegion.end() && it->startAddress <= nx->startAddress && nx->startAddress <= it->endAddress){
						nx->removed= true; //remove the next region
						if (nx->endAddress <= it->endAddress){ // next region is taken care by current region.
							nx = std::next(nx, 1);
							continue;
						}
						it->endAddress= nx->endAddress;
						it->size= it->endAddress - it->startAddress;
						nx = std::next(nx, 1);
					}
					//
					trackedMemoryRegion.remove_if([](const _RegionInfo & o) { return o.removed; });
				}

				Logger::getInstance()->write(LOG_INFO, "After fixing overlapping regions\n");
				printTrackingInfo();

				break;
			}
		}
		
		// New region
		if (it == trackedMemoryRegion.end()){
			Logger::getInstance()->write(LOG_INFO, "Its a New region.\n");
			trackedMemoryRegion.push_back(_RegionInfo(new_startaddress,new_size));
			// do the sorting now.
			trackedMemoryRegion.sort([](const _RegionInfo & a, const _RegionInfo & b) { return a.startAddress < b.startAddress; }); // sort it based on the startaddress

			Logger::getInstance()->write(LOG_INFO, "After adding new region\n");
			printTrackingInfo();
		}

		// Contigous region. At a time we will have only one contigous region.
		it = trackedMemoryRegion.begin();
		bool didamerge= false;
        for (; it != trackedMemoryRegion.end(); it++){
			auto nx = std::next(it, 1);
			while (nx != trackedMemoryRegion.end() && nx->startAddress == it->endAddress+1){
				Logger::getInstance()->write(LOG_INFO, "Doing merging of contigous regions\n");
				nx->removed= true;
				it->endAddress= nx->endAddress;
				it->size= it->endAddress - it->startAddress;
				nx = std::next(nx, 1);
				didamerge= true;
			}

			if(didamerge){
				trackedMemoryRegion.remove_if([](const _RegionInfo & o) { return o.removed; });
				Logger::getInstance()->write(LOG_INFO, "After merging contigous regions\n");
				printTrackingInfo();
				break;
			}
		}

		Logger::getInstance()->write(LOG_INFO, "\nFinished tracking this region\n");

    }



	/*void stopTracking(DWORD address, DWORD size)
    {
        this->stopTracking(this->findTracked(address, size));
    }*/

private:
	std::list<_RegionInfo> trackedMemoryRegion;
};