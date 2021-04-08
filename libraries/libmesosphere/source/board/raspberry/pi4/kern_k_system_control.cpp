/*
 * Copyright (c) 2018-2020 Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <mesosphere.hpp>

namespace ams::kern::board::raspberry::pi4 {

    namespace {
        
        constexpr size_t SecureAlignment        = 128_KB;
        
        /* Global variables for panic. */
        constinit bool g_call_smc_on_panic;
        
        /* Global variables for secure memory. */
        constexpr size_t SecureAppletMemorySize = 4_MB;
        constinit KSpinLock g_secure_applet_lock;
        constinit bool g_secure_applet_memory_used = false;
        constinit KVirtualAddress g_secure_applet_memory_address = Null<KVirtualAddress>;

        constinit KSpinLock g_secure_region_lock;
        constinit bool g_secure_region_used = false;
        constinit KPhysicalAddress g_secure_region_phys_addr = Null<KPhysicalAddress>;
        constinit size_t g_secure_region_size = 0;
        
        /* Global variables for randomness. */
        /* Nintendo uses std::mt19937_t for randomness. */
        /* To save space (and because mt19337_t isn't secure anyway), */
        /* We will use TinyMT. */
        constinit bool         g_initialized_random_generator;
        constinit util::TinyMT g_random_generator;
        constinit KSpinLock    g_random_lock;

        ALWAYS_INLINE u64 GenerateRandomU64FromGenerator() {
            return g_random_generator.GenerateRandomU64();
        }

        template<typename F>
        ALWAYS_INLINE u64 GenerateUniformRange(u64 min, u64 max, F f) {
            /* Handle the case where the difference is too large to represent. */
            if (max == std::numeric_limits<u64>::max() && min == std::numeric_limits<u64>::min()) {
                return f();
            }

            /* Iterate until we get a value in range. */
            const u64 range_size    = ((max + 1) - min);
            const u64 effective_max = (std::numeric_limits<u64>::max() / range_size) * range_size;
            while (true) {
                if (const u64 rnd = f(); rnd < effective_max) {
                    return min + (rnd % range_size);
                }
            }
        }
        
        bool SetSecureRegion(KPhysicalAddress phys_addr, size_t size) {
            /* Ensure address and size are aligned. */
            if (!util::IsAligned(GetInteger(phys_addr), SecureAlignment)) {
                return false;
            }
            if (!util::IsAligned(size, SecureAlignment)) {
                return false;
            }

            /* Disable interrupts and acquire the secure region lock. */
            KScopedInterruptDisable di;
            KScopedSpinLock lk(g_secure_region_lock);

            /* If size is non-zero, we're allocating the secure region. Otherwise, we're freeing it. */
            if (size != 0) {
                /* Verify that the secure region is free. */
                if (g_secure_region_used) {
                    return false;
                }

                /* Set the secure region. */
                g_secure_region_used      = true;
                g_secure_region_phys_addr = phys_addr;
                g_secure_region_size      = size;
            } else {
                /* Verify that the secure region is in use. */
                if (!g_secure_region_used) {
                    return false;
                }

                /* Verify that the address being freed is the secure region. */
                if (phys_addr != g_secure_region_phys_addr) {
                    return false;
                }

                /* Clear the secure region. */
                g_secure_region_used      = false;
                g_secure_region_phys_addr = Null<KPhysicalAddress>;
                g_secure_region_size      = 0;
            }

            return true;
        }

        Result AllocateSecureMemoryForApplet(KVirtualAddress *out, size_t size) {
            /* Verify that the size is valid. */
            R_UNLESS(util::IsAligned(size, PageSize), svc::ResultInvalidSize());
            R_UNLESS(size <= SecureAppletMemorySize,  svc::ResultOutOfMemory());

            /* Disable interrupts and acquire the secure applet lock. */
            KScopedInterruptDisable di;
            KScopedSpinLock lk(g_secure_applet_lock);

            /* Check that memory is reserved for secure applet use. */
            MESOSPHERE_ABORT_UNLESS(g_secure_applet_memory_address != Null<KVirtualAddress>);

            /* Verify that the secure applet memory isn't already being used. */
            R_UNLESS(!g_secure_applet_memory_used, svc::ResultOutOfMemory());

            /* Return the secure applet memory. */
            g_secure_applet_memory_used = true;
            *out = g_secure_applet_memory_address;

            return ResultSuccess();
        }

        void FreeSecureMemoryForApplet(KVirtualAddress address, size_t size) {
            /* Disable interrupts and acquire the secure applet lock. */
            KScopedInterruptDisable di;
            KScopedSpinLock lk(g_secure_applet_lock);

            /* Verify that the memory being freed is correct. */
            MESOSPHERE_ABORT_UNLESS(address == g_secure_applet_memory_address);
            MESOSPHERE_ABORT_UNLESS(size <= SecureAppletMemorySize);
            MESOSPHERE_ABORT_UNLESS(util::IsAligned(size, PageSize));
            MESOSPHERE_ABORT_UNLESS(g_secure_applet_memory_used);

            /* Release the secure applet memory. */
            g_secure_applet_memory_used = false;
        }
        
    }
    
    bool KSystemControl::Init::ShouldIncreaseThreadResourceLimit() {
        return false; // Adds 160 thread slots, don't think we need this
    }

    u64 KSystemControl::Init::GenerateRandomRange(u64 min, u64 max) {
        return GenerateUniformRange(min, max, GenerateRandomU64);
    }

    /* System Initialization. */
    void KSystemControl::InitializePhase1() {
        /* Initialize our random generator. */
        {
            u64 seed = 0xdfbc6cfef9d442aa; // from random.org (#fairdiceroll)
            g_random_generator.Initialize(reinterpret_cast<u32*>(std::addressof(seed)), sizeof(seed) / sizeof(u32));
            g_initialized_random_generator = true;
        }

        /* Set IsDebugMode. */
        {
            KTargetSystem::SetIsDebugMode(true); // Force debug mode

            /* If debug mode, we want to initialize uart logging. */
            KTargetSystem::EnableDebugLogging(KTargetSystem::IsDebugMode());
            KDebugLog::Initialize();
        }

        /* Set Kernel Configuration. */
        {
            KTargetSystem::EnableDebugMemoryFill(false);
            KTargetSystem::EnableUserExceptionHandlers(false);
            KTargetSystem::EnableUserPmuAccess(false);

            g_call_smc_on_panic = false;
        }

        /* Set Kernel Debugging. */
        {
            /* NOTE: This is used to restrict access to SvcKernelDebug/SvcChangeKernelTraceState. */
            /* Mesosphere may wish to not require this, as we'd ideally keep ProgramVerification enabled for userland. */
            KTargetSystem::EnableKernelDebugging(false);
        }

        /* Configure the Kernel Carveout region. */
        {
            const auto carveout = KMemoryLayout::GetCarveoutRegionExtents();
            MESOSPHERE_ABORT_UNLESS(carveout.GetEndAddress() != 0);
        }

        /* System ResourceLimit initialization. */
        {
            /* Construct the resource limit object. */
            KResourceLimit &sys_res_limit = Kernel::GetSystemResourceLimit();
            KAutoObject::Create(std::addressof(sys_res_limit));
            sys_res_limit.Initialize();

            /* Set the initial limits. */
            const auto [total_memory_size, kernel_memory_size] = KMemoryLayout::GetTotalAndKernelMemorySizes();
            const auto &slab_counts = init::GetSlabResourceCounts();
            MESOSPHERE_R_ABORT_UNLESS(sys_res_limit.SetLimitValue(ams::svc::LimitableResource_PhysicalMemoryMax,      total_memory_size));
            MESOSPHERE_R_ABORT_UNLESS(sys_res_limit.SetLimitValue(ams::svc::LimitableResource_ThreadCountMax,         slab_counts.num_KThread));
            MESOSPHERE_R_ABORT_UNLESS(sys_res_limit.SetLimitValue(ams::svc::LimitableResource_EventCountMax,          slab_counts.num_KEvent));
            MESOSPHERE_R_ABORT_UNLESS(sys_res_limit.SetLimitValue(ams::svc::LimitableResource_TransferMemoryCountMax, slab_counts.num_KTransferMemory));
            MESOSPHERE_R_ABORT_UNLESS(sys_res_limit.SetLimitValue(ams::svc::LimitableResource_SessionCountMax,        slab_counts.num_KSession));

            /* Reserve system memory. */
            MESOSPHERE_ABORT_UNLESS(sys_res_limit.Reserve(ams::svc::LimitableResource_PhysicalMemoryMax, kernel_memory_size));
        }
    }

    void KSystemControl::InitializePhase2() {
        /* Reserve secure applet memory. */
        if (GetTargetFirmware() >= TargetFirmware_5_0_0) {
            MESOSPHERE_ABORT_UNLESS(g_secure_applet_memory_address == Null<KVirtualAddress>);
            MESOSPHERE_ABORT_UNLESS(Kernel::GetSystemResourceLimit().Reserve(ams::svc::LimitableResource_PhysicalMemoryMax, SecureAppletMemorySize));

            constexpr auto SecureAppletAllocateOption = KMemoryManager::EncodeOption(KMemoryManager::Pool_System, KMemoryManager::Direction_FromFront);
            g_secure_applet_memory_address = Kernel::GetMemoryManager().AllocateAndOpenContinuous(SecureAppletMemorySize / PageSize, 1, SecureAppletAllocateOption);
            MESOSPHERE_ABORT_UNLESS(g_secure_applet_memory_address != Null<KVirtualAddress>);
        }

        /* Initialize KTrace. */
        if constexpr (IsKTraceEnabled) {
            const auto &ktrace = KMemoryLayout::GetKernelTraceBufferRegion();
            KTrace::Initialize(ktrace.GetAddress(), ktrace.GetSize());
        }
    }

    u32 KSystemControl::GetCreateProcessMemoryPool() {
        return KMemoryManager::Pool_Unsafe;
    }

    /* Privileged Access. */
    Result KSystemControl::ReadWriteRegister(u32 *out, ams::svc::PhysicalAddress address, u32 mask, u32 value) {
        MESOSPHERE_UNUSED(out, address, mask, value);
        return svc::ResultNotImplemented();
    }

    /* Randomness. */
    void KSystemControl::GenerateRandomBytes(void *dst, size_t size) {
        MESOSPHERE_INIT_ABORT_UNLESS(size <= 0x38);
        
        //shouldn't really matter
        char* buffer = (char*)dst;
        for(size_t i = 0; i < size; i++)
        {
            *buffer = 0x13; // fair dice roll as usual
        }
    }

    u64 KSystemControl::GenerateRandomU64() {
        KScopedInterruptDisable intr_disable;
        KScopedSpinLock lk(g_random_lock);

        if (AMS_LIKELY(g_initialized_random_generator)) {
            return GenerateRandomU64FromGenerator();
        } else {
            return 4; // fairer dice roll
        }
    }
    
    u64 KSystemControl::GenerateRandomRange(u64 min, u64 max) {
        KScopedInterruptDisable intr_disable;
        KScopedSpinLock lk(g_random_lock);


        if (AMS_LIKELY(g_initialized_random_generator)) {
            return GenerateUniformRange(min, max, GenerateRandomU64FromGenerator);
        } else {
            return min; // fairest dice roll
        }
    }

    void KSystemControl::SleepSystem() {
        MESOSPHERE_LOG("SleepSystem() was called\n");
        // No sleep on RPi4.
        AMS_INFINITE_LOOP();
    }

    void KSystemControl::StopSystem(void *arg) {
        MESOSPHERE_UNUSED(arg);
        AMS_INFINITE_LOOP();
    }

    /* User access. */
    void KSystemControl::CallSecureMonitorFromUser(ams::svc::lp64::SecureMonitorArguments *args) {
        MESOSPHERE_UNUSED(args);
        // No secmon on RPi4.
    }

    /* Secure Memory. */
    size_t KSystemControl::CalculateRequiredSecureMemorySize(size_t size, u32 pool) {
        if (pool == KMemoryManager::Pool_Applet) {
            return 0;
        }
        return size;
    }

    Result KSystemControl::AllocateSecureMemory(KVirtualAddress *out, size_t size, u32 pool) {
        /* Applet secure memory is handled separately. */
        if (pool == KMemoryManager::Pool_Applet) {
            return AllocateSecureMemoryForApplet(out, size);
        }

        /* Ensure the size is aligned. */
        const size_t alignment = (pool == KMemoryManager::Pool_System ? PageSize : SecureAlignment);
        R_UNLESS(util::IsAligned(size, alignment), svc::ResultInvalidSize());

        /* Allocate the memory. */
        const size_t num_pages = size / PageSize;
        const KVirtualAddress vaddr = Kernel::GetMemoryManager().AllocateAndOpenContinuous(num_pages, alignment / PageSize, KMemoryManager::EncodeOption(static_cast<KMemoryManager::Pool>(pool), KMemoryManager::Direction_FromFront));
        R_UNLESS(vaddr != Null<KVirtualAddress>, svc::ResultOutOfMemory());

        /* Ensure we don't leak references to the memory on error. */
        auto mem_guard = SCOPE_GUARD { Kernel::GetMemoryManager().Close(vaddr, num_pages); };

        /* If the memory isn't already secure, set it as secure. */
        if (pool != KMemoryManager::Pool_System) {
            /* Get the physical address. */
            const KPhysicalAddress paddr = KPageTable::GetHeapPhysicalAddress(vaddr);
            MESOSPHERE_ABORT_UNLESS(paddr != Null<KPhysicalAddress>);

            /* Set the secure region. */
            R_UNLESS(SetSecureRegion(paddr, size), svc::ResultOutOfMemory());
        }

        /* We succeeded. */
        mem_guard.Cancel();
        *out = vaddr;
        return ResultSuccess();
    }

    void KSystemControl::FreeSecureMemory(KVirtualAddress address, size_t size, u32 pool) {
        /* Applet secure memory is handled separately. */
        if (pool == KMemoryManager::Pool_Applet) {
            return FreeSecureMemoryForApplet(address, size);
        }

        /* Ensure the size is aligned. */
        const size_t alignment = (pool == KMemoryManager::Pool_System ? PageSize : SecureAlignment);
        MESOSPHERE_ABORT_UNLESS(util::IsAligned(GetInteger(address), alignment));
        MESOSPHERE_ABORT_UNLESS(util::IsAligned(size, alignment));

        /* If the memory isn't secure system, reset the secure region. */
        if (pool != KMemoryManager::Pool_System) {
            /* Check that the size being freed is the current secure region size. */
            MESOSPHERE_ABORT_UNLESS(g_secure_region_size == size);

            /* Get the physical address. */
            const KPhysicalAddress paddr = KPageTable::GetHeapPhysicalAddress(address);
            MESOSPHERE_ABORT_UNLESS(paddr != Null<KPhysicalAddress>);

            /* Check that the memory being freed is the current secure region. */
            MESOSPHERE_ABORT_UNLESS(paddr == g_secure_region_phys_addr);

            /* Free the secure region. */
            MESOSPHERE_ABORT_UNLESS(SetSecureRegion(paddr, 0));
        }

        /* Close the secure region's pages. */
        Kernel::GetMemoryManager().Close(address, size / PageSize);
    }

}