//! Process management syscalls

use crate::mm::{translated_va_to_pa, MapPermission, PageTable, VPNRange, VirtAddr};
use crate::task::{change_program_brk, current_user_token, delete_framed_area, exit_current_and_run_next, get_syscall_time, insert_framed_area, suspend_current_and_run_next};
use crate::timer::get_time_us;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    unsafe {
        let token = current_user_token();
        let ts = usize::from(translated_va_to_pa(token, ts as *const u8)) as *mut TimeVal;
        *ts = TimeVal {
            sec: us / 1000000,
            usec: us % 1000000,
        }
    }
    0
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(_trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    match _trace_request {
        0 => {
            let id = id as *const u8;
            let token = current_user_token();
            let id = usize::from(translated_va_to_pa(token, id)) as *mut u8;
            let ret = unsafe { id.read() };
            ret as isize
        }
        1 => {
            let id = id as *mut u8;
            let token = current_user_token();
            let id = usize::from(translated_va_to_pa(token, id)) as *mut u8;
            unsafe { id.write(data as u8) };
            0
        }
        2 => get_syscall_time(id) as isize,
        _ => -1,
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap NOT IMPLEMENTED YET!");
    let start_offset = VirtAddr(start).page_offset();

    if start_offset != 0 || port & !0x7 != 0 || port & 0x7 == 0 {
        return -1;
    }
    let start_vpn = VirtAddr(start).floor();
    let end_vpn = VirtAddr(start + len).ceil();

    let token = current_user_token();
    let page_table = PageTable::from_token(token);
    for vpn in VPNRange::new(start_vpn, end_vpn) {
        match page_table.translate(vpn) {
            Some(pte) => {
                if pte.is_valid() {
                    return -1;
                }
            }
            None => {}
        }
    }
    let permission = MapPermission::from_bits_truncate((port < 1) as u8);
    insert_framed_area(VirtAddr::from(start_vpn), VirtAddr::from(end_vpn), permission | MapPermission::U);
    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_mmap NOT IMPLEMENTED YET!");
    let start_offset = VirtAddr(start).page_offset();

    if start_offset != 0 {
        return -1;
    }
    let start_vpn = VirtAddr(start).floor();
    let end_vpn = VirtAddr(start + len).ceil();

    let token = current_user_token();
    let page_table = PageTable::from_token(token);
    for vpn in VPNRange::new(start_vpn, end_vpn) {
        match page_table.translate(vpn) {
            Some(pte) => {
                if !pte.is_valid() {
                    return -1;
                }
            }
            None => {}
        }
    }
    delete_framed_area(VirtAddr::from(start_vpn), VirtAddr::from(end_vpn));
    0
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
