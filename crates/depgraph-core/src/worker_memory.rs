//! Sample the resident memory charged to a worker's isolated process group.
//! Shared pages are charged to each process, making the limit conservative.

#[cfg(unix)]
use std::io;

#[cfg(target_os = "linux")]
pub(crate) fn process_group_memory(process_group: i32) -> io::Result<u64> {
    use std::io::Read;

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = 0_u64;
    for (index, entry) in std::fs::read_dir("/proc")?.enumerate() {
        if index >= 131_072 {
            return Err(io::Error::other("process inventory exceeds its bound"));
        }
        let entry = entry?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let mut stat = String::new();
        let file = match std::fs::File::open(entry.path().join("stat")) {
            Ok(file) => file,
            Err(error) => {
                // Ignore inaccessible unrelated processes, but never silently
                // omit a live member of this worker's process group.
                if unsafe { libc::getpgid(pid) } == process_group {
                    return Err(error);
                }
                continue;
            }
        };
        if let Err(error) = file.take(16_384).read_to_string(&mut stat) {
            if unsafe { libc::getpgid(pid) } == process_group {
                return Err(error);
            }
            continue;
        }
        if let Some((group, resident_pages)) = linux_process_stat(&stat)
            && group == process_group
        {
            bytes = bytes.saturating_add(resident_pages.saturating_mul(page_size as u64));
        } else if linux_process_stat(&stat).is_none()
            && unsafe { libc::getpgid(pid) } == process_group
        {
            return Err(io::Error::other("worker process memory record is invalid"));
        }
    }
    Ok(bytes)
}

#[cfg(any(target_os = "linux", test))]
fn linux_process_stat(stat: &str) -> Option<(i32, u64)> {
    // comm is parenthesized and may itself contain spaces and parentheses.
    let (_, fields) = stat.rsplit_once(')')?;
    let mut fields = fields.split_whitespace();
    let process_group = fields.nth(2)?.parse().ok()?;
    let resident_pages = fields.nth(18)?.parse().ok()?;
    Some((process_group, resident_pages))
}

#[cfg(target_os = "macos")]
pub(crate) fn process_group_memory(process_group: i32) -> io::Result<u64> {
    const PROC_PGRP_ONLY: u32 = 2; // sys/proc_info.h
    const MAX_GROUP_PROCESSES: usize = 16_384;
    let mut pids = vec![0_i32; MAX_GROUP_PROCESSES];
    let buffer_bytes = std::mem::size_of_val(pids.as_slice());
    let count = unsafe {
        libc::proc_listpids(
            PROC_PGRP_ONLY,
            process_group as u32,
            pids.as_mut_ptr().cast(),
            buffer_bytes as i32,
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    if count as usize >= buffer_bytes {
        return Err(io::Error::other("worker process group exceeds its bound"));
    }
    let mut bytes = 0_u64;
    for pid in pids
        .into_iter()
        .take(count as usize / std::mem::size_of::<i32>())
    {
        if pid <= 0 {
            continue;
        }
        let mut info = std::mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
        let observed = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTASKINFO,
                0,
                info.as_mut_ptr().cast(),
                std::mem::size_of::<libc::proc_taskinfo>() as i32,
            )
        };
        if observed == std::mem::size_of::<libc::proc_taskinfo>() as i32 {
            bytes = bytes.saturating_add(unsafe { info.assume_init() }.pti_resident_size);
        } else {
            let error = io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) {
                return Err(error);
            }
        }
    }
    Ok(bytes)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) fn process_group_memory(_process_group: i32) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "worker memory accounting is unavailable",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_stat_accounts_for_parentheses_in_process_name() {
        let mut fields = vec!["0"; 22];
        fields[0] = "S";
        fields[2] = "42";
        fields[21] = "1234";
        let stat = format!("12 (worker (child)) {}", fields.join(" "));
        assert_eq!(linux_process_stat(&stat), Some((42, 1234)));
        assert_eq!(linux_process_stat("12 (worker) S 0 42"), None);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn current_process_group_has_resident_memory() {
        let process_group = unsafe { libc::getpgrp() };
        assert!(process_group_memory(process_group).unwrap() > 0);
    }
}
