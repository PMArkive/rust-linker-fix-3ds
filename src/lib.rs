#![no_std]

use ctru_sys::__errno;

// Avoid conflicting a real POSIX errno by using a value < 0
// Should we define this in ctru-sys somewhere or something?
const ECTRU: libc::c_int = -1;

/// Provides the libc `getrandom` API.
///
/// # Safety
///
/// `buflen` must be less than or equal to the size of the buffer pointed to by `buf`.
///
#[no_mangle]
pub unsafe extern "C" fn getrandom(
    buf: *mut libc::c_void,
    mut buflen: libc::size_t,
    flags: libc::c_uint,
) -> libc::ssize_t {
    // Based on https://man7.org/linux/man-pages/man2/getrandom.2.html
    // Technically we only have one source (no true /dev/random), but the
    // behavior should be more expected this way.
    let maxlen = if flags & libc::GRND_RANDOM != 0 {
        512
    } else {
        0x1FF_FFFF
    };
    buflen = buflen.min(maxlen);

    let ret = ctru_sys::psInit();

    // Error handling code for psInit
    if ctru_sys::R_FAILED(ret) {
        // Best-effort attempt at translating return codes
        *__errno() = match ctru_sys::R_SUMMARY(ret).try_into() {
            // The service handle is full (would block to await availability)
            Ok(ctru_sys::RS_WOULDBLOCK) => libc::EAGAIN,
            // The caller doesn't have the right to call the service
            _ => ECTRU,
        };
        return -1;
    }

    let ret = ctru_sys::PS_GenerateRandomBytes(buf, buflen);

    // Error handling code for PS_GenerateRandomBytes
    if ctru_sys::R_SUCCEEDED(ret) {
        // Safe because above ensures buflen < isize::MAX
        buflen as libc::ssize_t
    } else {
        // Best-effort attempt at translating return codes
        *__errno() = match ctru_sys::R_SUMMARY(ret).try_into() {
            Ok(ctru_sys::RS_WOULDBLOCK) => libc::EAGAIN,
            Ok(ctru_sys::RS_INVALIDARG | ctru_sys::RS_WRONGARG) => {
                match ctru_sys::R_DESCRIPTION(ret).try_into() {
                    // The handle is incorrect (even though we just made it)
                    Ok(ctru_sys::RD_INVALID_HANDLE) => ECTRU,
                    _ => libc::EINVAL,
                }
            }
            _ => ECTRU,
        };

        -1
    }
}
