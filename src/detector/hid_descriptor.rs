//! Identifying FIDO U2F/CTAP HID devices among `/dev/hidraw*` nodes.
//!
//! A hidraw device declares what it is via its HID report descriptor,
//! fetched with two ioctls (`HIDIOCGRDESCSIZE` then `HIDIOCGRDESC`, per
//! <https://github.com/torvalds/linux/blob/master/include/uapi/linux/hidraw.h>).
//! A device is a FIDO U2F/CTAP device if that descriptor declares both the
//! FIDO alliance usage page and the CTAPHID usage
//! (<https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html>).

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

// https://github.com/torvalds/linux/blob/master/include/linux/hid.h
const HID_ITEM_TYPE_GLOBAL: u8 = 1;
const HID_ITEM_TYPE_LOCAL: u8 = 2;
const HID_GLOBAL_ITEM_TAG_USAGE_PAGE: u8 = 0;
const HID_LOCAL_ITEM_TAG_USAGE: u8 = 0;
const FIDO_USAGE_PAGE: u32 = 0xf1d0;
const FIDO_USAGE_CTAPHID: u8 = 0x01;

const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;

#[repr(C)]
struct HidrawReportDescriptor {
    size: u32,
    value: [u8; HID_MAX_DESCRIPTOR_SIZE],
}

nix::ioctl_read!(hidiocgrdescsize, b'H', 0x01, libc::c_int);
nix::ioctl_read!(hidiocgrdesc, b'H', 0x02, HidrawReportDescriptor);

/// Opens `device_path` and checks whether its HID report descriptor
/// declares the FIDO usage page and CTAPHID usage. Returns `false` (rather
/// than propagating an error) for any device that isn't a readable hidraw
/// node or doesn't support these ioctls, matching the original
/// implementation's "best-effort guess, never fatal" approach.
pub fn is_fido_u2f_device(device_path: &Path) -> bool {
    if !device_path.to_string_lossy().starts_with("/dev/hidraw") {
        return false;
    }

    let Ok(file) = File::open(device_path) else {
        return false;
    };
    let fd = file.as_raw_fd();

    let mut size: libc::c_int = 0;
    // SAFETY: `size` is a valid, correctly-sized out-param for this ioctl.
    if unsafe { hidiocgrdescsize(fd, &mut size) }.is_err() {
        return false;
    }

    let mut descriptor = HidrawReportDescriptor {
        size: size.max(0) as u32,
        value: [0u8; HID_MAX_DESCRIPTOR_SIZE],
    };
    // SAFETY: `descriptor.size` was just filled in by HIDIOCGRDESCSIZE,
    // which is what tells the kernel how many bytes of `value` to fill in.
    if unsafe { hidiocgrdesc(fd, &mut descriptor) }.is_err() {
        return false;
    }

    let len = (descriptor.size as usize).min(HID_MAX_DESCRIPTOR_SIZE);
    descriptor_declares_fido_ctaphid(&descriptor.value[..len])
}

/// Pure HID item-stream walk, kept separate from any ioctl/file I/O so it's
/// unit-testable against fixture byte arrays.
///
/// Deliberately mirrors the original implementation's simplified item walk
/// rather than a fully spec-compliant HID item parser: it treats each
/// item's 2-bit size code (0..3) as a literal byte count. That's exact for
/// the two items being matched here (a 2-byte Usage Page value and a
/// 1-byte Usage value both use size codes that equal their byte count),
/// even though HID's actual encoding maps size code `3` to 4 bytes, not 3.
/// Preserved as-is for behavioral parity rather than "fixed", since it's a
/// heuristic either way. Byte access beyond the slice is treated as `0`
/// rather than panicking, since a real report descriptor is not adversarial
/// input but shouldn't be able to crash a long-running background thread.
fn descriptor_declares_fido_ctaphid(descriptor: &[u8]) -> bool {
    let mut is_fido = false;
    let mut has_u2f = false;
    let mut i = 0usize;

    while i < descriptor.len() {
        let prefix = descriptor[i];
        let tag = (prefix & 0b1111_0000) >> 4;
        let item_type = (prefix & 0b0000_1100) >> 2;
        let item_size = prefix & 0b0000_0011;

        let val1b = descriptor.get(i + 1).copied().unwrap_or(0);
        let val2b =
            u32::from(val1b) | (u32::from(descriptor.get(i + 2).copied().unwrap_or(0)) << 8);

        if item_type == HID_ITEM_TYPE_GLOBAL
            && tag == HID_GLOBAL_ITEM_TAG_USAGE_PAGE
            && val2b == FIDO_USAGE_PAGE
        {
            is_fido = true;
        } else if item_type == HID_ITEM_TYPE_LOCAL
            && tag == HID_LOCAL_ITEM_TAG_USAGE
            && val1b == FIDO_USAGE_CTAPHID
        {
            has_u2f = true;
        }

        if is_fido && has_u2f {
            return true;
        }

        i += item_size as usize + 1;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const USAGE_PAGE_FIDO: [u8; 3] = [0x06, 0xd0, 0xf1];
    const USAGE_CTAPHID: [u8; 2] = [0x09, 0x01];

    #[test]
    fn recognizes_fido_usage_page_and_ctaphid_usage_together() {
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&USAGE_PAGE_FIDO);
        descriptor.extend_from_slice(&USAGE_CTAPHID);

        assert!(descriptor_declares_fido_ctaphid(&descriptor));
    }

    #[test]
    fn order_of_the_two_items_does_not_matter() {
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&USAGE_CTAPHID);
        descriptor.extend_from_slice(&USAGE_PAGE_FIDO);

        assert!(descriptor_declares_fido_ctaphid(&descriptor));
    }

    #[test]
    fn usage_page_alone_is_not_enough() {
        assert!(!descriptor_declares_fido_ctaphid(&USAGE_PAGE_FIDO));
    }

    #[test]
    fn ctaphid_usage_alone_is_not_enough() {
        assert!(!descriptor_declares_fido_ctaphid(&USAGE_CTAPHID));
    }

    #[test]
    fn unrelated_items_are_skipped() {
        // A Global Logical Minimum item (type=1, tag=1, size=1) with an
        // unrelated value, surrounding the two items that matter.
        let unrelated = [0x15u8, 0x00];
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&unrelated);
        descriptor.extend_from_slice(&USAGE_PAGE_FIDO);
        descriptor.extend_from_slice(&unrelated);
        descriptor.extend_from_slice(&USAGE_CTAPHID);
        descriptor.extend_from_slice(&unrelated);

        assert!(descriptor_declares_fido_ctaphid(&descriptor));
    }

    #[test]
    fn empty_descriptor_is_not_fido() {
        assert!(!descriptor_declares_fido_ctaphid(&[]));
    }

    #[test]
    fn truncated_item_near_end_of_slice_does_not_panic() {
        // Claims a 2-byte value but only the prefix byte is actually
        // present; must not index out of bounds.
        assert!(!descriptor_declares_fido_ctaphid(&[0x06]));
    }

    #[test]
    fn non_hidraw_path_is_rejected_before_any_io() {
        assert!(!is_fido_u2f_device(Path::new("/dev/not-hidraw")));
        assert!(!is_fido_u2f_device(Path::new("/tmp/hidraw0")));
    }

    #[test]
    fn nonexistent_hidraw_device_is_not_fido() {
        assert!(!is_fido_u2f_device(Path::new(
            "/dev/hidraw-does-not-exist-in-tests"
        )));
    }
}
