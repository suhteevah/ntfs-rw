# ntfs-rw

[![no_std](https://img.shields.io/badge/no__std-yes-blue)](https://rust-embedded.github.io/book/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

A `no_std` NTFS filesystem implementation in Rust with read and write support.

Designed for bare-metal, embedded, and OS development environments where the standard library is not available. Only requires `alloc`.

## Features

- **Boot sector / BPB parsing** with full validation (OEM ID, signature, geometry)
- **Master File Table (MFT)** entry parsing with Update Sequence Array (fixup) support
- **Attribute parsing** for both resident and non-resident attributes
- **Data run encoding/decoding** (mapping pairs) for non-resident data
- **`$FILE_NAME` attribute** parsing with UTF-16LE filenames, timestamps, and namespace support (POSIX, Win32, DOS, Win32+DOS)
- **B+ tree index traversal** for directory lookups (`$INDEX_ROOT` and `$INDEX_ALLOCATION`)
- **`$UpCase` table** for case-insensitive filename comparison per the NTFS spec
- **VCN-to-LCN mapping** for non-contiguous file data
- **High-level API**: `read_file`, `write_file`, `mkdir`, `list_dir`
- **Serialization support**: boot sector, MFT entries, data runs, and filenames can be written back to disk

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
ntfs-rw = "0.1"
```

Implement the `BlockDevice` trait for your storage backend:

```rust
use ntfs_rw::{NtfsFs, BlockDevice, NtfsError};

struct MyDisk {
    // your storage backend (NVMe, virtio-blk, RAM disk, disk image, etc.)
}

impl BlockDevice for MyDisk {
    fn read_bytes(&self, offset: u64, buf: &mut [u8]) -> Result<(), NtfsError> {
        // Read buf.len() bytes from the partition starting at byte offset
        todo!()
    }

    fn write_bytes(&self, offset: u64, buf: &[u8]) -> Result<(), NtfsError> {
        // Write buf to the partition starting at byte offset
        todo!()
    }

    fn flush(&self) -> Result<(), NtfsError> {
        // Optional: flush cached writes to storage
        Ok(())
    }
}

fn example(disk: MyDisk) -> Result<(), NtfsError> {
    // Mount the filesystem
    let fs = NtfsFs::mount(disk)?;

    // Read a file
    let data = fs.read_file(b"/path/to/file.txt")?;

    // Write a file (creates if not exists, overwrites if exists)
    fs.write_file(b"/output.txt", b"Hello, NTFS!")?;

    // Create a directory
    fs.mkdir(b"/new_directory")?;

    // List directory contents
    let entries = fs.list_dir(b"/")?;
    for entry in &entries {
        // entry.name, entry.is_directory, entry.size, etc.
    }

    Ok(())
}
```

## Architecture

The crate is organized into focused modules:

| Module | Description |
|--------|-------------|
| `boot_sector` | NTFS boot sector / BPB parsing and serialization |
| `mft` | MFT entry parsing, fixup arrays, attribute iteration |
| `attribute` | Attribute header parsing (resident and non-resident) |
| `data_runs` | Data run (mapping pairs) encoding and decoding |
| `filename` | `$FILE_NAME` attribute with UTF-16LE support |
| `index` | B+ tree index structures for directory traversal |
| `upcase` | `$UpCase` table for case-insensitive comparisons |
| `readwrite` | High-level filesystem API (`NtfsFs`, `BlockDevice`) |

## Limitations

This is a work-in-progress implementation. Known limitations:

- **No journaling**: writes do not go through `$LogFile`
- **No compression/encryption**: LZNT1 compressed and EFS encrypted attributes are detected but not decoded
- **Limited write support**: growing files beyond their current allocation and resident-to-non-resident conversion are not yet implemented
- **Directory index updates**: newly created files/directories are written to MFT but not yet inserted into the parent directory's B+ tree index
- **No `$ATTRIBUTE_LIST` support**: files with attributes spanning multiple MFT entries are not handled

## NTFS References

- [Linux NTFS Documentation](https://flatcap.github.io/linux-ntfs/) -- detailed on-disk structure reference
- [Microsoft MFT Documentation](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/suhteevah/ntfs-rw).

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

## Support This Project

If you find this project useful, consider buying me a coffee! Your support helps me keep building and sharing open-source tools.

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg?logo=paypal)](https://www.paypal.me/baal_hosting)

**PayPal:** [baal_hosting@live.com](https://paypal.me/baal_hosting)

Every donation, no matter how small, is greatly appreciated and motivates continued development. Thank you!
