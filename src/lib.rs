//! # ntfs-rw
//!
//! A `no_std` NTFS filesystem implementation in Rust with read and write support.
//!
//! This crate provides read and write access to NTFS filesystems from bare-metal
//! or embedded environments. No standard library required — only `alloc`.
//!
//! ## Features
//!
//! - Boot sector / BPB parsing and validation
//! - Master File Table (MFT) entry parsing with fixup array (Update Sequence Array) support
//! - Attribute parsing (resident and non-resident) with data run decoding
//! - `$FILE_NAME` attribute parsing (UTF-16LE filenames, timestamps, namespaces)
//! - B+ tree index traversal for directory lookups
//! - `$UpCase` table for case-insensitive filename comparison
//! - Data run encoding and decoding (mapping pairs)
//! - High-level `read_file` / `write_file` / `mkdir` / `list_dir` API
//!
//! ## Usage
//!
//! ```rust,no_run
//! use ntfs_rw::{NtfsFs, BlockDevice, NtfsError};
//!
//! struct MyDisk { /* ... */ }
//!
//! impl BlockDevice for MyDisk {
//!     fn read_bytes(&self, offset: u64, buf: &mut [u8]) -> Result<(), NtfsError> {
//!         // read from your storage backend
//!         Ok(())
//!     }
//!     fn write_bytes(&self, offset: u64, buf: &[u8]) -> Result<(), NtfsError> {
//!         // write to your storage backend
//!         Ok(())
//!     }
//! }
//!
//! // Mount the filesystem:
//! // let fs = NtfsFs::mount(MyDisk { /* ... */ }).expect("failed to mount NTFS");
//! // let data = fs.read_file(b"/Windows/System32/config/SAM").expect("read failed");
//! ```

#![no_std]

extern crate alloc;

pub mod attribute;
pub mod boot_sector;
pub mod data_runs;
pub mod filename;
pub mod index;
pub mod mft;
pub mod readwrite;
pub mod upcase;

pub use readwrite::{BlockDevice, NtfsFs, NtfsError, DirEntry};
pub use boot_sector::BootSector;
pub use mft::{MftEntry, MftEntryHeader, MFT_ENTRY_FLAG_IN_USE, MFT_ENTRY_FLAG_DIRECTORY};
pub use attribute::{AttributeHeader, ResidentHeader, NonResidentHeader, AttributeType};
pub use filename::{FileNameAttr, FileNamespace};
pub use index::{IndexRoot, IndexEntry, IndexNodeHeader};
pub use data_runs::{DataRun, decode_data_runs};
pub use upcase::UpCaseTable;
