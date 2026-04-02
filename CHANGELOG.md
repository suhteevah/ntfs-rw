# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-02

### Added

- Boot sector / BPB parsing and serialization with full NTFS validation
- Master File Table (MFT) entry parsing with Update Sequence Array (fixup) support
- MFT entry serialization for write-back to disk
- Attribute parsing for all standard NTFS attribute types (resident and non-resident)
- Data run (mapping pairs) encoding and decoding
- VCN-to-LCN mapping for non-contiguous file data
- `$FILE_NAME` attribute parsing with UTF-16LE filenames, timestamps, and namespace support
- `$FILE_NAME` attribute serialization
- B+ tree index traversal for directory lookups (`$INDEX_ROOT` and `$INDEX_ALLOCATION`)
- `$UpCase` table loading and ASCII fallback for case-insensitive filename comparison
- High-level `BlockDevice` trait for storage backend abstraction
- `NtfsFs::mount()` to initialize filesystem from a block device
- `NtfsFs::read_file()` to read file contents by path
- `NtfsFs::write_file()` to create or overwrite files
- `NtfsFs::mkdir()` to create directories
- `NtfsFs::list_dir()` to enumerate directory contents
- MFT entry allocation via `$MFT` bitmap scanning
- Cluster allocation via volume `$Bitmap` scanning
- Full `no_std` support (requires only `alloc`)
