use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::{fs, io, mem};
use subspace_core_primitives::crypto::blake3_hash_list;
use subspace_core_primitives::{Blake3Hash, Piece, PieceIndex};
use subspace_farmer_components::file_ext::{FileExt, OpenOptionsExt};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Disk piece cache open error
#[derive(Debug, Error)]
pub enum DiskPieceCacheError {
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Can't preallocate cache file, probably not enough space on disk
    #[error("Can't preallocate cache file, probably not enough space on disk: {0}")]
    CantPreallocateCacheFile(io::Error),
    /// Offset outsize of range
    #[error("Offset outsize of range: provided {provided}, max {max}")]
    OffsetOutsideOfRange {
        /// Provided offset
        provided: usize,
        /// Max offset
        max: usize,
    },
    /// Cache size has zero capacity, this is not supported
    #[error("Cache size has zero capacity, this is not supported")]
    ZeroCapacity,
    /// Checksum mismatch
    #[error("Checksum mismatch")]
    ChecksumMismatch,
}

/// Piece cache stored on one disk
#[derive(Debug, Clone, Default)]
pub struct DiskPieceCacheV2 {
    directory: PathBuf,
}

impl DiskPieceCacheV2 {
    pub fn new(directory: PathBuf) -> Result<Self, DiskPieceCacheError> {
        fs::create_dir_all(&directory)?;
        Ok(DiskPieceCacheV2 { directory })
    }

    pub(super) const fn element_size() -> usize {
        PieceIndex::SIZE + Piece::SIZE + mem::size_of::<Blake3Hash>()
    }

    /// Store piece in cache at specified offset, replacing existing piece if there is any
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    pub(crate) fn write_piece(
        &self,
        piece_index: PieceIndex,
        piece: &Piece,
    ) -> Result<(), DiskPieceCacheError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .advise_random_access()
            .open(self.directory.join(format!("{:?}", piece_index)))?;

        file.advise_random_access()?;

        let piece_index_bytes = piece_index.to_bytes();
        file.write_all_at(&piece_index_bytes, 0)?;
        file.write_all_at(piece.as_ref(), PieceIndex::SIZE as u64)?;
        file.write_all_at(
            &blake3_hash_list(&[&piece_index_bytes, piece.as_ref()]),
            PieceIndex::SIZE as u64 + Piece::SIZE as u64,
        )?;

        Ok(())
    }

    /// Read piece from cache at specified offset.
    ///
    /// Returns `None` if offset is out of range.
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    pub(crate) fn read_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, DiskPieceCacheError> {
        let path = self.directory.join(format!("{:?}", piece_index));
        if !path.exists() {
            return Ok(None);
        }

        let file = OpenOptions::new()
            .read(true)
            .advise_random_access()
            .open(path)?;

        file.advise_random_access()?;

        let mut element = vec![0; Self::element_size()];
        if Self::read_piece_internal(&file, &mut element)?.is_some() {
            let mut piece = Piece::default();
            piece.copy_from_slice(&element[PieceIndex::SIZE..][..Piece::SIZE]);
            Ok(Some(piece))
        } else {
            Ok(None)
        }
    }

    fn read_piece_internal(
        file: &File,
        element: &mut [u8],
    ) -> Result<Option<PieceIndex>, DiskPieceCacheError> {
        file.read_exact_at(element, 0)?;

        let (piece_index_bytes, remaining_bytes) = element.split_at(PieceIndex::SIZE);
        let (piece_bytes, expected_checksum) = remaining_bytes.split_at(Piece::SIZE);

        // Verify checksum
        let actual_checksum = blake3_hash_list(&[piece_index_bytes, piece_bytes]);
        if actual_checksum != expected_checksum {
            if element.iter().all(|&byte| byte == 0) {
                return Ok(None);
            }

            debug!(
                actual_checksum = %hex::encode(actual_checksum),
                expected_checksum = %hex::encode(expected_checksum),
                "Hash doesn't match, corrupted piece in cache"
            );

            return Err(DiskPieceCacheError::ChecksumMismatch);
        }

        let piece_index = PieceIndex::from_bytes(
            piece_index_bytes
                .try_into()
                .expect("Statically known to have correct size; qed"),
        );
        Ok(Some(piece_index))
    }
}
