use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;
use subspace_farmer_components::file_ext::{FileExt, OpenOptionsExt};
use subspace_farmer_components::{ReadAtSectorIndexSync, ReadAtSync, WriteSectorSync};
use tracing::trace;

/// Wrapper data structure for multiple files to be used with [`rayon`] thread pool, where the same
/// file is opened multiple times, once for each thread.
pub struct RayonFilesManger {
    files: Vec<File>,
}

impl ReadAtSectorIndexSync for RayonFilesManger {
    fn read_at_sector_index(
        &self,
        buf: &mut [u8],
        sector_index: u16,
        offset: usize,
    ) -> io::Result<()> {
        let thread_index = rayon::current_thread_index().unwrap_or_default();
        let file = self.files.get(sector_index as usize).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "No files entry for this rayon sector index thread",
            )
        })?;
        trace!(
            thread_index = %thread_index,
            sector_index = %sector_index,
            offset = %offset,
            "read_at_sector_index",
        );

        file.read_at(buf, offset)
    }
}

impl ReadAtSectorIndexSync for &RayonFilesManger {
    fn read_at_sector_index(
        &self,
        buf: &mut [u8],
        sector_index: u16,
        offset: usize,
    ) -> io::Result<()> {
        (*self).read_at_sector_index(buf, sector_index, offset)
    }
}

impl WriteSectorSync for RayonFilesManger {
    fn write(&self, sector_index: u16, buf: &[u8]) -> io::Result<()> {
        let thread_index = rayon::current_thread_index().unwrap_or_default();
        trace!(
            thread_index = %thread_index,
            sector_index = %sector_index,
            "write",
        );
        let file = self.files.get(sector_index as usize).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "No files entry for this rayon sector index thread",
            )
        })?;
        file.write_all_at(buf, 0)
    }
}

impl RayonFilesManger {
    /// Open file at specified as many times as there is number of threads in current [`rayon`]
    /// thread pool.
    pub fn open(directory: &Path, target_sector_count: u16) -> io::Result<Self> {
        let files = (0..target_sector_count)
            .map(|sector_index| {
                let path = format!("{}/{:?}", directory.display(), sector_index);
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .advise_random_access()
                    .open(path)?;
                file.advise_random_access()?;

                Ok::<_, io::Error>(file)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { files })
    }
}
