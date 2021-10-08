#[cfg(test)]
mod tests;

use parity_scale_codec::{Decode, Encode};
use rocksdb::DB;
use std::path::Path;
use std::sync::Arc;
use subspace_core_primitives::objects::GlobalObject;
use subspace_core_primitives::Sha256Hash;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum ObjectMappingError {
    #[error("DB error: {0}")]
    Db(rocksdb::Error),
}

#[derive(Debug, Clone)]
pub(super) struct ObjectMappings {
    db: Arc<DB>,
}

impl ObjectMappings {
    /// Creates a new object mappings database
    pub(super) fn new(path: &Path) -> Result<Self, ObjectMappingError> {
        let db = DB::open_default(path).map_err(ObjectMappingError::Db)?;

        Ok(Self { db: Arc::new(db) })
    }

    // TODO: Remove suppression once we start using this
    #[allow(dead_code)]
    /// Retrieve mapping for object
    pub(super) fn retrieve(
        &self,
        object_id: &Sha256Hash,
    ) -> Result<Option<GlobalObject>, ObjectMappingError> {
        Ok(self
            .db
            .get(object_id)
            .map_err(ObjectMappingError::Db)?
            .and_then(|global_object| GlobalObject::decode(&mut global_object.as_ref()).ok()))
    }

    /// Store object mappings in database
    pub(super) fn store(
        &self,
        object_mapping: &[(Sha256Hash, GlobalObject)],
    ) -> Result<(), ObjectMappingError> {
        let mut tmp = Vec::new();

        for (object_id, global_object) in object_mapping {
            global_object.encode_to(&mut tmp);
            self.db
                .put(object_id, &tmp)
                .map_err(ObjectMappingError::Db)?;

            tmp.clear();
        }

        Ok(())
    }
}
