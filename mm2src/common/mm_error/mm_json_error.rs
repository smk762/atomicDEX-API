use crate::mm_error::{MmError, NotMmError};
use ser_error::SerializeErrorType;
use serde_json::{self as json, Error as JsonError, Value as Json};
use std::fmt;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MmJsonError(Json);

impl fmt::Display for MmJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0.to_string()) }
}

/// We are sure that `MmJsonError` is constructed from a type that implements `SerializeErrorTypeImpl`.
/// See [`MmJsonError::from`].
impl ser_error::__private::SerializeErrorTypeImpl for MmJsonError {}

impl MmJsonError {
    pub fn new<E: SerializeErrorType>(error: E) -> Result<MmJsonError, JsonError> {
        json::to_value(error).map(MmJsonError)
    }

    pub fn from_mm_error<E: SerializeErrorType + NotMmError>(
        error: MmError<E>,
    ) -> Result<MmError<MmJsonError>, JsonError> {
        let (etype, trace) = error.split();
        let etype_json = MmJsonError::new(etype)?;
        Ok(MmError::new_with_trace(etype_json, trace))
    }
}
