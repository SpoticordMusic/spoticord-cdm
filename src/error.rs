use thiserror::Error;

use crate::ffi::cdm;

#[derive(Error, Debug)]
pub enum Error {
    #[error("The CDM library has not yet been initialized")]
    NotInitialized,

    #[error("The CDM instance failed to initialize")]
    InitializationError,

    #[error("A promise was unexpectedly dropped before it was resolved or rejected")]
    PromiseDropped,

    #[error("A promise was rejected: {exception:?}")]
    PromiseRejection {
        exception: cdm::Exception,
        system_code: u32,
        message: Option<String>,
    },

    #[error("Decoder needs more data to produce a decoded frame/sample")]
    NeedMoreData,

    #[error("The required decryption key is not available")]
    NoKey,

    #[error("Decryption failed")]
    DecryptError,

    #[error("Error decoding audio or video")]
    DecodeError,

    #[error("Decoder is not ready for initialization")]
    DeferredInitialization,

    #[error(transparent)]
    LoadError(#[from] libloading::Error),
}

impl Error {
    pub fn promise_rejection(
        exception: cdm::Exception,
        system_code: u32,
        message: Option<String>,
    ) -> Self {
        Self::PromiseRejection {
            exception,
            system_code,
            message,
        }
    }
}
