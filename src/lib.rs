mod error;
pub mod ffi;
mod loading;
mod promises;

use std::{
    ffi::{CStr, c_void},
    fmt::Debug,
    path::Path,
    ptr::{null, null_mut},
};

use crate::{
    ffi::{
        bridge::{
            self, CdmKeyInfo, CdmSessionMessage, HostContext, cdm_decrypted_block_data,
            cdm_decrypted_block_free, cdm_session_decrypt,
        },
        cdm,
    },
    promises::{NewSessionPromise, OnInitializedPromise, PromiseRegistry, StandardPromise},
};

pub fn initialize(path: impl AsRef<Path>) -> Result<(), error::Error> {
    let cdm = loading::initialize_cdm(path)?;

    unsafe {
        bridge::cdm_module_initialize(cdm.initialize_cdm_module as _);
    }

    Ok(())
}

pub enum EncryptedData<'a, 'b> {
    Cenc(&'a [u8], &'b [cdm::SubsampleEntry]),
    Cbcs(&'a [u8], cdm::Pattern),
    Unencrypted(&'a [u8]),
}

impl<'a, 'b> EncryptedData<'a, 'b> {
    pub fn cenc(data: &'a [u8], subsamples: &'b [cdm::SubsampleEntry]) -> Self {
        Self::Cenc(data.as_ref(), subsamples)
    }

    pub fn cbcs(data: &'a [u8], pattern: cdm::Pattern) -> Self {
        Self::Cbcs(data, pattern)
    }

    pub fn unencrypted(data: &'a [u8]) -> Self {
        Self::Unencrypted(data)
    }

    pub fn encryption_scheme(&self) -> cdm::EncryptionScheme {
        match self {
            Self::Cenc(_, _) => cdm::EncryptionScheme::kCenc,
            Self::Cbcs(_, _) => cdm::EncryptionScheme::kCbcs,
            Self::Unencrypted(_) => cdm::EncryptionScheme::kUnencrypted,
        }
    }

    pub fn data(&self) -> &'a [u8] {
        match self {
            Self::Cenc(data, _) => data,
            Self::Cbcs(data, _) => data,
            Self::Unencrypted(data) => data,
        }
    }
}

pub struct CdmInstance {
    cdm: *mut c_void,
    context: *const HostContext,
}

impl CdmInstance {
    pub fn create() -> Result<Self, error::Error> {
        let cdm = loading::get_cdm().ok_or(error::Error::NotInitialized)?;

        let host_context = Box::new(HostContext::new());
        let promise = host_context
            .promises()
            .create_with_id::<OnInitializedPromise>(PromiseRegistry::PROMISE_ID_INITIALIZE);

        let host_context_ptr = Box::into_raw(host_context) as *mut c_void;
        let host = unsafe { bridge::cdm_create_host(host_context_ptr) };

        let instance = Self {
            cdm: unsafe { bridge::cdm_create_instance(cdm.create_cdm_instance as _, host) },
            context: host_context_ptr as _,
        };

        unsafe { bridge::cdm_instance_initialize(instance.cdm, false, false, false) };

        if !promise.recv().map_err(|_| error::Error::PromiseDropped)?? {
            return Err(error::Error::InitializationError);
        };

        Ok(instance)
    }

    // TODO: I'm uncertain about thread safety here. Should we enforce &mut self in all our functions?

    pub fn set_server_certificate(&self, data: impl AsRef<[u8]>) -> Result<(), error::Error> {
        let context = unsafe { &*self.context };
        let (id, rx) = context.promises().create::<StandardPromise>();

        let server_certificate_data = data.as_ref();
        let server_certificate_data_size = server_certificate_data.len() as u32;

        unsafe {
            bridge::cdm_set_server_certificate(
                self.cdm,
                id,
                server_certificate_data.as_ptr(),
                server_certificate_data_size,
            )
        };

        rx.recv().map_err(|_| error::Error::PromiseDropped)?
    }

    pub fn create_session<'a>(
        &'a self,
        init_data: impl AsRef<[u8]>,
    ) -> Result<(CdmSession<'a>, CdmSessionMessage), error::Error> {
        let context = unsafe { &*self.context };
        let (id, rx) = context.promises().create::<NewSessionPromise>();

        let init_data = init_data.as_ref();
        let init_data_size = init_data.len() as u32;

        unsafe {
            bridge::cdm_create_session(self.cdm, id, init_data.as_ptr(), init_data_size);
        }

        let session_id = rx.recv().map_err(|_| error::Error::PromiseDropped)??;
        let session = CdmSession::new(self, session_id.clone());
        let initial_message = session.next_message();

        Ok((session, initial_message))
    }

    pub fn update_session(
        &self,
        session_id: &str,
        response: impl AsRef<[u8]>,
    ) -> Result<(), error::Error> {
        let context = unsafe { &*self.context };
        let (id, rx) = context.promises().create::<StandardPromise>();

        let response = response.as_ref();
        let response_size = response.len() as u32;

        unsafe {
            bridge::cdm_update_session(
                self.cdm,
                id,
                session_id.as_ptr(),
                session_id.len() as _,
                response.as_ptr(),
                response_size,
            );
        }

        rx.recv().map_err(|_| error::Error::PromiseDropped)??;

        Ok(())
    }

    pub fn decrypt(
        &self,
        encrypted: EncryptedData<'_, '_>,
        iv: impl AsRef<[u8]>,
        key_id: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, error::Error> {
        let data = encrypted.data();
        let iv = iv.as_ref();
        let key_id = key_id.as_ref();

        let mut input = cdm::InputBuffer_2 {
            data: data.as_ptr(),
            data_size: data.len() as _,

            iv: iv.as_ptr(),
            iv_size: iv.len() as _,

            key_id: key_id.as_ptr(),
            key_id_size: key_id.len() as _,

            encryption_scheme: encrypted.encryption_scheme(),

            ..Default::default()
        };

        match encrypted {
            EncryptedData::Cbcs(_, pattern) => {
                input.pattern = pattern;
            }

            EncryptedData::Cenc(_, subsamples) => {
                input.subsamples = subsamples.as_ptr();
                input.num_subsamples = subsamples.len() as _;
            }

            EncryptedData::Unencrypted(_) => {}
        }

        let mut decrypted = null_mut();
        let status = unsafe { cdm_session_decrypt(self.cdm, &input, &mut decrypted) };

        match status {
            cdm::Status::kSuccess => {}
            cdm::Status::kDecodeError => return Err(error::Error::DecodeError),
            cdm::Status::kDecryptError => return Err(error::Error::DecryptError),
            cdm::Status::kDeferredInitialization => {
                return Err(error::Error::DeferredInitialization);
            }
            cdm::Status::kInitializationError => return Err(error::Error::InitializationError),
            cdm::Status::kNeedMoreData => return Err(error::Error::NeedMoreData),
            cdm::Status::kNoKey => return Err(error::Error::NoKey),
        }

        let mut data = null();
        let mut size = 0;

        unsafe { cdm_decrypted_block_data(decrypted, &mut data, &mut size) };

        // TODO: We could potentially wrap the slice in a struct and only call free when that struct is dropped, which would save an extra allocation
        let plaintext = unsafe { std::slice::from_raw_parts(data, size as _).to_vec() };

        unsafe { cdm_decrypted_block_free(decrypted) };

        Ok(plaintext)
    }

    fn close_session(&self, session_id: &str) -> Result<(), error::Error> {
        let context = unsafe { &*self.context };
        let (id, rx) = context.promises().create::<NewSessionPromise>();

        unsafe {
            bridge::cdm_close_session(self.cdm, id, session_id.as_ptr(), session_id.len() as _);
        }

        rx.recv().map_err(|_| error::Error::PromiseDropped)??;

        Ok(())
    }
}

pub struct CdmSession<'a> {
    cdm: &'a CdmInstance,
    session_id: String,
}

impl<'a> CdmSession<'a> {
    pub fn new(cdm: &'a CdmInstance, session_id: String) -> Self {
        Self { cdm, session_id }
    }

    pub fn update(&self, response: impl AsRef<[u8]>) -> Result<(), error::Error> {
        self.cdm.update_session(&self.session_id, response)
    }

    pub fn next_message(&self) -> CdmSessionMessage {
        let context = unsafe { &*self.cdm.context };
        let mut messages = context.messages();
        loop {
            if let Some(queue) = messages.get_mut(&self.session_id) {
                if let Some(msg) = queue.pop_front() {
                    return msg;
                }
            }
            messages = context.cv().wait(messages).unwrap();
        }
    }

    pub fn keys(&self) -> Vec<CdmKeyInfo> {
        let context = unsafe { &*self.cdm.context };

        context
            .keys()
            .get(&self.session_id)
            .cloned()
            .unwrap_or_else(|| Vec::new())
    }
}

impl<'a> Drop for CdmSession<'a> {
    fn drop(&mut self) {
        _ = self.cdm.close_session(&self.session_id);
    }
}

impl<'a> Debug for CdmSession<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CdmSession")
            .field("session_id", &self.session_id)
            .finish()
    }
}

pub fn cdm_version() -> Result<String, error::Error> {
    let cdm = loading::get_cdm().ok_or(error::Error::NotInitialized)?;
    let version = unsafe { CStr::from_ptr(bridge::cdm_get_version(cdm.get_cdm_version as _)) }
        .to_string_lossy();

    Ok(version.into_owned())
}
