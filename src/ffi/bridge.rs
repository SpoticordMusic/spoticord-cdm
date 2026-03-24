use std::{
    collections::{HashMap, VecDeque},
    ffi::c_void,
    sync::{Condvar, Mutex, MutexGuard},
};

use crate::{
    ffi::cdm,
    promises::{NewSessionPromise, OnInitializedPromise, PromiseRegistry, StandardPromise},
};

#[derive(Debug)]
pub struct CdmSessionMessage {
    pub message_type: cdm::MessageType,
    pub message: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CdmKeyInfo {
    pub key_id: Vec<u8>,
    pub status: cdm::KeyStatus,
    pub system_code: u32,
}

impl AsRef<[u8]> for CdmKeyInfo {
    fn as_ref(&self) -> &[u8] {
        &self.key_id
    }
}

pub struct HostContext {
    messages: Mutex<HashMap<String, VecDeque<CdmSessionMessage>>>,
    keys: Mutex<HashMap<String, Vec<CdmKeyInfo>>>,
    cv: Condvar,

    promises: PromiseRegistry,
}

impl HostContext {
    pub fn new() -> Self {
        Self {
            messages: Mutex::new(HashMap::new()),
            keys: Mutex::new(HashMap::new()),
            cv: Condvar::new(),

            promises: PromiseRegistry::new(),
        }
    }

    pub fn messages<'a>(&'a self) -> MutexGuard<'a, HashMap<String, VecDeque<CdmSessionMessage>>> {
        self.messages.lock().unwrap()
    }

    pub fn keys<'a>(&'a self) -> MutexGuard<'a, HashMap<String, Vec<CdmKeyInfo>>> {
        self.keys.lock().unwrap()
    }

    pub fn cv(&self) -> &Condvar {
        &self.cv
    }

    pub fn promises(&self) -> &PromiseRegistry {
        &self.promises
    }
}

// C++ -> Rust bridge functions

#[unsafe(no_mangle)]
unsafe extern "C" fn rs_on_initialized(context: *const HostContext, success: bool) {
    let context = unsafe { &*context };

    context
        .promises
        .resolve::<OnInitializedPromise>(PromiseRegistry::PROMISE_ID_INITIALIZE, success);
}

#[unsafe(no_mangle)]
extern "C" fn rs_on_resolve_promise(context: *const HostContext, promise_id: u32) {
    let context = unsafe { &*context };

    context.promises.resolve::<StandardPromise>(promise_id, ());
}

#[unsafe(no_mangle)]
extern "C" fn rs_on_resolve_session_promise(
    context: *const HostContext,
    promise_id: u32,
    session_id: *const u8,
    session_id_size: u32,
) {
    let context = unsafe { &*context };
    if session_id.is_null() {
        context.promises.reject(
            promise_id,
            cdm::Exception::kExceptionInvalidStateError,
            0,
            Some("Session ID was null".into()),
        );

        return;
    }

    let session_id = unsafe {
        String::from_utf8_lossy(std::slice::from_raw_parts(session_id, session_id_size as _))
            .into_owned()
    };

    context
        .promises
        .resolve::<NewSessionPromise>(promise_id, session_id);
}

#[unsafe(no_mangle)]
extern "C" fn rs_on_reject_promise(
    context: *mut HostContext,
    promise_id: u32,
    exception: cdm::Exception,
    system_code: u32,
    error_message: *const u8,
    error_message_size: u32,
) {
    let context = unsafe { &*context };
    let message = unsafe {
        if error_message_size == 0 || error_message.is_null() {
            None
        } else {
            Some(
                String::from_utf8_lossy(std::slice::from_raw_parts(
                    error_message,
                    error_message_size as _,
                ))
                .into_owned(),
            )
        }
    };

    context
        .promises
        .reject(promise_id, exception, system_code, message);
}

#[unsafe(no_mangle)]
extern "C" fn rs_on_session_message(
    context: *const HostContext,
    session_id: *const u8,
    session_id_size: u32,
    message_type: cdm::MessageType,
    message: *const u8,
    message_size: u32,
) {
    let context = unsafe { &*context };
    let session_id = unsafe {
        String::from_utf8_lossy(std::slice::from_raw_parts(session_id, session_id_size as _))
            .into_owned()
    };
    let message = unsafe { std::slice::from_raw_parts(message, message_size as _).to_vec() };

    let mut messages = context.messages.lock().unwrap();
    messages
        .entry(session_id)
        .or_insert_with(|| VecDeque::new())
        .push_back(CdmSessionMessage {
            message_type,
            message,
        });

    context.cv.notify_one();
}

#[unsafe(no_mangle)]
unsafe extern "C" fn rs_on_session_keys_change(
    context: *const HostContext,
    session_id: *const u8,
    session_id_size: u32,
    _has_additional_usable_key: bool,
    keys_info: *const cdm::KeyInformation,
    keys_info_count: u32,
) {
    let context = unsafe { &*context };
    let session_id = unsafe {
        String::from_utf8_lossy(std::slice::from_raw_parts(session_id, session_id_size as _))
            .into_owned()
    };

    let keys_infos = unsafe { std::slice::from_raw_parts(keys_info, keys_info_count as _) };
    let keys = keys_infos
        .into_iter()
        .map(|info| CdmKeyInfo {
            key_id: unsafe {
                std::slice::from_raw_parts(info.key_id, info.key_id_size as _).to_vec()
            },
            status: info.status,
            system_code: info.system_code,
        })
        .collect();

    context.keys.lock().unwrap().insert(session_id, keys);
}

// Rust -> C++ bridge functions

unsafe extern "C" {
    pub unsafe fn cdm_module_initialize(proc: *mut c_void);

    pub unsafe fn cdm_create_host(context: *mut c_void) -> *mut c_void;
    pub unsafe fn cdm_get_version(proc: *mut c_void) -> *const i8;

    pub unsafe fn cdm_create_instance(proc: *mut c_void, host: *mut c_void) -> *mut c_void;
    pub unsafe fn cdm_instance_initialize(
        cdm: *mut c_void,
        allow_distinctive_identifier: bool,
        allow_persistent_state: bool,
        use_hw_secure_codecs: bool,
    );
    pub unsafe fn cdm_set_server_certificate(
        cdm: *mut c_void,
        promise_id: u32,
        server_certificate_data: *const u8,
        server_certificate_data_size: u32,
    );
    pub unsafe fn cdm_create_session(
        cdm: *mut c_void,
        promise_id: u32,
        init_data: *const u8,
        init_data_size: u32,
    );
    pub unsafe fn cdm_update_session(
        cdm: *mut c_void,
        promise_id: u32,
        session_id: *const u8,
        session_id_size: u32,
        response: *const u8,
        response_size: u32,
    );
    pub unsafe fn cdm_session_decrypt(
        cdm: *mut c_void,
        encrypted_buffer: *const cdm::InputBuffer_2,
        decrypted_buffer: *mut *mut c_void,
    ) -> cdm::Status;
    pub unsafe fn cdm_close_session(
        cdm: *mut c_void,
        promise_id: u32,
        session_id: *const u8,
        session_id_size: u32,
    );

    pub unsafe fn cdm_decrypted_block_data(
        block: *mut c_void,
        data: *mut *const u8,
        data_size: *mut u32,
    );
    pub unsafe fn cdm_decrypted_block_free(block: *mut c_void);
}
