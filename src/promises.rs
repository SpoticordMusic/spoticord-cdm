use std::{
    any::Any,
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicU32, Ordering},
    },
};

use oneshot::Receiver;

use crate::ffi::cdm;

pub trait Promise: 'static {
    type Result: Send + 'static;
}

trait ErasedPromise: Send {
    fn reject(self: Box<Self>, err: crate::error::Error);
    fn as_any(self: Box<Self>) -> Box<dyn Any + Send>;
}

struct PromiseHolder<T> {
    sender: oneshot::Sender<Result<T, crate::error::Error>>,
}

impl<T: Send + 'static> ErasedPromise for PromiseHolder<T> {
    fn reject(self: Box<Self>, err: crate::error::Error) {
        _ = self.sender.send(Err(err));
    }

    fn as_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

pub struct PromiseRegistry {
    next_id: AtomicU32,
    promises: Mutex<HashMap<u32, Box<dyn ErasedPromise>>>,
}

impl PromiseRegistry {
    pub const PROMISE_ID_INITIALIZE: u32 = u32::MAX - 1;

    pub fn new() -> Self {
        Self {
            next_id: AtomicU32::new(0),
            promises: Mutex::new(HashMap::new()),
        }
    }

    fn next_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn create<P: Promise>(&self) -> (u32, Receiver<Result<P::Result, crate::error::Error>>) {
        let id = self.next_id();

        (id, self.create_with_id::<P>(id))
    }

    pub fn create_with_id<P: Promise>(
        &self,
        id: u32,
    ) -> Receiver<Result<P::Result, crate::error::Error>> {
        let (tx, rx) = oneshot::channel();
        let holder = PromiseHolder { sender: tx };
        self.promises.lock().unwrap().insert(id, Box::new(holder));

        rx
    }

    pub fn resolve<P: Promise>(&self, id: u32, result: P::Result) {
        if let Some(promise) = self.promises.lock().unwrap().remove(&id) {
            let boxed_any = promise.as_any();

            if let Ok(holder) = boxed_any.downcast::<PromiseHolder<P::Result>>() {
                _ = holder.sender.send(Ok(result));
            }
        }
    }

    pub fn reject(
        &self,
        id: u32,
        exception: cdm::Exception,
        system_code: u32,
        message: Option<String>,
    ) {
        if let Some(promise) = self.promises.lock().unwrap().remove(&id) {
            promise.reject(crate::error::Error::promise_rejection(
                exception,
                system_code,
                message,
            ));
        }
    }
}

pub struct StandardPromise;
pub struct OnInitializedPromise;
pub struct NewSessionPromise;

impl Promise for StandardPromise {
    type Result = ();
}

impl Promise for OnInitializedPromise {
    type Result = bool;
}

impl Promise for NewSessionPromise {
    type Result = String;
}
