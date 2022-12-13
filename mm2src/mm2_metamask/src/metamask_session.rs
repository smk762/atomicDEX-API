use crate::metamask::Metamask;
use futures::lock::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use web3::{Transport, Web3};

lazy_static::lazy_static! {
    static ref METAMASK_MUTEX: AsyncMutex<()> = AsyncMutex::new(());
}

pub struct MetamaskSession<'a, T> {
    metamask: Metamask<T>,
    _guard: AsyncMutexGuard<'a, ()>,
}

impl<'a, T: Transport> MetamaskSession<'a, T> {
    /// Locks the global `METAMASK_MUTEX` to prevent simultaneously requests.
    pub async fn lock(web3: &'a Web3<T>) -> MetamaskSession<'a, T> {
        MetamaskSession {
            metamask: Metamask::new(web3.transport().clone()),
            _guard: METAMASK_MUTEX.lock().await,
        }
    }

    pub fn metamask(&self) -> &Metamask<T> { &self.metamask }
}
