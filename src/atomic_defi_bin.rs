#![feature(non_ascii_idents)]
#![feature(drain_filter)]
#![recursion_limit = "512"]

#[macro_use] extern crate common;
#[macro_use] extern crate fomat_macros;
#[macro_use] extern crate gstuff;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serialization_derive;
#[macro_use] extern crate unwrap;

#[path = "atomic_defi.rs"] mod atomic_defi;

fn main() {
    #[cfg(feature = "native")]
    {
        atomic_defi::atomic_defi_main()
    }
}
