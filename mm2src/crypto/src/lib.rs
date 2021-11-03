#[macro_use]
extern crate serde_derive;

mod hw_client;
mod crypto_ctx;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
