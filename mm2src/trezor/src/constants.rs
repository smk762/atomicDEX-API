use derive_more::Display;

#[derive(Clone, Copy, Debug, Display)]
pub enum TrezorCoin {
    Bitcoin,
    Komodo,
    Qtum,
}
