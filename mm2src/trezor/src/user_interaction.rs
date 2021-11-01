#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "interaction")]
#[serde(rename_all = "lowercase")]
pub enum TrezorUserInteraction {
    ButtonRequest,
    PinMatrix3x3,
    PlugInDevice,
}

/// Use the numeric keypad to describe number positions.
/// The layout is:
/// 7 8 9
/// 4 5 6
/// 1 2 3
#[derive(Debug, Deserialize, Serialize)]
pub struct TrezorPinMatrix3x3Response {
    pub sequence: String,
}
