use common::log::{error, info};
use inquire::{validator::Validation, Confirm, CustomType, CustomUserError, Password, Text};
use serde::Serialize;
use std::net::Ipv4Addr;
use std::ops::Not;
use std::path::Path;

use super::helpers;
use super::inquire_extentions::{InquireOption, DEFAULT_DEFAULT_OPTION_BOOL_FORMATTER, DEFAULT_OPTION_BOOL_FORMATTER,
                                OPTION_BOOL_PARSER};
use common::password_policy;

const DEFAULT_NET_ID: u16 = 7777;
const DEFAULT_GID: &str = concat!("QA CLI ", env!("CARGO_PKG_VERSION"));
const DEFAULT_OPTION_PLACEHOLDER: &str = "Tap enter to skip";

pub fn init_mm2_cfg(cfg_file: &str) -> Result<(), ()> {
    let mut mm2_cfg = Mm2Cfg::new();
    info!("Start collecting mm2_cfg into: {cfg_file}");
    mm2_cfg.inquire()?;
    helpers::rewrite_json_file(&mm2_cfg, cfg_file)?;
    info!("mm2_cfg has been writen into: {cfg_file}");

    Ok(())
}

#[derive(Serialize)]
pub struct Mm2Cfg {
    pub gui: Option<String>,
    pub net_id: Option<u16>,
    pub rpc_password: Option<String>,
    pub passphrase: Option<String>,
    pub allow_weak_password: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userhome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dbdir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpcip: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpcport: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_local_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i_am_seed: Option<bool>,
    #[serde(skip_serializing_if = "Vec::<Ipv4Addr>::is_empty")]
    pub seednodes: Vec<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hd_account_id: Option<u64>,
}

impl Mm2Cfg {
    pub fn new() -> Mm2Cfg {
        Mm2Cfg {
            gui: None,
            net_id: None,
            rpc_password: None,
            passphrase: None,
            allow_weak_password: None,
            userhome: None,
            dbdir: None,
            rpcip: None,
            rpcport: None,
            rpc_local_only: None,
            i_am_seed: None,
            seednodes: Vec::<Ipv4Addr>::new(),
            hd_account_id: None,
        }
    }

    fn inquire(&mut self) -> Result<(), ()> {
        self.inquire_gui()?;
        self.inquire_net_id()?;
        self.inquire_passphrase()?;
        self.inquire_rpc_password()?;
        self.inquire_allow_weak_password()?;
        self.inquire_userhome()?;
        self.inquire_dbdir()?;
        self.inquire_rpcip()?;
        self.inquire_rpcport()?;
        self.inquire_rpc_local_only()?;
        self.inquire_i_am_a_seed()?;
        self.inquire_seednodes()?;
        self.inquire_hd_account_id()?;
        Ok(())
    }

    fn inquire_dbdir(&mut self) -> Result<(), ()> {
        let is_reachable_dir = |dbdir: &InquireOption<String>| -> Result<Validation, CustomUserError> {
            match dbdir {
                InquireOption::None => Ok(Validation::Valid),
                InquireOption::Some(dbdir) => {
                    let path = Path::new(dbdir);
                    if path.is_dir().not() {
                        return Ok(Validation::Invalid(
                            format!("\"{dbdir}\" - is not a directory or does not exist").into(),
                        ));
                    }
                    Ok(Validation::Valid)
                },
            }
        };

        self.dbdir = CustomType::<InquireOption<String>>::new("What is dbdir")
            .with_placeholder(DEFAULT_OPTION_PLACEHOLDER)
            .with_help_message("AtomicDEX API database path. Optional, defaults to a subfolder named DB in the path of your mm2 binary")
            .with_validator(is_reachable_dir)
            .prompt()
            .map_err(|error| {
                error!("Failed to get dbdir: {error}");
            })?.into();

        Ok(())
    }

    fn inquire_gui(&mut self) -> Result<(), ()> {
        self.gui = Text::new("What is the client identifier, gui:")
            .with_default(DEFAULT_GID)
            .with_placeholder(DEFAULT_GID)
            .with_help_message("Information about your GUI; place essential info about your application (name, version, etc.) here. For example: AtomicDEX iOS 1.0.1")
            .prompt()
            .map_err(|error| {
                error!("Failed to get gui: {error}");
            })?.into();
        Ok(())
    }

    fn inquire_net_id(&mut self) -> Result<(), ()> {
        self.net_id = CustomType::<u16>::new("What is the network `mm2` is going to be a part, net_id:")
            .with_default(DEFAULT_NET_ID)
            .with_help_message(r#"Nework ID number, telling the AtomicDEX API which network to join. 7777 is the current main network, though alternative netids can be used for testing or "private" trades"#)
            .with_placeholder(format!("{DEFAULT_NET_ID}").as_str())
            .prompt()
            .map_err(|error| {
                error!("Failed to get net_id: {error}");
            })?.into();
        Ok(())
    }

    fn inquire_passphrase(&mut self) -> Result<(), ()> {
        self.passphrase = Password::new("What is the passphrase:")
            .with_validator(Self::pwd_validator)
            .with_help_message("Your passphrase; this is the source of each of your coins private keys. KEEP IT SAFE!")
            .prompt()
            .map_err(|error| {
                error!("Failed to get passphrase: {error}");
            })?
            .into();
        Ok(())
    }

    fn inquire_rpc_password(&mut self) -> Result<(), ()> {
        self.rpc_password = Password::new("What is the rpc_password:")
            .with_validator(Self::pwd_validator)
            .with_help_message("Your password for protected RPC methods (userpass)")
            .prompt()
            .map_err(|error| {
                error!("Failed to get rpc_password: {error}");
            })?
            .into();
        Ok(())
    }

    fn inquire_allow_weak_password(&mut self) -> Result<(), ()> {
        self.allow_weak_password = Confirm::new("Allow weak password:")
            .with_default(false)
            .with_placeholder("No")
            .with_help_message(r#"If true, will allow low entropy rpc_password. If false rpc_password must not have 3 of the same characters in a row, must be between 8-32 characters in length, must contain at least one of each of the following: numeric, uppercase, lowercase, special character (e.g. !#$*). It also can not contain the word "password", or the chars <, >, and &. Defaults to false."#)
            .prompt()
            .map_err(|error| {
                error!("Failed to get allow_weak_password: {error}");
            })?
            .into();
        Ok(())
    }

    fn pwd_validator(pwd: &str) -> Result<Validation, CustomUserError> {
        match password_policy::password_policy(pwd) {
            Err(error) => Ok(Validation::Invalid(error.into())),
            Ok(_) => Ok(Validation::Valid),
        }
    }

    fn inquire_userhome(&mut self) -> Result<(), ()> {
        self.userhome = CustomType::<InquireOption<String>>::new("What is userhome:")
            .with_placeholder(DEFAULT_OPTION_PLACEHOLDER)
            .with_help_message(r#"The path to your home, called from your environment variables and entered as a regular expression. Example: /${HOME#"/"}"#)
            .prompt()
            .map_err(|error| {
                error!("Failed to get userhome: {error}");
            })?.into();
        Ok(())
    }

    fn inquire_rpcip(&mut self) -> Result<(), ()> {
        self.rpcip = CustomType::<InquireOption<Ipv4Addr>>::new("What is rpcip:")
            .with_placeholder(DEFAULT_OPTION_PLACEHOLDER)
            .with_help_message("IP address to bind to for RPC server. Optional, defaults to 127.0.0.1")
            .prompt()
            .map_err(|error| {
                error!("Failed to get rpcip: {error}");
            })?
            .into();
        Ok(())
    }

    fn inquire_rpcport(&mut self) -> Result<(), ()> {
        self.rpcport = CustomType::<InquireOption<u16>>::new("What is the rpcport:")
            .with_help_message(r#"Port to use for RPC communication. Optional, defaults to 7783"#)
            .with_placeholder(DEFAULT_OPTION_PLACEHOLDER)
            .prompt()
            .map_err(|error| {
                error!("Failed to get rpcport: {error}");
            })?
            .into();
        Ok(())
    }

    fn inquire_rpc_local_only(&mut self) -> Result<(), ()> {
        self.rpc_local_only = CustomType::<InquireOption<bool>>::new("What is rpc_local_only:")
            .with_parser(OPTION_BOOL_PARSER)
            .with_formatter(DEFAULT_OPTION_BOOL_FORMATTER)
            .with_default_value_formatter(DEFAULT_DEFAULT_OPTION_BOOL_FORMATTER)
            .with_default(InquireOption::None)
            .with_help_message("If false the AtomicDEX API will allow rpc methods sent from external IP addresses. Optional, defaults to true. Warning: Only use this if you know what you are doing, and have put the appropriate security measures in place.")
            .prompt()
            .map_err(|error| {
                error!("Failed to get rpc_local_only: {error}");
            })?.into();
        Ok(())
    }

    fn inquire_i_am_a_seed(&mut self) -> Result<(), ()> {
        self.i_am_seed = CustomType::<InquireOption<bool>>::new("What is i_am_a_seed:")
            .with_parser(OPTION_BOOL_PARSER)
            .with_formatter(DEFAULT_OPTION_BOOL_FORMATTER)
            .with_default_value_formatter(DEFAULT_DEFAULT_OPTION_BOOL_FORMATTER)
            .with_default(InquireOption::None)
            .with_help_message("Runs AtomicDEX API as a seed node mode (acting as a relay for AtomicDEX API clients). Optional, defaults to false. Use of this mode is not reccomended on the main network (7777) as it could result in a pubkey ban if non-compliant. on alternative testing or private networks, at least one seed node is required to relay information to other AtomicDEX API clients using the same netID.")
            .prompt()
            .map_err(|error| {
                error!("Failed to get i_am_a_seed: {error}");
            })?.into();
        Ok(())
    }

    fn inquire_seednodes(&mut self) -> Result<(), ()> {
        info!("Reading seed nodes until tap enter is met");
        loop {
            let seednode: Option<Ipv4Addr> = CustomType::<InquireOption<Ipv4Addr>>::new("What is next seednode:")
              .with_help_message("Optional. If operating on a test or private netID, the IP address of at least one seed node is required (on the main network, these are already hardcoded)")
              .with_placeholder(DEFAULT_OPTION_PLACEHOLDER)
              .prompt()
              .map_err(|error| {
                  error!("Failed to get seed node: {error}");
              })?.into();
            if seednode.is_none() {
                break;
            }
            self.seednodes.push(seednode.unwrap());
        }
        Ok(())
    }

    fn inquire_hd_account_id(&mut self) -> Result<(), ()> {
        self.hd_account_id = CustomType::<InquireOption<u64>>::new("What is hd_account_id:")
            .with_help_message(r#"Optional. If this value is set, the AtomicDEX-API will work in only the HD derivation mode, coins will need to have a coin derivation path entry in the coins file for activation. The hd_account_id value effectively takes its place in the full derivation as follows: m/44'/COIN_ID'/<hd_account_id>'/CHAIN/ADDRESS_ID"#)
            .with_placeholder(DEFAULT_OPTION_PLACEHOLDER)
            .prompt()
            .map_err(|error| {
                error!("Failed to get hd_account_id: {error}");
            })?
            .into();
        Ok(())
    }
}
