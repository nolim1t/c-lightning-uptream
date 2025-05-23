// This file is autogenerated by `msggen`
// Do not edit it manually, your changes will be overwritten



use crate::primitives::*;
use serde::{Serialize, Deserialize};
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Notification {
    #[serde(rename = "block_added")]
    BlockAdded(BlockAddedNotification),
    #[serde(rename = "channel_open_failed")]
    ChannelOpenFailed(ChannelOpenFailedNotification),
    #[serde(rename = "channel_opened")]
    ChannelOpened(ChannelOpenedNotification),
    #[serde(rename = "connect")]
    Connect(ConnectNotification),
    #[serde(rename = "custommsg")]
    CustomMsg(CustomMsgNotification),
    #[serde(rename = "channel_state_changed")]
    ChannelStateChanged(ChannelStateChangedNotification),
}


#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockAddedNotification {
    pub hash: Sha256,
    pub height: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChannelOpenFailedNotification {
    pub channel_id: Sha256,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChannelOpenedNotification {
    pub channel_ready: bool,
    pub funding_msat: Amount,
    pub funding_txid: String,
    pub id: PublicKey,
}

/// ['Direction of the connection']
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum ConnectDirection {
    #[serde(rename = "in")]
    IN = 0,
    #[serde(rename = "out")]
    OUT = 1,
}

impl TryFrom<i32> for ConnectDirection {
    type Error = anyhow::Error;
    fn try_from(c: i32) -> Result<ConnectDirection, anyhow::Error> {
        match c {
    0 => Ok(ConnectDirection::IN),
    1 => Ok(ConnectDirection::OUT),
            o => Err(anyhow::anyhow!("Unknown variant {} for enum ConnectDirection", o)),
        }
    }
}

impl ToString for ConnectDirection {
    fn to_string(&self) -> String {
        match self {
            ConnectDirection::IN => "IN",
            ConnectDirection::OUT => "OUT",
        }.to_string()
    }
}

/// ['Type of connection (*torv2*/*torv3* only if **direction** is *out*)']
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum ConnectAddressType {
    #[serde(rename = "local socket")]
    LOCAL_SOCKET = 0,
    #[serde(rename = "ipv4")]
    IPV4 = 1,
    #[serde(rename = "ipv6")]
    IPV6 = 2,
    #[serde(rename = "torv2")]
    TORV2 = 3,
    #[serde(rename = "torv3")]
    TORV3 = 4,
}

impl TryFrom<i32> for ConnectAddressType {
    type Error = anyhow::Error;
    fn try_from(c: i32) -> Result<ConnectAddressType, anyhow::Error> {
        match c {
    0 => Ok(ConnectAddressType::LOCAL_SOCKET),
    1 => Ok(ConnectAddressType::IPV4),
    2 => Ok(ConnectAddressType::IPV6),
    3 => Ok(ConnectAddressType::TORV2),
    4 => Ok(ConnectAddressType::TORV3),
            o => Err(anyhow::anyhow!("Unknown variant {} for enum ConnectAddressType", o)),
        }
    }
}

impl ToString for ConnectAddressType {
    fn to_string(&self) -> String {
        match self {
            ConnectAddressType::LOCAL_SOCKET => "LOCAL_SOCKET",
            ConnectAddressType::IPV4 => "IPV4",
            ConnectAddressType::IPV6 => "IPV6",
            ConnectAddressType::TORV2 => "TORV2",
            ConnectAddressType::TORV3 => "TORV3",
        }.to_string()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConnectAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket: Option<String>,
    // Path `connect.address.type`
    #[serde(rename = "type")]
    pub item_type: ConnectAddressType,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConnectNotification {
    // Path `connect.direction`
    pub direction: ConnectDirection,
    pub address: ConnectAddress,
    pub id: PublicKey,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CustomMsgNotification {
    pub payload: String,
    pub peer_id: PublicKey,
}

/// ['The cause of the state change.']
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum ChannelStateChangedCause {
    #[serde(rename = "unknown")]
    UNKNOWN = 0,
    #[serde(rename = "local")]
    LOCAL = 1,
    #[serde(rename = "user")]
    USER = 2,
    #[serde(rename = "remote")]
    REMOTE = 3,
    #[serde(rename = "protocol")]
    PROTOCOL = 4,
    #[serde(rename = "onchain")]
    ONCHAIN = 5,
}

impl TryFrom<i32> for ChannelStateChangedCause {
    type Error = anyhow::Error;
    fn try_from(c: i32) -> Result<ChannelStateChangedCause, anyhow::Error> {
        match c {
    0 => Ok(ChannelStateChangedCause::UNKNOWN),
    1 => Ok(ChannelStateChangedCause::LOCAL),
    2 => Ok(ChannelStateChangedCause::USER),
    3 => Ok(ChannelStateChangedCause::REMOTE),
    4 => Ok(ChannelStateChangedCause::PROTOCOL),
    5 => Ok(ChannelStateChangedCause::ONCHAIN),
            o => Err(anyhow::anyhow!("Unknown variant {} for enum ChannelStateChangedCause", o)),
        }
    }
}

impl ToString for ChannelStateChangedCause {
    fn to_string(&self) -> String {
        match self {
            ChannelStateChangedCause::UNKNOWN => "UNKNOWN",
            ChannelStateChangedCause::LOCAL => "LOCAL",
            ChannelStateChangedCause::USER => "USER",
            ChannelStateChangedCause::REMOTE => "REMOTE",
            ChannelStateChangedCause::PROTOCOL => "PROTOCOL",
            ChannelStateChangedCause::ONCHAIN => "ONCHAIN",
        }.to_string()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChannelStateChangedNotification {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_state: Option<ChannelState>,
    // Path `channel_state_changed.cause`
    pub cause: ChannelStateChangedCause,
    // Path `channel_state_changed.new_state`
    pub new_state: ChannelState,
    pub channel_id: Sha256,
    pub message: String,
    pub peer_id: PublicKey,
    pub short_channel_id: ShortChannelId,
    pub timestamp: String,
}

pub mod requests{
use serde::{Serialize, Deserialize};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct StreamBlockAddedRequest {
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct StreamChannelOpenFailedRequest {
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct StreamChannelOpenedRequest {
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct StreamConnectRequest {
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct StreamCustomMsgRequest {
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct StreamChannelStateChangedRequest {
    }

}
