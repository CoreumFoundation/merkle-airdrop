use cosmwasm_schema::cw_serde;

use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::{Item, Map};
use cw_utils::{Expiration, Scheduled};

/// Top level storage key. Values must not conflict.
/// Each key is only one byte long to ensure we use the smallest possible storage keys.
#[repr(u8)]
pub enum TopKey {
    Config = b'1',
    LatestStage = b'2',
    StageExpiration = b'3',
    StageStart = b'4',
    StageAmount = b'5',
    StageAmountClaimed = b'6',
    StageAccountMap = b'7',
    MerkleRoot = b'8',
    Claim = b'9',
    ClaimedAmount = b'a',
    HrpPrefix = b'b',
    StagePaused = b'c',
}

impl TopKey {
    const fn as_str(&self) -> &str {
        let array_ref = unsafe { std::mem::transmute::<_, &[u8; 1]>(self) };
        match core::str::from_utf8(array_ref) {
            Ok(a) => a,
            Err(_) => panic!("Non-utf8 enum value found. Use a-z, A-Z and 0-9"),
        }
    }
}
#[cw_serde]
pub struct Config {
    /// Owner If None set, contract is frozen.
    pub owner: Option<Addr>,
    pub native_token: String,
}

pub const CONFIG: Item<Config> = Item::new(TopKey::Config.as_str());
pub const LATEST_STAGE: Item<u8> = Item::new(TopKey::LatestStage.as_str());
pub const STAGE_EXPIRATION: Map<u8, Expiration> = Map::new(TopKey::StageExpiration.as_str());
pub const STAGE_START: Map<u8, Scheduled> = Map::new(TopKey::StageStart.as_str());
pub const STAGE_AMOUNT: Map<u8, Uint128> = Map::new(TopKey::StageAmount.as_str());
pub const STAGE_AMOUNT_CLAIMED: Map<u8, Uint128> = Map::new(TopKey::StageAmountClaimed.as_str());
pub const STAGE_ACCOUNT_MAP: Map<(u8, String), String> = Map::new(TopKey::StageAccountMap.as_str());
pub const MERKLE_ROOT: Map<u8, String> = Map::new(TopKey::MerkleRoot.as_str());
pub const CLAIM: Map<(String, u8), bool> = Map::new(TopKey::Claim.as_str());
pub const CLAIMED_AMOUNT: Map<(&Addr, u8), bool> = Map::new(TopKey::ClaimedAmount.as_str());
pub const HRP: Map<u8, String> = Map::new(TopKey::HrpPrefix.as_str());
pub const STAGE_PAUSED: Map<u8, bool> = Map::new(TopKey::StagePaused.as_str());
