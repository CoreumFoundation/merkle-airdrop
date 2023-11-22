use crate::enumerable::query_all_address_map;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    attr, from_json, to_json_binary, Addr, BankMsg, Binary, Coin, Deps, DepsMut, Env,
    MessageInfo, Response, StdResult, Uint128,
};
use cw2::set_contract_version;
use cw_utils::{Expiration, Scheduled};
use sha2::Digest;
use std::convert::TryInto;

use crate::error::ContractError;
use crate::helpers::CosmosSignature;
use crate::msg::{
    AccountMapResponse, ConfigResponse, ExecuteMsg, InstantiateMsg, IsClaimedResponse,
    IsPausedResponse, LatestStageResponse, MerkleRootResponse, QueryMsg, SignatureInfo,
    TotalClaimedResponse,
};
use crate::state::{
    Config, CLAIM, CONFIG, HRP, LATEST_STAGE, MERKLE_ROOT, STAGE_ACCOUNT_MAP, STAGE_AMOUNT,
    STAGE_AMOUNT_CLAIMED, STAGE_EXPIRATION, STAGE_PAUSED, STAGE_START,
};

// Version info, for migration info
const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let owner = msg
        .owner
        .map_or(Ok(info.sender), |o| deps.api.addr_validate(&o))?;

    let stage = 0;
    LATEST_STAGE.save(deps.storage, &stage)?;

    make_config(deps, Some(owner), msg.native_token)?;

    Ok(Response::new().add_attribute("action", "instantiate_merkle_airdrop_contract"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::UpdateConfig {
            new_owner,
            new_native_token,
        } => execute_update_config(deps, info, new_owner, new_native_token),
        ExecuteMsg::RegisterMerkleRoot {
            merkle_root,
            expiration,
            start,
            total_amount,
            hrp,
        } => execute_register_merkle_root(
            deps,
            info,
            merkle_root,
            expiration,
            start,
            total_amount,
            hrp,
        ),
        ExecuteMsg::Claim {
            stage,
            amount,
            proof,
            sig_info,
        } => execute_claim(deps, env, info, stage, amount, proof, sig_info),
        ExecuteMsg::Burn { stage } => execute_burn(deps, env, info, stage),
        ExecuteMsg::Withdraw { stage, address } => {
            execute_withdraw(deps, env, info, stage, address)
        }
        ExecuteMsg::BurnAll {} => execute_burn_all(deps, env, info),
        ExecuteMsg::WithdrawAll { address, amount } => {
            execute_withdraw_all(deps, env, info, address, amount)
        }
        ExecuteMsg::Pause { stage } => execute_pause(deps, env, info, stage),
        ExecuteMsg::Resume {
            stage,
            new_expiration,
        } => execute_resume(deps, env, info, stage, new_expiration),
    }
}

pub fn make_config(
    deps: DepsMut,
    owner: Option<Addr>,
    native_token: String,
) -> Result<(), ContractError> {
    let config = Config {
        owner,
        native_token,
    };
    CONFIG.save(deps.storage, &config)?;
    Ok(())
}

pub fn execute_update_config(
    deps: DepsMut,
    info: MessageInfo,
    new_owner: Option<String>,
    native_token: String,
) -> Result<Response, ContractError> {
    // authorize owner
    let cfg = CONFIG.load(deps.storage)?;
    let owner = cfg.owner.ok_or(ContractError::Unauthorized {})?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    // if owner some validated to addr, otherwise set to none
    let mut tmp_owner = None;
    if let Some(addr) = new_owner {
        tmp_owner = Some(deps.api.addr_validate(&addr)?)
    }

    make_config(deps, tmp_owner, native_token)?;

    Ok(Response::new().add_attribute("action", "update_config"))
}

pub fn execute_register_merkle_root(
    deps: DepsMut,
    info: MessageInfo,
    merkle_root: String,
    expiration: Option<Expiration>,
    start: Option<Scheduled>,
    total_amount: Option<Uint128>,
    hrp: Option<String>,
) -> Result<Response, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;

    // if owner set validate, otherwise unauthorized
    let owner = cfg.owner.ok_or(ContractError::Unauthorized {})?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    // check merkle root length
    let mut root_buf: [u8; 32] = [0; 32];
    hex::decode_to_slice(&merkle_root, &mut root_buf)?;

    let stage = LATEST_STAGE.update(deps.storage, |stage| -> StdResult<_> { Ok(stage + 1) })?;

    MERKLE_ROOT.save(deps.storage, stage, &merkle_root)?;
    LATEST_STAGE.save(deps.storage, &stage)?;

    // save expiration
    let exp = expiration.unwrap_or(Expiration::Never {});
    STAGE_EXPIRATION.save(deps.storage, stage, &exp)?;

    // save start
    if let Some(start) = start {
        STAGE_START.save(deps.storage, stage, &start)?;
    }

    // save hrp
    if let Some(hrp) = hrp {
        HRP.save(deps.storage, stage, &hrp)?;
    }

    STAGE_PAUSED.save(deps.storage, stage, &false)?;

    // save total airdropped amount
    let amount = total_amount.unwrap_or_else(Uint128::zero);
    STAGE_AMOUNT.save(deps.storage, stage, &amount)?;
    STAGE_AMOUNT_CLAIMED.save(deps.storage, stage, &Uint128::zero())?;

    Ok(Response::new().add_attributes(vec![
        attr("action", "register_merkle_root"),
        attr("stage", stage.to_string()),
        attr("merkle_root", merkle_root),
        attr("total_amount", amount),
    ]))
}

pub fn execute_claim(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    stage: u8,
    amount: Uint128,
    proof: Vec<String>,
    sig_info: Option<SignatureInfo>,
) -> Result<Response, ContractError> {
    // airdrop begun
    let start = STAGE_START.may_load(deps.storage, stage)?;
    if let Some(start) = start {
        if !start.is_triggered(&env.block) {
            return Err(ContractError::StageNotBegun { stage, start });
        }
    }
    // not expired
    let expiration = STAGE_EXPIRATION.load(deps.storage, stage)?;
    if expiration.is_expired(&env.block) {
        return Err(ContractError::StageExpired { stage, expiration });
    }

    let is_paused = STAGE_PAUSED.load(deps.storage, stage)?;
    if is_paused {
        return Err(ContractError::StagePaused { stage });
    }

    // if present verify signature and extract external address or use info.sender as proof
    // if signature is not present in the message, verification will fail since info.sender is not present in the merkle root
    let proof_addr = match sig_info {
        None => info.sender.to_string(),
        Some(sig) => {
            // verify signature
            let cosmos_signature: CosmosSignature = from_json(&sig.signature)?;
            cosmos_signature.verify(deps.as_ref(), &sig.claim_msg)?;
            // get airdrop stage bech32 prefix and derive proof address from public key
            let hrp = HRP.load(deps.storage, stage)?;
            let proof_addr = cosmos_signature.derive_addr_from_pubkey(hrp.as_str())?;

            if sig.extract_addr()? != info.sender {
                return Err(ContractError::VerificationFailed {});
            }

            // Save external address index
            STAGE_ACCOUNT_MAP.save(
                deps.storage,
                (stage, proof_addr.clone()),
                &info.sender.to_string(),
            )?;

            proof_addr
        }
    };

    // verify not claimed
    let claimed = CLAIM.may_load(deps.storage, (proof_addr.clone(), stage))?;
    if claimed.is_some() {
        return Err(ContractError::Claimed {});
    }

    // verify merkle root
    let config = CONFIG.load(deps.storage)?;
    let merkle_root = MERKLE_ROOT.load(deps.storage, stage)?;

    let user_input = format!("{}{}", proof_addr, amount);
    let hash = sha2::Sha256::digest(user_input.as_bytes())
        .as_slice()
        .try_into()
        .map_err(|_| ContractError::WrongLength {})?;

    let hash = proof.into_iter().try_fold(hash, |hash, p| {
        let mut proof_buf = [0; 32];
        hex::decode_to_slice(p, &mut proof_buf)?;
        let mut hashes = [hash, proof_buf];
        hashes.sort_unstable();
        sha2::Sha256::digest(hashes.concat())
            .as_slice()
            .try_into()
            .map_err(|_| ContractError::WrongLength {})
    })?;

    let mut root_buf: [u8; 32] = [0; 32];
    hex::decode_to_slice(merkle_root, &mut root_buf)?;
    if root_buf != hash {
        return Err(ContractError::VerificationFailed {});
    }

    // Update claim index to the current stage
    CLAIM.save(deps.storage, (proof_addr, stage), &true)?;

    // Update total claimed to reflect
    let mut claimed_amount = STAGE_AMOUNT_CLAIMED.load(deps.storage, stage)?;
    claimed_amount += amount;
    STAGE_AMOUNT_CLAIMED.save(deps.storage, stage, &claimed_amount)?;

    let balance = deps
        .querier
        .query_balance(env.contract.address, config.native_token.clone())?;

    if balance.amount < amount {
        return Err(ContractError::InsufficientFunds {
            balance: balance.amount,
            amount,
        });
    }

    let msg = BankMsg::Send {
        to_address: info.sender.to_string(),
        amount: vec![Coin {
            denom: config.native_token.clone(),
            amount,
        }],
    };

    Ok(Response::new().add_message(msg).add_attributes(vec![
        attr("action", "claim"),
        attr("stage", stage.to_string()),
        attr("address", info.sender.to_string()),
        attr("amount", amount),
    ]))
}

pub fn execute_burn(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    stage: u8,
) -> Result<Response, ContractError> {
    // authorize owner
    let cfg = CONFIG.load(deps.storage)?;
    let owner = cfg.owner.ok_or(ContractError::Unauthorized {})?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    // make sure is expired if the stage is not paused
    let is_paused = STAGE_PAUSED.load(deps.storage, stage)?;
    if !is_paused {
        let expiration = STAGE_EXPIRATION.load(deps.storage, stage)?;
        if !expiration.is_expired(&env.block) {
            return Err(ContractError::StageNotExpired { stage, expiration });
        }
    }

    // Get total amount per stage and total claimed
    let total_amount = STAGE_AMOUNT.load(deps.storage, stage)?;
    let claimed_amount = STAGE_AMOUNT_CLAIMED.load(deps.storage, stage)?;

    // impossible but who knows
    if claimed_amount > total_amount {
        return Err(ContractError::Unauthorized {});
    }

    // Get balance
    let balance_to_burn = total_amount - claimed_amount;

    let balance = deps
        .querier
        .query_balance(env.contract.address, cfg.native_token.clone())?;
    if balance.amount < balance_to_burn {
        return Err(ContractError::InsufficientFunds {
            balance: balance.amount,
            amount: balance_to_burn,
        });
    }
    let msg = BankMsg::Burn {
        amount: vec![Coin {
            denom: cfg.native_token.clone(),
            amount: balance_to_burn,
        }],
    };

    Ok(Response::new().add_message(msg).add_attributes(vec![
        attr("action", "burn"),
        attr("stage", stage.to_string()),
        attr("address", info.sender),
        attr("amount", balance_to_burn),
    ]))
}

pub fn execute_withdraw(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    stage: u8,
    address: String,
) -> Result<Response, ContractError> {
    // authorize owner
    let cfg = CONFIG.load(deps.storage)?;
    let owner = cfg.owner.ok_or(ContractError::Unauthorized {})?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    // make sure is expired if the stage is not paused
    let is_paused = STAGE_PAUSED.load(deps.storage, stage)?;
    if !is_paused {
        let expiration = STAGE_EXPIRATION.load(deps.storage, stage)?;
        if !expiration.is_expired(&env.block) {
            return Err(ContractError::StageNotExpired { stage, expiration });
        }
    }

    // Get total amount per stage and total claimed
    let total_amount = STAGE_AMOUNT.load(deps.storage, stage)?;
    let claimed_amount = STAGE_AMOUNT_CLAIMED.load(deps.storage, stage)?;

    // impossible but who knows
    if claimed_amount > total_amount {
        return Err(ContractError::Unauthorized {});
    }

    // Get balance
    let balance_to_withdraw = total_amount - claimed_amount;

    // Validate address
    let recipient = deps.api.addr_validate(&address)?;
    let balance = deps
        .querier
        .query_balance(env.contract.address, cfg.native_token.clone())?;
    if balance.amount < balance_to_withdraw {
        return Err(ContractError::InsufficientFunds {
            balance: balance.amount,
            amount: balance_to_withdraw,
        });
    }
    let msg = BankMsg::Send {
        to_address: recipient.into(),
        amount: vec![Coin {
            denom: cfg.native_token,
            amount: balance_to_withdraw,
        }],
    };

    Ok(Response::new().add_message(msg).add_attributes(vec![
        attr("action", "withdraw"),
        attr("stage", stage.to_string()),
        attr("address", info.sender),
        attr("amount", balance_to_withdraw),
        attr("recipient", address),
    ]))
}

pub fn execute_burn_all(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    // authorize owner
    let cfg = CONFIG.load(deps.storage)?;
    let owner = cfg.owner.ok_or(ContractError::Unauthorized {})?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    // make sure all the stages are either paused or expired
    let latest_stage = LATEST_STAGE.load(deps.storage)?;
    for stage_id in 1..=latest_stage {
        let is_paused = STAGE_PAUSED.load(deps.storage, stage_id)?;
        if !is_paused {
            let expiration = STAGE_EXPIRATION.load(deps.storage, stage_id)?;
            if !expiration.is_expired(&env.block) {
                return Err(ContractError::StageNotExpired {
                    stage: stage_id,
                    expiration,
                });
            }
        }
    }

    // Get the current total balance for the contract
    let total_amount = deps
        .querier
        .query_balance(env.contract.address, cfg.native_token.clone())?
        .amount;

    // Burn the tokens and response
    let msg = BankMsg::Burn {
        amount: vec![Coin {
            denom: cfg.native_token,
            amount: total_amount,
        }],
    };

    Ok(Response::new().add_message(msg).add_attributes(vec![
        attr("action", "burn_all"),
        attr("address", info.sender),
        attr("amount", total_amount),
    ]))
}

pub fn execute_withdraw_all(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    address: String,
    amount: Option<Uint128>,
) -> Result<Response, ContractError> {
    // authorize owner
    let cfg = CONFIG.load(deps.storage)?;
    let owner = cfg.owner.ok_or(ContractError::Unauthorized {})?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    // make sure all the stages are either paused or expired
    let latest_stage = LATEST_STAGE.load(deps.storage)?;
    for stage_id in 1..=latest_stage {
        let is_paused = STAGE_PAUSED.load(deps.storage, stage_id)?;
        if !is_paused {
            let expiration = STAGE_EXPIRATION.load(deps.storage, stage_id)?;
            if !expiration.is_expired(&env.block) {
                return Err(ContractError::StageNotExpired {
                    stage: stage_id,
                    expiration,
                });
            }
        }
    }

    // Get the current total balance for the contract
    let total_amount = deps
        .querier
        .query_balance(env.contract.address, cfg.native_token.clone())?
        .amount;

    let amount_to_withdraw = match amount {
        Some(amount) => {
            if amount > total_amount {
                return Err(ContractError::InsufficientFunds {
                    balance: total_amount,
                    amount,
                });
            }
            amount
        }
        None => total_amount,
    };

    // Validate address
    let recipient = deps.api.addr_validate(&address)?;

    // Withdraw the tokens and return a response
    let msg = BankMsg::Send {
        to_address: recipient.into(),
        amount: vec![Coin {
            denom: cfg.native_token,
            amount: amount_to_withdraw,
        }],
    };

    Ok(Response::new().add_message(msg).add_attributes(vec![
        attr("action", "withdraw_all"),
        attr("address", info.sender),
        attr("amount", amount_to_withdraw),
        attr("recipient", address),
    ]))
}

pub fn execute_pause(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    stage: u8,
) -> Result<Response, ContractError> {
    // authorize owner
    let cfg = CONFIG.load(deps.storage)?;
    let owner = cfg.owner.ok_or(ContractError::Unauthorized {})?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    let start = STAGE_START.may_load(deps.storage, stage)?;
    if let Some(start) = start {
        if !start.is_triggered(&env.block) {
            return Err(ContractError::StageNotBegun { stage, start });
        }
    }

    let expiration = STAGE_EXPIRATION.load(deps.storage, stage)?;
    if expiration.is_expired(&env.block) {
        return Err(ContractError::StageExpired { stage, expiration });
    }

    STAGE_PAUSED.save(deps.storage, stage, &true)?;
    Ok(Response::new().add_attributes(vec![attr("action", "pause"), attr("stage_paused", "true")]))
}

pub fn execute_resume(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    stage: u8,
    new_expiration: Option<Expiration>,
) -> Result<Response, ContractError> {
    // authorize owner
    let cfg = CONFIG.load(deps.storage)?;
    let owner = cfg.owner.ok_or(ContractError::Unauthorized {})?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    let start = STAGE_START.may_load(deps.storage, stage)?;
    if let Some(start) = start {
        if !start.is_triggered(&env.block) {
            return Err(ContractError::StageNotBegun { stage, start });
        }
    }

    let expiration = STAGE_EXPIRATION.load(deps.storage, stage)?;
    if expiration.is_expired(&env.block) {
        return Err(ContractError::StageExpired { stage, expiration });
    }

    let is_paused = STAGE_PAUSED.load(deps.storage, stage)?;
    if !is_paused {
        return Err(ContractError::StageNotPaused { stage });
    }

    if let Some(new_expiration) = new_expiration {
        if new_expiration.is_expired(&env.block) {
            return Err(ContractError::StageExpired { stage, expiration });
        }
        STAGE_EXPIRATION.save(deps.storage, stage, &new_expiration)?;
    }

    STAGE_PAUSED.save(deps.storage, stage, &false)?;
    Ok(Response::new().add_attributes(vec![
        attr("action", "resume"),
        attr("stage_paused", "false"),
    ]))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_json_binary(&query_config(deps)?),
        QueryMsg::MerkleRoot { stage } => to_json_binary(&query_merkle_root(deps, stage)?),
        QueryMsg::LatestStage {} => to_json_binary(&query_latest_stage(deps)?),
        QueryMsg::IsClaimed { stage, address } => {
            to_json_binary(&query_is_claimed(deps, stage, address)?)
        }
        QueryMsg::IsPaused { stage } => to_json_binary(&query_is_paused(deps, stage)?),
        QueryMsg::TotalClaimed { stage } => to_json_binary(&query_total_claimed(deps, stage)?),
        QueryMsg::AccountMap {
            stage,
            external_address,
        } => to_json_binary(&query_address_map(deps, stage, external_address)?),
        QueryMsg::AllAccountMaps {
            stage,
            start_after,
            limit,
        } => to_json_binary(&query_all_address_map(deps, stage, start_after, limit)?),
    }
}

pub fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let cfg = CONFIG.load(deps.storage)?;
    Ok(ConfigResponse {
        owner: cfg.owner.map(|o| o.to_string()),
        native_token: cfg.native_token,
    })
}

pub fn query_merkle_root(deps: Deps, stage: u8) -> StdResult<MerkleRootResponse> {
    let merkle_root = MERKLE_ROOT.load(deps.storage, stage)?;
    let expiration = STAGE_EXPIRATION.load(deps.storage, stage)?;
    let start = STAGE_START.may_load(deps.storage, stage)?;
    let total_amount = STAGE_AMOUNT.load(deps.storage, stage)?;

    let resp = MerkleRootResponse {
        stage,
        merkle_root,
        expiration,
        start,
        total_amount,
    };

    Ok(resp)
}

pub fn query_latest_stage(deps: Deps) -> StdResult<LatestStageResponse> {
    let latest_stage = LATEST_STAGE.load(deps.storage)?;
    let resp = LatestStageResponse { latest_stage };

    Ok(resp)
}

pub fn query_is_claimed(deps: Deps, stage: u8, address: String) -> StdResult<IsClaimedResponse> {
    let is_claimed = CLAIM
        .may_load(deps.storage, (address, stage))?
        .unwrap_or(false);
    let resp = IsClaimedResponse { is_claimed };

    Ok(resp)
}

pub fn query_is_paused(deps: Deps, stage: u8) -> StdResult<IsPausedResponse> {
    let is_paused = STAGE_PAUSED.may_load(deps.storage, stage)?.unwrap_or(false);
    let resp = IsPausedResponse { is_paused };

    Ok(resp)
}

pub fn query_total_claimed(deps: Deps, stage: u8) -> StdResult<TotalClaimedResponse> {
    let total_claimed = STAGE_AMOUNT_CLAIMED.load(deps.storage, stage)?;
    let resp = TotalClaimedResponse { total_claimed };

    Ok(resp)
}

pub fn query_address_map(
    deps: Deps,
    stage: u8,
    external_address: String,
) -> StdResult<AccountMapResponse> {
    let host_address = STAGE_ACCOUNT_MAP.load(deps.storage, (stage, external_address.clone()))?;
    let resp = AccountMapResponse {
        host_address,
        external_address,
    };

    Ok(resp)
}
