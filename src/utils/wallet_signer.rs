use crate::utils::{audit, config, confirmation, crypto, hardware_wallet, print as p};
use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use zeroize::Zeroizing;

/// Describes how a transaction should be signed.
#[derive(Debug, Clone)]
pub struct SigningRequest {
    pub local_secret: Option<Zeroizing<String>>,
    pub hardware: Option<hardware_wallet::HardwareWalletKind>,
    pub hd_path: String,
    pub network: String,
    pub skip_confirm: bool,
    pub wallet_name: Option<String>,
    pub usage_policy: Option<config::WalletUsagePolicy>,
    pub fee_stroops: Option<u64>,
    pub target: SigningTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningTarget {
    Unspecified,
    NonContract,
    Contract(Option<String>),
}

impl SigningRequest {
    /// Build a signing request from CLI flags and an optional local wallet entry.
    pub fn from_options(
        wallet: Option<&config::WalletEntry>,
        hardware: Option<hardware_wallet::HardwareWalletKind>,
        hd_path: Option<&str>,
        network: &str,
        skip_confirm: bool,
        operation_label: &str,
    ) -> Result<Self> {
        let hd_path = hd_path
            .map(str::to_string)
            .unwrap_or_else(|| hardware_wallet::STELLAR_HD_PATH.to_string());

        if let Some(kind) = hardware {
            let public_key = wallet
                .map(|w| w.public_key.as_str())
                .unwrap_or("(derived from device)");
            prompt_hardware_confirmation(kind, public_key, network, skip_confirm, operation_label)?;
            let mut request = Self {
                local_secret: None,
                hardware: Some(kind),
                hd_path,
                network: network.to_string(),
                skip_confirm,
                wallet_name: None,
                usage_policy: None,
                fee_stroops: None,
                target: SigningTarget::Unspecified,
            };
            request.attach_wallet_policy(wallet);
            return Ok(request);
        }

        let wallet = wallet.ok_or_else(|| {
            anyhow::anyhow!(
                "A wallet is required for local signing. Provide --from/--wallet or use --hardware."
            )
        })?;

        enforce_mainnet_plaintext_policy(wallet, network)?;
        let secret = resolve_local_secret(wallet, &wallet.name)?;
        let mut request = Self {
            local_secret: Some(secret),
            hardware: None,
            hd_path,
            network: network.to_string(),
            skip_confirm,
            wallet_name: None,
            usage_policy: None,
            fee_stroops: None,
            target: SigningTarget::Unspecified,
        };
        request.attach_wallet_policy(Some(wallet));
        Ok(request)
    }

    pub fn local_secret(secret_key: Zeroizing<String>, network: &str) -> Self {
        Self {
            local_secret: Some(secret_key),
            hardware: None,
            hd_path: hardware_wallet::STELLAR_HD_PATH.to_string(),
            network: network.to_string(),
            skip_confirm: true,
            wallet_name: None,
            usage_policy: None,
            fee_stroops: None,
            target: SigningTarget::Unspecified,
        }
    }

    pub fn hardware(
        kind: hardware_wallet::HardwareWalletKind,
        hd_path: &str,
        network: &str,
        skip_confirm: bool,
        public_key: &str,
        operation_label: &str,
    ) -> Result<Self> {
        prompt_hardware_confirmation(kind, public_key, network, skip_confirm, operation_label)?;
        Ok(Self {
            local_secret: None,
            hardware: Some(kind),
            hd_path: hd_path.to_string(),
            network: network.to_string(),
            skip_confirm,
            wallet_name: None,
            usage_policy: None,
            fee_stroops: None,
            target: SigningTarget::Unspecified,
        })
    }

    fn attach_wallet_policy(&mut self, wallet: Option<&config::WalletEntry>) {
        if let Some(wallet) = wallet {
            self.wallet_name = Some(wallet.name.clone());
            self.usage_policy = Some(wallet.usage_policy.clone());
        }
    }

    pub fn with_fee_stroops(mut self, fee_stroops: u64) -> Self {
        self.fee_stroops = Some(fee_stroops);
        self
    }

    pub fn with_contract_id(mut self, contract_id: &str) -> Self {
        self.target = SigningTarget::Contract(Some(contract_id.to_string()));
        self
    }

    pub fn for_contract_deploy(mut self) -> Self {
        self.target = SigningTarget::Contract(None);
        self
    }

    pub fn for_non_contract(mut self) -> Self {
        self.target = SigningTarget::NonContract;
        self
    }
}

/// Prompt the user before initiating a hardware wallet signing session.
pub fn prompt_hardware_confirmation(
    kind: hardware_wallet::HardwareWalletKind,
    public_key: &str,
    network: &str,
    skip_confirm: bool,
    operation_label: &str,
) -> Result<()> {
    if skip_confirm {
        return Ok(());
    }

    let summary = confirmation::OperationSummary::new(
        format!("Hardware Wallet — {}", operation_label),
        network.to_string(),
        confirmation::RiskLevel::High,
    )
    .add("Device", kind.to_string())
    .add("Account", public_key)
    .add("Next step", "Review and approve on your device screen");

    let confirm_config = confirmation::ConfirmationConfig {
        risk_level: confirmation::RiskLevel::High,
        network: network.to_string(),
        skip_confirm: false,
        dry_run: false,
        prompt: Some("Proceed with hardware wallet signing?".to_string()),
        require_type_confirmation: network == "mainnet",
        ..Default::default()
    };

    if !confirmation::confirm_operation(&summary, &confirm_config)? {
        anyhow::bail!("Hardware wallet signing cancelled by user");
    }

    p::info(&format!(
        "Connect your {} and approve the {} on the device screen.",
        kind,
        operation_label.to_lowercase()
    ));
    Ok(())
}

/// Resolve a plaintext secret key from a wallet entry, decrypting when needed.
fn enforce_mainnet_plaintext_policy(
    wallet: &config::WalletEntry,
    network: &str,
) -> Result<()> {
    enforce_mainnet_plaintext_policy_with_override(
        wallet,
        network,
        crate::utils::network_guard::allow_plaintext_mainnet(),
    )
}

fn enforce_mainnet_plaintext_policy_with_override(
    wallet: &config::WalletEntry,
    network: &str,
    allow_override: bool,
) -> Result<()> {
    let Some(secret) = wallet.secret_key.as_ref() else {
        return Ok(());
    };

    let plaintext = !secret.contains(':') && secret.starts_with('S') && secret.len() == 56;

    if network != "mainnet" || !plaintext {
        return Ok(());
    }

    if !allow_override {
        anyhow::bail!(
            "Refusing mainnet signing with plaintext wallet '{}'. Encrypt the wallet before signing with `starforge wallet create --encrypt <name>` or `starforge wallet import --encrypt`. Alternatively use a hardware wallet with `--hardware ledger` or `--hardware trezor`. If you deliberately accept the risk, retry with `--allow-plaintext-mainnet`.",
            wallet.name
        );
    }

    crate::utils::print::warn(
        "WARNING: plaintext mainnet signing override enabled. Your secret key is stored unencrypted at rest."
    );

    let mut details = std::collections::HashMap::new();
    details.insert("network".to_string(), "mainnet".to_string());
    details.insert("wallet".to_string(), wallet.name.clone());
    details.insert("plaintext_secret".to_string(), "true".to_string());
    details.insert("override".to_string(), "allow-plaintext-mainnet".to_string());

    if let Err(e) = crate::utils::audit::log_action(
        "allow_plaintext_mainnet_signing",
        "cli",
        "wallet",
        &wallet.name,
        details,
        true,
        None,
    ) {
        crate::utils::print::warn(&format!(
            "Could not write plaintext-mainnet override audit entry: {}",
            e
        ));
    }

    Ok(())
}

pub fn resolve_local_secret(
    wallet: &config::WalletEntry,
    wallet_name: &str,
) -> Result<Zeroizing<String>> {
    let sk = wallet.secret_key.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Wallet '{}' has no local secret key. Use --hardware ledger or --hardware trezor.",
            wallet_name
        )
    })?;

    if !sk.contains(':') && sk.starts_with('S') && sk.len() == 56 {
        return Ok(Zeroizing::new(sk.clone()));
    }

    let pwd = crypto::prompt_password(
        &format!("Enter password to decrypt wallet '{}'", wallet_name),
        false,
    )?;
    Ok(Zeroizing::new(crypto::decrypt_secret(&pwd, sk).map_err(
        |_| {
            anyhow::anyhow!(
                "Incorrect password or unable to decrypt wallet '{}'.",
                wallet_name
            )
        },
    )?))
}

/// Sign a base64-encoded transaction XDR using local or hardware credentials.
pub fn sign_transaction_xdr(transaction_xdr: &str, request: &SigningRequest) -> Result<String> {
    let policy_request = request_with_envelope_fee(transaction_xdr, request);
    enforce_wallet_policy(&policy_request)?;

    if let Some(kind) = request.hardware {
        let tx_bytes = decode_transaction_bytes(transaction_xdr)?;
        let passphrase = config::get_network_passphrase(&request.network);
        let signature =
            hardware_wallet::sign_transaction(kind, &request.hd_path, &tx_bytes, &passphrase)
                .map_err(|err| hardware_wallet::map_signing_error(err, kind))?;

        let signed = format!(
            "hw_signed_{}_{}_{}",
            kind.to_string().to_lowercase(),
            hex::encode(&signature[..signature.len().min(8)]),
            &transaction_xdr[..transaction_xdr.len().min(16)]
        );
        return Ok(general_purpose::STANDARD.encode(signed));
    }

    let secret_key: &str = request
        .local_secret
        .as_deref()
        .context("No local secret key available for signing")?;

    let signed_mock = format!(
        "signed_{}_with_{}",
        transaction_xdr,
        &secret_key[..secret_key.len().min(8)]
    );
    Ok(general_purpose::STANDARD.encode(signed_mock))
}

fn request_with_envelope_fee(transaction_xdr: &str, request: &SigningRequest) -> SigningRequest {
    let mut policy_request = request.clone();
    if let Ok(envelope) = crate::utils::tx_xdr::parse_envelope(transaction_xdr) {
        policy_request.fee_stroops = Some(crate::utils::tx_xdr::summarize(&envelope).fee_stroops);
    }
    policy_request
}

#[derive(Debug, thiserror::Error)]
#[error("{code}: {reason}")]
struct WalletPolicyViolation {
    code: &'static str,
    reason: String,
}

fn evaluate_wallet_policy(
    request: &SigningRequest,
) -> std::result::Result<(), WalletPolicyViolation> {
    let Some(policy) = request.usage_policy.as_ref() else {
        return Ok(());
    };

    if !policy.allowed_networks.is_empty()
        && !policy
            .allowed_networks
            .iter()
            .any(|network| network.eq_ignore_ascii_case(&request.network))
    {
        return Err(WalletPolicyViolation {
            code: "WALLET_POLICY_NETWORK_DENIED",
            reason: format!(
                "network '{}' is not in this wallet's allowlist",
                request.network
            ),
        });
    }

    if let Some(max_fee) = policy.max_fee {
        let Some(fee_stroops) = request.fee_stroops else {
            return Err(WalletPolicyViolation {
                code: "WALLET_POLICY_FEE_UNKNOWN",
                reason: "transaction fee is unavailable for the configured fee cap".to_string(),
            });
        };
        if fee_stroops > max_fee {
            return Err(WalletPolicyViolation {
                code: "WALLET_POLICY_FEE_EXCEEDED",
                reason: format!("fee {fee_stroops} stroops exceeds cap {max_fee} stroops"),
            });
        }
    }

    if !policy.allowed_contracts.is_empty() {
        match &request.target {
            SigningTarget::NonContract => {}
            SigningTarget::Contract(Some(contract_id)) => {
                if !policy
                    .allowed_contracts
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(contract_id))
                {
                    return Err(WalletPolicyViolation {
                        code: "WALLET_POLICY_CONTRACT_DENIED",
                        reason: format!(
                            "contract '{}' is not in this wallet's allowlist",
                            contract_id
                        ),
                    });
                }
            }
            SigningTarget::Contract(None) | SigningTarget::Unspecified => {
                return Err(WalletPolicyViolation {
                    code: "WALLET_POLICY_CONTRACT_UNKNOWN",
                    reason: "transaction contract is unavailable for the configured allowlist"
                        .to_string(),
                });
            }
        }
    }

    Ok(())
}

fn enforce_wallet_policy(request: &SigningRequest) -> Result<()> {
    let Some(policy) = request.usage_policy.as_ref() else {
        return Ok(());
    };

    if let Err(violation) = evaluate_wallet_policy(request) {
        log_wallet_policy_violation(request, &violation)?;
        return Err(violation.into());
    }

    if wallet_requires_confirmation(request) {
        let wallet_name = request.wallet_name.as_deref().unwrap_or("unknown");
        let mut summary = confirmation::OperationSummary::new(
            "Wallet policy confirmation",
            request.network.clone(),
            confirmation::RiskLevel::High,
        )
        .add("Wallet", wallet_name);
        if let Some(fee) = request.fee_stroops {
            summary = summary.add("Fee", format!("{fee} stroops"));
        }
        if let SigningTarget::Contract(Some(contract_id)) = &request.target {
            summary = summary.add("Contract", contract_id);
        }
        let confirm_config = confirmation::ConfirmationConfig {
            risk_level: confirmation::RiskLevel::High,
            network: request.network.clone(),
            skip_confirm: false,
            dry_run: false,
            prompt: Some("Proceed with signing using this wallet?".to_string()),
            require_type_confirmation: request.network.eq_ignore_ascii_case("mainnet"),
            ..Default::default()
        };
        if !confirmation::confirm_operation(&summary, &confirm_config)? {
            let violation = WalletPolicyViolation {
                code: "WALLET_POLICY_CONFIRMATION_DECLINED",
                reason: "required signing confirmation was declined".to_string(),
            };
            log_wallet_policy_violation(request, &violation)?;
            anyhow::bail!("WALLET_POLICY_CONFIRMATION_DECLINED: signing was cancelled");
        }
    }

    Ok(())
}

pub(crate) fn authorize_wallet_policy(request: &SigningRequest) -> Result<()> {
    enforce_wallet_policy(request)
}

fn log_wallet_policy_violation(
    request: &SigningRequest,
    violation: &WalletPolicyViolation,
) -> Result<()> {
    let wallet_name = request.wallet_name.as_deref().unwrap_or("unknown");
    let mut details = std::collections::HashMap::new();
    details.insert("code".to_string(), violation.code.to_string());
    details.insert("network".to_string(), request.network.clone());
    if let Some(fee) = request.fee_stroops {
        details.insert("fee_stroops".to_string(), fee.to_string());
    }
    if let SigningTarget::Contract(Some(contract_id)) = &request.target {
        details.insert("contract_id".to_string(), contract_id.clone());
    }
    audit::log_action(
        "wallet_policy_violation",
        wallet_name,
        "wallet",
        wallet_name,
        details,
        false,
        Some(violation.to_string()),
    )
    .map_err(|audit_error| anyhow::anyhow!("{}; audit logging failed: {}", violation, audit_error))
}

fn wallet_requires_confirmation(request: &SigningRequest) -> bool {
    request
        .usage_policy
        .as_ref()
        .is_some_and(|policy| policy.require_confirmation)
}

/// Produce a partial signature for multi-sig collection flows.
pub fn sign_transaction_partial(
    transaction_xdr: &str,
    request: &SigningRequest,
    signer_label: &str,
) -> Result<String> {
    if request.hardware.is_some() {
        p::info(&format!(
            "Collecting partial signature from hardware wallet for signer '{}'.",
            signer_label
        ));
    }
    sign_transaction_xdr(transaction_xdr, request)
}

fn decode_transaction_bytes(transaction_xdr: &str) -> Result<Vec<u8>> {
    general_purpose::STANDARD
        .decode(transaction_xdr)
        .or_else(|_| Ok(transaction_xdr.as_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with_policy(policy: config::WalletUsagePolicy) -> SigningRequest {
        let mut request = SigningRequest::local_secret(
            Zeroizing::new("SABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901234567890".to_string()),
            "testnet",
        );
        request.wallet_name = Some("admin".to_string());
        request.usage_policy = Some(policy);
        request
    }

    #[test]
    fn local_signing_request_produces_encoded_xdr() {
        let request = SigningRequest::local_secret(
            Zeroizing::new("SABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123456789012345678".to_string()),
            "testnet",
        );
        let signed = sign_transaction_xdr("mock_tx_payload", &request).unwrap();
        assert!(!signed.is_empty());
        let decoded = general_purpose::STANDARD.decode(signed).unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert!(decoded_str.contains("signed_"));
    }

    fn test_wallet(secret_key: Option<&str>) -> config::WalletEntry {
        config::WalletEntry {
            name: "mainnet-test".to_string(),
            public_key: "GTESTPUBLICKEY".to_string(),
            secret_key: secret_key.map(str::to_string),
            network: "mainnet".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            funded: true,
            kdf_options: None,
            rotation_history: Vec::new(),
        }
    }

    #[test]
    fn plaintext_mainnet_signing_is_blocked_by_default() {
        let wallet = test_wallet(Some(
            "SABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123456789012345678",
        ));

        let result = enforce_mainnet_plaintext_policy_with_override(&wallet, "mainnet", false);

        assert!(result.is_err());
        let message = result.unwrap_err().to_string();
        assert!(message.contains("Refusing mainnet signing"));
        assert!(message.contains("--allow-plaintext-mainnet"));
        assert!(message.contains("--encrypt"));
        assert!(message.contains("--hardware"));
    }

    #[test]
    fn plaintext_mainnet_signing_override_is_allowed() {
        let wallet = test_wallet(Some(
            "SABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123456789012345678",
        ));

        let result = enforce_mainnet_plaintext_policy_with_override(&wallet, "mainnet", true);

        assert!(result.is_ok());
    }

    #[test]
    fn encrypted_mainnet_signing_does_not_require_override() {
        let wallet = test_wallet(Some("enc:v1:encrypted-wallet-secret"));

        assert!(enforce_mainnet_plaintext_policy_with_override(&wallet, "mainnet", false).is_ok());
    }

    #[test]
    fn plaintext_testnet_signing_does_not_require_override() {
        let wallet = test_wallet(Some(
            "SABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123456789012345678",
        ));

        assert!(enforce_mainnet_plaintext_policy_with_override(&wallet, "testnet", false).is_ok());
    }

    #[test]
    fn hardware_wallet_without_local_secret_does_not_require_override() {
        let wallet = test_wallet(None);

        assert!(enforce_mainnet_plaintext_policy_with_override(&wallet, "mainnet", false).is_ok());
    }

    #[test]
    fn hardware_signing_requires_feature_or_disabled_message() {
        let request = SigningRequest {
            local_secret: None,
            hardware: Some(hardware_wallet::HardwareWalletKind::Ledger),
            hd_path: hardware_wallet::STELLAR_HD_PATH.to_string(),
            network: "testnet".to_string(),
            skip_confirm: true,
            wallet_name: None,
            usage_policy: None,
            fee_stroops: None,
            target: SigningTarget::Unspecified,
        };
        let result = sign_transaction_xdr("dGVzdA==", &request);
        assert!(result.is_err());
        let message = result.unwrap_err().to_string().to_lowercase();
        assert!(
            message.contains("hardware")
                || message.contains("ledger")
                || message.contains("disabled"),
            "unexpected error: {}",
            message
        );
    }

    #[test]
    fn network_policy_returns_stable_violation_code() {
        let request = request_with_policy(config::WalletUsagePolicy {
            allowed_networks: vec!["mainnet".to_string()],
            ..Default::default()
        });
        let violation = evaluate_wallet_policy(&request).unwrap_err();
        assert_eq!(violation.code, "WALLET_POLICY_NETWORK_DENIED");
        assert!(violation.reason.contains("testnet"));
    }

    #[test]
    fn fee_policy_rejects_unknown_and_over_cap_fees() {
        let policy = config::WalletUsagePolicy {
            max_fee: Some(100),
            ..Default::default()
        };
        let unknown = request_with_policy(policy.clone());
        assert_eq!(
            evaluate_wallet_policy(&unknown).unwrap_err().code,
            "WALLET_POLICY_FEE_UNKNOWN"
        );

        let over_cap = unknown.with_fee_stroops(101);
        assert_eq!(
            evaluate_wallet_policy(&over_cap).unwrap_err().code,
            "WALLET_POLICY_FEE_EXCEEDED"
        );
        assert!(evaluate_wallet_policy(&over_cap.with_fee_stroops(100)).is_ok());
    }

    #[test]
    fn parsed_envelope_fee_overrides_a_lower_caller_estimate() {
        let envelope = crate::utils::tx_xdr::unsigned_envelope(
            &stellar_xdr::curr::MuxedAccount::Ed25519(stellar_xdr::curr::Uint256([1; 32])),
            1,
            Vec::new(),
        )
        .unwrap();
        let xdr = crate::utils::tx_xdr::write_envelope(
            &envelope,
            crate::utils::tx_xdr::WireFormat::Base64,
        )
        .unwrap();
        let request = request_with_policy(config::WalletUsagePolicy {
            max_fee: Some(99),
            ..Default::default()
        })
        .with_fee_stroops(1);

        let policy_request = request_with_envelope_fee(&xdr, &request);
        assert_eq!(policy_request.fee_stroops, Some(100));
        assert_eq!(
            evaluate_wallet_policy(&policy_request).unwrap_err().code,
            "WALLET_POLICY_FEE_EXCEEDED"
        );
    }

    #[test]
    fn contract_policy_rejects_unknown_and_unlisted_contracts() {
        let request = request_with_policy(config::WalletUsagePolicy {
            allowed_contracts: vec!["Callowed".to_string()],
            ..Default::default()
        });
        assert_eq!(
            evaluate_wallet_policy(&request).unwrap_err().code,
            "WALLET_POLICY_CONTRACT_UNKNOWN"
        );
        assert_eq!(
            evaluate_wallet_policy(&request.with_contract_id("Cother"))
                .unwrap_err()
                .code,
            "WALLET_POLICY_CONTRACT_DENIED"
        );
        assert!(evaluate_wallet_policy(&request.with_contract_id("Callowed")).is_ok());
        assert!(evaluate_wallet_policy(&request.for_non_contract()).is_ok());
    }

    #[test]
    fn confirmation_policy_requires_prompt_even_when_skip_confirm_is_set() {
        let mut request = request_with_policy(config::WalletUsagePolicy {
            require_confirmation: true,
            ..Default::default()
        });
        request.skip_confirm = true;
        assert!(wallet_requires_confirmation(&request));
        request.usage_policy = Some(config::WalletUsagePolicy::default());
        assert!(!wallet_requires_confirmation(&request));
    }
}
