package ctis

import "time"

// Web3 profile (CTIS 2.0, spec section "Profiles"). Web3 is an optional
// profile, not a finding type: a smart-contract issue is a vulnerability or a
// weakness finding that carries a web3 block, and web3 assets carry
// technical.web3. Vendor and product vocabularies in this profile (auditors,
// analysis tools, marketplaces, wallet providers, exchanges, oracles, flash
// loan providers, bounty platforms) are open tokens.

// =============================================================================
// Web3 Technical Details
// =============================================================================

// Web3Technical contains Web3-specific technical details for smart contracts,
// wallets, tokens, and other blockchain assets.
type Web3Technical struct {
	// Blockchain network: ethereum, polygon, bsc, arbitrum, optimism, avalanche, solana, etc.
	Chain string `json:"chain,omitempty"`

	// Chain ID (EVM chains): 1 (mainnet), 137 (polygon), 56 (bsc), etc.
	ChainID int64 `json:"chain_id,omitempty"`

	// Network type: mainnet, testnet, devnet
	NetworkType string `json:"network_type,omitempty"`

	// Contract/wallet address
	Address string `json:"address,omitempty"`

	// For smart contracts
	Contract *SmartContractDetails `json:"contract,omitempty"`

	// For wallets
	Wallet *WalletDetails `json:"wallet,omitempty"`

	// For tokens (ERC-20, ERC-721, etc.)
	Token *TokenDetails `json:"token,omitempty"`

	// For DeFi protocols
	DeFi *DeFiDetails `json:"defi,omitempty"`

	// For NFT collections
	NFT *NFTCollectionDetails `json:"nft,omitempty"`
}

// SmartContractDetails contains smart contract-specific details.
type SmartContractDetails struct {
	// Contract name
	Name string `json:"name,omitempty"`

	// Contract address
	Address string `json:"address,omitempty"`

	// Deployer address
	DeployerAddress string `json:"deployer_address,omitempty"`

	// Deployment transaction hash
	DeploymentTxHash string `json:"deployment_tx_hash,omitempty"`

	// Deployment block number
	DeploymentBlock int64 `json:"deployment_block,omitempty"`

	// Deployment timestamp
	DeployedAt *time.Time `json:"deployed_at,omitempty"`

	// Is verified on explorer (etherscan, etc.)
	IsVerified bool `json:"is_verified,omitempty"`

	// Compiler version
	CompilerVersion string `json:"compiler_version,omitempty"`

	// EVM version
	EVMVersion string `json:"evm_version,omitempty"`

	// Optimization enabled
	IsOptimizationEnabled bool `json:"is_optimization_enabled,omitempty"`

	// Optimization runs
	OptimizationRuns int `json:"optimization_runs,omitempty"`

	// Contract type: erc20, erc721, erc1155, proxy, multisig, defi, custom
	ContractType string `json:"contract_type,omitempty"`

	// Is proxy contract
	IsProxy bool `json:"is_proxy,omitempty"`

	// Implementation address (for proxy contracts)
	ImplementationAddress string `json:"implementation_address,omitempty"`

	// Proxy type: transparent, uups, beacon, diamond
	ProxyType string `json:"proxy_type,omitempty"`

	// Is upgradeable
	IsUpgradeable bool `json:"is_upgradeable,omitempty"`

	// Owner/admin address
	OwnerAddress string `json:"owner_address,omitempty"`

	// Has renounced ownership
	IsOwnershipRenounced bool `json:"is_ownership_renounced,omitempty"`

	// Source code URL (GitHub, etc.)
	SourceCodeURL string `json:"source_code_url,omitempty"`

	// ABI (JSON string or base64 encoded)
	ABI string `json:"abi,omitempty"`

	// Bytecode hash (keccak256)
	BytecodeHash string `json:"bytecode_hash,omitempty"`

	// Source code hash
	SourceCodeHash string `json:"source_code_hash,omitempty"`

	// License type: MIT, GPL, UNLICENSED, etc.
	License string `json:"license,omitempty"`

	// External libraries used
	Libraries []ContractLibrary `json:"libraries,omitempty"`

	// Implemented interfaces: ERC20, ERC721, etc.
	Interfaces []string `json:"interfaces,omitempty"`

	// Contract balance (in wei)
	Balance string `json:"balance,omitempty"`

	// Total transactions
	TxCount int64 `json:"tx_count,omitempty"`
}

// ContractLibrary represents an external library linked to a contract.
type ContractLibrary struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// WalletDetails contains wallet-specific details.
type WalletDetails struct {
	// Wallet type: eoa, multisig, smart_wallet, mpc
	WalletType string `json:"wallet_type,omitempty"`

	// For multisig: required signatures
	RequiredSignatures int `json:"required_signatures,omitempty"`

	// For multisig: total owners
	TotalOwners int `json:"total_owners,omitempty"`

	// Owner addresses (for multisig)
	Owners []string `json:"owners,omitempty"`

	// Wallet provider: metamask, ledger, safe, argent, etc.
	Provider string `json:"provider,omitempty"`

	// Balance (native token, in wei)
	Balance string `json:"balance,omitempty"`

	// Token balances
	TokenBalances []TokenBalance `json:"token_balances,omitempty"`

	// NFT count
	NFTCount int `json:"nft_count,omitempty"`

	// First transaction timestamp
	FirstTxAt *time.Time `json:"first_tx_at,omitempty"`

	// Last transaction timestamp
	LastTxAt *time.Time `json:"last_tx_at,omitempty"`

	// Total transactions
	TxCount int64 `json:"tx_count,omitempty"`

	// ENS name (if applicable)
	ENSName string `json:"ens_name,omitempty"`

	// Labels (exchange, whale, hacker, etc.)
	Labels []string `json:"labels,omitempty"`
}

// TokenBalance represents a token balance for a wallet.
type TokenBalance struct {
	// Token contract address
	ContractAddress string `json:"contract_address"`

	// Token symbol
	Symbol string `json:"symbol,omitempty"`

	// Token name
	Name string `json:"name,omitempty"`

	// Token decimals
	Decimals int `json:"decimals,omitempty"`

	// Balance (raw value)
	Balance string `json:"balance"`

	// Balance formatted (human readable)
	BalanceFormatted string `json:"balance_formatted,omitempty"`

	// USD value
	USDValue float64 `json:"usd_value,omitempty"`
}

// TokenDetails contains token-specific details (ERC-20, etc.).
type TokenDetails struct {
	// Token standard: erc20, erc721, erc1155, bep20, spl
	Standard string `json:"standard,omitempty"`

	// Token symbol
	Symbol string `json:"symbol,omitempty"`

	// Token name
	Name string `json:"name,omitempty"`

	// Token decimals
	Decimals int `json:"decimals,omitempty"`

	// Total supply (raw value)
	TotalSupply string `json:"total_supply,omitempty"`

	// Max supply (if applicable)
	MaxSupply string `json:"max_supply,omitempty"`

	// Is mintable
	IsMintable bool `json:"is_mintable,omitempty"`

	// Is burnable
	IsBurnable bool `json:"is_burnable,omitempty"`

	// Is pausable
	IsPausable bool `json:"is_pausable,omitempty"`

	// Has blacklist/whitelist
	HasBlacklist bool `json:"has_blacklist,omitempty"`

	// Has transfer fee/tax
	HasTransferFee bool `json:"has_transfer_fee,omitempty"`

	// Transfer fee percentage
	TransferFeePercent float64 `json:"transfer_fee_percent,omitempty"`

	// Holder count
	HolderCount int64 `json:"holder_count,omitempty"`

	// Market cap USD
	MarketCapUSD float64 `json:"market_cap_usd,omitempty"`

	// Price USD
	PriceUSD float64 `json:"price_usd,omitempty"`

	// Liquidity USD
	LiquidityUSD float64 `json:"liquidity_usd,omitempty"`

	// Trading pairs
	TradingPairs []TradingPair `json:"trading_pairs,omitempty"`

	// Is honeypot
	IsHoneypot bool `json:"is_honeypot,omitempty"`

	// Honeypot reason
	HoneypotReason string `json:"honeypot_reason,omitempty"`
}

// TradingPair represents a trading pair for a token.
type TradingPair struct {
	// DEX name: uniswap, sushiswap, pancakeswap, etc.
	DEX string `json:"dex"`

	// Pair address
	PairAddress string `json:"pair_address"`

	// Quote token symbol (WETH, USDT, etc.)
	QuoteToken string `json:"quote_token"`

	// Liquidity USD
	LiquidityUSD float64 `json:"liquidity_usd,omitempty"`
}

// DeFiDetails contains DeFi protocol-specific details.
type DeFiDetails struct {
	// Protocol name: uniswap, aave, compound, etc.
	ProtocolName string `json:"protocol_name,omitempty"`

	// Protocol type: dex, lending, yield, bridge, derivatives, etc.
	ProtocolType string `json:"protocol_type,omitempty"`

	// Protocol version
	Version string `json:"version,omitempty"`

	// Total Value Locked (TVL) in USD
	TVLUSD float64 `json:"tvl_usd,omitempty"`

	// Supported chains
	SupportedChains []string `json:"supported_chains,omitempty"`

	// Core contracts
	CoreContracts []CoreContract `json:"core_contracts,omitempty"`

	// Governance token address
	GovernanceToken string `json:"governance_token,omitempty"`

	// Is audited
	IsAudited bool `json:"is_audited,omitempty"`

	// Audit reports
	AuditReports []AuditReport `json:"audit_reports,omitempty"`

	// Has bug bounty
	HasBugBounty bool `json:"has_bug_bounty,omitempty"`

	// Bug bounty platform: immunefi, hackerone, etc.
	BugBountyPlatform string `json:"bug_bounty_platform,omitempty"`

	// Max bug bounty payout
	MaxBountyUSD float64 `json:"max_bounty_usd,omitempty"`

	// Timelock duration (for governance)
	TimelockSeconds int `json:"timelock_seconds,omitempty"`

	// Is paused
	IsPaused bool `json:"is_paused,omitempty"`
}

// CoreContract represents a core contract of a DeFi protocol.
type CoreContract struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Role    string `json:"role,omitempty"` // router, factory, vault, etc.
}

// AuditReport represents a security audit report.
type AuditReport struct {
	Auditor       string     `json:"auditor"`
	ReportURL     string     `json:"report_url,omitempty"`
	PublishedAt   *time.Time `json:"published_at,omitempty"`
	Scope         string     `json:"scope,omitempty"`
	CriticalCount int        `json:"critical_count,omitempty"`
	HighCount     int        `json:"high_count,omitempty"`
	MediumCount   int        `json:"medium_count,omitempty"`
	LowCount      int        `json:"low_count,omitempty"`
}

// NFTCollectionDetails contains NFT collection-specific details.
type NFTCollectionDetails struct {
	// Collection name
	Name string `json:"name,omitempty"`

	// Collection symbol
	Symbol string `json:"symbol,omitempty"`

	// Token standard: erc721, erc1155
	Standard string `json:"standard,omitempty"`

	// Total supply
	TotalSupply int64 `json:"total_supply,omitempty"`

	// Max supply
	MaxSupply int64 `json:"max_supply,omitempty"`

	// Unique holders
	HolderCount int64 `json:"holder_count,omitempty"`

	// Floor price (in native token)
	FloorPrice string `json:"floor_price,omitempty"`

	// Floor price USD
	FloorPriceUSD float64 `json:"floor_price_usd,omitempty"`

	// Total volume (in native token)
	TotalVolume string `json:"total_volume,omitempty"`

	// Total volume USD
	TotalVolumeUSD float64 `json:"total_volume_usd,omitempty"`

	// Royalty percentage
	RoyaltyPercent float64 `json:"royalty_percent,omitempty"`

	// Royalty recipient
	RoyaltyRecipient string `json:"royalty_recipient,omitempty"`

	// Marketplace URLs
	Marketplaces []string `json:"marketplaces,omitempty"`

	// Is revealed
	IsRevealed bool `json:"is_revealed,omitempty"`

	// Base URI
	BaseURI string `json:"base_uri,omitempty"`

	// Metadata storage: ipfs, arweave, centralized
	MetadataStorage string `json:"metadata_storage,omitempty"`

	// Creator address
	Creator string `json:"creator,omitempty"`
}

// =============================================================================
// Web3 Vulnerability Details
// =============================================================================

// Web3VulnerabilityDetails contains Web3/smart contract vulnerability-specific details.
type Web3VulnerabilityDetails struct {
	// Vulnerability class/category (SWC ID or custom)
	// Common: reentrancy, overflow, access_control, front_running, etc.
	VulnerabilityClass string `json:"vulnerability_class,omitempty"`

	// SWC Registry ID (e.g., SWC-107 for reentrancy)
	SWCID string `json:"swc_id,omitempty"`

	// Contract address affected
	ContractAddress string `json:"contract_address,omitempty"`

	// Chain ID
	ChainID int64 `json:"chain_id,omitempty"`

	// Chain name
	Chain string `json:"chain,omitempty"`

	// Affected function signature
	FunctionSignature string `json:"function_signature,omitempty"`

	// Affected function selector (4 bytes)
	FunctionSelector string `json:"function_selector,omitempty"`

	// Vulnerable code pattern
	VulnerablePattern string `json:"vulnerable_pattern,omitempty"`

	// Bytecode offset (if found in bytecode analysis)
	BytecodeOffset int `json:"bytecode_offset,omitempty"`

	// Is exploitable on mainnet
	IsExploitableOnMainnet bool `json:"is_exploitable_on_mainnet,omitempty"`

	// Estimated impact in USD (if quantifiable)
	EstimatedImpactUSD float64 `json:"estimated_impact_usd,omitempty"`

	// Affected assets value in USD
	AffectedValueUSD float64 `json:"affected_value_usd,omitempty"`

	// Attack vector description
	AttackVector string `json:"attack_vector,omitempty"`

	// Proof of concept (if available)
	POC *Web3POC `json:"poc,omitempty"`

	// Related transaction hashes (if exploit occurred)
	RelatedTxHashes []string `json:"related_tx_hashes,omitempty"`

	// Attacker addresses (if known)
	AttackerAddresses []string `json:"attacker_addresses,omitempty"`

	// Tool that found this: slither, mythril, securify, manticore, etc.
	DetectionTool string `json:"detection_tool,omitempty"`

	// Detection confidence: high, medium, low
	DetectionConfidence string `json:"detection_confidence,omitempty"`

	// Is false positive
	IsFalsePositive bool `json:"is_false_positive,omitempty"`

	// Gas optimization issues (for gas-related findings)
	GasIssue *GasIssue `json:"gas_issue,omitempty"`

	// Access control details
	AccessControl *AccessControlIssue `json:"access_control,omitempty"`

	// Reentrancy details
	Reentrancy *ReentrancyIssue `json:"reentrancy,omitempty"`

	// Oracle manipulation details
	OracleManipulation *OracleManipulationIssue `json:"oracle_manipulation,omitempty"`

	// Flash loan attack details
	FlashLoan *FlashLoanIssue `json:"flash_loan,omitempty"`
}

// Web3POC contains proof of concept details for Web3 vulnerabilities.
type Web3POC struct {
	// POC type: transaction, script, foundry_test, hardhat_test
	Type string `json:"type,omitempty"`

	// POC code or script
	Code string `json:"code,omitempty"`

	// POC transaction data
	TxData string `json:"tx_data,omitempty"`

	// Expected outcome
	ExpectedOutcome string `json:"expected_outcome,omitempty"`

	// Tested on: mainnet_fork, testnet, local
	TestedOn string `json:"tested_on,omitempty"`

	// Fork block number (for mainnet fork tests)
	ForkBlockNumber int64 `json:"fork_block_number,omitempty"`
}

// GasIssue contains details about gas optimization issues.
type GasIssue struct {
	// Current gas cost
	CurrentGas int64 `json:"current_gas,omitempty"`

	// Optimized gas cost
	OptimizedGas int64 `json:"optimized_gas,omitempty"`

	// Gas savings percentage
	SavingsPercent float64 `json:"savings_percent,omitempty"`

	// Optimization suggestion
	Suggestion string `json:"suggestion,omitempty"`
}

// AccessControlIssue contains details about access control vulnerabilities.
type AccessControlIssue struct {
	// Missing modifier
	MissingModifier string `json:"missing_modifier,omitempty"`

	// Unprotected function
	UnprotectedFunction string `json:"unprotected_function,omitempty"`

	// Can be called by
	CallableBy string `json:"callable_by,omitempty"` // anyone, owner_only, etc.

	// Privilege escalation path
	EscalationPath string `json:"escalation_path,omitempty"`

	// Missing role check
	MissingRoleCheck string `json:"missing_role_check,omitempty"`
}

// ReentrancyIssue contains details about reentrancy vulnerabilities.
type ReentrancyIssue struct {
	// Reentrancy type: cross_function, cross_contract, read_only
	Type string `json:"type,omitempty"`

	// Vulnerable external call
	ExternalCall string `json:"external_call,omitempty"`

	// State variable modified after call
	StateModifiedAfterCall string `json:"state_modified_after_call,omitempty"`

	// Entry point function
	EntryPoint string `json:"entry_point,omitempty"`

	// Callback function
	Callback string `json:"callback,omitempty"`

	// Max reentrancy depth possible
	MaxDepth int `json:"max_depth,omitempty"`
}

// OracleManipulationIssue contains details about oracle manipulation vulnerabilities.
type OracleManipulationIssue struct {
	// Oracle type: chainlink, uniswap_twap, custom
	OracleType string `json:"oracle_type,omitempty"`

	// Oracle address
	OracleAddress string `json:"oracle_address,omitempty"`

	// Manipulation method: flash_loan, sandwich, time_manipulation
	ManipulationMethod string `json:"manipulation_method,omitempty"`

	// Price impact possible
	PriceImpactPercent float64 `json:"price_impact_percent,omitempty"`

	// Missing checks
	MissingChecks []string `json:"missing_checks,omitempty"`
}

// FlashLoanIssue contains details about flash loan attack vulnerabilities.
type FlashLoanIssue struct {
	// Flash loan provider: aave, dydx, uniswap, balancer
	Provider string `json:"provider,omitempty"`

	// Attack type: price_manipulation, governance_attack, collateral_theft
	AttackType string `json:"attack_type,omitempty"`

	// Required capital for attack
	RequiredCapitalUSD float64 `json:"required_capital_usd,omitempty"`

	// Potential profit
	PotentialProfitUSD float64 `json:"potential_profit_usd,omitempty"`

	// Attack steps
	AttackSteps []string `json:"attack_steps,omitempty"`
}

// Web3VulnerabilityClass represents common Web3 vulnerability classes.
type Web3VulnerabilityClass string

const (
	// SWC-100 series - Basic
	Web3VulnReentrancy          Web3VulnerabilityClass = "reentrancy"           // SWC-107
	Web3VulnIntegerOverflow     Web3VulnerabilityClass = "integer_overflow"     // SWC-101
	Web3VulnIntegerUnderflow    Web3VulnerabilityClass = "integer_underflow"    // SWC-101
	Web3VulnAccessControl       Web3VulnerabilityClass = "access_control"       // SWC-105
	Web3VulnUncheckedCall       Web3VulnerabilityClass = "unchecked_call"       // SWC-104
	Web3VulnDelegateCall        Web3VulnerabilityClass = "delegate_call"        // SWC-112
	Web3VulnSelfDestruct        Web3VulnerabilityClass = "self_destruct"        // SWC-106
	Web3VulnTxOrigin            Web3VulnerabilityClass = "tx_origin"            // SWC-115
	Web3VulnTimestampDependence Web3VulnerabilityClass = "timestamp_dependence" // SWC-116
	Web3VulnBlockHashDependence Web3VulnerabilityClass = "blockhash_dependence" // SWC-120

	// DeFi-specific
	Web3VulnFlashLoan          Web3VulnerabilityClass = "flash_loan_attack"
	Web3VulnOracleManipulation Web3VulnerabilityClass = "oracle_manipulation"
	Web3VulnFrontRunning       Web3VulnerabilityClass = "front_running"
	Web3VulnSandwichAttack     Web3VulnerabilityClass = "sandwich_attack"
	Web3VulnSlippage           Web3VulnerabilityClass = "slippage_attack"
	Web3VulnPriceManipulation  Web3VulnerabilityClass = "price_manipulation"
	Web3VulnGovernanceAttack   Web3VulnerabilityClass = "governance_attack"
	Web3VulnLiquidityDrain     Web3VulnerabilityClass = "liquidity_drain"
	Web3VulnMEV                Web3VulnerabilityClass = "mev_vulnerability"

	// Token-specific
	Web3VulnHoneypot          Web3VulnerabilityClass = "honeypot"
	Web3VulnHiddenMint        Web3VulnerabilityClass = "hidden_mint"
	Web3VulnHiddenFee         Web3VulnerabilityClass = "hidden_fee"
	Web3VulnBlacklistAbuse    Web3VulnerabilityClass = "blacklist_abuse"
	Web3VulnRenounceOwnership Web3VulnerabilityClass = "fake_renounce"

	// Proxy & Upgrade
	Web3VulnStorageCollision   Web3VulnerabilityClass = "storage_collision"
	Web3VulnUninitializedProxy Web3VulnerabilityClass = "uninitialized_proxy"
	Web3VulnUpgradeVuln        Web3VulnerabilityClass = "upgrade_vulnerability"

	// Cryptographic
	Web3VulnWeakRandomness        Web3VulnerabilityClass = "weak_randomness" // SWC-120
	Web3VulnSignatureMalleability Web3VulnerabilityClass = "signature_malleability"
	Web3VulnReplayAttack          Web3VulnerabilityClass = "replay_attack"

	// Gas & DoS
	Web3VulnDosGasLimit      Web3VulnerabilityClass = "dos_gas_limit"
	Web3VulnUnboundedLoop    Web3VulnerabilityClass = "unbounded_loop"
	Web3VulnDosBlockStuffing Web3VulnerabilityClass = "dos_block_stuffing"

	// Logic
	Web3VulnBusinessLogic      Web3VulnerabilityClass = "business_logic"
	Web3VulnInvariantViolation Web3VulnerabilityClass = "invariant_violation"
)

// AllWeb3VulnerabilityClasses returns all Web3 vulnerability classes.
func AllWeb3VulnerabilityClasses() []Web3VulnerabilityClass {
	return []Web3VulnerabilityClass{
		Web3VulnReentrancy,
		Web3VulnIntegerOverflow,
		Web3VulnIntegerUnderflow,
		Web3VulnAccessControl,
		Web3VulnUncheckedCall,
		Web3VulnDelegateCall,
		Web3VulnSelfDestruct,
		Web3VulnTxOrigin,
		Web3VulnTimestampDependence,
		Web3VulnBlockHashDependence,
		Web3VulnFlashLoan,
		Web3VulnOracleManipulation,
		Web3VulnFrontRunning,
		Web3VulnSandwichAttack,
		Web3VulnSlippage,
		Web3VulnPriceManipulation,
		Web3VulnGovernanceAttack,
		Web3VulnLiquidityDrain,
		Web3VulnMEV,
		Web3VulnHoneypot,
		Web3VulnHiddenMint,
		Web3VulnHiddenFee,
		Web3VulnBlacklistAbuse,
		Web3VulnRenounceOwnership,
		Web3VulnStorageCollision,
		Web3VulnUninitializedProxy,
		Web3VulnUpgradeVuln,
		Web3VulnWeakRandomness,
		Web3VulnSignatureMalleability,
		Web3VulnReplayAttack,
		Web3VulnDosGasLimit,
		Web3VulnUnboundedLoop,
		Web3VulnDosBlockStuffing,
		Web3VulnBusinessLogic,
		Web3VulnInvariantViolation,
	}
}
