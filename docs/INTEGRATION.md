# Integrating the Confidential Module into a Cosmos SDK Chain

This guide explains how to add the `confidential` module to any Cosmos SDK v0.53+ chain. The module provides account-based confidential transfers using ElGamal encryption with DLEQ proofs and bulletproof range proofs.

## Prerequisites

- Cosmos SDK `v0.53.0` or later (uses depinject/app wiring)
- Go `1.23+`
- The following packages (included as dependencies):
  - `github.com/nixprotocol/elgamal-bn254` — ElGamal encryption on BN254
  - `github.com/nixprotocol/bulletproofs-bn254` — Bulletproof range proofs

## What the Module Provides

| Feature | Description |
|---------|-------------|
| **Shield** | Move tokens from public balance to encrypted confidential balance |
| **Unshield** | Move tokens from confidential balance back to public |
| **Confidential Send** | Transfer encrypted tokens between accounts (amount hidden) |
| **Apply Pending** | Merge received tokens into available balance |
| **Key Registration** | Register an ElGamal public key for an account |
| **Key Rotation** | Rotate to a new ElGamal key with re-encryption proofs |
| **Auditor** | Optional auditor key for regulatory compliance |

## Step 1: Add Dependencies

Add to your chain's `go.mod`:

```go
require (
    github.com/nixprotocol/confidential-module v0.1.0
)
```

For local development, use replace directives:

```go
replace (
    github.com/nixprotocol/confidential-module => ../path/to/confidential-module
    github.com/nixprotocol/elgamal-bn254 => ../path/to/elgamal-bn254
    github.com/nixprotocol/bulletproofs-bn254 => ../path/to/bulletproofs-bn254
)
```

Run `go mod tidy`.

## Step 2: Register the Module (app_config.go)

### 2a. Add imports

```go
import (
    _ "github.com/nixprotocol/confidential-module/module" // side-effect import for depinject registration
    confidentialtypes "github.com/nixprotocol/confidential-module/types"
)
```

### 2b. Add module account permissions

In your `moduleAccPerms` slice:

```go
var moduleAccPerms = []*authmodulev1.ModuleAccountPermission{
    // ... existing entries ...
    {Account: confidentialtypes.ModuleAccountName},
}
```

### 2c. Register in module config

In your `appconfig.Compose` call, add the module:

```go
appConfig = appconfig.Compose(&appv1alpha1.Config{
    Modules: []*appv1alpha1.ModuleConfig{
        // ... existing modules ...
        {
            Name:   confidentialtypes.ModuleName,
            Config: appconfig.WrapAny(&confidentialtypes.Module{}),
        },
    },
})
```

To use a custom authority (instead of the default governance module):

```go
Config: appconfig.WrapAny(&confidentialtypes.Module{
    Authority: "cosmos1yourauthorityaddress...",
}),
```

### 2d. Add to lifecycle hooks

```go
BeginBlockers: []string{
    // ... existing entries ...
    confidentialtypes.ModuleName,
}

EndBlockers: []string{
    // ... existing entries ...
    confidentialtypes.ModuleName,
}

InitGenesis: []string{
    // ... existing entries (add AFTER bank module) ...
    confidentialtypes.ModuleName,
}
```

## Step 3: Wire the Keeper (app.go)

### 3a. Add import

```go
import (
    confidentialkeeper "github.com/nixprotocol/confidential-module/keeper"
)
```

### 3b. Add keeper to App struct

```go
type App struct {
    *runtime.App
    // ... existing keepers ...
    ConfidentialKeeper confidentialkeeper.Keeper
}
```

### 3c. Inject via depinject

In your `New()` constructor:

```go
if err := depinject.Inject(appConfig,
    // ... existing injections ...
    &app.ConfidentialKeeper,
); err != nil {
    panic(err)
}
```

That's it for the code changes. The module uses depinject for all wiring — the keeper is constructed automatically with its dependencies:

| Dependency | Provided by |
|-----------|-------------|
| `store.KVStoreService` | Runtime (automatic) |
| `codec.Codec` | Runtime (automatic) |
| `address.Codec` | Auth module |
| `types.BankKeeper` | Bank module |

### Required Bank Keeper Interface

The module requires the bank module to implement:

```go
type BankKeeper interface {
    SendCoinsFromAccountToModule(ctx context.Context, senderAddr sdk.AccAddress, recipientModule string, amt sdk.Coins) error
    SendCoinsFromModuleToAccount(ctx context.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error
}
```

This is satisfied by the standard Cosmos SDK bank keeper.

## Step 4: Genesis Configuration

### For a new chain

Add to your `genesis.json` (or genesis setup script):

```json
{
  "app_state": {
    "confidential": {
      "params": {
        "auditor_pub_key": "<base64-encoded BN254 G1 point, 64 bytes>",
        "auditor_key_grace_period": 100,
        "enabled_denoms": ["uatom"],
        "max_transfer_bits": 64,
        "rotation_cooldown": 100,
        "max_memo_size": 1024
      }
    }
  }
}
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `auditor_pub_key` | bytes (base64) | ElGamal public key for the auditor. All confidential sends encrypt the amount for this key. |
| `auditor_key_grace_period` | uint64 | Blocks after auditor key change during which the old key is still accepted |
| `enabled_denoms` | []string | Token denominations that support confidential transfers |
| `max_transfer_bits` | uint64 | Maximum bit-length for transfer amounts (typically 64) |
| `rotation_cooldown` | uint64 | Minimum blocks between key rotations for an account |
| `max_memo_size` | uint64 | Maximum size of encrypted memo in bytes (1024 recommended) |

### Generating an auditor key

```go
import elgamal "github.com/nixprotocol/elgamal-bn254"

sk, pk, _ := elgamal.KeyGen(rand.Reader)
auditorPubKeyBytes := elgamal.MarshalPublicKey(&pk)
auditorPubKeyBase64 := base64.StdEncoding.EncodeToString(auditorPubKeyBytes)
// Use auditorPubKeyBase64 as the "auditor_pub_key" parameter
// Store sk securely — the auditor needs it to decrypt transfer amounts
```

### For an existing running chain (upgrade handler)

Register an upgrade handler that initializes the module's genesis state:

```go
app.UpgradeKeeper.SetUpgradeHandler("v2-confidential", func(ctx context.Context, plan upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
    // The module's InitGenesis will be called automatically
    // if the module is new (not in fromVM).
    // Set params via governance after the upgrade, or set them here:
    sdkCtx := sdk.UnwrapSDKContext(ctx)
    params := confidentialtypes.Params{
        AuditorPubKey:         auditorPubKeyBytes,
        AuditorKeyGracePeriod: 100,
        EnabledDenoms:         []string{"uatom"},
        MaxTransferBits:       64,
        RotationCooldown:      100,
        MaxMemoSize:           1024,
    }
    app.ConfidentialKeeper.SetParams(sdkCtx, params)

    return app.ModuleManager.RunMigrations(ctx, app.Configurator(), fromVM)
})
```

Then submit a governance upgrade proposal targeting the `v2-confidential` upgrade name at a future block height.

## Step 5: Proto Generation (if modifying the module)

If you fork or modify the confidential module's proto files:

```bash
cd confidential-module/proto
buf generate
```

Requires:
- `buf` CLI (`brew install bufbuild/buf/buf`)
- `protoc-gen-gogo` (`go install github.com/cosmos/gogoproto/protoc-gen-gogo@latest`)

The module's `buf.gen.yaml` handles the generation config.

## Verification

After integration, verify the module is loaded:

```bash
# Check module is registered
your-chain-binary query auth module-accounts | grep confidential

# Query module params
your-chain-binary query confidential params

# Check an account's registration status
your-chain-binary query confidential account <address>
```

## Client Integration

The confidential module requires a client wallet that can:

1. **Generate ElGamal keypairs** (BN254 curve)
2. **Generate DLEQ proofs** for shield/unshield
3. **Generate equality proofs** for confidential sends (3-key)
4. **Generate bulletproof range proofs** for balance non-negativity
5. **Encrypt/decrypt** balances using the ElGamal scheme

A reference implementation is available in the `confidential-wallet` project, which includes:
- Go WASM module for all cryptographic operations
- React frontend with Keplr integration
- Encrypted memo support for cross-device state recovery

## Architecture

```
┌──────────────────────────────────────────────┐
│                   Client                      │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐ │
│  │ Keplr    │  │ WASM     │  │ Wallet UI  │ │
│  │ Signing  │  │ Proofs   │  │ (React)    │ │
│  └────┬─────┘  └────┬─────┘  └─────┬──────┘ │
└───────┼──────────────┼──────────────┼────────┘
        │              │              │
        ▼              ▼              ▼
┌──────────────────────────────────────────────┐
│              Cosmos SDK Chain                  │
│  ┌──────────────────────────────────────────┐ │
│  │          Confidential Module              │ │
│  │                                           │ │
│  │  MsgRegisterKey  → Store ElGamal pubkey   │ │
│  │  MsgShield       → Bank→Encrypted balance │ │
│  │  MsgSend         → Encrypted→Encrypted    │ │
│  │  MsgApplyPending → Merge pending→avail    │ │
│  │  MsgUnshield     → Encrypted→Bank balance │ │
│  │  MsgRotateKey    → Re-encrypt balances    │ │
│  │                                           │ │
│  │  Verify: DLEQ, Equality, Range proofs     │ │
│  │  Store: ElGamal ciphertexts (KV)          │ │
│  │  Events: encrypted_memo for recovery      │ │
│  └──────────────────────────────────────────┘ │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐ │
│  │ Bank     │  │ Auth     │  │ Staking    │ │
│  │ Module   │  │ Module   │  │ Module     │ │
│  └──────────┘  └──────────┘  └────────────┘ │
└──────────────────────────────────────────────┘
```

## Store Layout

The module uses these KV store prefixes:

| Prefix | Key format | Value |
|--------|-----------|-------|
| `confidential/pk/` | `+ addr_bytes` | ElGamal public key (64 bytes) |
| `confidential/kc/` | `+ addr_bytes` | Key counter (uint64) |
| `confidential/ab/` | `+ addr_bytes + "/" + denom` | Available balance ciphertext (128 bytes) |
| `confidential/pb/` | `+ addr_bytes + "/" + denom` | Pending balance ciphertext (128 bytes) |
| `confidential/pz/` | `+ addr_bytes + "/" + denom` | Pending-is-zero flag (bool) |
| `confidential/rh/` | `+ addr_bytes` | Last rotation height (uint64) |
| `confidential/params` | (none) | Module params (JSON) |

## Transaction Types

| Message | Signer | Description | Proofs Required |
|---------|--------|-------------|-----------------|
| `MsgRegisterKey` | sender | Register ElGamal public key | None (key validated on-curve) |
| `MsgShield` | sender | Deposit tokens into confidential balance | DLEQ proof |
| `MsgConfidentialSend` | sender | Private transfer to another account | Equality proof (3-key) + Aggregate range proof |
| `MsgApplyPending` | sender | Merge pending balance into available | ApplyPending proof |
| `MsgUnshield` | sender | Withdraw from confidential to public balance | DLEQ proof + Aggregate range proof |
| `MsgSetAuditorKey` | authority | Update the auditor public key | None (governance only) |
| `MsgRotateKey` | sender | Rotate ElGamal key with re-encrypted balances | Equality2 proofs per denom |

## Events Emitted

| Event | Attributes | Privacy |
|-------|-----------|---------|
| `register_key` | sender | Public |
| `shield` | sender, denom, amount, encrypted_memo | Amount public (matches bank debit) |
| `confidential_send` | sender, receiver, denom, auditor_ciphertext, encrypted_memo | **Amount hidden** |
| `apply_pending` | sender, denom, encrypted_memo | Amount hidden |
| `unshield` | sender, denom, amount, encrypted_memo | Amount public (matches bank credit) |

The `encrypted_memo` contains ECIES-encrypted state (randomness + amount) that only the sender can decrypt, enabling cross-device wallet recovery.
