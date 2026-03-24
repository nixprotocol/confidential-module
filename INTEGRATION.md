# x/confidential Integration Guide

Complete instructions for adding the `x/confidential` module to any Cosmos SDK chain.

## Prerequisites

- Cosmos SDK v0.53+ chain (depinject / App Wiring)
- Go 1.23+
- A running chain built with `cosmossdk.io/depinject` and `appconfig`

## Step 1: Add Dependencies

Add the following to your chain's `go.mod`:

```
require (
    github.com/nixprotocol/confidential-module v0.1.0
    github.com/nixprotocol/elgamal-bn254       v0.1.0
    github.com/nixprotocol/bulletproofs-bn254   v0.1.0
)
```

Run `go mod tidy` to resolve transitive dependencies. The module depends on `github.com/consensys/gnark-crypto` for BN254 curve operations.

## Step 2: Register the Module Account

In your `app_config.go`, add the confidential module account to the `moduleAccPerms` slice:

```go
import (
    confidentialtypes "github.com/nixprotocol/confidential-module/types"
)

var moduleAccPerms = []*authmodulev1.ModuleAccountPermission{
    // ... existing module accounts ...
    {Account: confidentialtypes.ModuleAccountName},
}
```

> **WARNING**: This is CRITICAL. Without a registered module account, any call to
> `SendCoinsFromAccountToModule` (used by `MsgShield`) or
> `SendCoinsFromModuleToAccount` (used by `MsgUnshield`) will panic at runtime
> with "module account not found". The module account name is `"confidential"`.

## Step 3: Add the Keeper to your App struct

In your `app.go`:

```go
import (
    confidentialkeeper "github.com/nixprotocol/confidential-module/keeper"
)

type App struct {
    *runtime.App
    // ... existing keepers ...
    ConfidentialKeeper confidentialkeeper.Keeper
}
```

Then wire it into the `depinject.Inject` call:

```go
if err := depinject.Inject(appConfig,
    &appBuilder,
    &appModules,
    // ... existing keepers ...
    &app.ConfidentialKeeper,
); err != nil {
    panic(err)
}
```

## Step 4: Wire in app_config.go (depinject)

Import the module package for its `init()` side-effect (which calls `appconfig.Register`), and add the module configuration:

```go
import (
    _ "github.com/nixprotocol/confidential-module/module" // import for side-effects
    confidentialtypes "github.com/nixprotocol/confidential-module/types"
)
```

In your `appConfig` module list, add:

```go
{
    Name:   confidentialtypes.ModuleName,
    Config: appconfig.WrapAny(&confidentialtypes.Module{}),
},
```

The `types.Module` struct has an optional `Authority` field. If left empty, the module authority defaults to the governance module address (`x/gov`). To use a custom authority:

```go
Config: appconfig.WrapAny(&confidentialtypes.Module{
    Authority: "cosmos1...", // custom authority address
}),
```

## Step 5: Module Ordering

Add `confidentialtypes.ModuleName` to the runtime module ordering lists.

**BeginBlockers** (the confidential module's BeginBlocker is a no-op, but must be registered):
```go
BeginBlockers: []string{
    // ... existing modules ...
    confidentialtypes.ModuleName,
},
```

**EndBlockers** (also a no-op, but must be registered):
```go
EndBlockers: []string{
    // ... existing modules ...
    confidentialtypes.ModuleName,
},
```

**InitGenesis** (place after `bank`, `auth`, and `staking` since the module uses `x/bank`):
```go
InitGenesis: []string{
    // ... consensus, auth, bank, staking, etc. ...
    confidentialtypes.ModuleName,
},
```

## Step 6: Genesis Configuration

The module supports genesis configuration via JSON. In your chain's genesis file or Ignite `config.yml`:

```json
{
    "confidential": {
        "params": {
            "auditor_pub_key": "<64-byte hex-encoded ElGamal public key>",
            "enabled_denoms": ["uatom", "ibc/<USDC_HASH>"],
            "max_transfer_bits": 64,
            "auditor_key_grace_period": 100,
            "rotation_cooldown": 100,
            "max_memo_size": 1024
        },
        "accounts": []
    }
}
```

Parameter descriptions:

| Parameter | Description | Recommended Value |
|---|---|---|
| `auditor_pub_key` | 64-byte hex ElGamal public key for the compliance auditor | Required if `enabled_denoms` is non-empty |
| `enabled_denoms` | List of token denominations that can be shielded | Chain-specific (e.g., `["uatom"]`) |
| `max_transfer_bits` | Bit width for range proofs (max 64) | `64` |
| `auditor_key_grace_period` | Blocks during which the previous auditor key remains valid after rotation | `100` |
| `rotation_cooldown` | Minimum blocks between key rotations per account | `100` |
| `max_memo_size` | Maximum plaintext memo size in bytes (0-4096) | `1024` |

## Step 7: Generate Auditor Key

The auditor ElGamal keypair must be generated client-side. The private key enables decryption of all confidential transfers for compliance purposes.

```go
package main

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"

    elgamal "github.com/nixprotocol/elgamal-bn254"
)

func main() {
    sk, pk, err := elgamal.KeyGen(rand.Reader)
    if err != nil {
        panic(err)
    }

    pkBytes := elgamal.MarshalPublicKey(&pk)
    skBytes := sk.Marshal()

    fmt.Printf("Auditor Public Key (set in genesis/params): %s\n", hex.EncodeToString(pkBytes))
    fmt.Printf("Auditor Secret Key (store securely in HSM): %s\n", hex.EncodeToString(skBytes))
}
```

> **IMPORTANT**: The auditor private key MUST be stored securely. An HSM (Hardware Security Module) is strongly recommended for production deployments. Loss of the auditor key means loss of the ability to audit confidential transfers. Compromise of the auditor key means all transfer amounts become visible to the attacker.

## Step 8: User Operations

The full confidential transfer lifecycle:

### 1. Register Key
Each user generates an ElGamal keypair and registers the public key on-chain:

```
tx confidential register-key <64-byte-hex-pubkey>
```

This initializes encrypted zero-balances for all enabled denominations.

### 2. Shield (Deposit)
Convert plaintext tokens from `x/bank` into encrypted balances:

```
tx confidential shield <denom> <amount> <ciphertext-hex> <dleq-proof-hex>
```

The client encrypts the amount under their public key, generates a DLEQ proof, and the module debits the plaintext tokens while adding the encrypted amount to the available balance.

### 3. Confidential Send (Transfer)
Transfer encrypted tokens to another registered user:

```
tx confidential send <receiver> <denom> <sender-ct> <receiver-ct> <auditor-ct> <range-proof> <equality-proof> <receiver-key-counter>
```

The client creates three ciphertexts (sender, receiver, auditor) encrypting the same amount under each party's public key, proves equality via a zero-knowledge proof, and proves the transfer amount and remaining balance are non-negative via an aggregate range proof.

### 4. Apply Pending
Recipients must apply pending balances before they can spend them:

```
tx confidential apply-pending <denom> <new-available-update-ct> <apply-pending-proof>
```

The client decrypts their pending balance, re-encrypts it with fresh randomness, and proves correct decryption/re-encryption.

### 5. Unshield (Withdraw)
Convert encrypted balances back to plaintext tokens in `x/bank`:

```
tx confidential unshield <denom> <amount> <ciphertext-hex> <dleq-proof> <range-proof>
```

The client proves the ciphertext encrypts the claimed amount (DLEQ proof) and that the remaining balance after withdrawal is non-negative (range proof).

### 6. Rotate Key (Optional)
Replace the account's ElGamal public key:

```
tx confidential rotate-key <new-pubkey-hex> <new-counter> <re-encrypted-balances> <equality2-proofs>
```

Requires all pending balances to be applied first. The client proves each balance was correctly re-encrypted under the new key.

## Security Considerations

1. **Module account registration is mandatory.** Omitting the module account from `moduleAccPerms` causes panics when shielding or unshielding tokens.

2. **Auditor key should be set before enabling denominations.** The genesis validator rejects configurations with enabled denominations but no auditor key.

3. **MaxTransferBits=64 is recommended** for full uint64 range support. The range proof dimension is padded to 64 regardless, so smaller values offer no performance benefit.

4. **BSGS table size for auditor decryption.** The auditor decrypts ciphertexts using Baby-Step Giant-Step (BSGS). Recommend `halfBits=24` for production (approximately 1GB RAM), which supports decryption of amounts up to 2^48. Larger tables enable decryption of larger amounts.

5. **All proof generation is client-side.** The chain never sees plaintext amounts for confidential operations. Only shield and unshield reveal amounts publicly (by design, since they interact with `x/bank`).

6. **Deterministic zero-encryptions ensure consensus safety.** When the module creates encryptions of zero (during registration, apply-pending resets, and key rotation), it uses deterministic randomness derived from transaction context so all validators produce identical ciphertexts.

7. **Fiat-Shamir transcripts include chain context.** All proofs bind to `chain_id`, `sender`, `receiver`, and `denom` to prevent replay attacks across chains or between different operations.

## Known Limitations

- **No gRPC/REST endpoints in v1.** The module registers CLI commands and a direct keeper API, but full gRPC service registration requires protobuf service descriptors (planned for v2). Queries are accessible via CLI commands.

- **Auditor grace period during key rotation is not fully enforced.** The `auditor_key_grace_period` parameter is stored but transactions using the old auditor key after rotation will fail proof verification. Applications should coordinate auditor key rotation carefully.

- **Proto definitions planned for v2.** The current module uses manual Go types and JSON serialization rather than protobuf-generated types. This means `RegisterServices` is a no-op and the module cannot be discovered via gRPC reflection.

- **Self-sends are rejected.** `ValidateBasic` rejects `MsgConfidentialSend` where sender equals receiver. Use shield/unshield to adjust your own balance.

- **Pending balance model.** Received funds go to a pending balance that must be explicitly applied before spending. This is inherent to the ElGamal homomorphic encryption model -- the recipient must re-encrypt with known randomness to spend.

## Reference: Module Account Name

The module account name used for `x/bank` escrow is:

```go
const ModuleAccountName = "confidential"
```

This is defined in `github.com/nixprotocol/confidential-module/types.ModuleAccountName`.
