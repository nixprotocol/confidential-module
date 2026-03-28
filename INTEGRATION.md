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

4. **BSGS table size for auditor decryption.** The auditor decrypts ciphertexts using Baby-Step Giant-Step (BSGS). Each entry uses ~80 bytes (64-byte G1Affine key + 8-byte uint64 value + Go map overhead).

   **Standard BSGS (`DecryptionTable`):**

   | `halfBits` | Table Entries | Memory | Decryptable Range |
   |---|---|---|---|
   | 16 | 65,536 | ~5 MB | up to 2^32 (~4B) |
   | 20 | 1,048,576 | ~80 MB | up to 2^40 (~1T) |
   | 24 | 16,777,216 | ~1.3 GB | up to 2^48 |

   **Split BSGS (`SplitDecryptionTable`)** — trades decryption time for memory:

   | `splitBits` | `hiHalfBits` | Memory | Range | Worst-case time |
   |---|---|---|---|---|
   | 8 | 16 | ~5 MB | 2^40 | ~16M iters (~1-2s) |
   | 8 | 20 | ~80 MB | 2^48 | ~256M iters (~25s) |

   **Minimum auditor hardware requirements:**
   - Standard BSGS with `halfBits=20`: 4 GB RAM minimum (80 MB table + headroom)
   - Standard BSGS with `halfBits=24`: 4 GB RAM minimum (1.3 GB table + headroom)
   - Split BSGS: 1 GB RAM sufficient for most configurations
   - CPU: Table initialization is one-time; decryption itself is fast (sub-second for standard BSGS)
   - Disk: Negligible (tables are in-memory only)

5. **All proof generation is client-side.** The chain never sees plaintext amounts for confidential operations. Only shield and unshield reveal amounts publicly (by design, since they interact with `x/bank`).

6. **Deterministic zero-encryptions ensure consensus safety.** When the module creates encryptions of zero (during registration, apply-pending resets, and key rotation), it uses deterministic randomness derived from transaction context so all validators produce identical ciphertexts.

7. **Fiat-Shamir transcripts include chain context.** All proofs bind to `chain_id`, `sender`, `receiver`, and `denom` to prevent replay attacks across chains or between different operations.

## Rate Limiting / DoS Protection

The module relies on standard Cosmos SDK gas metering as the primary defense against spam and DoS. Proof verification is computationally expensive, so gas costs should reflect this. Chain integrators should consider the following additional protections:

### Recommended Ante Handler

Implement a custom ante handler to enforce per-account or per-block limits on confidential operations:

```go
type ConfidentialRateLimitDecorator struct {
    maxPerBlock    int
    maxPerAccount  int
    confidentialKeeper confidentialkeeper.Keeper
}

func (d ConfidentialRateLimitDecorator) AnteHandle(
    ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler,
) (sdk.Context, error) {
    for _, msg := range tx.GetMsgs() {
        switch msg.(type) {
        case *confidentialtypes.MsgConfidentialSend,
             *confidentialtypes.MsgShield,
             *confidentialtypes.MsgUnshield:
            // Check per-block and per-account counters
            // Return error if limits exceeded
        }
    }
    return next(ctx, tx, simulate)
}
```

### Built-in Gas Metering

The module charges gas for every proof verification, calibrated from benchmarks on Apple M1 Pro (arm64). These costs are defined in `keeper/verify.go` and can be adjusted by forking:

| Proof Type | Gas Cost | Benchmark Latency (M1 Pro) |
|---|---|---|
| DLEQ verify | 50,000 | ~200μs |
| Equality verify (3-key) | 100,000 | ~770μs |
| Equality2 verify (2-key) | 70,000 | ~500μs (est.) |
| ApplyPending verify | 70,000 | ~505μs |
| Aggregate range (base) | 150,000 | — |
| Aggregate range (per bit × commitments) | +2,000 | — |

**Total gas per message type** (with `MaxTransferBits=64`):

| Message | Proof Gas | Formula |
|---|---|---|
| `MsgShield` | 50,000 | DLEQ |
| `MsgUnshield` | 178,000 | DLEQ + AggRange(64 bits × 1 commitment) |
| `MsgConfidentialSend` | 506,000 | Equality + AggRange(64 bits × 2 commitments) |
| `MsgApplyPending` | 70,000 | ApplyPending |
| `MsgRotateKey` | 70,000 × N denoms | Equality2 per denom |

These are proof-only costs. Standard Cosmos SDK tx overhead (signature verification, storage reads/writes) adds on top. The key principle: gas cost must exceed the computational cost of proof verification to prevent validators from being overwhelmed. Chains with slower validator hardware should increase the constants proportionally.

### Gas Calibration for Your Hardware

The default gas constants in `keeper/verify.go` are calibrated for Apple M1 Pro. To recalibrate for your validator hardware:

1. **Run the cryptographic benchmarks** on a machine representative of your validators:
   ```bash
   cd bulletproofs-bn254 && go test -bench='Verify' -benchtime=5s -count=3
   cd elgamal-bn254     && go test -bench='Verify' -benchtime=5s -count=3
   ```

2. **Compare to M1 Pro baselines** and compute a scaling factor:
   ```
   scaling_factor = your_latency / m1_pro_latency
   ```
   For example, if `AggregateVerify_2x40bit` takes 18ms on your hardware vs. 9ms on M1 Pro, `scaling_factor = 2.0`.

3. **Scale all gas constants** by the factor, then add a 20% safety margin:
   ```
   new_gas = default_gas × scaling_factor × 1.2
   ```

4. **Update the constants** in `keeper/verify.go` (fork the module or use build tags):
   ```go
   const (
       GasDLEQVerify           = 120_000  // 50_000 × 2.0 × 1.2
       GasEqualityVerify       = 240_000  // 100_000 × 2.0 × 1.2
       // ...
   )
   ```

5. **Verify** that a `MsgConfidentialSend` with `MaxTransferBits=64` does not exceed your chain's block gas limit. With default constants, the proof gas alone is ~506,000.

### Parameter Bounds

The following governance-controlled parameters have enforced bounds to prevent misconfiguration:

| Parameter | Min | Max | Default |
|---|---|---|---|
| `rotation_cooldown` | 1 | 1,000,000 | 100 |
| `auditor_key_grace_period` | 1 | 1,000,000 | 100 |
| `max_transfer_bits` | 1 | 64 | 64 |
| `max_memo_size` | 0 | 4,096 | 1,024 |

## Auditor Key Rotation

The auditor ElGamal key can be rotated via governance. The module stores the previous key for a grace period so that in-flight transactions using the old key can still be audited.

### Procedure

1. **Generate new keypair** offline (HSM recommended):
   ```bash
   # Use the key generation tool from Step 7 above
   # Store the new private key in the HSM before proceeding
   ```

2. **Submit governance proposal** to update the auditor key:
   ```bash
   tx gov submit-proposal \
     --type=sdk.MsgSetAuditorKey \
     --authority=<gov-module-address> \
     --pubkey=<new-64-byte-hex-pubkey>
   ```
   The `MsgSetAuditorKey` handler (restricted to the governance authority) will:
   - Save the current key as `prev_auditor_pub_key`
   - Set the new key as `auditor_pub_key`
   - Record the rotation height as `auditor_rotation_height`

3. **Grace period** (`auditor_key_grace_period` blocks, default 100):
   - The previous key is stored in params and remains available for auditors to decrypt ciphertexts created before the rotation
   - New transactions use the new auditor key for their auditor ciphertext
   - Auditor infrastructure should monitor both keys during this window

4. **After the grace period**:
   - The previous key is still stored in params but clients should only use the current key
   - The auditor should retain the old private key permanently to decrypt historical ciphertexts from before the rotation
   - A subsequent rotation will overwrite `prev_auditor_pub_key` with the current key

### Important Notes

- **Never discard old auditor private keys.** Each key is needed to decrypt ciphertexts created during its tenure. Historical audit capability requires all past keys.
- **Coordinate with clients.** Clients query the current `auditor_pub_key` from params when constructing `MsgConfidentialSend`. Ensure clients refresh params after a rotation vote passes.
- **Grace period should exceed max transaction latency.** Set `auditor_key_grace_period` higher than the maximum expected time between transaction creation and inclusion (typically 100-1000 blocks).

## Known Limitations

- **No gRPC/REST endpoints in v1.** The module registers CLI commands and a direct keeper API, but full gRPC service registration requires protobuf service descriptors (planned for v2). Queries are accessible via CLI commands.

- **Proto definitions planned for v2.** The current module uses manual Go types and JSON serialization rather than protobuf-generated types. This means `RegisterServices` is a no-op and the module cannot be discovered via gRPC reflection.

- **Self-sends are rejected.** `ValidateBasic` rejects `MsgConfidentialSend` where sender equals receiver. Use shield/unshield to adjust your own balance.

- **Pending balance model.** Received funds go to a pending balance that must be explicitly applied before spending. This is inherent to the ElGamal homomorphic encryption model -- the recipient must re-encrypt with known randomness to spend.

## Reference: Module Account Name

The module account name used for `x/bank` escrow is:

```go
const ModuleAccountName = "confidential"
```

This is defined in `github.com/nixprotocol/confidential-module/types.ModuleAccountName`.
