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
    github.com/nixprotocol/confidential-module v0.1.4
    github.com/nixprotocol/elgamal-bn254       v0.1.0
    github.com/nixprotocol/bulletproofs-bn254  v0.1.1
)
```

> On Go 1.26, use `confidential-module` v0.1.3 or later. Earlier versions carry
> the required `bytedance/sonic` bump as a `replace` directive, which Go applies
> only to the main module — as a dependency it is ignored, and the build fails
> in `cosmossdk.io/log` with `undefined: GoMapIterator`.

> **Do not pin the earlier versions of these two.**
> `confidential-module` v0.1.0 was published with `replace` directives pointing
> at local filesystem paths, so it cannot be resolved by anyone else; v0.1.1 was
> retired when this repository's history was rewritten. Both tags are gone from
> GitHub, though `proxy.golang.org` still serves them, so builds already pinning
> them will not break.
> `bulletproofs-bn254 v0.1.0` resolves an earlier `elgamal-bn254` that still
> accepted non-canonical curve point encodings, which leaves proof and ciphertext
> bytes malleable.

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
            "auditor_pub_key": "<base64-encoded 64-byte ElGamal public key>",
            "max_transfer_bits": 64
        },
        "accounts": []
    }
}
```

`Params` has exactly these two fields:

| Parameter | Description | Recommended Value |
|---|---|---|
| `auditor_pub_key` | 64-byte ElGamal public key for the compliance auditor. Unset means no auditor data is required. | Deployment-specific |
| `max_transfer_bits` | Bit width for range proofs (max 64) | `64` |

> **There is no denom allowlist.** `enabled_denoms` was removed from the proto,
> and nothing in the module checks `msg.Denom` against a list — `Shield` accepts
> any bank denom. Setting it in genesis grants no control: `GenesisState` is
> decoded with stdlib `encoding/json`, which silently discards unknown fields,
> so the chain boots and the parameter simply does not exist. Restricting denoms
> requires a module change, not configuration.
>
> `auditor_key_grace_period`, `rotation_cooldown` and `max_memo_size` were
> removed along with it. Memo size is bounded by the `MaxEncryptedMemoSize`
> constant (1116) enforced in `ValidateBasic`, not by a parameter.
>
> The genesis value is base64, not hex: std-json decodes `[]byte` from base64.

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
tx confidential send <receiver> <denom> <sender-update-hex> <receiver-update-hex> <auditor-update-hex> <range-proof-hex> <equality-proof-hex>
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
tx confidential unshield <denom> <amount> <ciphertext-hex> <range-proof-hex> <decryption-proof-hex>
```

The client proves the ciphertext encrypts the claimed amount (DLEQ proof) and that the remaining balance after withdrawal is non-negative (range proof).

> **There is no key rotation.** `MsgRotateKey` and `tx confidential rotate-key`
> do not exist; the message set is the six listed above. Registration is
> permanent — see the comment in `keeper/msg_register_key.go`. An account that
> needs a new ElGamal key must unshield and register a fresh account.

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

6. **Deterministic zero-encryptions ensure consensus safety.** The module creates an encryption of zero in exactly one place — resetting the pending balance in `ApplyPending` — and derives the randomness from transaction context so every validator produces an identical ciphertext. Registration stores only the public key and initialises no balances; balances are lazily zero until first use.

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
| `MsgRegisterKey` | 30,000 | PoP |
| `MsgShield` | 50,000 | DLEQ |
| `MsgUnshield` | 398,000 | DLEQ 50k + CommitmentEquality 70k + AggRange(150k base + 64×1×2k) |
| `MsgConfidentialSend` | 646,000 | Equality 100k + 2× CommitmentEquality 140k + AggRange(150k base + 64×2×2k) |
| `MsgApplyPending` | 70,000 | ApplyPending |

These figures are derived from the handlers: each row lists exactly the
`verify*` calls its message makes (see `keeper/msg_*.go`), priced with the
constants in `keeper/verify.go`.

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

5. **Verify** that a `MsgConfidentialSend` with `MaxTransferBits=64` does not
   exceed your chain's block gas limit. With default constants the proof gas
   alone is ~646,000.

   Check that a block gas limit is actually set. CometBFT defaults
   `consensus.params.block.max_gas` to `-1`, meaning unlimited, and under that
   default per-transaction gas metering does not bound a block at all — blocks
   are capped only by `max_bytes`, so an attacker fills one with valid
   proof-carrying transactions and every validator performs all of the
   verification regardless of what each transaction paid. Size the limit from
   the worst gas-to-CPU ratio you are willing to accept: a `MsgConfidentialSend`
   is ~646,000 gas for ~10.6ms of verification, about 61 gas/µs.

### Parameter Bounds

The following governance-controlled parameters have enforced bounds to prevent misconfiguration:

| Parameter | Min | Max | Default |
|---|---|---|---|
| `max_transfer_bits` | 1 | 64 | 64 |

`max_transfer_bits` is the only bounded numeric parameter; `auditor_pub_key` is
validated as an on-curve, non-identity point rather than range-checked.

## Auditor Key Rotation

The auditor ElGamal key can be rotated via governance. The module stores the previous key for a grace period so that in-flight transactions using the old key can still be audited.

### Procedure

1. **Generate new keypair** offline (HSM recommended):
   ```bash
   # Use the key generation tool from Step 7 above
   # Store the new private key in the HSM before proceeding
   ```

2. **Submit a governance proposal** carrying `MsgSetAuditorKey`. SDK v0.53 takes
   a proposal JSON file rather than `--type` flags:
   ```bash
   tx gov submit-proposal proposal.json --from <key>
   ```
   where `proposal.json` contains a `MsgSetAuditorKey` with `authority` set to
   the gov module address and `pubkey` set to the new 64-byte key.

   The handler checks the authority, validates the key is on-curve and not the
   identity, and **overwrites** `auditor_pub_key`. That is the whole operation.

3. **There is no grace period, and no previous key is retained.** The module
   stores a single auditor key. `prev_auditor_pub_key`,
   `auditor_rotation_height` and `auditor_key_grace_period` do not exist — they
   were removed from the proto along with the rest of the rotation machinery.

   The verifier pins the auditor key to the current parameter value, so a
   transaction proving against the old key fails from the block the change
   lands. The effect of a rotation is that in-flight transactions built against
   the old key are rejected. That is a liveness cost, not a safety one: a user
   cannot move value while encrypting to an old or attacker-chosen auditor key.

### Important Notes

- **Never discard old auditor private keys.** Each is needed to decrypt
  ciphertexts created during its tenure. The chain does not retain past public
  keys, so the auditor must keep its own records.
- **Coordinate with clients before the vote lands.** Clients read
  `auditor_pub_key` from params when building `MsgConfidentialSend`. Because
  there is no grace window, any client still using the old key starts failing
  immediately. Ensure clients refresh params, and prefer a low-traffic window.

## Known Limitations

- **No REST (gRPC-gateway) routes.** `RegisterGRPCGatewayRoutes` is empty, so
  there are no HTTP/JSON endpoints; generating them needs a separate
  `protoc-gen-grpc-gateway` pass. gRPC and CLI both work.

  Note this is the *only* part of the RPC surface that is missing.
  `RegisterServices` registers real `Msg` and `Query` servers, and the types are
  protobuf-generated (`types/tx.pb.go`, `types/query.pb.go`,
  `types/types.pb.go`) — earlier revisions of this document claimed the
  opposite on both counts.

- **Self-sends are rejected.** `ValidateBasic` rejects `MsgConfidentialSend` where sender equals receiver. Use shield/unshield to adjust your own balance.

- **Pending balance model.** Received funds go to a pending balance that must be explicitly applied before spending. This is inherent to the ElGamal homomorphic encryption model -- the recipient must re-encrypt with known randomness to spend.

## Reference: Module Account Name

The module account name used for `x/bank` escrow is:

```go
const ModuleAccountName = "confidential"
```

This is defined in `github.com/nixprotocol/confidential-module/types.ModuleAccountName`.
