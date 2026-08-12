# confidential-module

A Cosmos SDK module for **confidential token transfers**. Account balances are
stored as ElGamal ciphertexts over BN254; Bulletproofs range proofs and Sigma
protocols enforce solvency and conservation without revealing any amount.

Chain-agnostic — it drops into any Cosmos SDK v0.53+ chain via depinject. An
auditor key gives regulated deployments a compliance view without making
balances public.

```bash
go get github.com/nixprotocol/confidential-module@v0.1.4
```

> **Use v0.1.4.** It fixes a break in the bundled browser client, which derived
> the confidential spending key from the account's *public* key — so anyone could
> recompute it and decrypt that account's balance. The Go API is unchanged from
> v0.1.3.
>
> Do not use anything before v0.1.3 on Go 1.26: earlier versions pinned the
> `bytedance/sonic` fix with a `replace` directive, which Go honours only in the
> main module and ignores for imported packages, so they fail to compile for
> consumers. v0.1.3 carries it as a `require` bump instead.

> The two oldest tags have been withdrawn from this repository:
> `v0.1.0` was published with `replace` directives pointing at local filesystem
> paths and cannot be resolved by anyone, and `v0.1.1` was retired when history
> was rewritten. Both remain fetchable from `proxy.golang.org`, so existing
> builds that pin them keep working, but neither should be used for new work.

## Model

Each account holds two ElGamal ciphertexts under its own public key:

- **available** — spendable now
- **pending** — incoming transfers, not yet spendable

Incoming transfers land in `pending` and the owner folds them into `available`
with `ApplyPending`. The split exists because ElGamal is additively homomorphic:
anyone can add to your `pending` without your key, so a sender cannot invalidate
a proof you are concurrently building against `available`.

Amounts are never in the clear on chain. What the chain verifies instead is that
each transaction is *consistent*: the sender's balance decreases by the same
amount the receiver's increases, and no balance goes negative.

## Messages

| Message | Description |
|---|---|
| `MsgRegisterKey` | Publish an ElGamal public key, with a Schnorr proof of possession |
| `MsgShield` | Move public `bank` tokens into a confidential balance |
| `MsgConfidentialSend` | Transfer a hidden amount to another registered account |
| `MsgApplyPending` | Fold `pending` into `available` |
| `MsgUnshield` | Move a confidential balance back to public `bank` tokens |
| `MsgSetAuditorKey` | Governance-only: rotate the auditor key |

## Queries

| Query | Description |
|---|---|
| `Balance` | Encrypted available and pending balances for an account |
| `AccountInfo` | Registration status and public key |
| `AuditorKey` | Current auditor public key |
| `Params` | Module parameters |

## What the proofs establish

A `ConfidentialSend` carries, and the keeper verifies:

- **Aggregate Bulletproofs range proof** over the transfer amount and the
  sender's remaining balance — both are in `[0, 2^64)`, so the sender cannot
  transfer more than they hold or wrap the balance negative.
- **Three-key equality** — the same amount is encrypted under the sender's,
  the receiver's, and the auditor's public keys. The auditor sees what the
  receiver sees; a sender cannot hide a transfer from audit.
- **Commitment equality** — each ElGamal ciphertext encrypts the same value as
  the Pedersen commitment the range proof is taken over. Without this the range
  proof constrains a commitment unrelated to the actual transfer.
- **DLEQ** — on `Unshield`, the public amount released really is the amount
  removed from the confidential balance.

### Two properties worth stating explicitly

**The range proof blinding base must be nothing-up-my-sleeve.** Range proofs are
taken over Pedersen commitments blinded by a NUMS generator derived by
hash-to-curve (`bulletproofs.H`), never an account key. If a prover knows
`dlog_G(H)`, it can re-open any commitment to any value and prove *anything* is
in range — an unlimited mint. `bulletproofs-bn254` carries a regression test that
performs exactly that forgery to keep the requirement visible.

**Curve points are accepted in one encoding only.** gnark reads the point format
from flag bits in the first byte, so a 64-byte slot could hold a compressed
encoding whose trailing 32 bytes are ignored — giving one ciphertext or proof
many valid byte representations. Every point is required to be uncompressed, so
that anything keying state or deduplicating by proof bytes is sound.

## Integration

Full instructions, including the module account registration that
`Shield`/`Unshield` require, are in [`INTEGRATION.md`](INTEGRATION.md).

Minimum wiring:

```go
import (
    confidentialkeeper "github.com/nixprotocol/confidential-module/keeper"
    confidentialmodule "github.com/nixprotocol/confidential-module/module"
    confidentialtypes "github.com/nixprotocol/confidential-module/types"
)

app.ConfidentialKeeper = confidentialkeeper.NewKeeper(
    runtime.NewKVStoreService(keys[confidentialtypes.StoreKey]),
    appCodec,
    app.AccountKeeper.AddressCodec(),
    authtypes.NewModuleAddress(govtypes.ModuleName), // authority, as []byte
    app.BankKeeper,
)

app.ModuleManager.Modules[confidentialtypes.ModuleName] = confidentialmodule.NewAppModule(
    appCodec, app.ConfidentialKeeper, app.BankKeeper,
)
```

> `Shield` and `Unshield` move real tokens through the module account
> `confidential`, which **must** be registered in `moduleAccPerms` or those
> handlers will fail. Register it with **no permissions** —
> `{Account: confidentialtypes.ModuleAccountName}`. See `INTEGRATION.md` step 2.

The module is **escrow-only**. Its `BankKeeper` interface declares just
`SendCoinsFromAccountToModule` and `SendCoinsFromModuleToAccount` — no
`MintCoins`, no `BurnCoins`. Shielding moves tokens into the module account and
unshielding moves them back out, so total supply is invariant and the module
cannot inflate it even if the confidential accounting were wrong. Granting it
minter or burner permissions would discard that guarantee for nothing.

## Clients

- `client/cli` — chain CLI commands
- `client/sdk` — Go client SDK, including transaction randomness derivation
- `client/web` — browser/WASM client

Client-side randomness is derived from a context that binds chain ID, denom,
operation, sequence, **amount, and receiver**. Binding only up to sequence is not
sufficient: a resubmitted transaction reuses its sequence, which would reuse the
ElGamal randomness and leak the relationship between the two ciphertexts.

## Dependencies

| Module | Purpose |
|---|---|
| [`elgamal-bn254`](https://github.com/nixprotocol/elgamal-bn254) | ElGamal encryption, Sigma protocols, transcripts |
| [`bulletproofs-bn254`](https://github.com/nixprotocol/bulletproofs-bn254) | Aggregate range proofs |

Pin `bulletproofs-bn254` at **v0.1.1 or later**. `v0.1.0` resolves an earlier
`elgamal-bn254` that still accepted non-canonical point encodings.

## Testing

```bash
go test ./...
```

The keeper suite includes adversarial, soundness, negative, and fuzz tests, plus
a full mint/transfer/claim/burn lifecycle with decrypted balance assertions.

## License

Apache 2.0 — see [LICENSE](LICENSE).
