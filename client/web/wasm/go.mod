module github.com/nixprotocol/confidential-wallet/wasm

go 1.24.0

require (
	github.com/consensys/gnark-crypto v0.19.2
	github.com/nixprotocol/bulletproofs-bn254 v0.0.0
	github.com/nixprotocol/elgamal-bn254 v0.0.0
	golang.org/x/crypto v0.45.0
)

require (
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
)

replace (
	github.com/nixprotocol/bulletproofs-bn254 => ../../../../bulletproofs-bn254
	github.com/nixprotocol/elgamal-bn254 => ../../../../elgamal-bn254
)
