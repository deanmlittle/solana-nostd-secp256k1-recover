# Solana NoStd Secp256k1 Recover

A more efficient implementation of Secp256k1 Recover for SVM.

# Installation

```cargo add solana-nostd-secp256k1-recover```

# Features

- No `Secp256k1Pubkey type` struct. Returns a `[u8;64]` directly.
- Makes use of MaybeUninit to skip zero allocations

# Performance

| library                   | function                    | CU cost |
|---------------------------|-----------------------------|---------|
| nostd-secp256k1-recover   | secp256k1_recover_unchecked | 25006   |
| nostd-secp256k1-recover   | secp256k1_recover           | 25006   |
| solana-program            | secp256k1_recover           | 25193   |
