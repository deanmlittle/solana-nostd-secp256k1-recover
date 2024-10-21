# Solana NoStd BigModExp

A more efficient implementation of Big Number Modular Exponentiation for SVM.

# Installation

```cargo add solana-nostd-big-mod-exp```

# Features

- Makes use of MaybeUninit to skip zero allocations
- Implements a fixed size `big_mod_exp_fixed` function to avoid heap allocations

# Performance

| library              | function             | CU cost |
|----------------------|----------------------|---------|
| nostd-big-mod-exp    | big_mod_exp_fixed    | 2102    |
| nostd-big-mod-exp    | big_mod_exp          | 2122    |
| solana-program       | big_mod_exp          | 2151    |
