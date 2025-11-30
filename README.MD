Auther leon sage otr437
# Zashi + Starknet Multichain Wallet

**Shielded Zcash ↔ Starknet L2 – atomic swaps, no bridges, no custodians.**

### v1 – Fully working single-file edition
→ See: [`src/v1-complete-single-file.kt`](src/v1-complete-single-file.kt)

- Full Zcash SDK (shielded + transparent)
- Starknet StandardAccount + proper key derivation
- Biometric + encrypted storage
- Background sync + portfolio view
- Real atomic swap engine (HTLC logic 100% done)
- Unified transaction history

Only two things left for 100% trustless:
1. Deployed Starknet HTLC contract (in progress)
2. Zcash SPV proof verification (optional for v1)

**Star if you want the first real private cross-chain mobile wallet.**

v2 → modular + real atomic swaps live on mainnet.