# Hash-Sig Crate Integration

## Status

The keystore crate has been updated to use the `b-wagn/hash-sig` Rust crate instead of Docker. However, the actual key generation implementation is currently a placeholder.

## Current Implementation

- ✅ Dependency added: `hashsig = { git = "https://github.com/b-wagn/hash-sig", branch = "main" }`
- ✅ Docker dependencies removed
- ✅ Key storage/retrieval implemented
- ⚠️ Key generation: Placeholder implementation (returns zero bytes)

## Next Steps

To complete the integration, we need to:

1. **Explore the hash-sig crate API**
   - Check what types and functions are exported
   - Understand how to create a `GeneralizedXmssScheme`
   - Determine how to generate key pairs

2. **Implement key generation**
   - Replace `generate_xmss_public_key()` and `generate_xmss_private_key()` placeholders
   - Use the hash-sig crate API to generate actual keys
   - Configure scheme parameters:
     - LOG_LIFETIME = 32
     - LOG_NUM_ACTIVE_EPOCHS = configurable (from `log_num_active_epochs`)
     - DIM = 64
     - BASE = 8

3. **Test key generation**
   - Verify generated keys are valid
   - Test key storage and retrieval
   - Ensure keys can be used for signing/verification

## Resources

- Hash-sig crate: https://github.com/b-wagn/hash-sig
- Scheme: SIGTopLevelTargetSumLifetime32Dim64Base8
- Reference implementation: `blockblaz/lean-quickstart/generate-genesis.sh`

## Notes

The placeholder implementation currently generates zero-byte keys. This allows the code to compile and the storage/retrieval logic to be tested, but actual key generation needs to be implemented using the hash-sig crate API.
