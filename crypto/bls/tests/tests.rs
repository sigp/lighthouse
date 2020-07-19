use bls::{Hash256, INFINITY_PUBLIC_KEY, INFINITY_SIGNATURE};

macro_rules! test_suite {
    ($impls: ident) => {
        use super::*;
        use bls::$impls::*;

        struct SignatureTester {
            sig: Signature,
            pubkey: PublicKey,
            msg: Hash256,
        }

        impl Default for SignatureTester {
            fn default() -> Self {
                let secret = SecretKey::deserialize(&[42; 32]).unwrap();
                let pubkey = secret.public_key();
                let msg = Hash256::from_low_u64_be(42);

                Self {
                    sig: secret.sign(msg),
                    pubkey,
                    msg,
                }
            }
        }

        impl SignatureTester {
            pub fn infinity_sig(mut self) -> Self {
                self.sig = Signature::deserialize(&INFINITY_SIGNATURE[..]).unwrap();
                self
            }

            pub fn infinity_pubkey(mut self) -> Self {
                self.pubkey = PublicKey::deserialize(&INFINITY_PUBLIC_KEY[..]).unwrap();
                self
            }

            pub fn assert_verify(self, is_valid: bool) {
                assert_eq!(self.sig.verify(&self.pubkey, self.msg), is_valid);
            }
        }

        #[test]
        fn standard_signature_is_valid_with_standard_pubkey() {
            SignatureTester::default().assert_verify(true)
        }

        #[test]
        fn infinity_signature_is_valid_with_infinity_pubkey() {
            SignatureTester::default()
                .infinity_sig()
                .infinity_pubkey()
                .assert_verify(true)
        }

        #[test]
        fn infinity_signature_is_invalid_with_standard_pubkey() {
            SignatureTester::default()
                .infinity_sig()
                .assert_verify(false)
        }

        #[test]
        fn standard_signature_is_invalid_with_infinity_pubkey() {
            SignatureTester::default()
                .infinity_pubkey()
                .assert_verify(false)
        }

        struct AggregateSignatureTester {
            sig: AggregateSignature,
            pubkeys: Vec<PublicKey>,
            msgs: Vec<Hash256>,
        }

        impl AggregateSignatureTester {
            fn new_with_single_msg(num_pubkeys: u64) -> Self {
                let mut pubkeys = Vec::with_capacity(num_pubkeys as usize);
                let mut sig = AggregateSignature::zero();
                let msg = Hash256::from_low_u64_be(42);

                for i in 0..num_pubkeys {
                    let mut secret_bytes = [0; 32];
                    // Use i + 1 to avoid the all-zeros secret key.
                    secret_bytes[32 - 8..].copy_from_slice(&(i + 1).to_be_bytes());
                    let secret = SecretKey::deserialize(&secret_bytes).unwrap();
                    pubkeys.push(secret.public_key());
                    sig.add_assign(&secret.sign(msg));
                }

                Self {
                    sig,
                    pubkeys,
                    msgs: vec![msg],
                }
            }

            pub fn empty_sig(mut self) -> Self {
                self.sig = AggregateSignature::empty();
                self
            }

            pub fn wrong_sig(mut self) -> Self {
                let sk = SecretKey::deserialize(&[1; 32]).unwrap();
                self.sig = AggregateSignature::zero();
                self.sig.add_assign(&sk.sign(Hash256::from_low_u64_be(1)));
                self
            }

            pub fn infinity_sig(mut self) -> Self {
                self.sig = AggregateSignature::deserialize(&INFINITY_SIGNATURE[..]).unwrap();
                self
            }

            pub fn aggregate_empty_sig(mut self) -> Self {
                self.sig.add_assign(&Signature::empty());
                self
            }

            pub fn aggregate_empty_agg_sig(mut self) -> Self {
                self.sig.add_assign_aggregate(&AggregateSignature::empty());
                self
            }

            pub fn aggregate_infinity_sig(mut self) -> Self {
                self.sig
                    .add_assign(&Signature::deserialize(&INFINITY_SIGNATURE[..]).unwrap());
                self
            }

            pub fn single_infinity_pubkey(mut self) -> Self {
                self.pubkeys = vec![PublicKey::deserialize(&INFINITY_PUBLIC_KEY[..]).unwrap()];
                self
            }

            pub fn push_infinity_pubkey(mut self) -> Self {
                self.pubkeys
                    .push(PublicKey::deserialize(&INFINITY_PUBLIC_KEY[..]).unwrap());
                self
            }

            pub fn assert_single_message_verify(self, is_valid: bool) {
                assert!(self.msgs.len() == 1);
                let msg = self.msgs.first().unwrap();
                let pubkeys = self.pubkeys.iter().collect::<Vec<_>>();

                assert_eq!(
                    self.sig.fast_aggregate_verify(*msg, &pubkeys),
                    is_valid,
                    "fast_aggregate_verify expected {} but got {}",
                    is_valid,
                    !is_valid
                );

                let msgs = pubkeys.iter().map(|_| msg.clone()).collect::<Vec<_>>();

                assert_eq!(
                    self.sig.aggregate_verify(&msgs, &pubkeys),
                    is_valid,
                    "aggregate_verify expected {} but got {}",
                    is_valid,
                    !is_valid
                );
            }
        }

        /// An aggregate without any signatures should not verify.
        #[test]
        fn fast_aggregate_verify_0_pubkeys() {
            AggregateSignatureTester::new_with_single_msg(0).assert_single_message_verify(false)
        }

        /// An aggregate of size 1 should verify.
        #[test]
        fn fast_aggregate_verify_1_pubkey() {
            AggregateSignatureTester::new_with_single_msg(1).assert_single_message_verify(true)
        }

        /// An aggregate of size 128 should verify.
        #[test]
        fn fast_aggregate_verify_128_pubkeys() {
            AggregateSignatureTester::new_with_single_msg(128).assert_single_message_verify(true)
        }

        /// The infinity signature should not verify against 1 non-infinity pubkey.
        #[test]
        fn fast_aggregate_verify_infinity_signature_with_1_regular_public_key() {
            AggregateSignatureTester::new_with_single_msg(1)
                .infinity_sig()
                .assert_single_message_verify(false)
        }

        /// The infinity signature should not verify against 128 non-infinity pubkeys.
        #[test]
        fn fast_aggregate_verify_infinity_signature_with_128_regular_public_keys() {
            AggregateSignatureTester::new_with_single_msg(128)
                .infinity_sig()
                .assert_single_message_verify(false)
        }

        /// The infinity signature and one infinity pubkey should verify.
        #[test]
        fn fast_aggregate_verify_infinity_signature_with_one_infinity_pubkey() {
            AggregateSignatureTester::new_with_single_msg(1)
                .infinity_sig()
                .single_infinity_pubkey()
                .assert_single_message_verify(true)
        }

        /// Adding a infinity signature (without an infinity pubkey) should verify.
        #[test]
        fn fast_aggregate_verify_with_one_aggregated_infinity_sig() {
            AggregateSignatureTester::new_with_single_msg(1)
                .aggregate_infinity_sig()
                .assert_single_message_verify(true)
        }

        /// Adding four infinity signatures (without any infinity pubkeys) should verify.
        #[test]
        fn fast_aggregate_verify_with_four_aggregated_infinity_sig() {
            AggregateSignatureTester::new_with_single_msg(1)
                .aggregate_infinity_sig()
                .aggregate_infinity_sig()
                .aggregate_infinity_sig()
                .aggregate_infinity_sig()
                .assert_single_message_verify(true)
        }

        /// Adding a infinity pubkey and an infinity signature should verify.
        #[test]
        fn fast_aggregate_verify_with_one_additional_infinity_pubkey_and_matching_sig() {
            AggregateSignatureTester::new_with_single_msg(1)
                .aggregate_infinity_sig()
                .push_infinity_pubkey()
                .assert_single_message_verify(true)
        }

        /// Adding a single infinity pubkey **without** updating the signature **should verify**.
        #[test]
        fn fast_aggregate_verify_with_one_additional_infinity_pubkey() {
            AggregateSignatureTester::new_with_single_msg(1)
                .push_infinity_pubkey()
                .assert_single_message_verify(true)
        }

        /// Adding multiple infinity pubkeys **without** updating the signature **should verify**.
        #[test]
        fn fast_aggregate_verify_with_four_additional_infinity_pubkeys() {
            AggregateSignatureTester::new_with_single_msg(1)
                .push_infinity_pubkey()
                .push_infinity_pubkey()
                .push_infinity_pubkey()
                .push_infinity_pubkey()
                .assert_single_message_verify(true)
        }

        /// The wrong signature should not verify.
        #[test]
        fn fast_aggregate_verify_wrong_signature() {
            AggregateSignatureTester::new_with_single_msg(1)
                .wrong_sig()
                .assert_single_message_verify(false)
        }

        /// An "empty" signature should not verify.
        #[test]
        fn fast_aggregate_verify_empty_signature() {
            AggregateSignatureTester::new_with_single_msg(1)
                .empty_sig()
                .assert_single_message_verify(false)
        }

        /// Aggregating an "empty" signature should have no effect.
        #[test]
        fn fast_aggregate_verify_with_aggregated_empty_sig() {
            AggregateSignatureTester::new_with_single_msg(1)
                .aggregate_empty_sig()
                .assert_single_message_verify(true)
        }

        /// Aggregating an "empty" aggregate signature should have no effect.
        #[test]
        fn fast_aggregate_verify_with_aggregated_empty_agg_sig() {
            AggregateSignatureTester::new_with_single_msg(1)
                .aggregate_empty_agg_sig()
                .assert_single_message_verify(true)
        }
    };
}

mod blst {
    test_suite!(blst_implementations);
}

#[cfg(not(debug_assertions))]
mod milagro {
    test_suite!(milagro_implementations);
}
