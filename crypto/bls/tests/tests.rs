use bls::{Hash256, INFINITY_SIGNATURE, SECRET_KEY_BYTES_LEN};
use ssz::{Decode, Encode};
use std::borrow::Cow;
use std::fmt::Debug;

fn ssz_round_trip<T: Encode + Decode + PartialEq + Debug>(item: T) {
    assert_eq!(item, T::from_ssz_bytes(&item.as_ssz_bytes()).unwrap());
}

macro_rules! test_suite {
    ($impls: ident) => {
        use super::*;
        use bls::$impls::*;

        fn secret_from_u64(i: u64) -> SecretKey {
            let mut secret_bytes = [0; 32];
            // Use i + 1 to avoid the all-zeros secret key.
            secret_bytes[32 - 8..].copy_from_slice(&(i + 1).to_be_bytes());
            SecretKey::deserialize(&secret_bytes).unwrap()
        }

        #[test]
        fn invalid_zero_secret_key() {
            assert!(SecretKey::deserialize(&[0; SECRET_KEY_BYTES_LEN]).is_err());
        }

        #[test]
        fn infinity_agg_sig() {
            assert_eq!(
                &AggregateSignature::infinity().serialize()[..],
                &INFINITY_SIGNATURE[..]
            );
            assert_eq!(
                AggregateSignature::deserialize(&INFINITY_SIGNATURE).unwrap(),
                AggregateSignature::infinity(),
            );
            assert!(AggregateSignature::infinity().is_infinity());
        }

        #[test]
        fn ssz_round_trip_multiple_types() {
            let mut agg_sig = AggregateSignature::infinity();
            ssz_round_trip(agg_sig.clone());

            let msg = Hash256::from_low_u64_be(42);
            let secret = secret_from_u64(42);

            let sig = secret.sign(msg);
            ssz_round_trip(sig.clone());

            agg_sig.add_assign(&sig);
            ssz_round_trip(agg_sig);
        }

        #[test]
        fn ssz_round_trip_sig_empty() {
            ssz_round_trip(Signature::empty())
        }

        #[test]
        fn ssz_round_trip_agg_sig_empty() {
            ssz_round_trip(AggregateSignature::empty())
        }

        #[test]
        fn ssz_round_trip_agg_sig_infinity() {
            ssz_round_trip(AggregateSignature::infinity())
        }

        #[test]
        fn partial_eq_empty_sig() {
            assert_eq!(Signature::empty(), Signature::empty())
        }

        #[test]
        fn partial_eq_empty_sig_and_non_empty_sig() {
            assert!(Signature::empty() != SignatureTester::default().sig)
        }

        #[test]
        fn partial_eq_empty_agg_sig() {
            assert_eq!(AggregateSignature::empty(), AggregateSignature::empty())
        }

        #[test]
        fn partial_eq_empty_agg_sig_and_real_agg_sig() {
            assert!(
                AggregateSignature::empty() != AggregateSignatureTester::new_with_single_msg(1).sig
            )
        }

        #[test]
        fn partial_eq_infinity_agg_sig() {
            assert_eq!(
                AggregateSignature::infinity(),
                AggregateSignature::infinity()
            )
        }

        #[test]
        fn partial_eq_infinity_agg_sig_and_real_agg_sig() {
            assert!(
                AggregateSignature::infinity()
                    != AggregateSignatureTester::new_with_single_msg(1).sig
            )
        }

        #[test]
        fn partial_eq_infinity_agg_sig_and_empty_agg_sig() {
            assert!(AggregateSignature::infinity() != AggregateSignature::empty())
        }

        /// A helper struct for composing tests via the builder pattern.
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

            pub fn assert_verify(self, is_valid: bool) {
                assert_eq!(self.sig.verify(&self.pubkey, self.msg), is_valid);

                // Check a single-signature signature set.
                assert_eq!(
                    SignatureSet::single_pubkey(&self.sig, Cow::Borrowed(&self.pubkey), self.msg,)
                        .verify(),
                    is_valid
                )
            }
        }

        #[test]
        fn standard_signature_is_valid_with_standard_pubkey() {
            SignatureTester::default().assert_verify(true)
        }

        #[test]
        fn infinity_signature_is_invalid_with_standard_pubkey() {
            SignatureTester::default()
                .infinity_sig()
                .assert_verify(false)
        }

        /// A helper struct for composing tests via the builder pattern.
        struct AggregateSignatureTester {
            sig: AggregateSignature,
            pubkeys: Vec<PublicKey>,
            msgs: Vec<Hash256>,
        }

        impl AggregateSignatureTester {
            fn new_with_single_msg(num_pubkeys: u64) -> Self {
                let mut pubkeys = Vec::with_capacity(num_pubkeys as usize);
                let mut sig = AggregateSignature::infinity();
                let msg = Hash256::from_low_u64_be(42);

                for i in 0..num_pubkeys {
                    let secret = secret_from_u64(i);
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
                self.sig = AggregateSignature::infinity();
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

        /// Adding two infinity signatures should yield the infinity signature.
        #[test]
        fn add_two_infinity_signatures() {
            let tester = AggregateSignatureTester::new_with_single_msg(1)
                .infinity_sig()
                .aggregate_infinity_sig();
            assert!(tester.sig.is_infinity());
            assert_eq!(tester.sig, AggregateSignature::infinity());
            tester.assert_single_message_verify(false)
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

        /// A helper struct to make it easer to deal with `SignatureSet` lifetimes.
        struct OwnedSignatureSet {
            signature: AggregateSignature,
            signing_keys: Vec<PublicKey>,
            message: Hash256,
            should_be_valid: bool,
        }

        impl OwnedSignatureSet {
            pub fn multiple_pubkeys(&self) -> SignatureSet {
                let signing_keys = self.signing_keys.iter().map(Cow::Borrowed).collect();
                SignatureSet::multiple_pubkeys(&self.signature, signing_keys, self.message)
            }

            pub fn run_checks(&self) {
                assert_eq!(
                    self.multiple_pubkeys().verify(),
                    self.should_be_valid,
                    "multiple pubkey expected {} but got {}",
                    self.should_be_valid,
                    !self.should_be_valid
                )
            }
        }

        /// A helper struct for composing tests via the builder pattern.
        #[derive(Default)]
        struct SignatureSetTester {
            owned_sets: Vec<OwnedSignatureSet>,
        }

        impl SignatureSetTester {
            pub fn push_valid_set(mut self, num_signers: usize) -> Self {
                let mut signature = AggregateSignature::infinity();
                let message = Hash256::from_low_u64_be(42);

                let signing_keys = (0..num_signers)
                    .map(|i| {
                        let secret = secret_from_u64(i as u64);
                        signature.add_assign(&secret.sign(message));

                        secret.public_key()
                    })
                    .collect();

                self.owned_sets.push(OwnedSignatureSet {
                    signature,
                    signing_keys,
                    message,
                    should_be_valid: true,
                });

                self
            }

            pub fn push_invalid_set(mut self) -> Self {
                let mut signature = AggregateSignature::infinity();
                let message = Hash256::from_low_u64_be(42);

                signature.add_assign(&secret_from_u64(0).sign(message));

                self.owned_sets.push(OwnedSignatureSet {
                    signature,
                    signing_keys: vec![secret_from_u64(42).public_key()],
                    message,
                    should_be_valid: false,
                });

                self
            }

            pub fn push_invalid_pubkey_infinity_set(mut self) -> Self {
                self.owned_sets.push(OwnedSignatureSet {
                    signature: AggregateSignature::deserialize(&INFINITY_SIGNATURE).unwrap(),
                    signing_keys: vec![secret_from_u64(42).public_key()],
                    message: Hash256::zero(),
                    should_be_valid: false,
                });
                self
            }

            pub fn run_checks(self) {
                assert!(!self.owned_sets.is_empty(), "empty test is meaningless");

                for owned_set in &self.owned_sets {
                    owned_set.run_checks()
                }

                let should_be_valid = self
                    .owned_sets
                    .iter()
                    .all(|owned_set| owned_set.should_be_valid);

                let signature_sets = self
                    .owned_sets
                    .iter()
                    .map(|owned_set| owned_set.multiple_pubkeys())
                    .collect::<Vec<_>>();

                assert_eq!(
                    verify_signature_sets(signature_sets.iter()),
                    should_be_valid
                );
            }
        }

        #[test]
        fn signature_set_1_valid_set_with_1_signer() {
            SignatureSetTester::default().push_valid_set(1).run_checks()
        }

        #[test]
        fn signature_set_1_invalid_set() {
            SignatureSetTester::default()
                .push_invalid_set()
                .run_checks()
        }

        #[test]
        fn signature_set_1_valid_set_with_2_signers() {
            SignatureSetTester::default().push_valid_set(2).run_checks()
        }

        #[test]
        fn signature_set_1_valid_set_with_128_signers() {
            SignatureSetTester::default()
                .push_valid_set(128)
                .run_checks()
        }

        #[test]
        fn signature_set_2_valid_set_with_one_signer_each() {
            SignatureSetTester::default()
                .push_valid_set(1)
                .push_valid_set(1)
                .run_checks()
        }

        #[test]
        fn signature_set_2_valid_set_with_2_signers_each() {
            SignatureSetTester::default()
                .push_valid_set(2)
                .push_valid_set(2)
                .run_checks()
        }

        #[test]
        fn signature_set_2_valid_set_with_1_invalid_set() {
            SignatureSetTester::default()
                .push_valid_set(2)
                .push_invalid_set()
                .run_checks()
        }

        #[test]
        fn signature_set_3_sets_with_one_invalid_pubkey_infinity_set() {
            SignatureSetTester::default()
                .push_valid_set(2)
                .push_invalid_pubkey_infinity_set()
                .push_valid_set(2)
                .run_checks()
        }
    };
}

mod blst {
    test_suite!(blst_implementations);
}

#[cfg(all(feature = "milagro", not(debug_assertions)))]
mod milagro {
    test_suite!(milagro_implementations);
}
