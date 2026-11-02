use bls::{
    FixedBytesExtended, Hash256, INFINITY_SIGNATURE, INFINITY_SIGNATURE_UNCOMPRESSED,
    SECRET_KEY_BYTES_LEN,
};
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
        fn infinity_sig_serializations_match() {
            let sig = Signature::deserialize(&INFINITY_SIGNATURE).unwrap();
            assert_eq!(
                sig.serialize_uncompressed().unwrap(),
                INFINITY_SIGNATURE_UNCOMPRESSED
            );
            let sig =
                Signature::deserialize_uncompressed(&INFINITY_SIGNATURE_UNCOMPRESSED).unwrap();
            assert_eq!(sig.serialize(), INFINITY_SIGNATURE);
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

        #[test]
        fn empty_aggregate_plus_infinity_should_be_infinity() {
            let mut agg = AggregateSignature::empty();
            let infinity_sig = Signature::deserialize(&INFINITY_SIGNATURE).unwrap();
            agg.add_assign(&infinity_sig);
            assert!(
                agg.is_infinity(),
                "is_infinity flag should be true after adding infinity to empty"
            );
        }

        #[test]
        fn deserialize_infinity_public_key() {
            PublicKey::deserialize(&bls::INFINITY_PUBLIC_KEY).unwrap_err();
        }

        /// A helper struct to make it easer to deal with `SignatureSet` lifetimes.
        struct OwnedSignatureSet {
            signature: AggregateSignature,
            signing_keys: Vec<PublicKey>,
            message: Hash256,
            should_be_valid: bool,
        }

        impl OwnedSignatureSet {
            pub fn multiple_pubkeys(&self) -> SignatureSet<'_> {
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

        /// Many valid sets sharing a single message exercise the "super batch" fold (a randomized
        /// multi-scalar multiplication over the whole group) at scale.
        #[test]
        fn signature_set_many_valid_sets_same_message() {
            let mut tester = SignatureSetTester::default();
            for _ in 0..16 {
                tester = tester.push_valid_set(1);
            }
            tester.run_checks()
        }

        /// A batch that mixes several messages, with multiple sets per message, must verify when
        /// every set is valid.
        #[test]
        fn signature_set_mixed_messages_all_valid() {
            // Three sets over message `1`, two over message `2`, one over message `3`.
            let message_layout = [1u64, 1, 1, 2, 2, 3];

            let mut signatures = Vec::new();
            let mut pubkeys = Vec::new();
            for (i, msg) in message_layout.iter().enumerate() {
                let secret = secret_from_u64(i as u64);
                let message = Hash256::from_low_u64_be(*msg);
                let mut signature = AggregateSignature::infinity();
                signature.add_assign(&secret.sign(message));
                signatures.push((signature, message));
                pubkeys.push(secret.public_key());
            }

            let sets = signatures
                .iter()
                .zip(pubkeys.iter())
                .map(|((signature, message), pubkey)| {
                    SignatureSet::single_pubkey(signature, Cow::Borrowed(pubkey), *message)
                })
                .collect::<Vec<_>>();

            assert!(verify_signature_sets(sets.iter()));
        }

        /// As above, but one set in a multi-set message group carries the wrong signature. The
        /// whole batch must fail.
        #[test]
        fn signature_set_mixed_messages_one_invalid() {
            let message_layout = [1u64, 1, 1, 2, 2, 3];

            let mut signatures = Vec::new();
            let mut pubkeys = Vec::new();
            for (i, msg) in message_layout.iter().enumerate() {
                let secret = secret_from_u64(i as u64);
                let message = Hash256::from_low_u64_be(*msg);
                let mut signature = AggregateSignature::infinity();
                // Corrupt the second set (one of the three sharing message `1`) by signing with the
                // wrong secret key.
                let signing_secret = if i == 1 {
                    secret_from_u64(999)
                } else {
                    secret_from_u64(i as u64)
                };
                signature.add_assign(&signing_secret.sign(message));
                signatures.push((signature, message));
                pubkeys.push(secret.public_key());
            }

            let sets = signatures
                .iter()
                .zip(pubkeys.iter())
                .map(|((signature, message), pubkey)| {
                    SignatureSet::single_pubkey(signature, Cow::Borrowed(pubkey), *message)
                })
                .collect::<Vec<_>>();

            assert!(!verify_signature_sets(sets.iter()));
        }

        /// The core soundness property of the super-batch optimization: two attestations that are
        /// individually invalid but whose signatures cancel out when *naively* summed must be rejected.
        ///
        /// Here set A carries signer 2's signature but claims signer 1's public key, and set B does
        /// the reverse. Neither verifies alone, yet `sig_a + sig_b` is a valid aggregate signature
        /// under `pk1 + pk2`. The per-signature randomization in the fold is what defeats this.
        #[test]
        fn signature_set_rejects_cancellation_attack() {
            let message = Hash256::from_low_u64_be(42);

            let sk1 = secret_from_u64(1);
            let sk2 = secret_from_u64(2);
            let pk1 = sk1.public_key();
            let pk2 = sk2.public_key();

            // Each set carries the *other* signer's signature, so neither is valid on its own.
            let mut sig_a = AggregateSignature::infinity();
            sig_a.add_assign(&sk2.sign(message));
            let mut sig_b = AggregateSignature::infinity();
            sig_b.add_assign(&sk1.sign(message));

            let set_a = SignatureSet::single_pubkey(&sig_a, Cow::Borrowed(&pk1), message);
            let set_b = SignatureSet::single_pubkey(&sig_b, Cow::Borrowed(&pk2), message);
            assert!(
                !set_a.clone().verify(),
                "set A must be individually invalid"
            );
            assert!(
                !set_b.clone().verify(),
                "set B must be individually invalid"
            );

            // Sanity-check that the attack is real: the naive aggregate (sum of signatures under
            // the sum of public keys) *does* verify, because the swapped signatures cancel.
            let mut naive_aggregate = AggregateSignature::infinity();
            naive_aggregate.add_assign(&sk2.sign(message));
            naive_aggregate.add_assign(&sk1.sign(message));
            assert!(
                naive_aggregate.fast_aggregate_verify(message, &[&pk1, &pk2]),
                "the naive aggregate must verify, otherwise the test is not exercising the attack"
            );

            // The randomized super-batch verification must reject the crafted sets.
            let sets = [set_a, set_b];
            assert!(
                !verify_signature_sets(sets.iter()),
                "super-batch verification must reject individually-invalid signatures that only \
                 cancel out when naively summed"
            );
        }
    };
}

mod blst {
    test_suite!(blst_implementations);
}
