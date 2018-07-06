extern crate bls;
extern crate pairing;

use self::bls::AggregateSignature as GenericAggregateSignature;
use self::bls::Signature as GenericSignature;
use self::bls::Keypair as GenericKeypair;
use self::bls::PublicKey as GenericPublicKey;
use self::pairing::bls12_381::Bls12;

pub type AggregateSignature = GenericAggregateSignature<Bls12>;
pub type Signature = GenericSignature<Bls12>;
pub type Keypair = GenericKeypair<Bls12>;
pub type PublicKey = GenericPublicKey<Bls12>;
