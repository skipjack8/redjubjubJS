use bech32::{self, FromBase32, ToBase32, Error};
use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use blake2s_simd::Params as Blake2sParams;
use jubjub::{AffinePoint, ExtendedPoint};

use std::io::{self, Write};
use std::convert::{TryInto};

use crate::{constants, group_hash::group_hash, PublicKey, SpendAuth};

type Scalar = jubjub::Fr;

/// PRF^expand(sk, t) := BLAKE2b-512("Zcash_ExpandSeed", sk || t)
pub fn prf_expand(sk: &[u8], t: &[u8]) -> Blake2bHash {
    prf_expand_vec(sk, &[t])
}

pub fn prf_expand_vec(sk: &[u8], ts: &[&[u8]]) -> Blake2bHash {
    let mut h = Blake2bParams::new()
        .hash_length(64)
        .personal(constants::PRF_EXPAND_PERSONALIZATION)
        .to_state();
    h.update(sk);
    for t in ts {
        h.update(t);
    }
    h.finalize()
}

/// An outgoing viewing key
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OutgoingViewingKey(pub [u8; 32]);

/// A Sapling expanded spending key
#[derive(Clone)]
pub struct ExpandedSpendingKey {
    pub ask: Scalar,
    pub nsk: Scalar,
    pub ovk: OutgoingViewingKey,
}

impl ExpandedSpendingKey {
    pub fn from_spending_key(sk: &[u8]) -> Self {
        let mut ask_bytes:[u8; 64] = [0; 64];
        (&mut ask_bytes[..]).copy_from_slice(prf_expand(sk, &[0x00]).as_bytes());
        let ask = Scalar::from_bytes_wide(&ask_bytes);

        let mut nsk_bytes:[u8; 64] = [0; 64];
        (&mut nsk_bytes[..]).copy_from_slice(prf_expand(sk, &[0x01]).as_bytes());
        let nsk = Scalar::from_bytes_wide(&nsk_bytes);

        let mut ovk = OutgoingViewingKey([0u8; 32]);
        ovk.0.copy_from_slice(&prf_expand(sk, &[0x02]).as_bytes()[..32]);
        ExpandedSpendingKey { ask, nsk, ovk }
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        let mut result = [0u8; 96];
        (&mut result[..32]).copy_from_slice(&self.ask.to_bytes()[..]);
        (&mut result[32..64]).copy_from_slice(&self.nsk.to_bytes()[..]);
        (&mut result[64..96]).copy_from_slice(&self.ovk.0[..]);
        result
    }
}

#[derive(Debug)]
pub struct ViewingKey {
    pub ak: AffinePoint,
    pub nk: AffinePoint,
}

impl ViewingKey {
    pub fn ivk(&self) -> Option<Scalar> {
        let mut preimage = [0; 64];

        (&mut preimage[..32]).copy_from_slice(&self.ak.to_bytes()[..]);
        (&mut preimage[32..64]).copy_from_slice(&self.nk.to_bytes()[..]);

        let mut h = [0; 32];
        h.copy_from_slice(
            Blake2sParams::new()
                .hash_length(32)
                .personal(constants::CRH_IVK_PERSONALIZATION)
                .hash(&preimage)
                .as_bytes(),
        );

        // Drop the most significant five bits, so it can be interpreted as a scalar.
        h[31] &= 0b0000_0111;

        //It should be succeed.
        let result = Scalar::from_bytes(&h).unwrap();
        if result == Scalar::zero() {
            None
        } else {
            Some(result)
        }
    }
}


#[derive(Debug)]
pub struct FullViewingKey {
    pub vk: ViewingKey,
    pub ovk: OutgoingViewingKey,
}

impl FullViewingKey {
    pub fn from_expanded_spending_key(expsk: &ExpandedSpendingKey) -> Self {
        let nk_basepoint: jubjub::ExtendedPoint = jubjub::AffinePoint::from_bytes(constants::NK_BASEPOINT_BYTES).unwrap().into();
        FullViewingKey {
            vk: ViewingKey {
                ak: AffinePoint::from(PublicKey::<SpendAuth>::from_secret(&expsk.ask).point),
                nk: AffinePoint::from(&nk_basepoint * &expsk.nsk),
            },
            ovk: expsk.ovk,
        }
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        let mut result = [0u8; 96];
        (&mut result[..32]).copy_from_slice(&self.vk.ak.to_bytes()[..]);
        (&mut result[32..64]).copy_from_slice(&self.vk.nk.to_bytes()[..]);
        (&mut result[64..96]).copy_from_slice(&self.ovk.0[..]);
        result
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Diversifier(pub [u8; 11]);

impl Diversifier {
    pub fn g_d(&self) -> Option<AffinePoint> {
        group_hash(
            &self.0,
            constants::KEY_DIVERSIFICATION_PERSONALIZATION,
        )
    }

    pub fn to_payment_address(
        &self,
        ivk: Scalar,
    ) -> Option<PaymentAddress> {
        let maybe_point = self.g_d();
        if maybe_point.is_some() {
            let pk_d = ExtendedPoint::from(maybe_point.unwrap()) * ivk;
            PaymentAddress::from_parts(*self, AffinePoint::from(pk_d))
        } else {
            None
        }
    }
}

/// `pk_d` is guaranteed to be prime-order (i.e. in the prime-order subgroup of Jubjub,
/// and not the identity).
#[derive(Clone, Debug)]
pub struct PaymentAddress {
    pk_d: AffinePoint,
    diversifier: Diversifier,
}

impl PaymentAddress {
    /// Constructs a PaymentAddress from a diversifier and a Jubjub point.
    ///
    /// Returns None if `pk_d` is the identity.
    pub fn from_parts(
        diversifier: Diversifier,
        pk_d: AffinePoint,
    ) -> Option<Self> {
        if pk_d == AffinePoint::identity() {
            None
        } else {
            Some(PaymentAddress { pk_d, diversifier })
        }
    }

    /// Parses a PaymentAddress from bytes.
    pub fn from_bytes(bytes: &[u8; 43]) -> Option<Self> {
        let diversifier = {
            let mut tmp = [0; 11];
            tmp.copy_from_slice(&bytes[0..11]);
            Diversifier(tmp)
        };
        // Check that the diversifier is valid
        if diversifier.g_d().is_none() {
            return None;
        }

        let pk_d_bytes: [u8; 32] = bytes[11..43].try_into().expect("It should not fail.");
        let maybe_point = AffinePoint::from_bytes(pk_d_bytes);
        if maybe_point.is_some().into() {
            let pk_d = maybe_point.unwrap();
            if pk_d.is_prime_order().unwrap_u8() != 0 {
                PaymentAddress::from_parts(diversifier, pk_d)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the byte encoding of this `PaymentAddress`.
    pub fn to_bytes(&self) -> [u8; 43] {
        let mut bytes = [0; 43];
        bytes[0..11].copy_from_slice(&self.diversifier.0);
        bytes[11..43].copy_from_slice(&self.pk_d.to_bytes());
        bytes
    }

    /// Returns the [`Diversifier`] for this `PaymentAddress`.
    pub fn diversifier(&self) -> &Diversifier {
        &self.diversifier
    }

    /// Returns `pk_d` for this `PaymentAddress`.
    pub fn pk_d(&self) -> AffinePoint {
        self.pk_d
    }

    pub fn g_d(&self) -> Option<AffinePoint> {
        self.diversifier.g_d()
    }

    pub fn encode_payment_address(&self) -> String {
        bech32_encode("ztron", |w| w.write_all(&self.to_bytes()))
    }

    pub fn decode_payment_address(s: &str) -> Result<Option<PaymentAddress>, Error> {
        bech32_decode("ztron", s, |data| {
            if data.len() != 43 {
                return None;
            }
            let mut bytes = [0; 43];
            bytes.copy_from_slice(&data);
            PaymentAddress::from_bytes(&bytes)
        })
    }

}

fn bech32_encode<F>(hrp: &str, write: F) -> String
    where
        F: Fn(&mut dyn Write) -> io::Result<()>,
{
    let mut data: Vec<u8> = vec![];
    write(&mut data).expect("Should be able to write to a Vec");
    bech32::encode(hrp, data.to_base32()).expect("hrp is invalid")
}

fn bech32_decode<T, F>(hrp: &str, s: &str, read: F) -> Result<Option<T>, Error>
    where
        F: Fn(Vec<u8>) -> Option<T>,
{
    let (decoded_hrp, data) = bech32::decode(s)?;
    if decoded_hrp == hrp {
        Vec::<u8>::from_base32(&data).map(|data| read(data))
    } else {
        Ok(None)
    }
}
