//! Implementation of [group hashing into Jubjub][grouphash].
//!
//! [grouphash]: https://zips.z.cash/protocol/protocol.pdf#concretegrouphashjubjub


use jubjub::{AffinePoint, ExtendedPoint};
use blake2s_simd::Params;
use std::convert::TryInto;
use crate::constants;

/// Produces a random point in the Jubjub curve.
/// The point is guaranteed to be prime order
/// and not the identity.
pub fn group_hash(
    tag: &[u8],
    personalization: &[u8],
) -> Option<AffinePoint> {
    assert_eq!(personalization.len(), 8);

    let h = Params::new()
        .hash_length(32)
        .personal(personalization)
        .to_state()
        .update(constants::GH_FIRST_BLOCK)
        .update(tag)
        .finalize();

    let hash_bytes: [u8; 32] = h.as_bytes()[..].try_into().expect("It should not fail.");
    let maybe_point = AffinePoint::from_bytes(hash_bytes);
    if maybe_point.is_some().into() {
        let point = maybe_point.unwrap().mul_by_cofactor();
        if point != ExtendedPoint::identity() {
            Some(AffinePoint::from(point))
        } else {
            None
        }
    } else {
       None
    }
}
