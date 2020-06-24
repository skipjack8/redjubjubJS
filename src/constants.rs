/// The byte-encoding of the basepoint for `SpendAuthSig`.
// Extracted ad-hoc from librustzcash
// XXX add tests for this value.
pub const SPENDAUTHSIG_BASEPOINT_BYTES: [u8; 32] = [
    48, 181, 242, 170, 173, 50, 86, 48, 188, 221, 219, 206, 77, 103, 101, 109, 5, 253, 28, 194,
    208, 55, 187, 83, 117, 182, 233, 109, 158, 1, 161, 215,
];

/// The byte-encoding of the basepoint for `BindingSig`.
// Extracted ad-hoc from librustzcash
// XXX add tests for this value.
pub const BINDINGSIG_BASEPOINT_BYTES: [u8; 32] = [
    139, 106, 11, 56, 185, 250, 174, 60, 59, 128, 59, 71, 176, 241, 70, 173, 80, 171, 34, 30, 110,
    42, 251, 230, 219, 222, 69, 203, 169, 211, 129, 237,
];

/// The byte-encoding of the basepoint for `ProofGenerationKey`.
// Extracted ad-hoc from librustzcash
pub const NK_BASEPOINT_BYTES: [u8; 32] = [231, 232, 93, 224, 247, 249, 122, 70, 210, 73, 161, 245,
    234, 81, 223, 80, 204, 72, 73, 15, 132, 1, 201, 222, 122, 42, 223, 24, 7, 209, 182, 212,
];

// BLAKE2B personalizations
// for PRF
pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Ztron_ExpandSeed";

// BLAKE2s invocation personalizations
/// BLAKE2s Personalization for CRH^ivk = BLAKE2s(ak | nk)
pub const CRH_IVK_PERSONALIZATION: &[u8; 8] = b"Zcashivk";

/// BLAKE2s Personalization for the group hash for key diversification
pub const KEY_DIVERSIFICATION_PERSONALIZATION: &[u8; 8] = b"Zcash_gd";

/// First 64 bytes of the BLAKE2s input during group hash.
/// This is chosen to be some random string that we couldn't have anticipated when we designed
/// the algorithm, for rigidity purposes.
/// We deliberately use an ASCII hex string of 32 bytes here.
pub const GH_FIRST_BLOCK: &[u8; 64] =
    b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";


