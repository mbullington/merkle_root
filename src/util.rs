// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use sha2::{Digest, Sha256};
use std::mem::{size_of, size_of_val};
use xxhash_rust::xxh3::xxh3_64;

use crate::{Hash, HashAlgorithm, BLOCK_SIZE};

type BlockIdentity = [u8; size_of::<u64>() + size_of::<u32>()];

/// Generate the bytes representing a block's identity.
fn make_identity(length: usize, level: usize, offset: usize) -> BlockIdentity {
    let offset_or_level = (offset as u64 | level as u64).to_le_bytes();
    let length = (length as u32).to_le_bytes();
    let mut ret: BlockIdentity = [0; size_of::<BlockIdentity>()];
    let (ret_offset_or_level, ret_length) = ret.split_at_mut(size_of_val(&offset_or_level));
    ret_offset_or_level.copy_from_slice(&offset_or_level);
    ret_length.copy_from_slice(&length);
    ret
}

pub(crate) fn hash_size(algorithm: HashAlgorithm) -> usize {
    match algorithm {
        HashAlgorithm::SHA256 => 32,
        HashAlgorithm::XXHash64 => 8,
    }
}

pub(crate) fn hashes_per_block(algorithm: HashAlgorithm) -> usize {
    BLOCK_SIZE / hash_size(algorithm)
}

pub(crate) fn hash(data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::SHA256 => Sha256::digest(data).to_vec(),
        HashAlgorithm::XXHash64 => xxh3_64(data).to_le_bytes().to_vec(),
    }
}

/// Compute the merkle hash of a block of data.
///
/// A merkle hash is the hash of a block of data with a small header built from the length
/// of the data, the level of the tree (0 for data blocks), and the offset into the level. The
/// block will be zero filled if its len is less than [`BLOCK_SIZE`], except for when the first
/// data block is completely empty.
///
/// # Panics
///
/// Panics if `block.len()` exceeds [`BLOCK_SIZE`] or if `offset` is not aligned to [`BLOCK_SIZE`]
pub fn hash_block(block: &[u8], offset: usize, algorithm: HashAlgorithm) -> Hash {
    assert!(block.len() <= BLOCK_SIZE);
    assert!(offset % BLOCK_SIZE == 0);

    let mut to_hash = Vec::<u8>::new();
    to_hash.extend_from_slice(&make_identity(block.len(), 0, offset));
    to_hash.extend_from_slice(block);
    // Zero fill block up to BLOCK_SIZE. As a special case, if the first data block is completely
    // empty, it is not zero filled.
    if block.len() != BLOCK_SIZE && !(block.is_empty() && offset == 0) {
        to_hash.extend_from_slice(&vec![0; BLOCK_SIZE - block.len()]);
    }

    hash(&to_hash, algorithm)
}

/// Compute the merkle hash of a block of hashes.
///
/// Both `hash_block` and `hash_hashes` will zero fill incomplete buffers, but unlike `hash_block`,
/// which includes the actual buffer size in the hash, `hash_hashes` always uses a size of
/// [`BLOCK_SIZE`] when computing the hash. Therefore, the following inputs are equivalent:
/// ```ignore
/// let data_hash = "15ec7bf0b50732b49f8228e07d24365338f9e3ab994b00af08e5a3bffe55fd8b"
///     .parse()
///     .unwrap();
/// let zero_hash = "0000000000000000000000000000000000000000000000000000000000000000"
///     .parse()
///     .unwrap();
/// let hash_of_single_hash = fuchsia_merkle::hash_hashes(&vec![data_hash], 0, 0);
/// let hash_of_single_hash_and_zero_hash =
///     fuchsia_merkle::hash_hashes(&vec![data_hash, zero_hash], 0, 0);
/// assert_eq!(hash_of_single_hash, hash_of_single_hash_and_zero_hash);
/// ```
///
/// # Panics
///
/// Panics if any of the following conditions are met:
/// - `hashes.len()` is 0
/// - `hashes.len() > HASHES_PER_BLOCK`
/// - `level` is 0
/// - `offset` is not aligned to [`BLOCK_SIZE`]
pub fn hash_hashes(hashes: &[Hash], level: usize, offset: usize, algorithm: HashAlgorithm) -> Hash {
    assert_ne!(hashes.len(), 0);
    assert!(hashes.len() <= hashes_per_block(algorithm));
    assert!(level > 0);
    assert!(offset % BLOCK_SIZE == 0);

    let mut to_hash = Vec::<u8>::new();
    to_hash.extend_from_slice(&make_identity(BLOCK_SIZE, level, offset));
    for hash in hashes.iter() {
        to_hash.extend_from_slice(hash);
    }
    for _ in 0..(hashes_per_block(algorithm) - hashes.len()) {
        // Repeat zero hash to fill the block (of size) HASH_SIZE.
        to_hash.extend_from_slice(&vec![0; hash_size(algorithm)]);
    }

    hash(&to_hash, algorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const HASH: HashAlgorithm = HashAlgorithm::SHA256;

    #[test]
    fn test_hash_block_empty() {
        let block = [];
        let hash = hash_block(&block[..], 0, HASH);
        let expected = "15ec7bf0b50732b49f8228e07d24365338f9e3ab994b00af08e5a3bffe55fd8b";
        assert_eq!(expected, &hex::encode(hash));
    }

    #[test]
    fn test_hash_block_single() {
        let block = vec![0xFF; 8192];
        let hash = hash_block(&block[..], 0, HASH);
        let expected = "68d131bc271f9c192d4f6dcd8fe61bef90004856da19d0f2f514a7f4098b0737";
        assert_eq!(expected, &hex::encode(hash));
    }

    #[test]
    fn test_hash_hashes_full_block() {
        let mut leafs = Vec::new();
        {
            let block = vec![0xFF; BLOCK_SIZE];
            for i in 0..hashes_per_block(HASH) {
                leafs.push(hash_block(&block, i * BLOCK_SIZE, HASH));
            }
        }
        let root = hash_hashes(&leafs, 1, 0, HASH);
        let expected = "1e6e9c870e2fade25b1b0288ac7c216f6fae31c1599c0c57fb7030c15d385a8d";
        assert_eq!(expected, &hex::encode(root));
    }

    #[test]
    fn test_hash_hashes_zero_pad_same_length() {
        let data_hash = "15ec7bf0b50732b49f8228e07d24365338f9e3ab994b00af08e5a3bffe55fd8b";
        let zero_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let hash_of_single_hash = hash_hashes(&[hex::decode(data_hash).unwrap()], 1, 0, HASH);
        let hash_of_single_hash_and_zero_hash = hash_hashes(
            &[
                hex::decode(data_hash).unwrap(),
                hex::decode(zero_hash).unwrap(),
            ],
            1,
            0,
            HASH,
        );
        assert_eq!(hash_of_single_hash, hash_of_single_hash_and_zero_hash);
    }
}
