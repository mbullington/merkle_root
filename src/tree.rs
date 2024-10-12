// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::hash_hashes;
use crate::util::hashes_per_block;
use crate::Hash;
use crate::HashAlgorithm;
use crate::BLOCK_SIZE;
use std::io;

/// A `MerkleTree` contains levels of hashes that can be used to verify the integrity of data.
///
/// While a single hash could be used to integrity check some data, if the data (or hash) is
/// corrupt, a single hash can not determine what part of the data is corrupt. A `MerkleTree`,
/// however, contains a hash for every 8K block of data, allowing it to identify which 8K blocks of
/// data are corrupt. A `MerkleTree` also allows individual 8K blocks of data to be verified
/// without having to verify the rest of the data.
///
/// Furthermore, a `MerkleTree` contains multiple levels of hashes, where each level
/// contains hashes of 8K blocks of hashes of the lower level. The top level always contains a
/// single hash, the merkle root. This tree of hashes allows a `MerkleTree` to determine which of
/// its own hashes are corrupt, if any.
///
/// # Structure Details
///
/// A merkle tree contains levels. A level is a row of the tree, starting at 0 and counting upward.
/// Level 0 represents the leaves of the tree which contain hashes of chunks of the input stream.
///
/// Each level consists of a hash for each 8K block of hashes from the previous level (or, for
/// level 0, each 8K block of data). When computing a hash, the 8K block is prepended with a block
/// identity.
///
/// A block identity is the binary OR of the starting byte index of the block within
/// the current level and the current level index, followed by the length of the block. For level
/// 0, the length of the block is 8K, except for the last block, which may be less than 8K. All
/// other levels use a block length of 8K.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Creates a `MerkleTree` from a well-formed tree of hashes.
    ///
    /// A tree of hashes is well-formed iff:
    /// - The length of the last level is 1.
    /// - The length of every hash level is the length of the prior hash level divided by
    ///   `HASHES_PER_BLOCK`, rounded up to the nearest integer.
    pub fn from_levels(levels: Vec<Vec<Hash>>) -> MerkleTree {
        MerkleTree { levels }
    }

    /// The root hash of the merkle tree.
    pub fn root(&self) -> &Hash {
        &self.levels[self.levels.len() - 1][0]
    }

    /// Creates a `MerkleTree` from all of the bytes of a `Read`er.
    ///
    /// # Examples
    /// ```
    /// # use fuchsia_merkle::MerkleTree;
    /// let data_to_hash = [0xffu8; 8192];
    /// let tree = MerkleTree::from_reader(&data_to_hash[..]).unwrap();
    /// assert_eq!(
    ///     tree.root(),
    ///     &hex::decode("68d131bc271f9c192d4f6dcd8fe61bef90004856da19d0f2f514a7f4098b0737").unwrap()
    /// );
    /// ```
    pub fn from_reader(mut reader: impl std::io::Read) -> Result<MerkleTree, io::Error> {
        let mut builder = crate::builder::MerkleTreeBuilder::new();
        let mut buf = [0u8; BLOCK_SIZE];
        loop {
            let size = reader.read(&mut buf)?;
            if size == 0 {
                break;
            }
            builder.write(&buf[0..size]);
        }
        Ok(builder.finish())
    }

    /// Compute a merkle tree from a series of "walked" directories.
    ///
    /// Notably, this function's MerkleTree can be used afterwards to check if a file
    /// is included in the set in `O(n)` time.
    pub fn from_walked_directory(walked_files: &[Hash], algorithm: HashAlgorithm) -> MerkleTree {
        let mut levels: Vec<Vec<Hash>> = Vec::new();
        levels.push(walked_files.to_vec());

        let mut current_level = 0;
        while levels[current_level].len() > 1 {
            let mut next_level = Vec::new();
            for chunk in levels[current_level].chunks(hashes_per_block(algorithm)) {
                next_level.push(hash_hashes(
                    chunk,
                    current_level + 1,
                    next_level.len() * BLOCK_SIZE,
                    algorithm,
                ));
            }

            levels.push(next_level);
            current_level += 1;
        }

        MerkleTree::from_levels(levels)
    }

    pub fn includes_hash(&self, hash: &Hash, algorithm: HashAlgorithm) -> bool {
        for level in &self.levels {
            if !level.contains(hash) {
                continue;
            }

            // We found our hash—on this level, create the new Merkle root, and
            // compare it to the root of the tree.
            let new_root = MerkleTree::from_walked_directory(level, algorithm);
            return new_root.root() == self.root();
        }

        false
    }
}

impl AsRef<[Vec<Hash>]> for MerkleTree {
    fn as_ref(&self) -> &[Vec<Hash>] {
        &self.levels[..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    use crate::{
        util::{hash_block, hash_hashes, hashes_per_block},
        HashAlgorithm,
    };

    use rand::Rng;

    pub const HASH: HashAlgorithm = HashAlgorithm::SHA256;

    impl MerkleTree {
        /// Given the index of a block of data, lookup its hash.
        fn clone_leaf_hash(&self, block: usize) -> Hash {
            self.levels[0][block].clone()
        }
    }

    #[test]
    fn test_single_full_hash_block() {
        let mut leafs = Vec::new();
        {
            let block = vec![0xFF; BLOCK_SIZE];
            for i in 0..hashes_per_block(HASH) {
                leafs.push(hash_block(&block, i * BLOCK_SIZE, HASH));
            }
        }
        let root = hash_hashes(&leafs, 1, 0, HASH);
        let tree = MerkleTree::from_levels(vec![leafs.clone(), vec![root]]);

        for (i, leaf) in leafs.iter().enumerate().take(hashes_per_block(HASH)) {
            assert_eq!(&tree.clone_leaf_hash(i), leaf);
        }
    }

    #[test]
    fn test_from_reader_empty() {
        let data_to_hash = [0x00u8; 0];
        let tree = MerkleTree::from_reader(&data_to_hash[..]).unwrap();
        let expected: Hash =
            hex::decode("15ec7bf0b50732b49f8228e07d24365338f9e3ab994b00af08e5a3bffe55fd8b")
                .unwrap();
        assert_eq!(tree.root(), &expected);
    }

    #[test]
    fn test_from_reader_oneblock() {
        let data_to_hash = [0xffu8; 8192];
        let tree = MerkleTree::from_reader(&data_to_hash[..]).unwrap();
        let expected: Hash =
            hex::decode("68d131bc271f9c192d4f6dcd8fe61bef90004856da19d0f2f514a7f4098b0737")
                .unwrap();
        assert_eq!(tree.root(), &expected);
    }

    #[test]
    fn test_from_reader_unaligned() {
        let size = 2_109_440usize;
        let mut the_bytes = Vec::with_capacity(size);
        the_bytes.extend(std::iter::repeat(0xff).take(size));
        let tree = MerkleTree::from_reader(&the_bytes[..]).unwrap();
        let expected: Hash =
            hex::decode("7577266aa98ce587922fdc668c186e27f3c742fb1b732737153b70ae46973e43")
                .unwrap();
        assert_eq!(tree.root(), &expected);
    }

    #[test]
    fn test_from_reader_error_propagation() {
        const CUSTOM_ERROR_MESSAGE: &str = "merkle tree custom error message";
        struct ReaderSuccessThenError {
            been_called: bool,
        }

        impl std::io::Read for ReaderSuccessThenError {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.been_called {
                    self.been_called = true;
                    buf[0] = 0;
                    Ok(1)
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, CUSTOM_ERROR_MESSAGE))
                }
            }
        }

        let reader = ReaderSuccessThenError { been_called: false };
        let result = MerkleTree::from_reader(reader);
        assert_eq!(result.unwrap_err().to_string(), CUSTOM_ERROR_MESSAGE);
    }

    #[test_case(0, 1 ; "test_empty")]
    #[test_case(256, 2 ; "test_two")]
    #[test_case(257, 3 ; "test_three")]
    #[test_case(65537, 4 ; "test_four")]

    fn test_from_walked_directory(len: usize, level: usize) {
        let mut data: Vec<Hash> = Vec::new();
        for _ in 0..len {
            data.push(vec![0; 32]);
        }

        let tree = MerkleTree::from_walked_directory(&data, HASH);
        assert_eq!(tree.levels.len(), level);
    }

    #[test]
    fn test_includes_hash() {
        let mut rng = rand::thread_rng();

        let mut data: Vec<Hash> = Vec::new();
        for _ in 0..255 {
            let hash: u64 = rng.gen_range(0..u64::MAX);
            data.push(hash.to_le_bytes().to_vec());
        }

        let tree = MerkleTree::from_walked_directory(&data, HashAlgorithm::XXHash64);
        for hash in &data {
            assert!(tree.includes_hash(hash, HashAlgorithm::XXHash64));
        }
    }
}
