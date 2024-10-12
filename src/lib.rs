// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! `fuchsia_merkle` contains types and methods for building and working with merkle trees.

#![warn(clippy::all)]

pub type Hash = Vec<u8>;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HashAlgorithm {
    SHA256,
    XXHash64,
}

/// The size of a single block of data (or hashes), in bytes.
pub const BLOCK_SIZE: usize = 8192;

mod util;
pub use crate::util::hash_block;
pub use crate::util::hash_hashes;

mod tree;
pub use crate::tree::MerkleTree;

mod builder;
pub use crate::builder::MerkleTreeBuilder;

mod writer;
pub use crate::writer::MerkleTreeWriter;
