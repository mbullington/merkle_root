// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::io::Write;

use crate::builder::MerkleTreeBuilder;
use crate::tree::MerkleTree;

/// A `MerkleTreeWriter` wraps a [`MerkleTreeBuilder`] and another type that implements
/// [`std::io::Write`].
///
/// `MerkleTreeWriter`s can be used to compute a [`MerkleTree`] while streaming data from one
/// location to another. To simply compute a [`MerkleTree`] without chaining writes to a separate
/// Writer, see [`MerkleTreeBuilder`].
///
/// # Examples
/// ```
/// # use fuchsia_merkle::*;
/// # use std::io::{Result,Write};
/// # fn main() -> Result<()> {
/// let data = vec![0xff; 8192];
/// let mut written = Vec::new();
/// {
///     let mut writer = MerkleTreeWriter::new(&mut written);
///     writer.write_all(&data)?;
///
///     let tree = writer.finish();
///     assert_eq!(
///         tree.root(),
///         &hex::decode("68d131bc271f9c192d4f6dcd8fe61bef90004856da19d0f2f514a7f4098b0737")
///             .unwrap()
///     );
/// }
/// assert_eq!(written, data);
/// #     Ok(())
/// # }
/// ```
pub struct MerkleTreeWriter<W> {
    inner: W,
    builder: MerkleTreeBuilder,
}

impl<W: Write> MerkleTreeWriter<W> {
    /// Creates a new `MerkleTreeWriter`
    pub fn new(inner: W) -> Self {
        MerkleTreeWriter {
            inner,
            builder: MerkleTreeBuilder::new(),
        }
    }

    /// Finalizes all levels of the merkle tree, converting this `MerkleTreeWriter` instance into a
    /// [`MerkleTree`].
    pub fn finish(self) -> MerkleTree {
        self.builder.finish()
    }
}

impl<W: Write> Write for MerkleTreeWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write_all(buf)?;
        self.builder.write(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;
    use test_case::test_case;

    #[allow(clippy::unused_unit)]
    #[test_case(vec![], "15ec7bf0b50732b49f8228e07d24365338f9e3ab994b00af08e5a3bffe55fd8b" ; "test_empty")]
    #[test_case(vec![0xFF; 8192], "68d131bc271f9c192d4f6dcd8fe61bef90004856da19d0f2f514a7f4098b0737"; "test_oneblock")]
    #[test_case(vec![0xFF; 65536], "f75f59a944d2433bc6830ec243bfefa457704d2aed12f30539cd4f18bf1d62cf"; "test_small")]
    #[test_case(vec![0xFF; 2105344], "7d75dfb18bfd48e03b5be4e8e9aeea2f89880cb81c1551df855e0d0a0cc59a67"; "test_large")]
    #[test_case(vec![0xFF; 2109440], "7577266aa98ce587922fdc668c186e27f3c742fb1b732737153b70ae46973e43"; "test_unaligned")]
    fn tests(input: Vec<u8>, output: &str) {
        let mut written = Vec::with_capacity(input.len());
        let actual = {
            let mut builder = MerkleTreeWriter::new(&mut written);
            builder.write_all(input.as_slice()).unwrap();

            let tree = builder.finish();
            tree.root().clone()
        };
        let expected: Hash = hex::decode(output).unwrap();
        assert_eq!(expected, actual);
        assert_eq!(input, written);
    }
}
