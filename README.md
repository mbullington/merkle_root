# `merkle-root`

Library for calculating the [Merkle root](https://fuchsia.dev/fuchsia-src/concepts/packages/merkleroot) of either a file, or walked directory.

Supports both `xxHash` (non-cryptographic) and `SHA2-256`.

- Files are split into 8kb blocks, then recursively hashed.
- Walked "directories" are hashes into `n` arbitrary levels. Individual files can be "tested" for inclusion in `O(n * log n)` time.

```rust
use merkle_root::MerkleTree;

let data_to_hash = [0xffu8; 8192];
let tree = MerkleTree::from_reader(&data_to_hash[..]).unwrap();
assert_eq!(
    tree.root(),
    hex::decode("68d131bc271f9c192d4f6dcd8fe61bef90004856da19d0f2f514a7f4098b0737").unwrap()
);
```

## Meta

This library is forked from [Fuchsia](https://github.com/vsrinivas/fuchsia/tree/30435a9d0f0b67c94e3c70760b522c9f7fbbd6be/src/sys/pkg/lib/fuchsia-merkle/src).

Changes:
- Support for non-cryptographic hashes (`xxhash-rust`).
- Create a `MerkleTree` from a walked directory.

## License

This work is originally under the BSD License.

Any new contributions are under the MIT License.