use std::collections::{HashMap, HashSet};

use bencode::WithRawBytes;
use buffers::{ByteBuf, ByteBufOwned};
use serde_derive::Deserialize;
use sha2::{Digest, Sha256};

use crate::{Error, Id20, Id32, Result};

const BLOCK_LENGTH: u32 = 16 * 1024;

pub type TorrentMetaV2Owned = TorrentMetaV2<ByteBufOwned>;

#[derive(Deserialize, Debug)]
#[serde(bound(deserialize = "Buf: serde::Deserialize<'de> + Eq + std::hash::Hash"))]
pub struct TorrentMetaV2<Buf> {
    pub info: WithRawBytes<TorrentMetaV2Info<Buf>, Buf>,
    #[serde(rename = "piece layers")]
    pub piece_layers: HashMap<Id32, Buf>,
    #[serde(skip)]
    pub info_hash: Id32,
}

#[derive(Deserialize)]
struct TorrentMetaV2Version {
    info: TorrentMetaV2VersionInfo,
}

#[derive(Deserialize)]
struct TorrentMetaV2VersionInfo {
    #[serde(rename = "meta version")]
    meta_version: u64,
}

impl<Buf> TorrentMetaV2<Buf> {
    pub fn handshake_info_hash(&self) -> Id20 {
        self.info_hash.truncate_for_dht()
    }
}

#[derive(Deserialize, Debug)]
#[serde(bound(deserialize = "Buf: serde::Deserialize<'de> + Eq + std::hash::Hash"))]
pub struct TorrentMetaV2Info<Buf> {
    #[serde(rename = "meta version")]
    pub meta_version: u64,
    #[serde(rename = "piece length")]
    pub piece_length: u32,
    #[serde(rename = "file tree")]
    pub file_tree: V2FileTree<Buf>,
    pub name: Option<Buf>,
    #[serde(default)]
    pub private: bool,
}

pub type V2FileTree<Buf> = HashMap<Buf, V2FileTreeEntry<Buf>>;

#[derive(Deserialize, Debug)]
#[serde(untagged)]
#[serde(bound(deserialize = "Buf: serde::Deserialize<'de> + Eq + std::hash::Hash"))]
pub enum V2FileTreeEntry<Buf> {
    Directory(V2FileTree<Buf>),
    File(V2FileProperties),
}

#[derive(Deserialize, Debug)]
pub struct V2FileProperties {
    pub length: u64,
    #[serde(rename = "pieces root")]
    pub pieces_root: Option<Id32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2File {
    pub path: Vec<Vec<u8>>,
    pub length: u64,
    pub pieces_root: Option<Id32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceLayer {
    pub root: Id32,
    pub hashes: Vec<Id32>,
}

#[derive(Debug)]
pub struct ValidatedTorrentMetaV2Info<Buf> {
    info: TorrentMetaV2Info<Buf>,
    files: Vec<V2File>,
}

impl<Buf> ValidatedTorrentMetaV2Info<Buf> {
    pub fn info(&self) -> &TorrentMetaV2Info<Buf> {
        &self.info
    }

    pub fn files(&self) -> &[V2File] {
        &self.files
    }
}

pub fn torrent_v2_from_bytes(buf: &[u8]) -> Result<TorrentMetaV2<ByteBuf<'_>>> {
    let version: TorrentMetaV2Version =
        bencode::from_bytes(buf).map_err(|_| Error::V2InvalidTorrent)?;
    validate_meta_version(version.info.meta_version)?;

    let mut torrent: TorrentMetaV2<ByteBuf<'_>> =
        bencode::from_bytes(buf).map_err(|_| Error::V2InvalidTorrent)?;
    torrent.info_hash = info_hash_v2(&torrent.info.raw_bytes);
    validate_metadata(&torrent.info.data, &torrent.piece_layers)?;
    Ok(torrent)
}

pub fn info_hash_v2(bytes: impl AsRef<[u8]>) -> Id32 {
    let mut digest = Sha256::new();
    digest.update(bytes.as_ref());
    let mut hash = [0; 32];
    hash.copy_from_slice(&digest.finalize());
    Id32::new(hash)
}

impl<Buf: AsRef<[u8]>> TorrentMetaV2Info<Buf> {
    pub fn validate(
        self,
        piece_layers: &HashMap<Id32, Buf>,
    ) -> Result<ValidatedTorrentMetaV2Info<Buf>> {
        validate_metadata(&self, piece_layers)?;
        let mut files = Vec::new();
        flatten_file_tree(&self.file_tree, &mut Vec::new(), &mut files)?;
        Ok(ValidatedTorrentMetaV2Info { info: self, files })
    }
}

impl PieceLayer {
    fn from_bytes(root: Id32, bytes: &[u8]) -> Result<Self> {
        if !bytes.len().is_multiple_of(32) {
            return Err(Error::InvalidV2PieceLayerLength {
                actual: bytes.len(),
            });
        }

        let hashes = bytes
            .chunks_exact(32)
            .map(|hash| {
                let mut bytes = [0; 32];
                bytes.copy_from_slice(hash);
                Id32::new(bytes)
            })
            .collect();
        Ok(Self { root, hashes })
    }
}

fn validate_metadata<Buf: AsRef<[u8]>>(
    info: &TorrentMetaV2Info<Buf>,
    piece_layers: &HashMap<Id32, Buf>,
) -> Result<()> {
    validate_meta_version(info.meta_version)?;
    if info.piece_length < BLOCK_LENGTH || !info.piece_length.is_power_of_two() {
        return Err(Error::V2InvalidPieceLength(info.piece_length));
    }

    for bytes in piece_layers.values() {
        if !bytes.as_ref().len().is_multiple_of(32) {
            return Err(Error::InvalidV2PieceLayerLength {
                actual: bytes.as_ref().len(),
            });
        }
    }
    let mut required_layers = HashMap::new();
    validate_file_tree(
        &info.file_tree,
        true,
        info.piece_length,
        piece_layers,
        &mut required_layers,
    )?;

    for (root, size) in required_layers {
        let bytes = piece_layers
            .get(&root)
            .ok_or_else(|| Error::V2MissingPieceLayersEntry(root.as_string()))?;
        let expected_hashes = checked_piece_count(size, info.piece_length)?;
        let actual_hashes = bytes.as_ref().len() / 32;
        if actual_hashes != expected_hashes {
            return Err(Error::V2PieceLayersWrongSize {
                expected: expected_hashes,
                actual: actual_hashes,
            });
        }
        let layer = PieceLayer::from_bytes(root, bytes.as_ref())?;
        if merkle_root(&layer.hashes, info.piece_length) != root {
            return Err(Error::V2PieceLayersRootMismatch);
        }
    }

    let required_roots = collect_required_roots(&info.file_tree, info.piece_length)?;
    if !piece_layers
        .keys()
        .all(|root| required_roots.contains(root))
    {
        return Err(Error::V2SmallFileShouldNotHavePieceLayers);
    }
    Ok(())
}

fn validate_file_tree<Buf: AsRef<[u8]>>(
    tree: &V2FileTree<Buf>,
    is_root: bool,
    piece_length: u32,
    piece_layers: &HashMap<Id32, Buf>,
    required_layers: &mut HashMap<Id32, u64>,
) -> Result<()> {
    let file_entry = tree
        .iter()
        .find(|(name, _)| name.as_ref().is_empty())
        .map(|(_, entry)| entry);

    if let Some(entry) = file_entry {
        if is_root {
            return Err(Error::V2FileTreeRootIsFile);
        }
        if tree.len() != 1 {
            return Err(Error::V2InvalidFileTreeEntry);
        }
        let V2FileTreeEntry::File(file) = entry else {
            return Err(Error::V2InvalidFileTreeEntry);
        };
        validate_file(file, piece_length, piece_layers, required_layers)?;
        return Ok(());
    }

    for (name, entry) in tree {
        validate_component(name.as_ref())?;
        let V2FileTreeEntry::Directory(child) = entry else {
            return Err(Error::V2InvalidFileTreeEntry);
        };
        validate_file_tree(child, false, piece_length, piece_layers, required_layers)?;
    }
    Ok(())
}

fn validate_component(component: &[u8]) -> Result<()> {
    match component {
        b"" => Err(Error::BadTorrentEmptyFilename),
        b"." => Err(Error::V2FileTreeDotComponent),
        b".." => Err(Error::BadTorrentPathTraversal),
        _ if component.contains(&b'/') || component.contains(&b'\\') => {
            Err(Error::BadTorrentSeparatorInName)
        }
        _ => Ok(()),
    }
}

fn validate_file<Buf: AsRef<[u8]>>(
    file: &V2FileProperties,
    piece_length: u32,
    piece_layers: &HashMap<Id32, Buf>,
    required_layers: &mut HashMap<Id32, u64>,
) -> Result<()> {
    match (file.length, file.pieces_root) {
        (0, Some(_)) => Err(Error::V2ZeroLengthFileHasPiecesRoot),
        (0, None) => Ok(()),
        (_, None) => Err(Error::V2SmallFileMissingPiecesRoot),
        (size, Some(root)) if size <= u64::from(piece_length) => {
            if piece_layers.contains_key(&root) {
                Err(Error::V2SmallFileShouldNotHavePieceLayers)
            } else {
                Ok(())
            }
        }
        (size, Some(root)) => {
            if let Some(previous_size) = required_layers.insert(root, size) {
                if previous_size != size {
                    return Err(Error::V2PieceLayerCountMismatch {
                        expected: 1,
                        actual: 2,
                    });
                }
            }
            Ok(())
        }
    }
}

fn collect_required_roots<Buf: AsRef<[u8]>>(
    tree: &V2FileTree<Buf>,
    piece_length: u32,
) -> Result<HashSet<Id32>> {
    let mut roots = HashSet::new();
    collect_required_roots_impl(tree, piece_length, &mut roots)?;
    Ok(roots)
}

fn collect_required_roots_impl<Buf: AsRef<[u8]>>(
    tree: &V2FileTree<Buf>,
    piece_length: u32,
    roots: &mut HashSet<Id32>,
) -> Result<()> {
    for (name, entry) in tree {
        if name.as_ref().is_empty() {
            let V2FileTreeEntry::File(file) = entry else {
                return Err(Error::V2InvalidFileTreeEntry);
            };
            if file.length > u64::from(piece_length) {
                roots.insert(
                    file.pieces_root
                        .ok_or(Error::V2SmallFileMissingPiecesRoot)?,
                );
            }
        } else {
            let V2FileTreeEntry::Directory(child) = entry else {
                return Err(Error::V2InvalidFileTreeEntry);
            };
            collect_required_roots_impl(child, piece_length, roots)?;
        }
    }
    Ok(())
}

fn flatten_file_tree<Buf: AsRef<[u8]>>(
    tree: &V2FileTree<Buf>,
    path: &mut Vec<Vec<u8>>,
    files: &mut Vec<V2File>,
) -> Result<()> {
    let mut entries = tree.iter().collect::<Vec<_>>();
    entries.sort_unstable_by(|(left, _), (right, _)| left.as_ref().cmp(right.as_ref()));
    for (name, entry) in entries {
        if name.as_ref().is_empty() {
            let V2FileTreeEntry::File(file) = entry else {
                return Err(Error::V2InvalidFileTreeEntry);
            };
            files.push(V2File {
                path: path.clone(),
                length: file.length,
                pieces_root: file.pieces_root,
            });
            continue;
        }

        path.push(name.as_ref().to_vec());
        let V2FileTreeEntry::Directory(child) = entry else {
            return Err(Error::V2InvalidFileTreeEntry);
        };
        flatten_file_tree(child, path, files)?;
        path.pop();
    }
    Ok(())
}

fn piece_count(size: u64, piece_length: u32) -> u64 {
    size.div_ceil(u64::from(piece_length))
}

fn checked_piece_count(size: u64, piece_length: u32) -> Result<usize> {
    checked_piece_count_with_limit(size, piece_length, usize::MAX as u64)
}

fn checked_piece_count_with_limit(size: u64, piece_length: u32, max_hashes: u64) -> Result<usize> {
    let count = piece_count(size, piece_length);
    if count > max_hashes {
        return Err(Error::V2PieceLayerCountTooLarge { count });
    }
    usize::try_from(count).map_err(|_| Error::V2PieceLayerCountTooLarge { count })
}

fn validate_meta_version(meta_version: u64) -> Result<()> {
    if meta_version != 2 {
        return Err(Error::V2UnsupportedMetaVersion(
            meta_version.try_into().unwrap_or(u32::MAX),
        ));
    }
    Ok(())
}

fn merkle_root(hashes: &[Id32], piece_length: u32) -> Id32 {
    let layer_depth = (piece_length / BLOCK_LENGTH).ilog2();
    let mut layer = hashes.to_vec();
    layer.resize(layer.len().next_power_of_two(), zero_hash(layer_depth));

    while layer.len() > 1 {
        for index in 0..layer.len() / 2 {
            layer[index] = hash_pair(layer[index], layer[index * 2 + 1]);
        }
        layer.truncate(layer.len() / 2);
    }
    layer[0]
}

fn zero_hash(depth: u32) -> Id32 {
    let mut hash = Id32::default();
    for _ in 0..depth {
        hash = hash_pair(hash, hash);
    }
    hash
}

fn hash_pair(left: Id32, right: Id32) -> Id32 {
    let mut digest = Sha256::new();
    digest.update(left.0);
    digest.update(right.0);
    let mut hash = [0; 32];
    hash.copy_from_slice(&digest.finalize());
    Id32::new(hash)
}

#[cfg(test)]
mod tests {
    use crate::{Error, Id32};

    use super::{checked_piece_count_with_limit, torrent_v2_from_bytes};

    #[test]
    fn parses_v2_info_and_uses_sha256_raw_info_hash() {
        let fixture = fixture_bytes();
        let torrent = torrent_v2_from_bytes(&fixture).unwrap();
        assert_eq!(torrent.info.data.meta_version, 2);
        assert_eq!(torrent.info_hash, expected_info_hash());
        assert_eq!(
            torrent.handshake_info_hash(),
            torrent.info_hash.truncate_for_dht()
        );
    }

    #[test]
    fn parses_two_file_tree_with_16_kib_leaves() {
        let fixture = two_file_fixture();
        let torrent = torrent_v2_from_bytes(&fixture).unwrap();
        let validated = torrent.info.data.validate(&torrent.piece_layers).unwrap();

        assert_eq!(validated.files().len(), 2);
        assert_eq!(validated.files()[0].length, 32 * 1024);
        assert_eq!(validated.files()[1].length, 16 * 1024);
    }

    #[test]
    fn flattens_files_in_canonical_path_order() {
        let fixture = two_file_fixture();
        let expected = vec![vec![b"a.bin".to_vec()], vec![b"b.bin".to_vec()]];

        for _ in 0..32 {
            let torrent = torrent_v2_from_bytes(&fixture).unwrap();
            let validated = torrent.info.data.validate(&torrent.piece_layers).unwrap();
            let paths = validated
                .files()
                .iter()
                .map(|file| file.path.clone())
                .collect::<Vec<_>>();
            assert_eq!(paths, expected);
        }
    }

    #[test]
    fn rejects_meta_version_other_than_two() {
        assert!(matches!(
            torrent_v2_from_bytes(&meta_version_three_fixture()),
            Err(Error::V2UnsupportedMetaVersion(3))
        ));
    }

    #[test]
    fn rejects_newer_meta_version_before_parsing_v2_fields() {
        assert!(matches!(
            torrent_v2_from_bytes(&newer_version_with_malformed_file_tree_fixture()),
            Err(Error::V2UnsupportedMetaVersion(3))
        ));
    }

    #[test]
    fn rejects_parent_path_component() {
        assert!(matches!(
            torrent_v2_from_bytes(&parent_path_fixture()),
            Err(Error::BadTorrentPathTraversal)
        ));
    }

    #[test]
    fn rejects_piece_layer_with_non_hash_aligned_length() {
        assert!(matches!(
            torrent_v2_from_bytes(&invalid_piece_layer_fixture()),
            Err(Error::InvalidV2PieceLayerLength { .. })
        ));
    }

    #[test]
    fn rejects_piece_layer_count_unrepresentable_on_32_bit_target() {
        const EXPECTED_COUNT: u64 = 1 << 32;
        assert!(matches!(
            checked_piece_count_with_limit(1 << 46, 16 * 1024, u32::MAX.into()),
            Err(Error::V2PieceLayerCountTooLarge {
                count: EXPECTED_COUNT
            })
        ));
    }

    fn fixture_bytes() -> Vec<u8> {
        let mut torrent = b"d4:info".to_vec();
        torrent.extend_from_slice(&single_file_info(2, b"file.bin", 16 * 1024, &[0xaa; 32]));
        torrent.extend_from_slice(b"12:piece layersdee");
        torrent
    }

    fn two_file_fixture() -> Vec<u8> {
        let large_file_root = Id32::new([
            0xf8, 0x18, 0xaf, 0xd3, 0x7a, 0x6d, 0xc3, 0xbc, 0x92, 0xfb, 0x44, 0x73, 0x10, 0x11,
            0x27, 0x70, 0x06, 0xdb, 0x4e, 0xfa, 0x6e, 0x90, 0x23, 0xcd, 0x74, 0x68, 0xc0, 0x23,
            0x35, 0xd2, 0x2a, 0x4d,
        ]);
        let mut info = b"d9:file treed5:a.bind0:d6:lengthi32768e11:pieces root32:".to_vec();
        info.extend_from_slice(&large_file_root.0);
        info.extend_from_slice(b"ee5:b.bind0:d6:lengthi16384e11:pieces root32:");
        info.extend_from_slice(&[0xbb; 32]);
        info.extend_from_slice(b"eee12:meta versioni2e4:name4:test12:piece lengthi16384ee");

        let mut torrent = b"d4:info".to_vec();
        torrent.extend_from_slice(&info);
        torrent.extend_from_slice(b"12:piece layersd32:");
        torrent.extend_from_slice(&large_file_root.0);
        torrent.extend_from_slice(b"64:");
        torrent.extend_from_slice(&[1; 32]);
        torrent.extend_from_slice(&[2; 32]);
        torrent.extend_from_slice(b"ee");
        torrent
    }

    fn meta_version_three_fixture() -> Vec<u8> {
        let mut torrent = b"d4:info".to_vec();
        torrent.extend_from_slice(&single_file_info(3, b"file.bin", 16 * 1024, &[0xaa; 32]));
        torrent.extend_from_slice(b"12:piece layersdee");
        torrent
    }

    fn newer_version_with_malformed_file_tree_fixture() -> Vec<u8> {
        b"d4:infod9:file tree3:bad12:meta versioni3ee12:piece layersdee".to_vec()
    }

    fn parent_path_fixture() -> Vec<u8> {
        let mut torrent = b"d4:infod9:file treed2:..d0:d6:lengthi0eeee12:meta versioni2e4:name4:test12:piece lengthi16384ee12:piece layersdee".to_vec();
        torrent.shrink_to_fit();
        torrent
    }

    fn invalid_piece_layer_fixture() -> Vec<u8> {
        let mut torrent = b"d4:info".to_vec();
        torrent.extend_from_slice(&single_file_info(2, b"large.bin", 32 * 1024, &[0xcc; 32]));
        torrent.extend_from_slice(b"12:piece layersd32:");
        torrent.extend_from_slice(&[0xcc; 32]);
        torrent.extend_from_slice(b"31:");
        torrent.extend_from_slice(&[0; 31]);
        torrent.extend_from_slice(b"ee");
        torrent
    }

    fn single_file_info(
        meta_version: u64,
        name: &[u8],
        length: u64,
        pieces_root: &[u8; 32],
    ) -> Vec<u8> {
        let mut info = b"d9:file treed".to_vec();
        info.extend_from_slice(name.len().to_string().as_bytes());
        info.push(b':');
        info.extend_from_slice(name);
        info.extend_from_slice(b"d0:d6:lengthi");
        info.extend_from_slice(length.to_string().as_bytes());
        info.extend_from_slice(b"e11:pieces root32:");
        info.extend_from_slice(pieces_root);
        info.extend_from_slice(b"eee12:meta versioni");
        info.extend_from_slice(meta_version.to_string().as_bytes());
        info.extend_from_slice(b"e4:name4:test12:piece lengthi16384ee");
        info
    }

    fn expected_info_hash() -> Id32 {
        Id32::new([
            0x92, 0xf7, 0x92, 0x78, 0x9c, 0x4d, 0x4c, 0x0a, 0x08, 0x34, 0x4d, 0x59, 0x39, 0x9b,
            0xe4, 0xec, 0xdd, 0x46, 0xda, 0x4d, 0x8a, 0xb4, 0xd1, 0xf0, 0x4d, 0x4f, 0x62, 0xb6,
            0xb0, 0x39, 0x1a, 0xeb,
        ])
    }
}
