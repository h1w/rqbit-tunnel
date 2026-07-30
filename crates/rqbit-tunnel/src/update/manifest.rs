use std::{
    collections::HashSet,
    io,
    path::{Component, Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    platform::{ServiceError, ServiceState},
    update::component::validate_portable_component,
    version::ActiveReleaseError,
};

/// The only release-manifest schema accepted by this launcher.
pub const RELEASE_MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Reject assets large enough to make update download accounting impractical.
pub const MAX_RELEASE_ASSET_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// File name used for a signed release manifest.
pub const RELEASE_MANIFEST_FILE_NAME: &str = "release-manifest.json";
/// File name used for the detached base64-encoded release manifest signature.
pub const RELEASE_MANIFEST_SIGNATURE_FILE_NAME: &str = "release-manifest.sig";
/// Returns whether a filename is reserved for release manifest metadata.
///
/// Comparisons are ASCII case-insensitive so assets cannot collide on
/// case-insensitive filesystems.
pub fn is_reserved_release_asset_filename(filename: &str) -> bool {
    filename.eq_ignore_ascii_case(RELEASE_MANIFEST_FILE_NAME)
        || filename.eq_ignore_ascii_case(RELEASE_MANIFEST_SIGNATURE_FILE_NAME)
}

/// Loads the immutable Ed25519 verification key compiled into every client release.
///
/// The corresponding signing seed is stored only in the protected GitHub Actions
/// secret and is never packaged with a client bundle.
pub fn pinned_release_public_key() -> Result<VerifyingKey, UpdateError> {
    parse_public_key_hex(include_str!("../../resources/release-public-key.hex"))
}

/// A signed description of one release and its platform-specific assets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub version: Version,
    pub launcher_abi: u32,
    pub assets: Vec<ReleaseAsset>,
}

impl ReleaseManifest {
    /// Validates every field that can affect update selection or file placement.
    pub fn validate(&self) -> Result<(), UpdateError> {
        validate_manifest(self)
    }
}

/// A downloadable archive belonging to a signed release.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReleaseAsset {
    pub target: String,
    pub archive: String,
    pub bytes: u64,
    pub sha256: String,
}

/// Errors from update trust, staging, and selection boundaries.
#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("release manifest signature is invalid")]
    InvalidSignature,
    #[error("release manifest is not valid JSON: {source}")]
    InvalidManifestJson {
        #[source]
        source: serde_json::Error,
    },
    #[error("GitHub releases metadata is not valid JSON: {source}")]
    InvalidGithubReleaseJson {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to build GitHub release client: {source}")]
    BuildGithubReleaseClient {
        #[source]
        source: reqwest::Error,
    },
    #[error("failed to request GitHub releases metadata: {source}")]
    RequestGithubReleases {
        #[source]
        source: reqwest::Error,
    },
    #[error("GitHub releases returned unexpected HTTP status {status}")]
    UnexpectedGithubReleasesStatus { status: reqwest::StatusCode },
    #[error("failed to read GitHub releases response: {source}")]
    ReadGithubReleasesResponse {
        #[source]
        source: reqwest::Error,
    },
    #[error("GitHub releases discovery exceeded {limit} pages")]
    GithubReleasePaginationLimit { limit: usize },
    #[error("GitHub releases contains no eligible rqbit-tunnel release")]
    NoEligibleGithubRelease,
    #[error("GitHub release source is missing selected release context")]
    MissingGithubReleaseSelectionContext,
    #[error("failed to request GitHub release asset {name}: {source}")]
    RequestGithubReleaseAsset {
        name: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("GitHub release asset {name} returned unexpected HTTP status {status}")]
    UnexpectedGithubReleaseAssetStatus {
        name: String,
        status: reqwest::StatusCode,
    },
    #[error("failed to read GitHub release asset {name}: {source}")]
    ReadGithubReleaseAsset {
        name: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("GitHub release asset name must not be empty")]
    EmptyGithubReleaseAssetName,
    #[error("GitHub release contains duplicate asset name {name:?}")]
    DuplicateGithubReleaseAsset { name: String },
    #[error("GitHub release has no asset named {name:?}")]
    MissingGithubReleaseAsset { name: String },
    #[error("GitHub release asset {name:?} has an invalid download URL {url:?}: {source}")]
    InvalidGithubReleaseAssetUrl {
        name: String,
        url: String,
        #[source]
        source: url::ParseError,
    },
    #[error("GitHub release asset {name:?} has unsafe download URL {url:?}: {reason}")]
    UnsafeGithubReleaseAssetUrl {
        name: String,
        url: String,
        reason: &'static str,
    },
    #[error("GitHub releases endpoint URL {url:?} is unsafe: {reason}")]
    UnsafeGithubReleasesUrl { url: String, reason: &'static str },
    #[error("release manifest schema version {actual} is unsupported (expected {expected})")]
    UnsupportedSchemaVersion { actual: u32, expected: u32 },
    #[error("release manifest version is not valid semantic version text: {version:?}")]
    InvalidVersion { version: String },
    #[error("release manifest version is not canonical semantic version text: {version:?}")]
    NonCanonicalVersion { version: String },
    #[error("release manifest launcher ABI must not be zero")]
    ZeroLauncherAbi,
    #[error("release manifest must contain at least one asset")]
    EmptyAssets,
    #[error("release manifest asset target must not be empty")]
    EmptyAssetTarget,
    #[error("release manifest contains duplicate asset target {target:?}")]
    DuplicateAssetTarget { target: String },
    #[error("release manifest archive filename is unsafe: {archive:?}")]
    UnsafeArchiveFilename { archive: String },
    #[error(
        "release manifest asset SHA-256 must be 64 lowercase hexadecimal characters: {sha256:?}"
    )]
    InvalidAssetSha256 { sha256: String },
    #[error("release manifest asset byte length {bytes} is outside 1..={max}")]
    InvalidAssetBytes { bytes: u64, max: u64 },
    #[error("release public key must be exactly 32 bytes encoded as hexadecimal")]
    InvalidPublicKey,
    #[error("no newer release is available")]
    NoUpdate,
    #[error(
        "the discovered release version {discovered} does not match requested version {requested}"
    )]
    RequestedVersionMismatch {
        requested: Version,
        discovered: Version,
    },
    #[error(
        "selected GitHub release version {selected} does not match signed manifest version {manifest}"
    )]
    GithubReleaseManifestVersionMismatch {
        selected: Version,
        manifest: Version,
    },
    #[error("updates are not supported for the current platform target")]
    UnsupportedPlatformTarget,
    #[error("release has no asset for target {target:?}")]
    NoMatchingAsset { target: String },
    #[error(
        "release requires launcher ABI {required}; installed ABI is {installed}; manually install the matching client bundle to upgrade the stable launcher"
    )]
    UnsupportedLauncherAbi { required: u32, installed: u32 },
    #[error("install root must be an absolute directory: {path}")]
    InvalidInstallRoot { path: PathBuf },
    #[error("failed to inspect install root {path}: {source}")]
    InspectInstallRoot {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to open update lock {path}: {source}")]
    OpenUpdateLock {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("another update is already running for installation root {path}")]
    UpdateAlreadyRunning { path: PathBuf },
    #[error("failed to acquire update lock {path}: {source}")]
    AcquireUpdateLock {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create update work directory under {path}: {source}")]
    CreateUpdateWorkDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create update staging directory {path}: {source}")]
    CreateUpdateStagingDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create downloaded release asset {path}: {source}")]
    CreateDownloadedReleaseAsset {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write downloaded release asset {asset}: {source}")]
    WriteDownloadedReleaseAsset {
        asset: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to sync downloaded release asset {path}: {source}")]
    SyncDownloadedReleaseAsset {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "downloaded release asset length did not match manifest: expected {expected} bytes, got {actual}"
    )]
    DownloadedArchiveLengthMismatch { expected: u64, actual: u64 },
    #[error("downloaded release asset SHA-256 did not match manifest")]
    DownloadedArchiveChecksumMismatch {
        expected_sha256: String,
        actual_sha256: String,
    },
    #[error("release asset archive format is unsupported: {archive}")]
    UnsupportedArchiveFormat { archive: String },
    #[error("failed to open verified archive {path}: {source}")]
    OpenVerifiedArchive {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to snapshot verified archive {path}: {source}")]
    SnapshotVerifiedArchive {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read verified archive {path}: {source}")]
    ReadVerifiedArchive {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("staging directory {path} could not be inspected: {source}")]
    InspectStagingDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("staging directory {path} must be an empty non-symlink directory")]
    UnsafeStagingDirectory { path: PathBuf },
    #[error("staging directory {path} must be empty")]
    NonEmptyStagingDirectory { path: PathBuf },
    #[error("archive entry path is not valid UTF-8")]
    ArchivePathNotUtf8,
    #[error("archive entry path {path:?} is unsafe: {reason}")]
    UnsafeArchiveEntryPath { path: String, reason: &'static str },
    #[error("archive contains duplicate normalized entry path {path:?}")]
    DuplicateArchiveEntryPath { path: String },
    #[error("archive entry type byte {entry_type:#04x} is not allowed")]
    UnsupportedArchiveEntryType { entry_type: u8 },
    #[error("ZIP archive entry {path:?} is unsupported: {reason}")]
    UnsupportedZipArchiveEntry { path: String, reason: &'static str },
    #[error("ZIP archive contains overlapping compressed file data")]
    OverlappingZipFileData,
    #[error("archive contains no entries")]
    EmptyArchive,
    #[error("archive contains non-padding data after its end marker")]
    ArchiveTrailingData,
    #[error("archive contains more than one top-level bundle directory: {first:?} and {found:?}")]
    MultipleArchiveBundleDirectories { first: String, found: String },
    #[error("archive contains a regular file at staging root: {path:?}")]
    ArchiveRootFile { path: String },
    #[error("archive path {path:?} is nested below regular file {ancestor:?}")]
    ArchiveFileAncestor { path: String, ancestor: String },
    #[error("verified archive changed between preflight and extraction")]
    ArchiveChangedDuringExtraction,
    #[error("extraction path {path} could not be inspected: {source}")]
    InspectExtractionPath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("extraction path {path} is not a non-symlink directory")]
    UnsafeExtractionPath { path: PathBuf },
    #[error("extraction file {path} already exists or is unsafe")]
    UnsafeExtractionFile { path: PathBuf },
    #[error("failed to create extraction directory {path}: {source}")]
    CreateExtractionDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create extracted file {path}: {source}")]
    CreateExtractionFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write extracted file {path}: {source}")]
    WriteExtractedFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to set permissions on extracted file {path}: {source}")]
    SetExtractedFilePermissions {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to sync extracted file {path}: {source}")]
    SyncExtractedFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to sync extracted staging directory {path}: {source}")]
    SyncExtractionDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("staged client bundle is missing required component {component:?}")]
    MissingClientPayloadComponent { component: String },
    #[error("staged client bundle component is not executable {component:?}")]
    NonExecutableClientPayloadComponent { component: String },
    #[error("release destination already exists: {path}")]
    ReleaseAlreadyExists { path: PathBuf },
    #[error("failed to discard rolled-back release candidate {path}: {source}")]
    DiscardRolledBackRelease {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create release destination directory {path}: {source}")]
    CreateReleaseDestination {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to open release destination directory {path}: {source}")]
    OpenReleaseDestination {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to promote staged bundle to {destination}: {source}")]
    PromoteStagedBundle {
        destination: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("secure no-overwrite bundle promotion is unsupported on this platform")]
    UnsupportedBundlePromotion,
    #[error("failed to construct the active release candidate: {source}")]
    CreateActiveReleaseCandidate {
        #[source]
        source: ActiveReleaseError,
    },
    #[error(
        "candidate payload directory {payload_dir} does not match required release layout {expected}"
    )]
    InvalidActivationPayloadDirectory {
        payload_dir: PathBuf,
        expected: PathBuf,
    },
    #[error("failed to read the current active release pointer: {source}")]
    ReadActiveRelease {
        #[source]
        source: ActiveReleaseError,
    },
    #[error("candidate payload executable could not be resolved safely: {source}")]
    ResolveCandidatePayload {
        #[source]
        source: ActiveReleaseError,
    },
    #[error("failed to activate the candidate release pointer: {source}")]
    WriteCandidateActiveRelease {
        #[source]
        source: ActiveReleaseError,
    },
    #[error("failed to restore the previous active release pointer: {source}")]
    RestorePreviousActiveRelease {
        #[source]
        source: ActiveReleaseError,
    },
    #[error("failed to stop the client service: {source}")]
    StopClientService {
        #[source]
        source: ServiceError,
    },
    #[error("client service stop returned unexpected state {state:?}")]
    UnexpectedClientStopState { state: ServiceState },
    #[error("failed to start the client service: {source}")]
    StartClientService {
        #[source]
        source: ServiceError,
    },
    #[error("client service start returned unexpected state {state:?}")]
    UnexpectedClientStartState { state: ServiceState },
    #[error("local client health check timed out")]
    HealthTimeout,
    #[error("activation failed but the previous release was restored: {source}")]
    RolledBack {
        #[source]
        source: Box<UpdateError>,
    },
    #[error("activation failed and rollback failed: activation: {source}; recovery: {recovery}")]
    RollbackFailed {
        #[source]
        source: Box<UpdateError>,
        recovery: Box<UpdateError>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifestDocument {
    schema_version: u32,
    version: String,
    launcher_abi: u32,
    assets: Vec<ReleaseAssetDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseAssetDocument {
    target: String,
    archive: String,
    bytes: u64,
    sha256: String,
}

/// Verifies a detached signature over the exact downloaded bytes, then parses
/// and validates the signed JSON manifest.
pub fn verify_manifest(
    raw: &[u8],
    signature_b64: &str,
    key: &VerifyingKey,
) -> Result<ReleaseManifest, UpdateError> {
    let signature_bytes = BASE64_STANDARD
        .decode(signature_b64.trim())
        .map_err(|_| UpdateError::InvalidSignature)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| UpdateError::InvalidSignature)?;
    key.verify_strict(raw, &signature)
        .map_err(|_| UpdateError::InvalidSignature)?;

    let document = serde_json::from_slice::<ReleaseManifestDocument>(raw)
        .map_err(|source| UpdateError::InvalidManifestJson { source })?;
    let manifest = ReleaseManifest {
        schema_version: document.schema_version,
        version: parse_canonical_version(&document.version)?,
        launcher_abi: document.launcher_abi,
        assets: document
            .assets
            .into_iter()
            .map(|asset| ReleaseAsset {
                target: asset.target,
                archive: asset.archive,
                bytes: asset.bytes,
                sha256: asset.sha256,
            })
            .collect(),
    };
    manifest.validate()?;
    Ok(manifest)
}

/// Parses semantic-version text only when its serialized spelling is canonical.
pub fn parse_canonical_version(value: &str) -> Result<Version, UpdateError> {
    let version = Version::parse(value).map_err(|_| UpdateError::InvalidVersion {
        version: value.to_owned(),
    })?;
    if version.to_string() != value {
        return Err(UpdateError::NonCanonicalVersion {
            version: value.to_owned(),
        });
    }
    Ok(version)
}

/// Parses a 32-byte Ed25519 public key encoded as hexadecimal.
///
/// This helper intentionally has no knowledge of where a pinned key is stored.
pub fn parse_public_key_hex(value: &str) -> Result<VerifyingKey, UpdateError> {
    let value = value.trim();
    if value.len() != 64 {
        return Err(UpdateError::InvalidPublicKey);
    }

    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| UpdateError::InvalidPublicKey)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| UpdateError::InvalidPublicKey)
}

/// Revalidates a manifest at the point where its contents become actionable.
pub fn validate_manifest(manifest: &ReleaseManifest) -> Result<(), UpdateError> {
    if manifest.schema_version != RELEASE_MANIFEST_SCHEMA_VERSION {
        return Err(UpdateError::UnsupportedSchemaVersion {
            actual: manifest.schema_version,
            expected: RELEASE_MANIFEST_SCHEMA_VERSION,
        });
    }
    if manifest.launcher_abi == 0 {
        return Err(UpdateError::ZeroLauncherAbi);
    }
    if manifest.assets.is_empty() {
        return Err(UpdateError::EmptyAssets);
    }

    let mut targets = HashSet::with_capacity(manifest.assets.len());
    for asset in &manifest.assets {
        if asset.target.trim().is_empty() {
            return Err(UpdateError::EmptyAssetTarget);
        }
        if !targets.insert(asset.target.as_str()) {
            return Err(UpdateError::DuplicateAssetTarget {
                target: asset.target.clone(),
            });
        }
        validate_asset(asset)?;
    }

    Ok(())
}

/// Selects an actionable release asset only after revalidating the manifest.
pub fn select_asset<'a>(
    manifest: &'a ReleaseManifest,
    target: &str,
    installed_version: &Version,
    installed_launcher_abi: u32,
) -> Result<&'a ReleaseAsset, UpdateError> {
    manifest.validate()?;
    if manifest.version <= *installed_version {
        return Err(UpdateError::NoUpdate);
    }
    if manifest.launcher_abi > installed_launcher_abi {
        return Err(UpdateError::UnsupportedLauncherAbi {
            required: manifest.launcher_abi,
            installed: installed_launcher_abi,
        });
    }

    manifest
        .assets
        .iter()
        .find(|asset| asset.target == target)
        .ok_or_else(|| UpdateError::NoMatchingAsset {
            target: target.to_owned(),
        })
}

fn validate_asset(asset: &ReleaseAsset) -> Result<(), UpdateError> {
    validate_archive_filename(&asset.archive)?;
    if asset.bytes == 0 || asset.bytes > MAX_RELEASE_ASSET_BYTES {
        return Err(UpdateError::InvalidAssetBytes {
            bytes: asset.bytes,
            max: MAX_RELEASE_ASSET_BYTES,
        });
    }
    if asset.sha256.len() != 64
        || !asset
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(UpdateError::InvalidAssetSha256 {
            sha256: asset.sha256.clone(),
        });
    }
    Ok(())
}

fn validate_archive_filename(archive: &str) -> Result<(), UpdateError> {
    let path = Path::new(archive);
    let bytes = archive.as_bytes();
    if is_reserved_release_asset_filename(archive)
        || archive.is_empty()
        || archive.contains('/')
        || archive.contains('\\')
        || archive.contains('\0')
        || path.is_absolute()
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
    {
        return Err(UpdateError::UnsafeArchiveFilename {
            archive: archive.to_owned(),
        });
    }

    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(UpdateError::UnsafeArchiveFilename {
            archive: archive.to_owned(),
        });
    }

    validate_portable_component(archive).map_err(|_| UpdateError::UnsafeArchiveFilename {
        archive: archive.to_owned(),
    })?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use rand_core::OsRng;
    use semver::Version;

    use super::{
        RELEASE_MANIFEST_FILE_NAME, RELEASE_MANIFEST_SIGNATURE_FILE_NAME, ReleaseAsset,
        ReleaseManifest, UpdateError, parse_public_key_hex, pinned_release_public_key,
        select_asset, verify_manifest,
    };

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn valid_raw_manifest() -> &'static [u8] {
        br#"{"schema_version":1,"version":"1.2.3","launcher_abi":1,"assets":[{"target":"x86_64-unknown-linux-gnu","archive":"rqbit-tunnel-x86_64-unknown-linux-gnu.tar.gz","bytes":42,"sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}"#
    }

    fn signed_fixture(raw: &[u8]) -> (String, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let signature = BASE64_STANDARD.encode(signing_key.sign(raw).to_bytes());
        (signature, signing_key.verifying_key())
    }

    fn assert_signed_manifest_rejects_archive(archive: &str) {
        let raw = format!(
            r#"{{"schema_version":1,"version":"1.2.3","launcher_abi":1,"assets":[{{"target":"x86_64-unknown-linux-gnu","archive":"{archive}","bytes":42,"sha256":"{SHA256}"}}]}}"#
        );
        let (signature, key) = signed_fixture(raw.as_bytes());

        assert!(matches!(
            verify_manifest(raw.as_bytes(), &signature, &key),
            Err(UpdateError::UnsafeArchiveFilename { archive: rejected }) if rejected == archive
        ));
    }

    fn valid_asset() -> ReleaseAsset {
        ReleaseAsset {
            target: TARGET.to_owned(),
            archive: "rqbit-tunnel-x86_64-unknown-linux-gnu.tar.gz".to_owned(),
            bytes: 42,
            sha256: SHA256.to_owned(),
        }
    }

    fn fixture_manifest(
        asset: ReleaseAsset,
        version: Version,
        launcher_abi: u32,
    ) -> ReleaseManifest {
        ReleaseManifest {
            schema_version: 1,
            version,
            launcher_abi,
            assets: vec![asset],
        }
    }

    #[test]
    fn verifier_maps_malformed_signature_text_to_invalid_signature() {
        let (_, key) = signed_fixture(valid_raw_manifest());

        assert!(matches!(
            verify_manifest(valid_raw_manifest(), "not-base64", &key),
            Err(UpdateError::InvalidSignature)
        ));
    }

    #[test]
    fn verifier_rejects_tampered_manifest_bytes() {
        let raw = valid_raw_manifest();
        let (signature, key) = signed_fixture(raw);
        let mut tampered = raw.to_vec();
        let version_offset = tampered
            .windows(b"1.2.3".len())
            .position(|bytes| bytes == b"1.2.3")
            .unwrap();
        tampered[version_offset] = b'2';

        assert!(verify_manifest(&tampered, &signature, &key).is_err());
    }

    #[test]
    fn verifier_rejects_equivalent_json_when_signature_covers_different_raw_bytes() {
        let raw = valid_raw_manifest();
        let (signature, key) = signed_fixture(raw);
        let equivalent_json = br#"{ "schema_version" : 1, "version" : "1.2.3", "launcher_abi" : 1, "assets" : [ { "target" : "x86_64-unknown-linux-gnu", "archive" : "rqbit-tunnel-x86_64-unknown-linux-gnu.tar.gz", "bytes" : 42, "sha256" : "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" } ] }"#;

        assert!(verify_manifest(equivalent_json, &signature, &key).is_err());
    }

    #[test]
    fn verifier_parses_valid_raw_json_after_strict_verification() {
        let raw = valid_raw_manifest();
        let (signature, key) = signed_fixture(raw);

        let manifest = verify_manifest(raw, &signature, &key).unwrap();
        assert_eq!(manifest.version, Version::new(1, 2, 3));
        assert_eq!(manifest.assets.len(), 1);
    }
    #[test]
    fn verifier_rejects_signed_manifest_with_portable_unsafe_archive_filename() {
        let raw = br#"{"schema_version":1,"version":"1.2.3","launcher_abi":1,"assets":[{"target":"x86_64-unknown-linux-gnu","archive":"asset?name","bytes":42,"sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}"#;
        let (signature, key) = signed_fixture(raw);

        assert!(matches!(
            verify_manifest(raw, &signature, &key),
            Err(UpdateError::UnsafeArchiveFilename { archive }) if archive == "asset?name"
        ));
    }

    #[test]
    fn verifier_rejects_signed_manifest_with_windows_device_archive_name() {
        for archive in ["CONIN$", "cOnOuT$.zip", "clock$.tar.gz"] {
            assert_signed_manifest_rejects_archive(archive);
        }
    }

    #[test]
    fn verifier_rejects_signed_manifest_with_reserved_metadata_archive_name() {
        let upper_manifest = RELEASE_MANIFEST_FILE_NAME.to_ascii_uppercase();
        let upper_signature = RELEASE_MANIFEST_SIGNATURE_FILE_NAME.to_ascii_uppercase();

        for archive in [
            RELEASE_MANIFEST_FILE_NAME,
            upper_manifest.as_str(),
            RELEASE_MANIFEST_SIGNATURE_FILE_NAME,
            upper_signature.as_str(),
        ] {
            assert_signed_manifest_rejects_archive(archive);
        }
    }

    #[test]
    fn selection_rejects_wrong_target_equal_or_older_version() {
        let current = Version::new(1, 2, 3);

        assert!(
            select_asset(
                &fixture_manifest(valid_asset(), Version::new(1, 2, 4), 1),
                "x86_64-pc-windows-msvc",
                &current,
                1,
            )
            .is_err()
        );
        assert!(
            select_asset(
                &fixture_manifest(valid_asset(), current.clone(), 1),
                TARGET,
                &current,
                1,
            )
            .is_err()
        );
        assert!(
            select_asset(
                &fixture_manifest(valid_asset(), Version::new(1, 2, 2), 1),
                TARGET,
                &current,
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn unsupported_launcher_abi_error_explains_manual_bundle_recovery() {
        let error = UpdateError::UnsupportedLauncherAbi {
            required: 2,
            installed: 1,
        };

        assert_eq!(
            error.to_string(),
            "release requires launcher ABI 2; installed ABI is 1; manually install the matching client bundle to upgrade the stable launcher"
        );
    }

    #[test]
    fn selection_rejects_unsupported_launcher_abi() {
        assert!(
            select_asset(
                &fixture_manifest(valid_asset(), Version::new(1, 2, 4), 2),
                TARGET,
                &Version::new(1, 2, 3),
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn selection_rejects_unsafe_archive_filename() {
        let mut asset = valid_asset();
        asset.archive = "../rqbit-tunnel.tar.gz".to_owned();

        assert!(
            select_asset(
                &fixture_manifest(asset, Version::new(1, 2, 4), 1),
                TARGET,
                &Version::new(1, 2, 3),
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn selection_rejects_malformed_sha256_and_invalid_byte_size() {
        let mut malformed_sha256 = valid_asset();
        malformed_sha256.sha256 = "not-a-sha256".to_owned();
        assert!(
            select_asset(
                &fixture_manifest(malformed_sha256, Version::new(1, 2, 4), 1),
                TARGET,
                &Version::new(1, 2, 3),
                1,
            )
            .is_err()
        );

        let mut zero_bytes = valid_asset();
        zero_bytes.bytes = 0;
        assert!(
            select_asset(
                &fixture_manifest(zero_bytes, Version::new(1, 2, 4), 1),
                TARGET,
                &Version::new(1, 2, 3),
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn selection_rejects_uppercase_sha256() {
        let mut asset = valid_asset();
        asset.sha256 = SHA256.to_ascii_uppercase();

        assert!(
            select_asset(
                &fixture_manifest(asset, Version::new(1, 2, 4), 1),
                TARGET,
                &Version::new(1, 2, 3),
                1,
            )
            .is_err()
        );
    }
    #[test]
    fn verifier_rejects_noncanonical_semver_after_verification() {
        let raw = br#"{"schema_version":1,"version":"01.2.3","launcher_abi":1,"assets":[{"target":"x86_64-unknown-linux-gnu","archive":"rqbit-tunnel-x86_64-unknown-linux-gnu.tar.gz","bytes":42,"sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}"#;
        let (signature, key) = signed_fixture(raw);

        assert!(verify_manifest(raw, &signature, &key).is_err());
    }

    #[test]
    fn public_key_hex_parser_requires_exact_32_bytes() {
        let (_, key) = signed_fixture(valid_raw_manifest());
        let encoded = hex::encode(key.to_bytes());

        assert_eq!(parse_public_key_hex(&encoded).unwrap(), key);
        assert!(parse_public_key_hex("not-a-32-byte-key").is_err());
    }
    #[test]
    fn bundled_release_public_key_is_valid() {
        assert!(pinned_release_public_key().is_ok());
    }
}
