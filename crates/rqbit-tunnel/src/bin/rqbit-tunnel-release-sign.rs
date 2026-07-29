#[cfg(windows)]
use std::fs::OpenOptions;
use std::{
    collections::HashSet,
    env,
    ffi::OsString,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use clap::{Arg, ArgAction, ArgMatches, Command as ClapCommand, error::ErrorKind};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use rqbit_tunnel::update::manifest::{
    MAX_RELEASE_ASSET_BYTES, RELEASE_MANIFEST_FILE_NAME, RELEASE_MANIFEST_SCHEMA_VERSION,
    RELEASE_MANIFEST_SIGNATURE_FILE_NAME, ReleaseAsset, ReleaseManifest, UpdateError,
    is_reserved_release_asset_filename, parse_canonical_version, pinned_release_public_key,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const SIGNING_KEY_ENVIRONMENT_VARIABLE: &str = "TUNNEL_RELEASE_SIGNING_KEY";
const KEYGEN_PUBLIC_KEY_ENVIRONMENT_VARIABLE: &str = "TUNNEL_RELEASE_PUBLIC_KEY";
const HASH_BUFFER_BYTES: usize = 64 * 1024;
const STAGING_DIRECTORY_ATTEMPTS: usize = 16;
const RELEASE_METADATA_DIRECTORY_NAME: &str = "release-metadata";

#[derive(Debug)]
struct Cli {
    command: Command,
}

#[derive(Debug)]
enum Command {
    Keygen(KeygenArguments),
    Sign(SignArguments),
}

#[derive(Debug)]
struct KeygenArguments {
    stdout: bool,
}

#[derive(Debug)]
struct SignArguments {
    assets: Vec<AssetArgument>,
    version: String,
    launcher_abi: u32,
    output: PathBuf,
}

#[derive(Clone, Debug)]
struct AssetArgument {
    target: String,
    path: PathBuf,
}

#[derive(Debug, Error)]
enum AssetArgumentError {
    #[error("asset must be formatted as TARGET=PATH")]
    MissingSeparator,
    #[error("asset target must not be empty")]
    EmptyTarget,
    #[error("asset path must not be empty")]
    EmptyPath,
}

impl FromStr for AssetArgument {
    type Err = AssetArgumentError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (target, path) = value
            .split_once('=')
            .ok_or(AssetArgumentError::MissingSeparator)?;
        if target.trim().is_empty() {
            return Err(AssetArgumentError::EmptyTarget);
        }
        if path.is_empty() {
            return Err(AssetArgumentError::EmptyPath);
        }
        Ok(Self {
            target: target.to_owned(),
            path: PathBuf::from(path),
        })
    }
}

impl Cli {
    fn from_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        let command = match matches.subcommand() {
            Some(("keygen", keygen_matches)) => Command::Keygen(KeygenArguments {
                stdout: keygen_matches.get_flag("stdout"),
            }),
            Some(("sign", sign_matches)) => Command::Sign(parse_sign_arguments(sign_matches)?),
            _ => {
                return Err(clap::Error::raw(
                    ErrorKind::MissingSubcommand,
                    "a signer subcommand is required",
                ));
            }
        };
        Ok(Self { command })
    }
}

fn parse_cli<I, T>(arguments: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = cli_command().try_get_matches_from(arguments)?;
    Cli::from_matches(&matches)
}

fn parse_sign_arguments(matches: &ArgMatches) -> Result<SignArguments, clap::Error> {
    let assets = matches
        .get_many::<String>("asset")
        .expect("clap enforces at least one --asset")
        .map(|value| {
            value
                .parse::<AssetArgument>()
                .map_err(|source| clap::Error::raw(ErrorKind::InvalidValue, source.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let launcher_abi = required_string(matches, "launcher-abi")
        .parse::<u32>()
        .map_err(|source| {
            clap::Error::raw(
                ErrorKind::InvalidValue,
                format!(
                    "invalid launcher ABI {:?}: {source}",
                    required_string(matches, "launcher-abi")
                ),
            )
        })?;

    Ok(SignArguments {
        assets,
        version: required_string(matches, "version").to_owned(),
        launcher_abi,
        output: PathBuf::from(required_string(matches, "output")),
    })
}

fn required_string<'a>(matches: &'a ArgMatches, name: &str) -> &'a str {
    matches
        .get_one::<String>(name)
        .expect("clap enforces required arguments")
}

fn cli_command() -> ClapCommand {
    ClapCommand::new("rqbit-tunnel-release-sign")
        .about("CI-only signer for one rqbit-tunnel release manifest")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            ClapCommand::new("keygen")
                .about("Generate a release signing seed and public key for an owner to store")
                .arg(
                    Arg::new("stdout")
                        .long("stdout")
                        .action(ArgAction::SetTrue)
                        .help("Explicitly allow secret seed material to be written to stdout once"),
                ),
        )
        .subcommand(
            ClapCommand::new("sign")
                .about("Sign explicitly listed release archives into one multi-target manifest")
                .arg(
                    Arg::new("asset")
                        .long("asset")
                        .value_name("TARGET=PATH")
                        .required(true)
                        .action(ArgAction::Append)
                        .help("Exact target and archive path; repeat for every release asset"),
                )
                .arg(
                    Arg::new("version")
                        .long("version")
                        .value_name("SEMVER")
                        .required(true)
                        .help("Canonical semantic version for the release"),
                )
                .arg(
                    Arg::new("launcher-abi")
                        .long("launcher-abi")
                        .value_name("ABI")
                        .required(true)
                        .help("Minimum stable-launcher ABI required by this release"),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .value_name("DIR")
                        .required(true)
                        .help("Existing directory where release-metadata/ will be published"),
                ),
        )
}

fn main() -> ExitCode {
    let cli = match parse_cli(std::env::args_os()) {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            return ExitCode::from(code as u8);
        }
    };

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rqbit-tunnel-release-sign: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), SignerError> {
    match cli.command {
        Command::Keygen(arguments) => keygen(arguments),
        Command::Sign(arguments) => sign(arguments),
    }
}

fn keygen(arguments: KeygenArguments) -> Result<(), SignerError> {
    if !arguments.stdout {
        return Err(SignerError::KeygenRequiresStdout);
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let mut seed = signing_key.to_bytes();
    let encoded_seed = BASE64_STANDARD.encode(seed);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    seed.fill(0);

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{SIGNING_KEY_ENVIRONMENT_VARIABLE}={encoded_seed}")
        .map_err(|source| SignerError::WriteKeygenOutput { source })?;
    writeln!(
        stdout,
        "{KEYGEN_PUBLIC_KEY_ENVIRONMENT_VARIABLE}={public_key}"
    )
    .map_err(|source| SignerError::WriteKeygenOutput { source })?;
    Ok(())
}

fn sign(arguments: SignArguments) -> Result<(), SignerError> {
    let signing_key = signing_key_from_environment()?;
    let pinned_public_key = pinned_release_public_key()?;
    validate_signing_key_matches_verifying_key(&signing_key, &pinned_public_key)?;

    let version = parse_canonical_version(&arguments.version)?;
    if arguments.launcher_abi == 0 {
        return Err(UpdateError::ZeroLauncherAbi.into());
    }

    let output_context = open_output_directory_context(&arguments.output)?;
    let assets = collect_release_assets_in_context(arguments.assets, &output_context)?;
    let manifest = ReleaseManifest {
        schema_version: RELEASE_MANIFEST_SCHEMA_VERSION,
        version,
        launcher_abi: arguments.launcher_abi,
        assets,
    };
    manifest.validate()?;

    let manifest_bytes =
        serde_json::to_vec(&manifest).map_err(|source| SignerError::EncodeManifest { source })?;
    let signature = BASE64_STANDARD.encode(signing_key.sign(&manifest_bytes).to_bytes());

    publish_release_metadata_in_context(&output_context, &manifest_bytes, signature.as_bytes())
}

fn signing_key_from_environment() -> Result<SigningKey, SignerError> {
    let encoded_seed =
        env::var(SIGNING_KEY_ENVIRONMENT_VARIABLE).map_err(|_| SignerError::MissingSigningKey)?;
    let seed = BASE64_STANDARD
        .decode(encoded_seed.trim())
        .map_err(|_| SignerError::InvalidSigningKey)?;
    let mut seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| SignerError::InvalidSigningKey)?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    Ok(signing_key)
}

fn validate_signing_key_matches_verifying_key(
    signing_key: &SigningKey,
    expected_verifying_key: &VerifyingKey,
) -> Result<(), SignerError> {
    if signing_key.verifying_key() == *expected_verifying_key {
        Ok(())
    } else {
        Err(SignerError::SigningKeyDoesNotMatchPinnedPublicKey)
    }
}

fn validate_directory(path: &Path, kind: &'static str) -> Result<(), SignerError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| SignerError::InspectDirectory {
        kind,
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SignerError::UnsafeDirectory {
            kind,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

struct OutputDirectoryContext {
    canonical_output_directory: PathBuf,
    #[cfg(unix)]
    output_directory: File,
    #[cfg(windows)]
    _output_directory: File,
    #[cfg(windows)]
    normalized_output_directory: PathBuf,
}

#[cfg(test)]
fn collect_release_assets(
    inputs: Vec<AssetArgument>,
    canonical_output_directory: &Path,
) -> Result<Vec<ReleaseAsset>, SignerError> {
    let output_context = open_output_directory_context_from_canonical(canonical_output_directory)?;
    collect_release_assets_in_context(inputs, &output_context)
}

fn collect_release_assets_in_context(
    inputs: Vec<AssetArgument>,
    output_context: &OutputDirectoryContext,
) -> Result<Vec<ReleaseAsset>, SignerError> {
    validate_unique_asset_targets(&inputs)?;

    let mut source_paths = HashSet::with_capacity(inputs.len());
    let mut archive_names = HashSet::with_capacity(inputs.len());
    let mut assets = Vec::with_capacity(inputs.len());
    for input in inputs {
        let canonical_path =
            validate_release_asset_path(&input.path, &output_context.canonical_output_directory)?;
        if !source_paths.insert(canonical_path.clone()) {
            return Err(SignerError::DuplicateAssetPath { path: input.path });
        }

        let archive = canonical_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| SignerError::AssetNameNotUtf8 {
                path: canonical_path.clone(),
            })?
            .to_owned();
        if is_reserved_release_asset_filename(&archive) {
            return Err(SignerError::ReservedAssetName { archive });
        }
        if !archive_names.insert(archive.clone()) {
            return Err(SignerError::DuplicateArchiveName { archive });
        }

        let file = open_asset_for_hashing(output_context, &canonical_path)?;
        let (bytes, sha256) = hash_asset(file, &canonical_path)?;
        assets.push(ReleaseAsset {
            target: input.target,
            archive,
            bytes,
            sha256,
        });
    }
    assets.sort_unstable_by(|left, right| left.target.cmp(&right.target));
    Ok(assets)
}

fn validate_release_asset_path(
    input_path: &Path,
    canonical_output_directory: &Path,
) -> Result<PathBuf, SignerError> {
    let metadata =
        fs::symlink_metadata(input_path).map_err(|source| SignerError::InspectAsset {
            path: input_path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SignerError::AssetNotRegular {
            path: input_path.to_path_buf(),
        });
    }

    let canonical_path =
        fs::canonicalize(input_path).map_err(|source| SignerError::CanonicalizeAsset {
            path: input_path.to_path_buf(),
            source,
        })?;
    if canonical_path.parent() != Some(canonical_output_directory) {
        return Err(SignerError::AssetOutsideOutputDirectory {
            path: input_path.to_path_buf(),
            output: canonical_output_directory.to_path_buf(),
        });
    }
    Ok(canonical_path)
}

fn validate_unique_asset_targets(inputs: &[AssetArgument]) -> Result<(), SignerError> {
    if inputs.is_empty() {
        return Err(UpdateError::EmptyAssets.into());
    }

    let mut targets = HashSet::with_capacity(inputs.len());
    for input in inputs {
        if input.target.trim().is_empty() {
            return Err(UpdateError::EmptyAssetTarget.into());
        }
        if !targets.insert(input.target.as_str()) {
            return Err(UpdateError::DuplicateAssetTarget {
                target: input.target.clone(),
            }
            .into());
        }
    }
    Ok(())
}

fn hash_asset(mut file: File, path: &Path) -> Result<(u64, String), SignerError> {
    let metadata = file
        .metadata()
        .map_err(|source| SignerError::InspectAsset {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || opened_asset_is_reparse_point(&metadata)
    {
        return Err(SignerError::AssetNotRegular {
            path: path.to_path_buf(),
        });
    }
    let expected_bytes = metadata.len();
    validate_asset_size(path, expected_bytes)?;

    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| SignerError::ReadAsset {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| SignerError::AssetChanged {
                path: path.to_path_buf(),
            })?;
        if bytes > MAX_RELEASE_ASSET_BYTES {
            return Err(SignerError::InvalidAssetBytes {
                path: path.to_path_buf(),
                bytes,
            });
        }
        hasher.update(&buffer[..read]);
    }
    if bytes != expected_bytes {
        return Err(SignerError::AssetChanged {
            path: path.to_path_buf(),
        });
    }

    Ok((bytes, hex::encode(hasher.finalize())))
}

fn validate_asset_size(path: &Path, bytes: u64) -> Result<(), SignerError> {
    if bytes == 0 || bytes > MAX_RELEASE_ASSET_BYTES {
        return Err(SignerError::InvalidAssetBytes {
            path: path.to_path_buf(),
            bytes,
        });
    }
    Ok(())
}

fn open_output_directory_context(
    output_directory: &Path,
) -> Result<OutputDirectoryContext, SignerError> {
    validate_directory(output_directory, "output")?;
    let canonical_output_directory = fs::canonicalize(output_directory).map_err(|source| {
        SignerError::CanonicalizeOutputDirectory {
            path: output_directory.to_path_buf(),
            source,
        }
    })?;
    open_output_directory_context_from_canonical(&canonical_output_directory)
}

#[cfg(all(test, unix))]
fn open_asset_context(
    canonical_output_directory: &Path,
) -> Result<OutputDirectoryContext, SignerError> {
    open_output_directory_context_from_canonical(canonical_output_directory)
}

#[cfg(unix)]
fn open_output_directory_context_from_canonical(
    canonical_output_directory: &Path,
) -> Result<OutputDirectoryContext, SignerError> {
    Ok(OutputDirectoryContext {
        canonical_output_directory: canonical_output_directory.to_path_buf(),
        output_directory: open_unix_asset_directory(canonical_output_directory)?,
    })
}

#[cfg(unix)]
fn open_unix_asset_directory(canonical_output_directory: &Path) -> Result<File, SignerError> {
    use std::os::fd::FromRawFd;

    let path = canonical_output_directory.to_path_buf();
    let canonical_output_directory =
        path_as_c_string(&path).map_err(|source| SignerError::OpenAssetDirectory {
            path: path.clone(),
            source,
        })?;
    let fd = unsafe {
        libc::open(
            canonical_output_directory.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(SignerError::OpenAssetDirectory {
            path: path.clone(),
            source: io::Error::last_os_error(),
        });
    }
    let directory = unsafe {
        // SAFETY: `open` returned a fresh owned file descriptor.
        File::from_raw_fd(fd)
    };
    let metadata = directory
        .metadata()
        .map_err(|source| SignerError::InspectDirectory {
            kind: "output",
            path: path.clone(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SignerError::UnsafeDirectory {
            kind: "output",
            path,
        });
    }
    Ok(directory)
}

#[cfg(windows)]
fn open_output_directory_context_from_canonical(
    canonical_output_directory: &Path,
) -> Result<OutputDirectoryContext, SignerError> {
    let output_directory = open_windows_asset_directory(canonical_output_directory)?;
    let normalized_output_directory =
        normalized_windows_final_path(&output_directory).map_err(|source| {
            SignerError::OpenAssetDirectory {
                path: canonical_output_directory.to_path_buf(),
                source,
            }
        })?;
    Ok(OutputDirectoryContext {
        canonical_output_directory: canonical_output_directory.to_path_buf(),
        _output_directory: output_directory,
        normalized_output_directory,
    })
}

#[cfg(not(any(unix, windows)))]
fn open_output_directory_context_from_canonical(
    canonical_output_directory: &Path,
) -> Result<OutputDirectoryContext, SignerError> {
    Err(SignerError::UnsupportedSecureAssetOpen {
        path: canonical_output_directory.to_path_buf(),
    })
}

#[cfg(unix)]
fn open_asset_for_hashing(
    context: &OutputDirectoryContext,
    canonical_path: &Path,
) -> Result<File, SignerError> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    };

    let file_name = canonical_path
        .file_name()
        .ok_or_else(|| SignerError::OpenAsset {
            path: canonical_path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "release asset has no direct-child filename",
            ),
        })?;
    let file_name =
        std::ffi::CString::new(file_name.as_bytes()).map_err(|_| SignerError::OpenAsset {
            path: canonical_path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "release asset filename contains a NUL byte",
            ),
        })?;
    let fd = unsafe {
        libc::openat(
            context.output_directory.as_raw_fd(),
            file_name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(SignerError::OpenAsset {
            path: canonical_path.to_path_buf(),
            source: io::Error::last_os_error(),
        });
    }
    Ok(unsafe {
        // SAFETY: `openat` returned a fresh owned file descriptor.
        File::from_raw_fd(fd)
    })
}

#[cfg(windows)]
fn open_asset_for_hashing(
    context: &OutputDirectoryContext,
    canonical_path: &Path,
) -> Result<File, SignerError> {
    let file = open_windows_asset_file(canonical_path)?;
    let normalized_asset_path =
        normalized_windows_final_path(&file).map_err(|source| SignerError::OpenAsset {
            path: canonical_path.to_path_buf(),
            source,
        })?;
    if normalized_asset_path.parent() != Some(context.normalized_output_directory.as_path()) {
        return Err(SignerError::AssetOutsideOutputDirectory {
            path: canonical_path.to_path_buf(),
            output: context.normalized_output_directory.clone(),
        });
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_asset_for_hashing(
    _context: &OutputDirectoryContext,
    canonical_path: &Path,
) -> Result<File, SignerError> {
    Err(SignerError::UnsupportedSecureAssetOpen {
        path: canonical_path.to_path_buf(),
    })
}

#[cfg(windows)]
fn open_windows_asset_directory(path: &Path) -> Result<File, SignerError> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows::{
        Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
                FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                FILE_SHARE_WRITE, GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL,
            },
        },
        core::PCWSTR,
    };

    let wide = wide_terminated(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            (FILE_READ_ATTRIBUTES | READ_CONTROL).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|source| SignerError::OpenAssetDirectory {
        path: path.to_path_buf(),
        source: io::Error::other(source),
    })?;
    let directory = unsafe {
        // SAFETY: `CreateFileW` returned a fresh handle owned by this File.
        File::from_raw_handle(handle.0)
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(directory.as_raw_handle()), &mut information) }
        .map_err(|source| SignerError::OpenAssetDirectory {
            path: path.to_path_buf(),
            source: io::Error::other(source),
        })?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(SignerError::UnsafeDirectory {
            kind: "output",
            path: path.to_path_buf(),
        });
    }
    Ok(directory)
}

#[cfg(windows)]
fn open_windows_asset_file(path: &Path) -> Result<File, SignerError> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows::{
        Win32::{
            Foundation::{GENERIC_READ, HANDLE},
            Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
                FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
                GetFileInformationByHandle, GetFileType, OPEN_EXISTING,
            },
        },
        core::PCWSTR,
    };

    let wide = wide_terminated(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|source| SignerError::OpenAsset {
        path: path.to_path_buf(),
        source: io::Error::other(source),
    })?;
    let file = unsafe {
        // SAFETY: `CreateFileW` returned a fresh handle owned by this File.
        File::from_raw_handle(handle.0)
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }.map_err(
        |source| SignerError::InspectAsset {
            path: path.to_path_buf(),
            source: io::Error::other(source),
        },
    )?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || unsafe { GetFileType(HANDLE(file.as_raw_handle())) } != FILE_TYPE_DISK
    {
        return Err(SignerError::AssetNotRegular {
            path: path.to_path_buf(),
        });
    }
    Ok(file)
}

#[cfg(windows)]
fn normalized_windows_final_path(file: &File) -> io::Result<PathBuf> {
    use std::{
        ffi::OsString,
        os::windows::{ffi::OsStringExt, io::AsRawHandle},
    };
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW},
    };

    let mut buffer = vec![0_u16; 260];
    loop {
        let length = unsafe {
            GetFinalPathNameByHandleW(
                HANDLE(file.as_raw_handle()),
                &mut buffer,
                FILE_NAME_NORMALIZED,
            )
        } as usize;
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        if length < buffer.len() {
            return Ok(PathBuf::from(OsString::from_wide(&buffer[..length])));
        }
        buffer.resize(length + 1, 0);
    }
}

#[cfg(windows)]
fn opened_asset_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
}

#[cfg(not(windows))]
fn opened_asset_is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
fn publish_release_metadata(
    output_directory: &Path,
    manifest: &[u8],
    signature: &[u8],
) -> Result<(), SignerError> {
    let output_context = open_output_directory_context_from_canonical(output_directory)?;
    publish_release_metadata_in_context(&output_context, manifest, signature)
}

#[cfg(unix)]
fn publish_release_metadata_in_context(
    output_context: &OutputDirectoryContext,
    manifest: &[u8],
    signature: &[u8],
) -> Result<(), SignerError> {
    publish_release_metadata_unix(output_context, manifest, signature)
}

#[cfg(windows)]
fn publish_release_metadata_in_context(
    output_context: &OutputDirectoryContext,
    manifest: &[u8],
    signature: &[u8],
) -> Result<(), SignerError> {
    publish_release_metadata_at_path(
        &output_context.normalized_output_directory,
        manifest,
        signature,
    )
}

#[cfg(not(any(unix, windows)))]
fn publish_release_metadata_in_context(
    output_context: &OutputDirectoryContext,
    _manifest: &[u8],
    _signature: &[u8],
) -> Result<(), SignerError> {
    Err(SignerError::UnsupportedSecureAssetOpen {
        path: output_context.canonical_output_directory.clone(),
    })
}

#[cfg(windows)]
fn publish_release_metadata_at_path(
    output_directory: &Path,
    manifest: &[u8],
    signature: &[u8],
) -> Result<(), SignerError> {
    let metadata_directory = output_directory.join(RELEASE_METADATA_DIRECTORY_NAME);
    ensure_release_metadata_destination_is_absent(&metadata_directory)?;
    let staging_directory = create_release_metadata_staging_directory(output_directory)?;
    let mut staging_directory_exists = true;
    let result = (|| {
        write_staged_release_metadata_file(
            &staging_directory,
            RELEASE_MANIFEST_FILE_NAME,
            manifest,
        )?;
        write_staged_release_metadata_file(
            &staging_directory,
            RELEASE_MANIFEST_SIGNATURE_FILE_NAME,
            signature,
        )?;
        sync_directory(&staging_directory).map_err(|source| {
            SignerError::SyncReleaseMetadataStagingDirectory {
                path: staging_directory.clone(),
                source,
            }
        })?;

        rename_staged_release_metadata_no_replace(&staging_directory, &metadata_directory)?;
        staging_directory_exists = false;

        sync_directory(output_directory).map_err(|source| {
            SignerError::SyncPublishedReleaseMetadata {
                path: output_directory.to_path_buf(),
                source,
            }
        })
    })();

    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            if staging_directory_exists {
                remove_release_metadata_staging_directory(&staging_directory)?;
            }
            Err(error)
        }
    }
}

#[cfg(unix)]
struct UnixReleaseMetadataStagingDirectory {
    name: String,
    directory: File,
}

#[cfg(unix)]
fn publish_release_metadata_unix(
    output_context: &OutputDirectoryContext,
    manifest: &[u8],
    signature: &[u8],
) -> Result<(), SignerError> {
    let metadata_directory = output_context
        .canonical_output_directory
        .join(RELEASE_METADATA_DIRECTORY_NAME);
    ensure_unix_release_metadata_destination_is_absent(output_context)?;

    let mut staging_directory = Some(create_unix_release_metadata_staging_directory(
        output_context,
    )?);
    let result = (|| {
        {
            let staging_directory = staging_directory
                .as_ref()
                .expect("release metadata staging directory must exist before publication");
            write_unix_staged_release_metadata_file(
                output_context,
                staging_directory,
                RELEASE_MANIFEST_FILE_NAME,
                manifest,
            )?;
            write_unix_staged_release_metadata_file(
                output_context,
                staging_directory,
                RELEASE_MANIFEST_SIGNATURE_FILE_NAME,
                signature,
            )?;
            staging_directory.directory.sync_all().map_err(|source| {
                SignerError::SyncReleaseMetadataStagingDirectory {
                    path: unix_staging_directory_path(output_context, staging_directory),
                    source,
                }
            })?;

            rename_unix_staged_release_metadata_no_replace(output_context, staging_directory)
                .map_err(|source| {
                    map_atomic_rename_error(
                        &unix_staging_directory_path(output_context, staging_directory),
                        &metadata_directory,
                        source,
                    )
                })?;
        }

        staging_directory = None;
        output_context
            .output_directory
            .sync_all()
            .map_err(|source| SignerError::SyncPublishedReleaseMetadata {
                path: output_context.canonical_output_directory.clone(),
                source,
            })
    })();

    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            if let Some(staging_directory) = staging_directory {
                remove_unix_release_metadata_staging_directory(output_context, staging_directory)?;
            }
            Err(error)
        }
    }
}

#[cfg(unix)]
fn ensure_unix_release_metadata_destination_is_absent(
    output_context: &OutputDirectoryContext,
) -> Result<(), SignerError> {
    use std::{mem::MaybeUninit, os::fd::AsRawFd};

    let metadata_directory = unix_name_as_c_string(RELEASE_METADATA_DIRECTORY_NAME);
    let mut metadata = MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            output_context.output_directory.as_raw_fd(),
            metadata_directory.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Err(SignerError::ReleaseMetadataAlreadyExists {
            path: output_context
                .canonical_output_directory
                .join(RELEASE_METADATA_DIRECTORY_NAME),
        });
    }

    let source = io::Error::last_os_error();
    if source.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(SignerError::InspectReleaseMetadataDestination {
            path: output_context
                .canonical_output_directory
                .join(RELEASE_METADATA_DIRECTORY_NAME),
            source,
        })
    }
}

#[cfg(unix)]
fn create_unix_release_metadata_staging_directory(
    output_context: &OutputDirectoryContext,
) -> Result<UnixReleaseMetadataStagingDirectory, SignerError> {
    use std::os::fd::{AsRawFd, FromRawFd};

    for _ in 0..STAGING_DIRECTORY_ATTEMPTS {
        let name = format!(".{RELEASE_METADATA_DIRECTORY_NAME}.{}.tmp", Uuid::new_v4());
        let name_as_c_string = unix_name_as_c_string(&name);
        let result = unsafe {
            libc::mkdirat(
                output_context.output_directory.as_raw_fd(),
                name_as_c_string.as_ptr(),
                0o700,
            )
        };
        if result != 0 {
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(SignerError::CreateReleaseMetadataStagingDirectory {
                path: output_context.canonical_output_directory.join(name),
                source,
            });
        }

        let directory_fd = unsafe {
            libc::openat(
                output_context.output_directory.as_raw_fd(),
                name_as_c_string.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        if directory_fd < 0 {
            let source = io::Error::last_os_error();
            let _ = unsafe {
                libc::unlinkat(
                    output_context.output_directory.as_raw_fd(),
                    name_as_c_string.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            };
            return Err(SignerError::CreateReleaseMetadataStagingDirectory {
                path: output_context.canonical_output_directory.join(name),
                source,
            });
        }
        let directory = unsafe {
            // SAFETY: `openat` returned a fresh owned file descriptor.
            File::from_raw_fd(directory_fd)
        };
        return Ok(UnixReleaseMetadataStagingDirectory { name, directory });
    }

    Err(SignerError::ReleaseMetadataStagingNameExhausted {
        directory: output_context.canonical_output_directory.clone(),
    })
}

#[cfg(unix)]
fn write_unix_staged_release_metadata_file(
    output_context: &OutputDirectoryContext,
    staging_directory: &UnixReleaseMetadataStagingDirectory,
    file_name: &str,
    contents: &[u8],
) -> Result<(), SignerError> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let file_name_as_c_string = unix_name_as_c_string(file_name);
    let path = unix_staging_directory_path(output_context, staging_directory).join(file_name);
    let fd = unsafe {
        libc::openat(
            staging_directory.directory.as_raw_fd(),
            file_name_as_c_string.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(SignerError::CreateStagedReleaseMetadataFile {
            path,
            source: io::Error::last_os_error(),
        });
    }
    let mut file = unsafe {
        // SAFETY: `openat` returned a fresh owned file descriptor.
        File::from_raw_fd(fd)
    };
    file.write_all(contents)
        .map_err(|source| SignerError::WriteStagedReleaseMetadataFile {
            path: path.clone(),
            source,
        })?;
    file.sync_all()
        .map_err(|source| SignerError::SyncStagedReleaseMetadataFile { path, source })
}

#[cfg(unix)]
fn rename_unix_staged_release_metadata_no_replace(
    output_context: &OutputDirectoryContext,
    staging_directory: &UnixReleaseMetadataStagingDirectory,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let staging_directory = unix_name_as_c_string(&staging_directory.name);
    let metadata_directory = unix_name_as_c_string(RELEASE_METADATA_DIRECTORY_NAME);
    atomic_rename_directory_no_replace_at(
        output_context.output_directory.as_raw_fd(),
        &staging_directory,
        &metadata_directory,
    )
}

#[cfg(unix)]
fn remove_unix_release_metadata_staging_directory(
    output_context: &OutputDirectoryContext,
    staging_directory: UnixReleaseMetadataStagingDirectory,
) -> Result<(), SignerError> {
    use std::os::fd::AsRawFd;

    let path = unix_staging_directory_path(output_context, &staging_directory);
    for file_name in [
        RELEASE_MANIFEST_FILE_NAME,
        RELEASE_MANIFEST_SIGNATURE_FILE_NAME,
    ] {
        let file_name = unix_name_as_c_string(file_name);
        let result = unsafe {
            libc::unlinkat(
                staging_directory.directory.as_raw_fd(),
                file_name.as_ptr(),
                0,
            )
        };
        if result != 0 {
            let source = io::Error::last_os_error();
            if source.kind() != io::ErrorKind::NotFound {
                return Err(SignerError::RemoveReleaseMetadataStagingDirectory { path, source });
            }
        }
    }

    let name = unix_name_as_c_string(&staging_directory.name);
    drop(staging_directory.directory);
    let result = unsafe {
        libc::unlinkat(
            output_context.output_directory.as_raw_fd(),
            name.as_ptr(),
            libc::AT_REMOVEDIR,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(SignerError::RemoveReleaseMetadataStagingDirectory { path, source })
        }
    }
}

#[cfg(unix)]
fn unix_staging_directory_path(
    output_context: &OutputDirectoryContext,
    staging_directory: &UnixReleaseMetadataStagingDirectory,
) -> PathBuf {
    output_context
        .canonical_output_directory
        .join(&staging_directory.name)
}

#[cfg(unix)]
fn unix_name_as_c_string(name: &str) -> std::ffi::CString {
    std::ffi::CString::new(name).expect("release metadata names must not contain NUL bytes")
}

#[cfg(target_os = "linux")]
fn atomic_rename_directory_no_replace_at(
    output_directory_fd: std::os::fd::RawFd,
    staging_directory: &std::ffi::CString,
    metadata_directory: &std::ffi::CString,
) -> io::Result<()> {
    let result = unsafe {
        libc::renameat2(
            output_directory_fd,
            staging_directory.as_ptr(),
            output_directory_fd,
            metadata_directory.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn atomic_rename_directory_no_replace_at(
    output_directory_fd: std::os::fd::RawFd,
    staging_directory: &std::ffi::CString,
    metadata_directory: &std::ffi::CString,
) -> io::Result<()> {
    let result = unsafe {
        libc::renameatx_np(
            output_directory_fd,
            staging_directory.as_ptr(),
            output_directory_fd,
            metadata_directory.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn atomic_rename_directory_no_replace_at(
    _output_directory_fd: std::os::fd::RawFd,
    _staging_directory: &std::ffi::CString,
    _metadata_directory: &std::ffi::CString,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace directory rename is unavailable on this platform",
    ))
}

#[cfg(windows)]
fn ensure_release_metadata_destination_is_absent(path: &Path) -> Result<(), SignerError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(SignerError::ReleaseMetadataAlreadyExists {
            path: path.to_path_buf(),
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SignerError::InspectReleaseMetadataDestination {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(windows)]
fn rename_staged_release_metadata_no_replace(
    staging_directory: &Path,
    metadata_directory: &Path,
) -> Result<(), SignerError> {
    atomic_rename_directory_no_replace(staging_directory, metadata_directory)
        .map_err(|source| map_atomic_rename_error(staging_directory, metadata_directory, source))
}

fn map_atomic_rename_error(
    staging_directory: &Path,
    metadata_directory: &Path,
    source: io::Error,
) -> SignerError {
    match source.kind() {
        io::ErrorKind::AlreadyExists => SignerError::ReleaseMetadataAlreadyExists {
            path: metadata_directory.to_path_buf(),
        },
        io::ErrorKind::Unsupported => SignerError::UnsupportedAtomicNoReplaceRename {
            staging: staging_directory.to_path_buf(),
            output: metadata_directory.to_path_buf(),
        },
        _ => SignerError::PublishReleaseMetadata {
            staging: staging_directory.to_path_buf(),
            output: metadata_directory.to_path_buf(),
            source,
        },
    }
}

#[cfg(windows)]
fn create_release_metadata_staging_directory(
    output_directory: &Path,
) -> Result<PathBuf, SignerError> {
    for _ in 0..STAGING_DIRECTORY_ATTEMPTS {
        let staging_directory = output_directory.join(format!(
            ".{RELEASE_METADATA_DIRECTORY_NAME}.{}.tmp",
            Uuid::new_v4()
        ));
        match fs::create_dir(&staging_directory) {
            Ok(()) => return Ok(staging_directory),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(SignerError::CreateReleaseMetadataStagingDirectory {
                    path: staging_directory,
                    source,
                });
            }
        }
    }

    Err(SignerError::ReleaseMetadataStagingNameExhausted {
        directory: output_directory.to_path_buf(),
    })
}

#[cfg(windows)]
fn write_staged_release_metadata_file(
    staging_directory: &Path,
    file_name: &str,
    contents: &[u8],
) -> Result<(), SignerError> {
    let path = staging_directory.join(file_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|source| SignerError::CreateStagedReleaseMetadataFile {
            path: path.clone(),
            source,
        })?;
    file.write_all(contents)
        .map_err(|source| SignerError::WriteStagedReleaseMetadataFile {
            path: path.clone(),
            source,
        })?;
    file.sync_all()
        .map_err(|source| SignerError::SyncStagedReleaseMetadataFile { path, source })
}

#[cfg(windows)]
fn remove_release_metadata_staging_directory(path: &Path) -> Result<(), SignerError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SignerError::RemoveReleaseMetadataStagingDirectory {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(unix)]
fn path_as_c_string(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "release metadata path contains a NUL byte",
        )
    })
}

#[cfg(windows)]
fn atomic_rename_directory_no_replace(
    staging_directory: &Path,
    metadata_directory: &Path,
) -> io::Result<()> {
    use windows::{
        Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW},
        core::PCWSTR,
    };

    let staging_directory = wide_terminated(staging_directory);
    let metadata_directory = wide_terminated(metadata_directory);
    unsafe {
        MoveFileExW(
            PCWSTR(staging_directory.as_ptr()),
            PCWSTR(metadata_directory.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )
        .map_err(windows_error_to_io_error)
    }
}

#[cfg(windows)]
fn windows_error_to_io_error(source: windows::core::Error) -> io::Error {
    let code = source.code().0 as u32;
    if code & 0xffff_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((code & 0xffff) as i32)
    } else {
        io::Error::other(source)
    }
}

#[cfg(windows)]
fn wide_terminated(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
fn sync_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

#[derive(Debug, Error)]
enum SignerError {
    #[error("key generation writes secret material only with `keygen --stdout`")]
    KeygenRequiresStdout,
    #[error("failed to write explicitly requested key-generation output: {source}")]
    WriteKeygenOutput {
        #[source]
        source: io::Error,
    },
    #[error(
        "environment variable {SIGNING_KEY_ENVIRONMENT_VARIABLE} is required to sign a release"
    )]
    MissingSigningKey,
    #[error(
        "environment variable {SIGNING_KEY_ENVIRONMENT_VARIABLE} must be base64 for exactly one 32-byte Ed25519 seed"
    )]
    InvalidSigningKey,
    #[error(
        "environment variable {SIGNING_KEY_ENVIRONMENT_VARIABLE} does not derive the public key compiled into rqbit-tunnel clients"
    )]
    SigningKeyDoesNotMatchPinnedPublicKey,
    #[error("failed to inspect {kind} directory {path}: {source}")]
    InspectDirectory {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{kind} directory {path} must be a real, non-symlink directory")]
    UnsafeDirectory { kind: &'static str, path: PathBuf },
    #[error("failed to canonicalize output directory {path}: {source}")]
    CanonicalizeOutputDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to securely open output directory {path} for release assets: {source}")]
    OpenAssetDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to inspect release asset {path}: {source}")]
    InspectAsset {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to canonicalize release asset {path}: {source}")]
    CanonicalizeAsset {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("release asset {path} must be a regular, non-symlink file")]
    AssetNotRegular { path: PathBuf },
    #[error("release asset {path} must resolve to a direct child of output directory {output}")]
    AssetOutsideOutputDirectory { path: PathBuf, output: PathBuf },
    #[error("release asset file name is not valid UTF-8: {path}")]
    AssetNameNotUtf8 { path: PathBuf },
    #[error("release asset archive filename {archive:?} is reserved for manifest metadata")]
    ReservedAssetName { archive: String },
    #[error("release asset {path} was specified more than once")]
    DuplicateAssetPath { path: PathBuf },
    #[error("multiple release assets share archive filename {archive:?}")]
    DuplicateArchiveName { archive: String },
    #[error("failed to open release asset {path}: {source}")]
    OpenAsset {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[cfg(not(any(unix, windows)))]
    #[error("platform cannot securely open release asset within output directory {path}")]
    UnsupportedSecureAssetOpen { path: PathBuf },
    #[error("failed to read release asset {path}: {source}")]
    ReadAsset {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("release asset {path} has byte length {bytes}; expected 1..={MAX_RELEASE_ASSET_BYTES}")]
    InvalidAssetBytes { path: PathBuf, bytes: u64 },
    #[error("release asset {path} changed while it was being hashed")]
    AssetChanged { path: PathBuf },
    #[error("failed to encode release manifest JSON: {source}")]
    EncodeManifest {
        #[source]
        source: serde_json::Error,
    },
    #[error("release metadata destination {path} already exists and will not be replaced")]
    ReleaseMetadataAlreadyExists { path: PathBuf },
    #[error("failed to inspect release metadata destination {path}: {source}")]
    InspectReleaseMetadataDestination {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create release metadata staging directory {path}: {source}")]
    CreateReleaseMetadataStagingDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not allocate a unique release metadata staging directory in {directory}")]
    ReleaseMetadataStagingNameExhausted { directory: PathBuf },
    #[error("failed to create staged release metadata file {path}: {source}")]
    CreateStagedReleaseMetadataFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write staged release metadata file {path}: {source}")]
    WriteStagedReleaseMetadataFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to sync staged release metadata file {path}: {source}")]
    SyncStagedReleaseMetadataFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to sync staged release metadata directory {path}: {source}")]
    SyncReleaseMetadataStagingDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to atomically publish staged release metadata {staging} to {output}: {source}")]
    PublishReleaseMetadata {
        staging: PathBuf,
        output: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "platform cannot atomically publish staged release metadata {staging} without replacing {output}"
    )]
    UnsupportedAtomicNoReplaceRename { staging: PathBuf, output: PathBuf },
    #[error("release metadata was published but syncing output directory {path} failed: {source}")]
    SyncPublishedReleaseMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to remove release metadata staging directory {path}: {source}")]
    RemoveReleaseMetadataStagingDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Update(#[from] UpdateError),
}

#[cfg(test)]
mod tests {
    use std::{fs, io, path::PathBuf};

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use rqbit_tunnel::update::manifest::{
        RELEASE_MANIFEST_FILE_NAME, RELEASE_MANIFEST_SCHEMA_VERSION,
        RELEASE_MANIFEST_SIGNATURE_FILE_NAME, ReleaseManifest, UpdateError, verify_manifest,
    };

    use super::{
        AssetArgument, Command, SignerError, collect_release_assets, map_atomic_rename_error,
        parse_cli, publish_release_metadata, validate_signing_key_matches_verifying_key,
        validate_unique_asset_targets,
    };
    #[cfg(unix)]
    use super::{
        hash_asset, open_asset_context, open_asset_for_hashing,
        open_output_directory_context_from_canonical, publish_release_metadata_in_context,
        validate_release_asset_path,
    };
    use clap::error::ErrorKind;
    use ed25519_dalek::{Signer, SigningKey};
    use semver::Version;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::{
        create_unix_release_metadata_staging_directory,
        remove_unix_release_metadata_staging_directory,
        rename_unix_staged_release_metadata_no_replace,
    };

    #[test]
    fn builder_parser_collects_repeatable_sign_assets() {
        let cli = parse_cli([
            "rqbit-tunnel-release-sign",
            "sign",
            "--version",
            "1.2.3",
            "--launcher-abi",
            "1",
            "--asset",
            "x86_64-unknown-linux-gnu=dist/linux.tar.gz",
            "--asset",
            "x86_64-pc-windows-msvc=dist/windows.zip",
            "--output",
            "dist",
        ])
        .unwrap();

        match cli.command {
            Command::Sign(arguments) => {
                assert_eq!(arguments.version, "1.2.3");
                assert_eq!(arguments.launcher_abi, 1);
                assert_eq!(arguments.output, PathBuf::from("dist"));
                assert_eq!(arguments.assets.len(), 2);
                assert_eq!(arguments.assets[0].target, "x86_64-unknown-linux-gnu");
                assert_eq!(arguments.assets[1].target, "x86_64-pc-windows-msvc");
            }
            Command::Keygen(_) => panic!("expected sign arguments"),
        }
    }

    #[test]
    fn release_signer_lists_each_target_once() {
        let output = tempfile::tempdir().unwrap();
        let canonical_output = fs::canonicalize(output.path()).unwrap();
        let fixtures = [
            ("x86_64-unknown-linux-gnu", "linux-amd64.tar.gz"),
            ("aarch64-unknown-linux-gnu", "linux-arm64.tar.gz"),
            ("x86_64-pc-windows-msvc", "windows-amd64.zip"),
        ];
        let mut inputs = Vec::with_capacity(fixtures.len());
        for (index, (target, name)) in fixtures.iter().enumerate() {
            let path = canonical_output.join(name);
            fs::write(&path, [index as u8 + 1]).unwrap();
            inputs.push(AssetArgument {
                target: (*target).to_owned(),
                path,
            });
        }

        let manifest = ReleaseManifest {
            schema_version: RELEASE_MANIFEST_SCHEMA_VERSION,
            version: Version::parse("1.2.3").unwrap(),
            launcher_abi: 1,
            assets: collect_release_assets(inputs, &canonical_output).unwrap(),
        };
        let raw = serde_json::to_vec(&manifest).unwrap();
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let signature = BASE64_STANDARD.encode(signing_key.sign(&raw).to_bytes());
        let verified = verify_manifest(&raw, &signature, &signing_key.verifying_key()).unwrap();

        assert_eq!(
            verified
                .assets
                .iter()
                .map(|asset| asset.target.as_str())
                .collect::<Vec<_>>(),
            vec![
                "aarch64-unknown-linux-gnu",
                "x86_64-pc-windows-msvc",
                "x86_64-unknown-linux-gnu",
            ]
        );
    }

    #[test]
    fn builder_parser_handles_keygen_stdout() {
        let cli = parse_cli(["rqbit-tunnel-release-sign", "keygen", "--stdout"]).unwrap();

        match cli.command {
            Command::Keygen(arguments) => assert!(arguments.stdout),
            Command::Sign(_) => panic!("expected keygen arguments"),
        }
    }

    #[test]
    fn builder_parser_returns_help_without_running_a_command() {
        assert_eq!(
            parse_cli(["rqbit-tunnel-release-sign", "--help"])
                .unwrap_err()
                .kind(),
            ErrorKind::DisplayHelp
        );
    }

    #[test]
    fn asset_argument_parses_one_explicit_target_and_path() {
        let asset: AssetArgument = "x86_64-unknown-linux-gnu=dist/release.tar.gz"
            .parse()
            .unwrap();

        assert_eq!(asset.target, "x86_64-unknown-linux-gnu");
        assert_eq!(asset.path, PathBuf::from("dist/release.tar.gz"));
    }

    #[test]
    fn asset_argument_rejects_missing_target_or_path() {
        assert!("release.tar.gz".parse::<AssetArgument>().is_err());
        assert!("=release.tar.gz".parse::<AssetArgument>().is_err());
        assert!(
            "x86_64-unknown-linux-gnu="
                .parse::<AssetArgument>()
                .is_err()
        );
    }

    #[test]
    fn duplicate_asset_targets_are_rejected_before_file_access() {
        let assets = vec![
            AssetArgument {
                target: "x86_64-unknown-linux-gnu".to_owned(),
                path: PathBuf::from("dist/linux.tar.gz"),
            },
            AssetArgument {
                target: "x86_64-unknown-linux-gnu".to_owned(),
                path: PathBuf::from("dist/linux-copy.tar.gz"),
            },
        ];

        assert!(matches!(
            validate_unique_asset_targets(&assets),
            Err(SignerError::Update(
                UpdateError::DuplicateAssetTarget { .. }
            ))
        ));
    }

    #[test]
    fn release_assets_reject_paths_that_are_not_direct_output_children() {
        let output = tempfile::tempdir().unwrap();
        let canonical_output = fs::canonicalize(output.path()).unwrap();
        let nested_directory = canonical_output.join("nested");
        fs::create_dir(&nested_directory).unwrap();
        let nested_asset = nested_directory.join("release.tar.gz");
        fs::write(&nested_asset, b"nested asset").unwrap();

        assert!(matches!(
            collect_release_assets(
                vec![AssetArgument {
                    target: "x86_64-unknown-linux-gnu".to_owned(),
                    path: nested_asset,
                }],
                &canonical_output,
            ),
            Err(SignerError::AssetOutsideOutputDirectory { .. })
        ));

        let packaged_asset = canonical_output.join("release.tar.gz");
        fs::write(&packaged_asset, b"packaged asset").unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_asset = outside.path().join("release.tar.gz");
        fs::write(&outside_asset, b"outside asset").unwrap();

        assert!(matches!(
            collect_release_assets(
                vec![AssetArgument {
                    target: "x86_64-pc-windows-msvc".to_owned(),
                    path: outside_asset,
                }],
                &canonical_output,
            ),
            Err(SignerError::AssetOutsideOutputDirectory { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn asset_hashing_rejects_final_path_replaced_by_symlink_after_validation() {
        use std::os::unix::fs::symlink;

        let output = tempfile::tempdir().unwrap();
        let canonical_output = fs::canonicalize(output.path()).unwrap();
        let asset = canonical_output.join("release.tar.gz");
        fs::write(&asset, b"original asset").unwrap();
        let context = open_asset_context(&canonical_output).unwrap();
        let canonical_asset = validate_release_asset_path(&asset, &canonical_output).unwrap();

        let outside = tempfile::tempdir().unwrap();
        let outside_asset = outside.path().join("release.tar.gz");
        fs::write(&outside_asset, b"unsafe replacement").unwrap();
        fs::remove_file(&asset).unwrap();
        symlink(&outside_asset, &asset).unwrap();

        assert!(matches!(
            open_asset_for_hashing(&context, &canonical_asset),
            Err(SignerError::OpenAsset { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn asset_hashing_uses_held_output_directory_after_parent_is_replaced() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let output = parent.path().join("output");
        fs::create_dir(&output).unwrap();
        let canonical_output = fs::canonicalize(&output).unwrap();
        let asset = canonical_output.join("release.tar.gz");
        fs::write(&asset, b"trusted asset").unwrap();
        let context = open_asset_context(&canonical_output).unwrap();
        let canonical_asset = validate_release_asset_path(&asset, &canonical_output).unwrap();

        let outside = tempfile::tempdir().unwrap();
        fs::write(
            outside.path().join("release.tar.gz"),
            b"unsafe replacement with a different length",
        )
        .unwrap();
        let moved_output = parent.path().join("moved-output");
        fs::rename(&canonical_output, &moved_output).unwrap();
        symlink(outside.path(), &canonical_output).unwrap();

        let file = open_asset_for_hashing(&context, &canonical_asset).unwrap();
        let (bytes, _) = hash_asset(file, &canonical_asset).unwrap();
        assert_eq!(bytes, b"trusted asset".len() as u64);
    }

    #[cfg(unix)]
    #[test]
    fn asset_hashing_rejects_final_fifo_without_blocking() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        let output = tempfile::tempdir().unwrap();
        let canonical_output = fs::canonicalize(output.path()).unwrap();
        let asset = canonical_output.join("release.tar.gz");
        fs::write(&asset, b"regular asset").unwrap();
        let context = open_asset_context(&canonical_output).unwrap();
        let canonical_asset = validate_release_asset_path(&asset, &canonical_output).unwrap();
        fs::remove_file(&asset).unwrap();
        let asset_bytes = CString::new(asset.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(asset_bytes.as_ptr(), 0o600) }, 0);

        let file = open_asset_for_hashing(&context, &canonical_asset).unwrap();
        assert!(matches!(
            hash_asset(file, &canonical_asset),
            Err(SignerError::AssetNotRegular { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn metadata_publication_uses_held_output_directory_after_parent_is_replaced() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let output = parent.path().join("output");
        fs::create_dir(&output).unwrap();
        let canonical_output = fs::canonicalize(&output).unwrap();
        let context = open_output_directory_context_from_canonical(&canonical_output).unwrap();

        let outside = tempfile::tempdir().unwrap();
        let moved_output = parent.path().join("moved-output");
        fs::rename(&canonical_output, &moved_output).unwrap();
        symlink(outside.path(), &canonical_output).unwrap();

        publish_release_metadata_in_context(&context, b"manifest", b"signature").unwrap();

        let metadata = moved_output.join("release-metadata");
        assert_eq!(
            fs::read(metadata.join(RELEASE_MANIFEST_FILE_NAME)).unwrap(),
            b"manifest"
        );
        assert_eq!(
            fs::read(metadata.join(RELEASE_MANIFEST_SIGNATURE_FILE_NAME)).unwrap(),
            b"signature"
        );
        assert!(!outside.path().join("release-metadata").exists());
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn release_metadata_publication_uses_one_nested_directory() {
        let output = tempfile::tempdir().unwrap();

        publish_release_metadata(output.path(), b"manifest", b"signature").unwrap();

        let metadata = output.path().join("release-metadata");
        assert_eq!(
            fs::read(metadata.join(RELEASE_MANIFEST_FILE_NAME)).unwrap(),
            b"manifest"
        );
        assert_eq!(
            fs::read(metadata.join(RELEASE_MANIFEST_SIGNATURE_FILE_NAME)).unwrap(),
            b"signature"
        );
        assert!(!output.path().join(RELEASE_MANIFEST_FILE_NAME).exists());
        assert!(
            !output
                .path()
                .join(RELEASE_MANIFEST_SIGNATURE_FILE_NAME)
                .exists()
        );
        assert_eq!(fs::read_dir(output.path()).unwrap().count(), 1);
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    #[test]
    fn release_metadata_publication_reports_unsupported_atomic_rename() {
        let output = tempfile::tempdir().unwrap();

        assert!(matches!(
            publish_release_metadata(output.path(), b"manifest", b"signature"),
            Err(SignerError::UnsupportedAtomicNoReplaceRename { .. })
        ));
        assert!(!output.path().join("release-metadata").exists());
        assert_eq!(fs::read_dir(output.path()).unwrap().count(), 0);
    }

    #[test]
    fn release_metadata_publication_never_overwrites_existing_metadata() {
        let output = tempfile::tempdir().unwrap();
        let metadata = output.path().join("release-metadata");
        fs::create_dir(&metadata).unwrap();
        fs::write(metadata.join("sentinel"), b"keep").unwrap();

        assert!(matches!(
            publish_release_metadata(output.path(), b"manifest", b"signature"),
            Err(SignerError::ReleaseMetadataAlreadyExists { .. })
        ));

        assert_eq!(fs::read(metadata.join("sentinel")).unwrap(), b"keep");
        assert_eq!(fs::read_dir(output.path()).unwrap().count(), 1);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn no_replace_metadata_rename_preserves_a_concurrent_destination() {
        let output = tempfile::tempdir().unwrap();
        let canonical_output = fs::canonicalize(output.path()).unwrap();
        let context = open_output_directory_context_from_canonical(&canonical_output).unwrap();
        let staging = create_unix_release_metadata_staging_directory(&context).unwrap();
        let staging_path = canonical_output.join(&staging.name);
        fs::write(
            staging_path.join(RELEASE_MANIFEST_FILE_NAME),
            b"staged manifest",
        )
        .unwrap();

        let metadata = canonical_output.join("release-metadata");
        fs::create_dir(&metadata).unwrap();

        let source =
            rename_unix_staged_release_metadata_no_replace(&context, &staging).unwrap_err();
        assert!(matches!(
            map_atomic_rename_error(&staging_path, &metadata, source),
            SignerError::ReleaseMetadataAlreadyExists { .. }
        ));
        assert!(metadata.is_dir());
        assert_eq!(fs::read_dir(&metadata).unwrap().count(), 0);
        assert_eq!(
            fs::read(staging_path.join(RELEASE_MANIFEST_FILE_NAME)).unwrap(),
            b"staged manifest"
        );
        remove_unix_release_metadata_staging_directory(&context, staging).unwrap();
    }

    #[test]
    fn unsupported_atomic_rename_error_is_typed() {
        let staging = PathBuf::from("staging");
        let metadata = PathBuf::from("release-metadata");

        assert!(matches!(
            map_atomic_rename_error(
                &staging,
                &metadata,
                io::Error::new(io::ErrorKind::Unsupported, "unsupported"),
            ),
            SignerError::UnsupportedAtomicNoReplaceRename { .. }
        ));
    }

    #[test]
    fn signing_key_must_match_the_expected_verifying_key() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let different_key = SigningKey::from_bytes(&[9; 32]);

        assert!(
            validate_signing_key_matches_verifying_key(&signing_key, &signing_key.verifying_key(),)
                .is_ok()
        );
        assert!(matches!(
            validate_signing_key_matches_verifying_key(
                &signing_key,
                &different_key.verifying_key(),
            ),
            Err(SignerError::SigningKeyDoesNotMatchPinnedPublicKey)
        ));
    }

    #[test]
    fn reserved_manifest_metadata_assets_are_rejected_before_hashing() {
        let output = tempfile::tempdir().unwrap();
        let canonical_output = fs::canonicalize(output.path()).unwrap();

        for file_name in [
            RELEASE_MANIFEST_FILE_NAME,
            RELEASE_MANIFEST_SIGNATURE_FILE_NAME,
        ] {
            let reserved = canonical_output.join(file_name);
            fs::write(&reserved, b"asset").unwrap();

            assert!(matches!(
                collect_release_assets(
                    vec![AssetArgument {
                        target: "x86_64-unknown-linux-gnu".to_owned(),
                        path: reserved,
                    }],
                    &canonical_output,
                ),
                Err(SignerError::ReservedAssetName { .. })
            ));
        }
    }

    #[test]
    fn reserved_asset_basenames_are_rejected_case_insensitively() {
        let output = tempfile::tempdir().unwrap();
        let canonical_output = fs::canonicalize(output.path()).unwrap();

        for archive in ["RELEASE-MANIFEST.JSON", "RELEASE-MANIFEST.SIG"] {
            let asset = canonical_output.join(archive);
            fs::write(&asset, b"asset").unwrap();

            assert!(matches!(
                collect_release_assets(
                    vec![AssetArgument {
                        target: "x86_64-unknown-linux-gnu".to_owned(),
                        path: asset,
                    }],
                    &canonical_output,
                ),
                Err(SignerError::ReservedAssetName { .. })
            ));
        }
    }
}
