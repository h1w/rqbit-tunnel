use std::{collections::HashMap, io::Write, time::Duration};

use semver::Version;
use serde::Deserialize;

use crate::update::manifest::{
    RELEASE_MANIFEST_FILE_NAME, RELEASE_MANIFEST_SIGNATURE_FILE_NAME, UpdateError,
};

const GITHUB_RELEASES_ENDPOINT: &str = "https://api.github.com/repos/h1w/rqbit-tunnel/releases";
const GITHUB_RELEASES_PER_PAGE: usize = 100;
const MAX_GITHUB_RELEASE_PAGES: usize = 10;
const TUNNEL_RELEASE_TAG_PREFIX: &str = "tunnel-v";
const GITHUB_RELEASE_USER_AGENT: &str = concat!("rqbit-tunnel/", env!("CARGO_PKG_VERSION"));
const MAX_GITHUB_RELEASE_ASSET_REDIRECTS: usize = 5;

/// The authenticated URLs advertised by a published GitHub release.
#[derive(Clone, Debug)]
pub struct ReleaseAssetUrls {
    urls: HashMap<String, reqwest::Url>,
}

impl ReleaseAssetUrls {
    /// Returns the URL GitHub advertised for an exact release asset name.
    pub fn url_for(&self, name: &str) -> Result<&reqwest::Url, UpdateError> {
        self.urls
            .get(name)
            .ok_or_else(|| UpdateError::MissingGithubReleaseAsset {
                name: name.to_owned(),
            })
    }
}

/// One immutable GitHub release selection and its validated asset URLs.
#[derive(Clone, Debug)]
pub(crate) struct SelectedGithubRelease {
    pub(crate) version: Version,
    pub(crate) assets: ReleaseAssetUrls,
}

type ReleaseAssetUrlParser = fn(&str, String) -> Result<reqwest::Url, UpdateError>;

/// Retrieves and selects the newest eligible rqbit-tunnel release from GitHub.
pub struct GitHubReleaseClient {
    metadata_client: reqwest::Client,
    asset_client: reqwest::Client,
    releases_url: reqwest::Url,
    parse_asset_url: ReleaseAssetUrlParser,
}

impl GitHubReleaseClient {
    /// Builds a client pinned to rqbit-tunnel's official releases endpoint.
    pub fn new() -> Result<Self, UpdateError> {
        let releases_url = reqwest::Url::parse(GITHUB_RELEASES_ENDPOINT)
            .expect("the fixed GitHub releases endpoint must be a valid URL");
        Self::with_releases_url(releases_url)
    }

    /// Builds a production client whose metadata URL uses GitHub's official API origin.
    pub fn with_releases_url(releases_url: reqwest::Url) -> Result<Self, UpdateError> {
        validate_github_releases_url(&releases_url)?;
        Self::with_urls(
            releases_url,
            parse_github_release_asset_url,
            is_safe_github_release_asset_redirect,
        )
    }

    #[cfg(test)]
    fn with_test_urls(releases_url: reqwest::Url) -> Result<Self, UpdateError> {
        validate_test_github_releases_url(&releases_url)?;
        Self::with_urls(
            releases_url,
            parse_test_github_release_asset_url,
            is_safe_test_github_release_asset_url,
        )
    }

    fn with_urls(
        releases_url: reqwest::Url,
        parse_asset_url: ReleaseAssetUrlParser,
        is_safe_asset_redirect: fn(&reqwest::Url) -> bool,
    ) -> Result<Self, UpdateError> {
        let metadata_client = build_github_release_client(reqwest::redirect::Policy::none())?;
        let asset_client = build_release_asset_client(is_safe_asset_redirect)?;

        Ok(Self {
            metadata_client,
            asset_client,
            releases_url,
            parse_asset_url,
        })
    }

    /// Fetches the newest published stable rqbit-tunnel release and its asset metadata.
    pub(crate) async fn fetch_selected_release(
        &self,
    ) -> Result<SelectedGithubRelease, UpdateError> {
        let mut newest_release = None;

        for page in 1..=MAX_GITHUB_RELEASE_PAGES {
            let releases = self.fetch_releases_page(page).await?;
            let release_count = releases.len();

            for release in releases {
                let Some(version) = parse_tunnel_release_tag(&release.tag_name) else {
                    continue;
                };
                if release.draft || release.prerelease {
                    continue;
                }

                let is_newest = match newest_release.as_ref() {
                    Some((newest_version, _)) => version.cmp(newest_version).is_gt(),
                    None => true,
                };
                if is_newest {
                    newest_release = Some((version, release));
                }
            }

            if release_count < GITHUB_RELEASES_PER_PAGE {
                let (version, release) =
                    newest_release.ok_or(UpdateError::NoEligibleGithubRelease)?;
                let assets =
                    parse_release_assets_with_url_parser(release.assets, self.parse_asset_url)?;
                return Ok(SelectedGithubRelease { version, assets });
            }
        }

        Err(UpdateError::GithubReleasePaginationLimit {
            limit: MAX_GITHUB_RELEASE_PAGES,
        })
    }

    /// Fetches only the asset URLs from one immutable selected release.
    pub async fn fetch_release_assets(&self) -> Result<ReleaseAssetUrls, UpdateError> {
        Ok(self.fetch_selected_release().await?.assets)
    }

    async fn fetch_releases_page(&self, page: usize) -> Result<Vec<GithubRelease>, UpdateError> {
        let mut url = self.releases_url.clone();
        url.query_pairs_mut()
            .clear()
            .append_pair("per_page", &GITHUB_RELEASES_PER_PAGE.to_string())
            .append_pair("page", &page.to_string());

        let response = self
            .metadata_client
            .get(url)
            .send()
            .await
            .map_err(|source| UpdateError::RequestGithubReleases { source })?;

        if !response.status().is_success() {
            return Err(UpdateError::UnexpectedGithubReleasesStatus {
                status: response.status(),
            });
        }

        let raw = response
            .bytes()
            .await
            .map_err(|source| UpdateError::ReadGithubReleasesResponse { source })?;
        serde_json::from_slice(&raw)
            .map_err(|source| UpdateError::InvalidGithubReleaseJson { source })
    }

    /// Streams one exact asset from a previously selected release into the supplied writer.
    ///
    /// The caller owns byte-count and digest verification, so partial downloads
    /// are never actionable.
    pub(crate) async fn download_selected_release_asset_to(
        &self,
        assets: &ReleaseAssetUrls,
        name: &str,
        output: &mut (dyn Write + Send),
    ) -> Result<(), UpdateError> {
        let url = assets.url_for(name)?.clone();
        let response = self.asset_client.get(url).send().await.map_err(|source| {
            UpdateError::RequestGithubReleaseAsset {
                name: name.to_owned(),
                source,
            }
        })?;

        if !response.status().is_success() {
            return Err(UpdateError::UnexpectedGithubReleaseAssetStatus {
                name: name.to_owned(),
                status: response.status(),
            });
        }

        let mut response = response;
        while let Some(chunk) =
            response
                .chunk()
                .await
                .map_err(|source| UpdateError::ReadGithubReleaseAsset {
                    name: name.to_owned(),
                    source,
                })?
        {
            output.write_all(&chunk).map_err(|source| {
                UpdateError::WriteDownloadedReleaseAsset {
                    asset: name.to_owned(),
                    source,
                }
            })?;
        }

        Ok(())
    }
}

fn build_github_release_client(
    redirect: reqwest::redirect::Policy,
) -> Result<reqwest::Client, UpdateError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(GITHUB_RELEASE_USER_AGENT)
        .redirect(redirect)
        .build()
        .map_err(|source| UpdateError::BuildGithubReleaseClient { source })
}

fn build_release_asset_client<F>(is_safe_redirect: F) -> Result<reqwest::Client, UpdateError>
where
    F: Fn(&reqwest::Url) -> bool + Send + Sync + 'static,
{
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(30))
        .user_agent(GITHUB_RELEASE_USER_AGENT)
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= MAX_GITHUB_RELEASE_ASSET_REDIRECTS {
                attempt.error("too many GitHub release asset redirects")
            } else if is_safe_redirect(attempt.url()) {
                attempt.follow()
            } else {
                attempt.error("unsafe GitHub release asset redirect")
            }
        }))
        .build()
        .map_err(|source| UpdateError::BuildGithubReleaseClient { source })
}

fn validate_github_releases_url(url: &reqwest::Url) -> Result<(), UpdateError> {
    if url.scheme() != "https" {
        return Err(unsafe_github_releases_url(url, "scheme must be HTTPS"));
    }
    if url.host_str() != Some("api.github.com") {
        return Err(unsafe_github_releases_url(
            url,
            "host must be api.github.com",
        ));
    }
    if has_url_credentials(url, url.as_str()) {
        return Err(unsafe_github_releases_url(
            url,
            "credentials are not allowed",
        ));
    }
    if url.port().is_some_and(|port| port != 443) {
        return Err(unsafe_github_releases_url(
            url,
            "port must be the HTTPS default",
        ));
    }
    if url.query().is_some() {
        return Err(unsafe_github_releases_url(url, "query is not allowed"));
    }
    if url.fragment().is_some() {
        return Err(unsafe_github_releases_url(url, "fragment is not allowed"));
    }
    Ok(())
}

#[cfg(test)]
fn validate_test_github_releases_url(url: &reqwest::Url) -> Result<(), UpdateError> {
    if is_safe_test_github_release_asset_url(url) {
        Ok(())
    } else {
        Err(unsafe_github_releases_url(
            url,
            "test URLs must use HTTP on 127.0.0.1 without credentials or fragments",
        ))
    }
}

fn unsafe_github_releases_url(url: &reqwest::Url, reason: &'static str) -> UpdateError {
    UpdateError::UnsafeGithubReleasesUrl {
        url: url.to_string(),
        reason,
    }
}

fn parse_tunnel_release_tag(tag: &str) -> Option<Version> {
    let tag_body = tag.strip_prefix(TUNNEL_RELEASE_TAG_PREFIX)?;
    let version = Version::parse(tag_body).ok()?;
    (version.pre.is_empty() && version.to_string() == tag_body).then_some(version)
}

#[cfg(test)]
fn parse_release_assets(assets: Vec<GithubReleaseAsset>) -> Result<ReleaseAssetUrls, UpdateError> {
    parse_release_assets_with_url_parser(assets, parse_github_release_asset_url)
}

fn parse_release_assets_with_url_parser(
    assets: Vec<GithubReleaseAsset>,
    parse_asset_url: ReleaseAssetUrlParser,
) -> Result<ReleaseAssetUrls, UpdateError> {
    let mut urls = HashMap::with_capacity(assets.len());
    for asset in assets {
        if asset.name.is_empty() {
            return Err(UpdateError::EmptyGithubReleaseAssetName);
        }
        if urls.contains_key(&asset.name) {
            return Err(UpdateError::DuplicateGithubReleaseAsset { name: asset.name });
        }

        let url = parse_asset_url(&asset.name, asset.browser_download_url)?;
        urls.insert(asset.name, url);
    }

    let assets = ReleaseAssetUrls { urls };
    assets.url_for(RELEASE_MANIFEST_FILE_NAME)?;
    assets.url_for(RELEASE_MANIFEST_SIGNATURE_FILE_NAME)?;
    Ok(assets)
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubReleaseAsset>,
}

#[derive(Deserialize)]
struct GithubReleaseAsset {
    name: String,
    browser_download_url: String,
}

fn parse_github_release_asset_url(
    name: &str,
    raw_url: String,
) -> Result<reqwest::Url, UpdateError> {
    let url = match reqwest::Url::parse(&raw_url) {
        Ok(url) => url,
        Err(source) => {
            return Err(UpdateError::InvalidGithubReleaseAssetUrl {
                name: name.to_owned(),
                url: raw_url,
                source,
            });
        }
    };

    if url.scheme() != "https" {
        return Err(unsafe_github_release_asset_url(
            name,
            &raw_url,
            "scheme must be HTTPS",
        ));
    }
    if !matches!(
        url.host_str(),
        Some(
            "github.com" | "objects.githubusercontent.com" | "release-assets.githubusercontent.com"
        )
    ) {
        return Err(unsafe_github_release_asset_url(
            name,
            &raw_url,
            "host is not an allowed GitHub download origin",
        ));
    }
    if has_url_credentials(&url, &raw_url) {
        return Err(unsafe_github_release_asset_url(
            name,
            &raw_url,
            "credentials are not allowed",
        ));
    }
    if url.port().is_some_and(|port| port != 443) {
        return Err(unsafe_github_release_asset_url(
            name,
            &raw_url,
            "port must be the HTTPS default",
        ));
    }
    if url.query().is_some() {
        return Err(unsafe_github_release_asset_url(
            name,
            &raw_url,
            "query is not allowed",
        ));
    }
    if url.fragment().is_some() {
        return Err(unsafe_github_release_asset_url(
            name,
            &raw_url,
            "fragment is not allowed",
        ));
    }

    Ok(url)
}

#[cfg(test)]
fn parse_test_github_release_asset_url(
    name: &str,
    raw_url: String,
) -> Result<reqwest::Url, UpdateError> {
    let url = match reqwest::Url::parse(&raw_url) {
        Ok(url) => url,
        Err(source) => {
            return Err(UpdateError::InvalidGithubReleaseAssetUrl {
                name: name.to_owned(),
                url: raw_url,
                source,
            });
        }
    };

    if !is_safe_test_github_release_asset_url(&url) {
        return Err(unsafe_github_release_asset_url(
            name,
            &raw_url,
            "test asset URLs must use HTTP on 127.0.0.1 without credentials or fragments",
        ));
    }

    Ok(url)
}

fn has_url_credentials(url: &reqwest::Url, raw_url: &str) -> bool {
    if !url.username().is_empty() || url.password().is_some() {
        return true;
    }

    raw_url
        .split_once(':')
        .and_then(|(_, remainder)| remainder.strip_prefix("//"))
        .and_then(|authority_and_path| authority_and_path.split(['/', '?', '#']).next())
        .is_some_and(|authority| authority.contains('@'))
}

fn is_safe_github_release_asset_redirect(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && matches!(
            url.host_str(),
            Some(
                "github.com"
                    | "objects.githubusercontent.com"
                    | "release-assets.githubusercontent.com"
            )
        )
        && !has_url_credentials(url, url.as_str())
        && !url.port().is_some_and(|port| port != 443)
        && url.fragment().is_none()
}

#[cfg(test)]
fn is_safe_test_github_release_asset_url(url: &reqwest::Url) -> bool {
    url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && !has_url_credentials(url, url.as_str())
        && url.fragment().is_none()
}

fn unsafe_github_release_asset_url(name: &str, url: &str, reason: &'static str) -> UpdateError {
    UpdateError::UnsafeGithubReleaseAssetUrl {
        name: name.to_owned(),
        url: url.to_owned(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GitHubReleaseClient, GithubRelease, build_release_asset_client,
        is_safe_github_release_asset_redirect, parse_release_assets,
    };
    use crate::update::manifest::{
        RELEASE_MANIFEST_FILE_NAME, RELEASE_MANIFEST_SIGNATURE_FILE_NAME, UpdateError,
    };
    use semver::Version;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]

    fn release_asset_discovery_requires_unique_https_assets() {
        let raw = format!(
            r#"{{"tag_name":"tunnel-v1.2.3","draft":false,"prerelease":false,"assets":[{{"name":"{RELEASE_MANIFEST_FILE_NAME}","browser_download_url":"https://github.com/h1w/rqbit-tunnel/releases/download/v1/{RELEASE_MANIFEST_FILE_NAME}"}},{{"name":"{RELEASE_MANIFEST_SIGNATURE_FILE_NAME}","browser_download_url":"https://github.com/h1w/rqbit-tunnel/releases/download/v1/{RELEASE_MANIFEST_SIGNATURE_FILE_NAME}"}},{{"name":"rqbit-tunnel-x86_64-unknown-linux-gnu.tar.gz","browser_download_url":"https://github.com/h1w/rqbit-tunnel/releases/download/v1/rqbit-tunnel-x86_64-unknown-linux-gnu.tar.gz"}}]}}"#
        );
        let release: GithubRelease =
            serde_json::from_slice(raw.as_bytes()).expect("fixture release must parse");
        let assets =
            parse_release_assets(release.assets).expect("published release assets should parse");

        assert_eq!(
            assets
                .url_for(RELEASE_MANIFEST_FILE_NAME)
                .expect("manifest asset must be available")
                .as_str(),
            format!(
                "https://github.com/h1w/rqbit-tunnel/releases/download/v1/{RELEASE_MANIFEST_FILE_NAME}"
            )
        );
        assert_eq!(
            assets
                .url_for("rqbit-tunnel-x86_64-unknown-linux-gnu.tar.gz")
                .expect("selected archive must be available")
                .as_str(),
            "https://github.com/h1w/rqbit-tunnel/releases/download/v1/rqbit-tunnel-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    #[tokio::test]
    async fn selected_release_assets_do_not_rediscover_metadata() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener must bind");
        let address = listener
            .local_addr()
            .expect("test listener must have an address");
        let archive_name = "rqbit-tunnel-x86_64-unknown-linux-gnu.tar.gz";
        let manifest_body = b"selected manifest".to_vec();
        let signature_body = b"selected signature".to_vec();
        let archive_body = b"selected archive".to_vec();
        let release_list = format!(
            r#"[{{"tag_name":"tunnel-v2.3.4","draft":false,"prerelease":false,"assets":[{{"name":"{RELEASE_MANIFEST_FILE_NAME}","browser_download_url":"http://{address}/assets/manifest"}},{{"name":"{RELEASE_MANIFEST_SIGNATURE_FILE_NAME}","browser_download_url":"http://{address}/assets/signature"}},{{"name":"{archive_name}","browser_download_url":"http://{address}/assets/archive"}}]}}]"#
        );
        let server = tokio::spawn(async move {
            let mut request_targets = Vec::new();
            for (expected_target, body) in [
                ("/releases?per_page=100&page=1", release_list.into_bytes()),
                ("/assets/manifest", manifest_body),
                ("/assets/signature", signature_body),
                ("/assets/archive", archive_body),
            ] {
                let (mut stream, _) = listener.accept().await.expect("test request must arrive");
                let mut request = [0_u8; 4096];
                let bytes = stream
                    .read(&mut request)
                    .await
                    .expect("test request must be readable");
                let request = String::from_utf8_lossy(&request[..bytes]);
                let target = request
                    .split_whitespace()
                    .nth(1)
                    .expect("HTTP request must contain a target")
                    .to_owned();
                assert_eq!(target, expected_target, "request must use the selected URL");
                request_targets.push(target);

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("response headers must be writable");
                stream
                    .write_all(&body)
                    .await
                    .expect("response body must be writable");
            }
            request_targets
        });

        let client = GitHubReleaseClient::with_test_urls(
            reqwest::Url::parse(&format!("http://{address}/releases"))
                .expect("test release URL must parse"),
        )
        .expect("test release client must build");
        let selected = client
            .fetch_selected_release()
            .await
            .expect("eligible tunnel release must be selected");
        assert_eq!(
            selected.version,
            Version::parse("2.3.4").expect("fixture version must parse")
        );

        let mut manifest = Vec::new();
        client
            .download_selected_release_asset_to(
                &selected.assets,
                RELEASE_MANIFEST_FILE_NAME,
                &mut manifest,
            )
            .await
            .expect("selected manifest must download");
        let mut signature = Vec::new();
        client
            .download_selected_release_asset_to(
                &selected.assets,
                RELEASE_MANIFEST_SIGNATURE_FILE_NAME,
                &mut signature,
            )
            .await
            .expect("selected signature must download");
        let mut archive = Vec::new();
        client
            .download_selected_release_asset_to(&selected.assets, archive_name, &mut archive)
            .await
            .expect("selected archive must download");

        assert_eq!(manifest, b"selected manifest");
        assert_eq!(signature, b"selected signature");
        assert_eq!(archive, b"selected archive");
        let request_targets = server.await.expect("test server must finish");
        assert_eq!(
            request_targets
                .iter()
                .filter(|target| target.as_str() == "/releases?per_page=100&page=1")
                .count(),
            1,
            "selected asset downloads must not rediscover release metadata"
        );
    }

    #[tokio::test]
    async fn release_discovery_ignores_newer_unrelated_releases_across_pages() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener must bind");
        let address = listener
            .local_addr()
            .expect("test listener must have an address");
        let first_page = format!(
            "[{}]",
            (0..100)
                .map(|minor| match minor {
                    0 => r#"{"tag_name":"tunnel-v01.2.3","draft":false,"prerelease":false,"assets":[]}"#
                        .to_owned(),
                    1 => r#"{"tag_name":"tunnel-v9.9.9","draft":true,"prerelease":false,"assets":[]}"#
                        .to_owned(),
                    2 => r#"{"tag_name":"tunnel-v9.9.8","draft":false,"prerelease":true,"assets":[]}"#
                        .to_owned(),
                    _ => format!(
                        r#"{{"tag_name":"v99.0.{minor}","draft":false,"prerelease":false,"assets":[]}}"#
                    ),
                })
                .collect::<Vec<_>>()
                .join(",")
        );
        let tunnel_release = |version: &str| {
            format!(
                r#"{{"tag_name":"tunnel-v{version}","draft":false,"prerelease":false,"assets":[{{"name":"{RELEASE_MANIFEST_FILE_NAME}","browser_download_url":"http://{address}/assets/{version}/{RELEASE_MANIFEST_FILE_NAME}"}},{{"name":"{RELEASE_MANIFEST_SIGNATURE_FILE_NAME}","browser_download_url":"http://{address}/assets/{version}/{RELEASE_MANIFEST_SIGNATURE_FILE_NAME}"}}]}}"#
            )
        };
        let second_page = format!("[{},{}]", tunnel_release("1.2.2"), tunnel_release("1.2.3"));
        let server = tokio::spawn(async move {
            for (page, body) in [(1, first_page), (2, second_page)] {
                let (mut stream, _) = listener.accept().await.expect("test request must arrive");
                let mut request = [0_u8; 1024];
                let bytes = stream
                    .read(&mut request)
                    .await
                    .expect("test request must be readable");
                assert!(
                    String::from_utf8_lossy(&request[..bytes])
                        .starts_with(&format!("GET /releases?per_page=100&page={page} HTTP/1.1")),
                    "release discovery must request page {page}"
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("test response must be writable");
            }
        });

        let client = GitHubReleaseClient::with_test_urls(
            reqwest::Url::parse(&format!("http://{address}/releases"))
                .expect("test release URL must parse"),
        )
        .expect("test release client must build");
        let assets = client
            .fetch_release_assets()
            .await
            .expect("eligible tunnel release must be selected");

        assert_eq!(
            assets
                .url_for(RELEASE_MANIFEST_FILE_NAME)
                .expect("manifest asset must be available")
                .as_str(),
            format!("http://{address}/assets/1.2.3/{RELEASE_MANIFEST_FILE_NAME}")
        );
        server.await.expect("test server must finish");
    }

    #[tokio::test]
    async fn release_discovery_rejects_semantic_prerelease_tags() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener must bind");
        let address = listener
            .local_addr()
            .expect("test listener must have an address");
        let release = |version: &str| {
            format!(
                r#"{{"tag_name":"tunnel-v{version}","draft":false,"prerelease":false,"assets":[{{"name":"{RELEASE_MANIFEST_FILE_NAME}","browser_download_url":"http://{address}/assets/{version}/{RELEASE_MANIFEST_FILE_NAME}"}},{{"name":"{RELEASE_MANIFEST_SIGNATURE_FILE_NAME}","browser_download_url":"http://{address}/assets/{version}/{RELEASE_MANIFEST_SIGNATURE_FILE_NAME}"}}]}}"#
            )
        };
        let releases = format!("[{},{}]", release("2.0.0-rc.1"), release("1.9.0"));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("test request must arrive");
            let mut request = [0_u8; 1024];
            let bytes = stream
                .read(&mut request)
                .await
                .expect("test request must be readable");
            assert!(
                String::from_utf8_lossy(&request[..bytes])
                    .starts_with("GET /releases?per_page=100&page=1 HTTP/1.1"),
                "release discovery must request the first page"
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{releases}",
                releases.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("test response must be writable");
        });

        let client = GitHubReleaseClient::with_test_urls(
            reqwest::Url::parse(&format!("http://{address}/releases"))
                .expect("test release URL must parse"),
        )
        .expect("test release client must build");
        let assets = client
            .fetch_release_assets()
            .await
            .expect("stable tunnel release must be selected");

        assert_eq!(
            assets
                .url_for(RELEASE_MANIFEST_FILE_NAME)
                .expect("manifest asset must be available")
                .as_str(),
            format!("http://{address}/assets/1.9.0/{RELEASE_MANIFEST_FILE_NAME}")
        );
        assert_eq!(
            assets
                .url_for(RELEASE_MANIFEST_SIGNATURE_FILE_NAME)
                .expect("manifest signature asset must be available")
                .as_str(),
            format!("http://{address}/assets/1.9.0/{RELEASE_MANIFEST_SIGNATURE_FILE_NAME}")
        );
        server.await.expect("test server must finish");
    }

    #[test]
    fn release_asset_discovery_rejects_duplicate_and_unsafe_assets() {
        for raw in [
            r#"{"tag_name":"tunnel-v1.2.3","draft":false,"prerelease":false,"assets":[{"name":"same","browser_download_url":"https://github.com/h1w/rqbit-tunnel/releases/download/v1/same"},{"name":"same","browser_download_url":"https://github.com/h1w/rqbit-tunnel/releases/download/v1/same-2"}]}"#,
            r#"{"tag_name":"tunnel-v1.2.3","draft":false,"prerelease":false,"assets":[{"name":"asset","browser_download_url":"http://github.com/h1w/rqbit-tunnel/releases/download/v1/asset"}]}"#,
        ] {
            let release: GithubRelease =
                serde_json::from_slice(raw.as_bytes()).expect("fixture release must parse");
            assert!(
                parse_release_assets(release.assets).is_err(),
                "release metadata must reject {raw}"
            );
        }
    }

    #[test]
    fn release_asset_discovery_requires_manifest_metadata_assets() {
        let release: GithubRelease = serde_json::from_slice(
            br#"{"tag_name":"tunnel-v1.2.3","draft":false,"prerelease":false,"assets":[{"name":"rqbit-tunnel-x86_64-unknown-linux-gnu.tar.gz","browser_download_url":"https://github.com/h1w/rqbit-tunnel/releases/download/v1/rqbit-tunnel-x86_64-unknown-linux-gnu.tar.gz"}]}"#,
        )
        .expect("fixture release must parse");
        let error = parse_release_assets(release.assets)
            .expect_err("release without signed manifest metadata must be rejected");

        assert!(matches!(
            error,
            UpdateError::MissingGithubReleaseAsset { name }
                if name == RELEASE_MANIFEST_FILE_NAME
        ));
    }
    #[test]
    fn asset_redirects_accept_only_safe_github_download_origins() {
        assert!(
            is_safe_github_release_asset_redirect(
                &reqwest::Url::parse(
                    "https://release-assets.githubusercontent.com/assets/1/archive.tar.gz?X-Amz-Signature=abc"
                )
                .expect("fixture URL must parse")
            )
        );
        for url in [
            "http://github.com/h1w/rqbit-tunnel/releases/download/v1/archive.tar.gz",
            "https://example.invalid/archive.tar.gz",
            "https://github.com:444/archive.tar.gz",
            "https://user@github.com/archive.tar.gz",
            "https://github.com/archive.tar.gz#fragment",
        ] {
            assert!(
                !is_safe_github_release_asset_redirect(
                    &reqwest::Url::parse(url).expect("fixture URL must parse")
                ),
                "redirect target must be rejected: {url}"
            );
        }
    }

    #[tokio::test]
    async fn asset_client_follows_a_permitted_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener must bind");
        let address = listener
            .local_addr()
            .expect("test listener must have an address");
        let server = tokio::spawn(async move {
            for response in [
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{address}/asset\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ),
                "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"
                    .to_owned(),
            ] {
                let (mut stream, _) = listener.accept().await.expect("test request must arrive");
                let mut request = [0_u8; 1024];
                stream
                    .read(&mut request)
                    .await
                    .expect("test request must be readable");
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("test response must be writable");
            }
        });

        let client = build_release_asset_client(|url| {
            url.scheme() == "http" && url.host_str() == Some("127.0.0.1")
        })
        .expect("test asset client must build");
        let response = client
            .get(format!("http://{address}/start"))
            .send()
            .await
            .expect("permitted redirect must be followed");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response.bytes().await.expect("payload must be readable"),
            "payload"
        );
        server.await.expect("test server must finish");
    }
}
