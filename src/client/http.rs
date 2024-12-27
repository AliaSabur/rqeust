use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use std::{collections::HashMap, convert::TryInto, net::SocketAddr};
use std::{fmt, str};

use crate::connect::sealed::{Conn, Unnameable};
use crate::error::BoxError;
use crate::util::client::{InnerRequest, NetworkScheme};
use crate::util::{
    self, client::connect::HttpConnector, client::Builder, common::Exec, rt::TokioExecutor,
};
use bytes::Bytes;
use http::header::{
    Entry, HeaderMap, HeaderValue, ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH,
    CONTENT_TYPE, LOCATION, PROXY_AUTHORIZATION, RANGE, REFERER, TRANSFER_ENCODING, USER_AGENT,
};
use http::uri::Scheme;
use http::{HeaderName, Uri, Version};
use hyper2::client::conn::{http1, http2};
use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::time::Sleep;
use tower::util::BoxCloneSyncServiceLayer;
use tower::{Layer, Service};

use super::decoder::Accepts;
use super::request::{Request, RequestBuilder};
use super::response::Response;
use super::Body;
use crate::connect::{BoxedConnectorLayer, BoxedConnectorService, Connector, ConnectorBuilder};
#[cfg(feature = "cookies")]
use crate::cookie;
#[cfg(feature = "hickory-dns")]
use crate::dns::hickory::HickoryDnsResolver;
use crate::dns::{gai::GaiResolver, DnsResolverWithOverrides, DynResolver, Resolve};
use crate::into_url::try_uri;
use crate::redirect::{self, remove_sensitive_headers};
use crate::tls::{self, BoringTlsConnector, Impersonate, ImpersonateSettings, TlsSettings};
use crate::{error, impl_debug};
use crate::{IntoUrl, Method, Proxy, StatusCode, Url};
#[cfg(feature = "hickory-dns")]
use hickory_resolver::config::LookupIpStrategy;
use log::{debug, trace};

type HyperResponseFuture = util::client::ResponseFuture;

/// An asynchronous `Client` to make Requests with.
///
/// The Client has various configuration values to tweak, but the defaults
/// are set to what is usually the most commonly desired value. To configure a
/// `Client`, use `Client::builder()`.
///
/// The `Client` holds a connection pool internally, so it is advised that
/// you create one and **reuse** it.
///
/// You do **not** have to wrap the `Client` in an [`Rc`] or [`Arc`] to **reuse** it,
/// because it already uses an [`Arc`] internally.
///
/// [`Rc`]: std::rc::Rc
#[derive(Clone, Debug)]
pub struct Client {
    inner: Arc<ClientRef>,
}

/// A `ClientBuilder` can be used to create a `Client` with custom configuration.
#[must_use]
#[derive(Debug)]
pub struct ClientBuilder {
    config: Config,
}

/// A `HttpVersionPref` is used to set the HTTP version preference.
#[derive(Debug, Clone, Copy, Default)]
pub enum HttpVersionPref {
    /// Prefer HTTP/1.1
    Http1,
    /// Prefer HTTP/2
    Http2,
    /// Prefer HTTP/1 and HTTP/2
    #[default]
    All,
}

#[cfg(feature = "cookies")]
type CookieStoreOption = Option<Arc<dyn cookie::CookieStore>>;
#[cfg(not(feature = "cookies"))]
type CookieStoreOption = ();

struct Config {
    // NOTE: When adding a new field, update `fmt::Debug for ClientBuilder`
    accepts: Accepts,
    headers: Cow<'static, HeaderMap>,
    headers_order: Option<Cow<'static, [HeaderName]>>,
    connect_timeout: Option<Duration>,
    connection_verbose: bool,
    pool_idle_timeout: Option<Duration>,
    pool_max_idle_per_host: usize,
    pool_max_size: Option<NonZeroUsize>,
    tcp_keepalive: Option<Duration>,
    proxies: Vec<Proxy>,
    auto_sys_proxy: bool,
    redirect_policy: redirect::Policy,
    referer: bool,
    timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    local_address_ipv6: Option<Ipv6Addr>,
    local_address_ipv4: Option<Ipv4Addr>,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    interface: Option<std::borrow::Cow<'static, str>>,
    nodelay: bool,
    #[cfg(feature = "cookies")]
    cookie_store: CookieStoreOption,
    hickory_dns: bool,
    error: Option<crate::Error>,
    dns_overrides: HashMap<String, Vec<SocketAddr>>,
    dns_resolver: Option<Arc<dyn Resolve>>,
    #[cfg(feature = "hickory-dns")]
    dns_strategy: Option<LookupIpStrategy>,
    base_url: Option<Url>,
    builder: Builder,
    https_only: bool,
    http2_max_retry_count: usize,
    tls_info: bool,
    connector_layers: Vec<BoxedConnectorLayer>,

    tls: TlsSettings,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder {
    /// Constructs a new `ClientBuilder`.
    ///
    /// This is the same as `Client::builder()`.
    pub fn new() -> ClientBuilder {
        // NOTE: This is a hack to ensure that the default headers are always the same
        // across all instances of ClientBuilder.
        static DEFAULT_HEADERS: LazyLock<HeaderMap> = LazyLock::new(|| {
            let mut headers = HeaderMap::with_capacity(2);
            headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
            headers
        });

        ClientBuilder {
            config: Config {
                error: None,
                accepts: Accepts::default(),
                headers: Cow::Borrowed(&*DEFAULT_HEADERS),
                headers_order: None,
                connect_timeout: None,
                connection_verbose: false,
                pool_idle_timeout: Some(Duration::from_secs(90)),
                pool_max_idle_per_host: usize::MAX,
                pool_max_size: None,
                // TODO: Re-enable default duration once hyper's HttpConnector is fixed
                // to no longer error when an option fails.
                tcp_keepalive: None,
                proxies: Vec::new(),
                auto_sys_proxy: true,
                redirect_policy: redirect::Policy::none(),
                referer: true,
                timeout: None,
                read_timeout: None,
                local_address_ipv6: None,
                local_address_ipv4: None,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                interface: None,
                nodelay: true,
                hickory_dns: cfg!(feature = "hickory-dns"),
                #[cfg(feature = "hickory-dns")]
                dns_strategy: None,
                #[cfg(feature = "cookies")]
                cookie_store: None,
                dns_overrides: HashMap::new(),
                dns_resolver: None,
                base_url: None,
                builder: crate::util::client::Client::builder(TokioExecutor::new()),
                https_only: false,
                http2_max_retry_count: 2,
                tls_info: false,
                connector_layers: Vec::new(),

                tls: Default::default(),
            },
        }
    }

    /// Returns a `Client` that uses this `ClientBuilder` configuration.
    ///
    /// # Errors
    ///
    /// This method fails if a TLS backend cannot be initialized, or the resolver
    /// cannot load the system configuration.
    pub fn build(self) -> crate::Result<Client> {
        let mut config = self.config;

        if let Some(err) = config.error {
            return Err(err);
        }

        let mut proxies = config.proxies;
        if config.auto_sys_proxy {
            proxies.push(Proxy::system());
        }
        let proxies_maybe_http_auth = proxies.iter().any(|p| p.maybe_has_http_auth());

        let mut connector_builder = {
            let mut resolver: Arc<dyn Resolve> = if let Some(dns_resolver) = config.dns_resolver {
                dns_resolver
            } else if config.hickory_dns {
                #[cfg(feature = "hickory-dns")]
                {
                    Arc::new(HickoryDnsResolver::new(config.dns_strategy)?)
                }
                #[cfg(not(feature = "hickory-dns"))]
                {
                    unreachable!("hickory-dns shouldn't be enabled unless the feature is")
                }
            } else {
                Arc::new(GaiResolver::new())
            };
            if !config.dns_overrides.is_empty() {
                resolver = Arc::new(DnsResolverWithOverrides::new(
                    resolver,
                    config.dns_overrides,
                ));
            }
            let mut http = HttpConnector::new_with_resolver(DynResolver::new(resolver));
            http.set_connect_timeout(config.connect_timeout);

            let tls = BoringTlsConnector::new(config.tls)?;
            ConnectorBuilder::new(http, tls, config.nodelay, config.tls_info)
        };

        connector_builder.set_timeout(config.connect_timeout);
        connector_builder.set_verbose(config.connection_verbose);
        connector_builder.set_keepalive(config.tcp_keepalive);

        config
            .builder
            .pool_idle_timeout(config.pool_idle_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .pool_max_size(config.pool_max_size);

        Ok(Client {
            inner: Arc::new(ClientRef {
                accepts: config.accepts,
                #[cfg(feature = "cookies")]
                cookie_store: config.cookie_store,
                hyper: config
                    .builder
                    .build(connector_builder.build(config.connector_layers)),
                headers: config.headers,
                headers_order: config.headers_order,
                redirect: config.redirect_policy,
                referer: config.referer,
                request_timeout: config.timeout,
                read_timeout: config.read_timeout,
                https_only: config.https_only,
                proxies_maybe_http_auth,
                base_url: config.base_url,
                http2_max_retry_count: config.http2_max_retry_count,

                proxies,
                local_addr_v4: config.local_address_ipv4,
                local_addr_v6: config.local_address_ipv6,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                interface: config.interface,
            }),
        })
    }

    /// Sets the necessary values to mimic the specified impersonate version, including headers and TLS settings.
    #[inline]
    pub fn impersonate(self, impersonate: Impersonate) -> ClientBuilder {
        let settings = tls::tls_settings(impersonate, true);
        self.apply_impersonate_settings(settings)
    }

    /// Sets the necessary values to mimic the specified impersonate version, skipping header configuration.
    /// This will only apply the required TLS settings.
    #[inline]
    pub fn impersonate_skip_headers(self, impersonate: Impersonate) -> ClientBuilder {
        let settings = tls::tls_settings(impersonate, false);
        self.apply_impersonate_settings(settings)
    }

    /// Apply the given impersonate settings directly.
    #[cfg(feature = "impersonate_settings")]
    #[inline]
    pub fn impersonate_settings(self, settings: ImpersonateSettings) -> ClientBuilder {
        self.apply_impersonate_settings(settings)
    }

    /// Apply the given TLS settings and header function.
    fn apply_impersonate_settings(mut self, mut settings: ImpersonateSettings) -> ClientBuilder {
        // Set the headers if needed
        if let Some(mut headers) = settings.headers {
            std::mem::swap(&mut self.config.headers, &mut headers);
        }

        // Set the headers order if needed
        std::mem::swap(&mut self.config.headers_order, &mut settings.headers_order);

        // Set the TLS settings
        std::mem::swap(&mut self.config.tls, &mut settings.tls);

        // Set the http2 preference
        self.config.builder.with_http2_builder(|builder| {
            let http2_headers_priority =
                crate::util::convert_headers_priority(settings.http2.headers_priority);

            builder
                .initial_stream_id(settings.http2.initial_stream_id)
                .initial_stream_window_size(settings.http2.initial_stream_window_size)
                .initial_connection_window_size(settings.http2.initial_connection_window_size)
                .max_concurrent_streams(settings.http2.max_concurrent_streams)
                .header_table_size(settings.http2.header_table_size)
                .max_frame_size(settings.http2.max_frame_size)
                .headers_priority(http2_headers_priority)
                .headers_pseudo_order(settings.http2.headers_pseudo_order)
                .settings_order(settings.http2.settings_order);

            if let Some(max_header_list_size) = settings.http2.max_header_list_size {
                builder.max_header_list_size(max_header_list_size);
            }

            if let Some(enable_push) = settings.http2.enable_push {
                builder.enable_push(enable_push);
            }

            if let Some(unknown_setting8) = settings.http2.unknown_setting8 {
                builder.unknown_setting8(unknown_setting8);
            }

            if let Some(unknown_setting9) = settings.http2.unknown_setting9 {
                builder.unknown_setting9(unknown_setting9);
            }
            builder
        });

        self
    }

    /// Enable Encrypted Client Hello (Secure SNI)
    pub fn enable_ech_grease(mut self, enabled: bool) -> ClientBuilder {
        self.config.tls.enable_ech_grease = enabled;
        self
    }

    /// Enable TLS permute_extensions
    pub fn permute_extensions(mut self, enabled: bool) -> ClientBuilder {
        self.config.tls.permute_extensions = Some(enabled);
        self
    }

    /// Enable TLS pre_shared_key
    pub fn pre_shared_key(mut self, enabled: bool) -> ClientBuilder {
        self.config.tls.pre_shared_key = enabled;
        self
    }

    // Higher-level options

    /// Sets the `User-Agent` header to be used by this client.
    ///
    /// # Example
    ///
    /// ```rust
    /// # async fn doc() -> Result<(), rquest::Error> {
    /// // Name your user agent after your app?
    /// static APP_USER_AGENT: &str = concat!(
    ///     env!("CARGO_PKG_NAME"),
    ///     "/",
    ///     env!("CARGO_PKG_VERSION"),
    /// );
    ///
    /// let client = rquest::Client::builder()
    ///     .user_agent(APP_USER_AGENT)
    ///     .build()?;
    /// let res = client.get("https://www.rust-lang.org").send().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn user_agent<V>(mut self, value: V) -> ClientBuilder
    where
        V: TryInto<HeaderValue>,
        V::Error: Into<http::Error>,
    {
        match value.try_into() {
            Ok(value) => {
                self.config.headers.to_mut().insert(USER_AGENT, value);
            }
            Err(e) => {
                self.config.error = Some(crate::error::builder(e.into()));
            }
        };
        self
    }

    /// Sets the default headers for every request.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rquest::header;
    /// # async fn doc() -> Result<(), rquest::Error> {
    /// let mut headers = header::HeaderMap::new();
    /// headers.insert("X-MY-HEADER", header::HeaderValue::from_static("value"));
    ///
    /// // Consider marking security-sensitive headers with `set_sensitive`.
    /// let mut auth_value = header::HeaderValue::from_static("secret");
    /// auth_value.set_sensitive(true);
    /// headers.insert(header::AUTHORIZATION, auth_value);
    ///
    /// // get a client builder
    /// let client = rquest::Client::builder()
    ///     .default_headers(headers)
    ///     .build()?;
    /// let res = client.get("https://www.rust-lang.org").send().await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Override the default headers:
    ///
    /// ```rust
    /// use rquest::header;
    /// # async fn doc() -> Result<(), rquest::Error> {
    /// let mut headers = header::HeaderMap::new();
    /// headers.insert("X-MY-HEADER", header::HeaderValue::from_static("value"));
    ///
    /// // get a client builder
    /// let client = rquest::Client::builder()
    ///     .default_headers(headers)
    ///     .build()?;
    /// let res = client
    ///     .get("https://www.rust-lang.org")
    ///     .header("X-MY-HEADER", "new_value")
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn default_headers(mut self, headers: HeaderMap) -> ClientBuilder {
        let headers_mut = self.config.headers.to_mut();
        for (key, value) in headers.into_iter().filter_map(|(k, v)| k.map(|k| (k, v))) {
            headers_mut.insert(key, value);
        }
        self
    }

    /// Change the order in which headers will be sent
    ///
    /// Warning
    ///
    /// The host header needs to be manually inserted if you want to modify its order.
    /// Otherwise it will be inserted by hyper after sorting.
    pub fn headers_order(mut self, order: impl Into<Cow<'static, [HeaderName]>>) -> ClientBuilder {
        self.config.headers_order = Some(order.into());
        self
    }

    /// Enable a persistent cookie store for the client.
    ///
    /// Cookies received in responses will be preserved and included in
    /// additional requests.
    ///
    /// By default, no cookie store is used.
    ///
    /// # Optional
    ///
    /// This requires the optional `cookies` feature to be enabled.
    #[cfg(feature = "cookies")]
    #[cfg_attr(docsrs, doc(cfg(feature = "cookies")))]
    pub fn cookie_store(mut self, enable: bool) -> ClientBuilder {
        if enable {
            self.cookie_provider(Arc::new(cookie::Jar::default()))
        } else {
            self.config.cookie_store = None;
            self
        }
    }

    /// Set the persistent cookie store for the client.
    ///
    /// Cookies received in responses will be passed to this store, and
    /// additional requests will query this store for cookies.
    ///
    /// By default, no cookie store is used.
    ///
    /// # Optional
    ///
    /// This requires the optional `cookies` feature to be enabled.
    #[cfg(feature = "cookies")]
    #[cfg_attr(docsrs, doc(cfg(feature = "cookies")))]
    pub fn cookie_provider<C: cookie::CookieStore + 'static>(
        mut self,
        cookie_store: Arc<C>,
    ) -> ClientBuilder {
        self.config.cookie_store = Some(cookie_store as _);
        self
    }

    /// Enable auto gzip decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto gzip decompression is turned on:
    ///
    /// - When sending a request and if the request's headers do not already contain
    ///   an `Accept-Encoding` **and** `Range` values, the `Accept-Encoding` header is set to `gzip`.
    ///   The request body is **not** automatically compressed.
    /// - When receiving a response, if its headers contain a `Content-Encoding` value of
    ///   `gzip`, both `Content-Encoding` and `Content-Length` are removed from the
    ///   headers' set. The response body is automatically decompressed.
    ///
    /// If the `gzip` feature is turned on, the default option is enabled.
    ///
    /// # Optional
    ///
    /// This requires the optional `gzip` feature to be enabled
    #[cfg(feature = "gzip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gzip")))]
    pub fn gzip(mut self, enable: bool) -> ClientBuilder {
        self.config.accepts.gzip = enable;
        self
    }

    /// Enable auto brotli decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto brotli decompression is turned on:
    ///
    /// - When sending a request and if the request's headers do not already contain
    ///   an `Accept-Encoding` **and** `Range` values, the `Accept-Encoding` header is set to `br`.
    ///   The request body is **not** automatically compressed.
    /// - When receiving a response, if its headers contain a `Content-Encoding` value of
    ///   `br`, both `Content-Encoding` and `Content-Length` are removed from the
    ///   headers' set. The response body is automatically decompressed.
    ///
    /// If the `brotli` feature is turned on, the default option is enabled.
    ///
    /// # Optional
    ///
    /// This requires the optional `brotli` feature to be enabled
    #[cfg(feature = "brotli")]
    #[cfg_attr(docsrs, doc(cfg(feature = "brotli")))]
    pub fn brotli(mut self, enable: bool) -> ClientBuilder {
        self.config.accepts.brotli = enable;
        self
    }

    /// Enable auto zstd decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto zstd decompression is turned on:
    ///
    /// - When sending a request and if the request's headers do not already contain
    ///   an `Accept-Encoding` **and** `Range` values, the `Accept-Encoding` header is set to `zstd`.
    ///   The request body is **not** automatically compressed.
    /// - When receiving a response, if its headers contain a `Content-Encoding` value of
    ///   `zstd`, both `Content-Encoding` and `Content-Length` are removed from the
    ///   headers' set. The response body is automatically decompressed.
    ///
    /// If the `zstd` feature is turned on, the default option is enabled.
    ///
    /// # Optional
    ///
    /// This requires the optional `zstd` feature to be enabled
    #[cfg(feature = "zstd")]
    #[cfg_attr(docsrs, doc(cfg(feature = "zstd")))]
    pub fn zstd(mut self, enable: bool) -> ClientBuilder {
        self.config.accepts.zstd = enable;
        self
    }

    /// Enable auto deflate decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto deflate decompression is turned on:
    ///
    /// - When sending a request and if the request's headers do not already contain
    ///   an `Accept-Encoding` **and** `Range` values, the `Accept-Encoding` header is set to `deflate`.
    ///   The request body is **not** automatically compressed.
    /// - When receiving a response, if it's headers contain a `Content-Encoding` value that
    ///   equals to `deflate`, both values `Content-Encoding` and `Content-Length` are removed from the
    ///   headers' set. The response body is automatically decompressed.
    ///
    /// If the `deflate` feature is turned on, the default option is enabled.
    ///
    /// # Optional
    ///
    /// This requires the optional `deflate` feature to be enabled
    #[cfg(feature = "deflate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
    pub fn deflate(mut self, enable: bool) -> ClientBuilder {
        self.config.accepts.deflate = enable;
        self
    }

    /// Disable auto response body zstd decompression.
    ///
    /// This method exists even if the optional `zstd` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use zstd decompression
    /// even if another dependency were to enable the optional `zstd` feature.
    pub fn no_zstd(self) -> ClientBuilder {
        #[cfg(feature = "zstd")]
        {
            self.zstd(false)
        }

        #[cfg(not(feature = "zstd"))]
        {
            self
        }
    }

    /// Disable auto response body gzip decompression.
    ///
    /// This method exists even if the optional `gzip` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use gzip decompression
    /// even if another dependency were to enable the optional `gzip` feature.
    pub fn no_gzip(self) -> ClientBuilder {
        #[cfg(feature = "gzip")]
        {
            self.gzip(false)
        }

        #[cfg(not(feature = "gzip"))]
        {
            self
        }
    }

    /// Disable auto response body brotli decompression.
    ///
    /// This method exists even if the optional `brotli` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use brotli decompression
    /// even if another dependency were to enable the optional `brotli` feature.
    pub fn no_brotli(self) -> ClientBuilder {
        #[cfg(feature = "brotli")]
        {
            self.brotli(false)
        }

        #[cfg(not(feature = "brotli"))]
        {
            self
        }
    }

    /// Disable auto response body deflate decompression.
    ///
    /// This method exists even if the optional `deflate` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use deflate decompression
    /// even if another dependency were to enable the optional `deflate` feature.
    pub fn no_deflate(self) -> ClientBuilder {
        #[cfg(feature = "deflate")]
        {
            self.deflate(false)
        }

        #[cfg(not(feature = "deflate"))]
        {
            self
        }
    }

    // Redirect options

    /// Set a `RedirectPolicy` for this client.
    ///
    /// Default will follow redirects up to a maximum of 10.
    pub fn redirect(mut self, policy: redirect::Policy) -> ClientBuilder {
        self.config.redirect_policy = policy;
        self
    }

    /// Enable or disable automatic setting of the `Referer` header.
    ///
    /// Default is `true`.
    pub fn referer(mut self, enable: bool) -> ClientBuilder {
        self.config.referer = enable;
        self
    }

    // Proxy options

    /// Add a `Proxy` to the list of proxies the `Client` will use.
    ///
    /// # Note
    ///
    /// Adding a proxy will disable the automatic usage of the "system" proxy.
    pub fn proxy(mut self, proxy: Proxy) -> ClientBuilder {
        self.config.proxies.push(proxy);
        self.config.auto_sys_proxy = false;
        self
    }

    /// Clear all `Proxies`, so `Client` will use no proxy anymore.
    ///
    /// # Note
    /// To add a proxy exclusion list, use [crate::proxy::Proxy::no_proxy()]
    /// on all desired proxies instead.
    ///
    /// This also disables the automatic usage of the "system" proxy.
    pub fn no_proxy(mut self) -> ClientBuilder {
        self.config.proxies.clear();
        self.config.auto_sys_proxy = false;
        self
    }

    // Timeout options

    /// Enables a request timeout.
    ///
    /// The timeout is applied from when the request starts connecting until the
    /// response body has finished.
    ///
    /// Default is no timeout.
    pub fn timeout(mut self, timeout: Duration) -> ClientBuilder {
        self.config.timeout = Some(timeout);
        self
    }

    /// Set a timeout for only the read phase of a `Client`.
    ///
    /// Default is `None`.
    pub fn read_timeout(mut self, timeout: Duration) -> ClientBuilder {
        self.config.read_timeout = Some(timeout);
        self
    }

    /// Set a timeout for only the connect phase of a `Client`.
    ///
    /// Default is `None`.
    ///
    /// # Note
    ///
    /// This **requires** the futures be executed in a tokio runtime with
    /// a tokio timer enabled.
    pub fn connect_timeout(mut self, timeout: Duration) -> ClientBuilder {
        self.config.connect_timeout = Some(timeout);
        self
    }

    /// Set whether connections should emit verbose logs.
    ///
    /// Enabling this option will emit [log][] messages at the `TRACE` level
    /// for read and write operations on connections.
    ///
    /// [log]: https://crates.io/crates/log
    pub fn connection_verbose(mut self, verbose: bool) -> ClientBuilder {
        self.config.connection_verbose = verbose;
        self
    }

    // HTTP options

    /// Set an optional timeout for idle sockets being kept-alive.
    ///
    /// Pass `None` to disable timeout.
    ///
    /// Default is 90 seconds.
    pub fn pool_idle_timeout<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.pool_idle_timeout = val.into();
        self
    }

    /// Sets the maximum idle connection per host allowed in the pool.
    pub fn pool_max_idle_per_host(mut self, max: usize) -> ClientBuilder {
        self.config.pool_max_idle_per_host = max;
        self
    }

    /// Sets the maximum number of connections in the pool.
    pub fn pool_max_size(mut self, max: impl Into<Option<NonZeroUsize>>) -> ClientBuilder {
        self.config.pool_max_size = max.into();
        self
    }

    /// Disable keep-alive for the client.
    pub fn no_keepalive(mut self) -> ClientBuilder {
        self.config.pool_max_idle_per_host = 0;
        self.config.tcp_keepalive = None;
        self
    }

    /// Only use HTTP/1.
    /// Default is Http/1.
    pub fn http1_only(mut self) -> ClientBuilder {
        {
            self.config.tls.alpn_protos = HttpVersionPref::Http1;
        }

        self.config.builder.http2_only(false);
        self
    }

    /// Only use HTTP/2.
    pub fn http2_only(mut self) -> ClientBuilder {
        {
            self.config.tls.alpn_protos = HttpVersionPref::Http2;
        }

        self.config.builder.http2_only(true);
        self
    }

    /// Sets the maximum number of safe retries for HTTP/2 connections.
    pub fn http2_max_retry_count(mut self, max: usize) -> ClientBuilder {
        self.config.http2_max_retry_count = max;
        self
    }

    /// With http1 builder
    ///
    /// # Example
    /// ```
    /// let client = rquest::Client::builder()
    ///     .with_http1_builder(|builder| {
    ///         builder.http09_responses(true)
    ///     })
    ///     .build()?;
    /// ```
    pub fn with_http1_builder<F>(mut self, f: F) -> ClientBuilder
    where
        F: FnOnce(&mut http1::Builder) -> &mut http1::Builder,
    {
        self.config.builder.with_http1_builder(f);
        self
    }

    /// With http2 builder
    ///
    /// # Example
    /// ```
    /// let client = rquest::Client::builder()
    ///     .with_http2_builder(|builder| {
    ///         builder.initial_stream_id(3)
    ///     })
    ///     .build()?;
    /// ```
    pub fn with_http2_builder<F>(mut self, f: F) -> ClientBuilder
    where
        F: FnOnce(&mut http2::Builder<Exec>) -> &mut http2::Builder<Exec>,
    {
        self.config.builder.with_http2_builder(f);
        self
    }

    // TCP options

    /// Set whether sockets have `TCP_NODELAY` enabled.
    ///
    /// Default is `true`.
    pub fn tcp_nodelay(mut self, enabled: bool) -> ClientBuilder {
        self.config.nodelay = enabled;
        self
    }

    /// Bind to a local IP Address.
    ///
    /// # Example
    ///
    /// ```
    /// use std::net::IpAddr;
    /// let local_addr = IpAddr::from([12, 4, 1, 8]);
    /// let client = rquest::Client::builder()
    ///     .local_address(local_addr)
    ///     .build().unwrap();
    /// ```
    pub fn local_address<T>(mut self, addr: T) -> ClientBuilder
    where
        T: Into<Option<IpAddr>>,
    {
        match addr.into() {
            Some(IpAddr::V4(v4)) => {
                self.config.local_address_ipv4 = Some(v4);
            }
            Some(IpAddr::V6(v6)) => {
                self.config.local_address_ipv6 = Some(v6);
            }
            _ => {}
        }
        self
    }

    /// Set that all sockets are bound to the configured IPv4 or IPv6 address (depending on host's
    /// preferences) before connection.
    pub fn local_addresses(mut self, addr_ipv4: Ipv4Addr, addr_ipv6: Ipv6Addr) -> ClientBuilder {
        self.config.local_address_ipv4 = Some(addr_ipv4);
        self.config.local_address_ipv6 = Some(addr_ipv6);
        self
    }

    /// Bind to an interface by `SO_BINDTODEVICE`.
    ///
    /// # Example
    ///
    /// ```
    /// let interface = "lo";
    /// let client = rquest::Client::builder()
    ///     .interface(interface)
    ///     .build().unwrap();
    /// ```
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn interface(
        mut self,
        interface: impl Into<std::borrow::Cow<'static, str>>,
    ) -> ClientBuilder {
        self.config.interface = Some(interface.into());
        self
    }

    /// Set that all sockets have `SO_KEEPALIVE` set with the supplied duration.
    ///
    /// If `None`, the option will not be set.
    pub fn tcp_keepalive<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.tcp_keepalive = val.into();
        self
    }

    /// Controls the use of certificate validation.
    ///
    /// Defaults to `false`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method. If
    /// invalid certificates are trusted, *any* certificate for *any* site
    /// will be trusted for use. This includes expired certificates. This
    /// introduces significant vulnerabilities, and should only be used
    /// as a last resort.
    ///
    /// # Optional
    ///
    /// feature to be enabled.
    pub fn danger_accept_invalid_certs(mut self, accept_invalid_certs: bool) -> ClientBuilder {
        self.config.tls.certs_verification = !accept_invalid_certs;
        self
    }

    /// Controls the use of TLS server name indication.
    ///
    /// Defaults to `true`.
    ///
    /// # Optional
    ///
    /// feature to be enabled.
    pub fn tls_sni(mut self, tls_sni: bool) -> ClientBuilder {
        self.config.tls.tls_sni = tls_sni;
        self
    }

    /// Set the minimum required TLS version for connections.
    ///
    /// By default the TLS backend's own default is used.
    ///
    /// # Errors
    ///
    /// A value of `tls::Version::TLS_1_3` will cause an error with the
    /// `native-tls`/`default-tls` backend. This does not mean the version
    /// isn't supported, just that it can't be set as a minimum due to
    /// technical limitations.
    ///
    /// # Optional
    ///
    /// feature to be enabled.
    pub fn min_tls_version(mut self, version: tls::TlsVersion) -> ClientBuilder {
        self.config.tls.min_tls_version = Some(version);
        self
    }

    /// Set the maximum allowed TLS version for connections.
    ///
    /// By default there's no maximum.
    ///
    /// # Errors
    ///
    /// A value of `tls::Version::TLS_1_3` will cause an error with the
    /// `native-tls`/`default-tls` backend. This does not mean the version
    /// isn't supported, just that it can't be set as a maximum due to
    /// technical limitations.
    ///
    /// # Optional
    ///
    /// feature to be enabled.
    pub fn max_tls_version(mut self, version: tls::TlsVersion) -> ClientBuilder {
        self.config.tls.max_tls_version = Some(version);
        self
    }

    /// Add TLS information as `TlsInfo` extension to responses.
    ///
    /// # Optional
    ///
    /// feature to be enabled.
    pub fn tls_info(mut self, tls_info: bool) -> ClientBuilder {
        self.config.tls_info = tls_info;
        self
    }

    /// Restrict the Client to be used with HTTPS only requests.
    ///
    /// Defaults to false.
    pub fn https_only(mut self, enabled: bool) -> ClientBuilder {
        self.config.https_only = enabled;
        self
    }

    /// Set root certificate store.
    pub fn root_certs_store(mut self, store: impl Into<tls::RootCertsStore>) -> ClientBuilder {
        self.config.tls.root_certs_store = store.into();
        self
    }

    /// Enables the `hickory-dns` asynchronous resolver instead of the default threadpool-based `getaddrinfo`.
    ///
    /// By default, if the `hickory-dns` feature is enabled, this option is used.
    ///
    /// # Optional
    ///
    /// Requires the `hickory-dns` feature to be enabled.
    #[cfg(feature = "hickory-dns")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hickory-dns")))]
    pub fn hickory_dns_strategy(mut self, strategy: LookupIpStrategy) -> ClientBuilder {
        self.config.dns_strategy = Some(strategy);
        self
    }

    /// Disables the hickory-dns async resolver.
    ///
    /// This method exists even if the optional `hickory-dns` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use the hickory-dns async resolver
    /// even if another dependency were to enable the optional `hickory-dns` feature.
    #[cfg(feature = "hickory-dns")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hickory-dns")))]
    pub fn no_hickory_dns(mut self) -> ClientBuilder {
        self.config.hickory_dns = false;
        self
    }

    /// Override DNS resolution for specific domains to a particular IP address.
    ///
    /// Warning
    ///
    /// Since the DNS protocol has no notion of ports, if you wish to send
    /// traffic to a particular port you must include this port in the URL
    /// itself, any port in the overridden addr will be ignored and traffic sent
    /// to the conventional port for the given scheme (e.g. 80 for http).
    pub fn resolve(self, domain: &str, addr: SocketAddr) -> ClientBuilder {
        self.resolve_to_addrs(domain, &[addr])
    }

    /// Override DNS resolution for specific domains to particular IP addresses.
    ///
    /// Warning
    ///
    /// Since the DNS protocol has no notion of ports, if you wish to send
    /// traffic to a particular port you must include this port in the URL
    /// itself, any port in the overridden addresses will be ignored and traffic sent
    /// to the conventional port for the given scheme (e.g. 80 for http).
    pub fn resolve_to_addrs(mut self, domain: &str, addrs: &[SocketAddr]) -> ClientBuilder {
        self.config
            .dns_overrides
            .insert(domain.to_string(), addrs.to_vec());
        self
    }

    /// Override the DNS resolver implementation.
    ///
    /// Pass an `Arc` wrapping a trait object implementing `Resolve`.
    /// Overrides for specific names passed to `resolve` and `resolve_to_addrs` will
    /// still be applied on top of this resolver.
    pub fn dns_resolver<R: Resolve + 'static>(mut self, resolver: Arc<R>) -> ClientBuilder {
        self.config.dns_resolver = Some(resolver as _);
        self
    }

    /// Sets a base URL for the client.
    ///
    /// The base URL will be used as the root for all relative request paths made by this client.
    /// If a request specifies an absolute URL, it will override the base URL.
    ///
    /// # Parameters
    /// - `base_url`: A value that can be converted into a URL, representing the base URL for the client.
    ///
    /// # Returns
    /// Returns the `ClientBuilder` with the base URL configured. If the provided `base_url` is invalid,
    /// an error is stored in the configuration, and the builder can no longer produce a valid client.
    ///
    /// # Example
    /// ```rust
    /// let client = Client::builder()
    ///     .base_url("https://api.example.com")
    ///     .build();
    ///
    /// let response = client.get("/users").send().await?; // Resolves to "https://api.example.com/users"
    /// ```
    pub fn base_url<U: IntoUrl>(mut self, base_url: U) -> ClientBuilder {
        match base_url.into_url() {
            Ok(base_url) => {
                self.config.base_url = Some(base_url);
            }
            Err(e) => {
                self.config.error = Some(e);
            }
        }
        self
    }

    /// Adds a new Tower [`Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) to the
    /// base connector [`Service`](https://docs.rs/tower/latest/tower/trait.Service.html) which
    /// is responsible for connection establishment.a
    ///
    /// Each subsequent invocation of this function will wrap previous layers.
    ///
    /// If configured, the `connect_timeout` will be the outermost layer.
    ///
    /// Example usage:
    /// ```
    /// use std::time::Duration;
    ///
    /// let client = rquest::Client::builder()
    ///                      // resolved to outermost layer, meaning while we are waiting on concurrency limit
    ///                      .connect_timeout(Duration::from_millis(200))
    ///                      // underneath the concurrency check, so only after concurrency limit lets us through
    ///                      .connector_layer(tower::timeout::TimeoutLayer::new(Duration::from_millis(50)))
    ///                      .connector_layer(tower::limit::concurrency::ConcurrencyLimitLayer::new(2))
    ///                      .build()
    ///                      .unwrap();
    /// ```
    ///
    pub fn connector_layer<L>(mut self, layer: L) -> ClientBuilder
    where
        L: Layer<BoxedConnectorService> + Clone + Send + Sync + 'static,
        L::Service:
            Service<Unnameable, Response = Conn, Error = BoxError> + Clone + Send + Sync + 'static,
        <L::Service as Service<Unnameable>>::Future: Send + 'static,
    {
        let layer = BoxCloneSyncServiceLayer::new(layer);
        self.config.connector_layers.push(layer);
        self
    }
}

type HyperClient = util::client::Client<Connector, super::Body>;

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Constructs a new `Client`.
    ///
    /// # Panics
    ///
    /// This method panics if a TLS backend cannot be initialized, or the resolver
    /// cannot load the system configuration.
    ///
    /// Use `Client::builder()` if you wish to handle the failure as an `Error`
    /// instead of panicking.
    pub fn new() -> Client {
        ClientBuilder::new().build().expect("Client::new()")
    }

    /// Create a `ClientBuilder` specifically configured for WebSocket connections.
    ///
    /// This method configures the `ClientBuilder` to use HTTP/1.0 only, which is required for certain WebSocket connections.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Convenience method to make a `GET` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn get<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    /// Upgrades the [`RequestBuilder`] to perform a
    /// websocket handshake. This returns a wrapped type, so you must do
    /// this after you set up your request, and just before you send the
    /// request.
    #[cfg(feature = "websocket")]
    pub fn websocket<U: IntoUrl>(&self, url: U) -> crate::WebSocketRequestBuilder {
        crate::WebSocketRequestBuilder::new(self.request(Method::GET, url))
    }

    /// Convenience method to make a `POST` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn post<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    /// Convenience method to make a `PUT` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn put<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::PUT, url)
    }

    /// Convenience method to make a `PATCH` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn patch<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }

    /// Convenience method to make a `DELETE` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn delete<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }

    /// Convenience method to make a `HEAD` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn head<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }

    /// Start building a `Request` with the `Method` and `Url`.
    ///
    /// Returns a `RequestBuilder`, which will allow setting headers and
    /// the request body before sending.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn request<U: IntoUrl>(&self, method: Method, url: U) -> RequestBuilder {
        let url = match self.inner.base_url {
            Some(ref base_url) => base_url.join(url.as_str()).map_err(error::builder),
            None => url.into_url(),
        };
        let req = url.map(move |url| Request::new(method, url));
        RequestBuilder::new(self.clone(), req)
    }

    /// Executes a `Request`.
    ///
    /// A `Request` can be built manually with `Request::new()` or obtained
    /// from a RequestBuilder with `RequestBuilder::build()`.
    ///
    /// You should prefer to use the `RequestBuilder` and
    /// `RequestBuilder::send()`.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while sending request,
    /// redirect loop was detected or redirect limit was exhausted.
    pub fn execute(
        &self,
        request: Request,
    ) -> impl Future<Output = Result<Response, crate::Error>> {
        self.execute_request(request)
    }

    pub(super) fn execute_request(&self, req: Request) -> Pending {
        let (
            method,
            url,
            mut headers,
            body,
            timeout,
            version,
            redirect,
            _cookie_store,
            network_scheme,
        ) = req.pieces();

        if url.scheme() != "http" && url.scheme() != "https" {
            return Pending::new_err(error::url_bad_scheme(url));
        }

        // check if we're in https_only mode and check the scheme of the current URL
        if self.inner.https_only && url.scheme() != "https" {
            return Pending::new_err(error::url_bad_scheme(url));
        }

        // insert default headers in the request headers
        // without overwriting already appended headers.
        for (key, value) in self.inner.headers.iter() {
            if let Entry::Vacant(entry) = headers.entry(key) {
                entry.insert(value.clone());
            }
        }

        #[cfg(feature = "cookies")]
        let cookie_store = _cookie_store
            .as_ref()
            .or_else(|| self.inner.cookie_store.as_ref());

        // Add cookies from the cookie store.
        #[cfg(feature = "cookies")]
        {
            if let Some(cookie_store) = cookie_store {
                if headers.get(crate::header::COOKIE).is_none() {
                    add_cookie_header(&mut headers, &**cookie_store, &url);
                }
            }
        }

        let accept_encoding = self.inner.accepts.as_str();

        if let Some(accept_encoding) = accept_encoding {
            if !headers.contains_key(ACCEPT_ENCODING) && !headers.contains_key(RANGE) {
                headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(accept_encoding));
            }
        }

        let uri = match try_uri(&url) {
            Some(uri) => uri,
            None => return Pending::new_err(error::url_bad_uri(url)),
        };

        let (reusable, body) = match body {
            Some(body) => {
                let (reusable, body) = body.try_reuse();
                (Some(reusable), body)
            }
            None => (None, Body::empty()),
        };

        self.inner.proxy_auth(&uri, &mut headers);

        let in_flight = {
            let req = InnerRequest::<Body>::builder()
                .network_scheme(self.inner.network_scheme(&uri, &network_scheme))
                .uri(uri)
                .method(method.clone())
                .version(version)
                .headers(headers.clone())
                .headers_order(self.inner.headers_order.as_deref())
                .body(body);

            ResponseFuture::Default(self.inner.hyper.request(req))
        };

        let total_timeout = timeout
            .or(self.inner.request_timeout)
            .map(tokio::time::sleep)
            .map(Box::pin);

        let read_timeout_fut = self
            .inner
            .read_timeout
            .map(tokio::time::sleep)
            .map(Box::pin);

        Pending {
            inner: PendingInner::Request(PendingRequest {
                method,
                url,
                headers,
                body: reusable,
                version,
                urls: Vec::new(),
                retry_count: 0,
                max_retry_count: self.inner.http2_max_retry_count,
                redirect,
                cookie_store: _cookie_store,
                network_scheme,
                client: self.inner.clone(),
                in_flight,
                total_timeout,
                read_timeout_fut,
                read_timeout: self.inner.read_timeout,
            }),
        }
    }

    /// Get the client user agent
    pub fn user_agent(&self) -> Option<&HeaderValue> {
        self.inner.headers.get(USER_AGENT)
    }

    /// Get a mutable reference to the headers for this client.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        self.inner_mut().headers.to_mut()
    }

    /// Returns a `String` of the header-value of all `Cookie` in a `Url`.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error parsing the cookies.
    #[cfg(feature = "cookies")]
    pub fn get_cookies<U: IntoUrl>(&self, url: U) -> Result<Option<HeaderValue>, error::Error> {
        // Parse the URL
        let target_url = url.into_url()?;

        // Check if the cookie_store is set
        let result = self
            .inner
            .cookie_store
            .as_ref()
            .and_then(|cookie_store| cookie_store.cookies(&target_url));

        Ok(result)
    }

    /// Injects a 'Cookie' into the 'CookieStore' for the specified URL.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error parsing the cookies.
    #[cfg(feature = "cookies")]
    pub fn set_cookies<U: IntoUrl>(
        &self,
        cookies: Vec<HeaderValue>,
        url: U,
    ) -> Result<(), error::Error> {
        // Parse the URL
        let target_url = url.into_url()?;

        // Check if the cookie_store is set
        if let Some(ref cookie_store) = self.inner.cookie_store {
            let mut iter = cookies.iter();
            cookie_store.set_cookies(&mut iter, &target_url);
        }

        Ok(())
    }
    /// Set the cookie provider for this client.
    #[cfg(feature = "cookies")]
    #[inline]
    pub fn set_cookie_provider<C: cookie::CookieStore + 'static>(&mut self, cookie_store: Arc<C>) {
        std::mem::swap(
            &mut self.inner_mut().cookie_store,
            &mut Some(cookie_store as _),
        );
    }

    /// Set the proxies for this client.
    ///
    /// Returns the old proxies.
    #[inline]
    pub fn set_proxies(&mut self, proxies: impl Into<Option<Vec<Proxy>>>) {
        let inner = self.inner_mut();
        match proxies.into() {
            Some(mut proxies) => {
                inner.proxies_maybe_http_auth = proxies.iter().any(|p| p.maybe_has_http_auth());
                std::mem::swap(&mut inner.proxies, &mut proxies);
            }
            None => {
                inner.proxies_maybe_http_auth = false;
                inner.proxies.clear();
            }
        }
    }

    /// Set that all sockets are bound to the configured address before connection.
    ///
    /// If `None`, the sockets will not be bound.
    ///
    /// Default is `None`.
    #[inline]
    pub fn set_local_address<T>(&mut self, addr: T)
    where
        T: Into<Option<IpAddr>>,
    {
        let inner = self.inner_mut();
        match addr.into() {
            Some(IpAddr::V4(a)) => inner.local_addr_v4 = Some(a),
            Some(IpAddr::V6(a)) => inner.local_addr_v6 = Some(a),
            _ => (),
        }
    }

    /// Set that all sockets are bound to the configured IPv4 or IPv6 address
    /// (depending on host's preferences) before connection.
    #[inline]
    pub fn set_local_addresses(&mut self, addr_ipv4: Ipv4Addr, addr_ipv6: Ipv6Addr) {
        let inner = self.inner_mut();
        inner.local_addr_v4 = Some(addr_ipv4);
        inner.local_addr_v6 = Some(addr_ipv6);
    }

    /// Bind to an interface by `SO_BINDTODEVICE`.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[inline]
    pub fn set_interface(&mut self, interface: impl Into<std::borrow::Cow<'static, str>>) {
        self.inner_mut().interface = Some(interface.into());
    }

    /// Set the headers order for this client.
    pub fn set_headers_order(&mut self, order: impl Into<Cow<'static, [HeaderName]>>) {
        std::mem::swap(&mut self.inner_mut().headers_order, &mut Some(order.into()));
    }

    /// Set the redirect policy for this client.
    pub fn set_redirect(&mut self, policy: impl Into<redirect::Policy>) {
        std::mem::swap(&mut self.inner_mut().redirect, &mut policy.into());
    }

    /// Set the bash url for this client.
    pub fn set_base_url<U: IntoUrl>(&mut self, url: U) {
        if let Ok(url) = url.into_url() {
            std::mem::swap(&mut self.inner_mut().base_url, &mut Some(url));
        }
    }

    /// Set the impersonate for this client.
    #[inline]
    pub fn set_impersonate(&mut self, var: Impersonate) -> crate::Result<()> {
        let settings = tls::tls_settings(var, true);
        self.impersonate_settings(settings)
    }

    /// Set the impersonate for this client without setting the headers.
    #[inline]
    pub fn set_impersonate_skip_headers(&mut self, var: Impersonate) -> crate::Result<()> {
        let settings = tls::tls_settings(var, false);
        self.impersonate_settings(settings)
    }

    /// Set the impersonate for this client with the given settings.
    #[cfg(feature = "impersonate_settings")]
    #[inline]
    pub fn set_impersonate_settings(&mut self, settings: ImpersonateSettings) -> crate::Result<()> {
        self.impersonate_settings(settings)
    }

    /// Apply the impersonate settings to the client.
    #[inline]
    fn impersonate_settings(&mut self, mut settings: ImpersonateSettings) -> crate::Result<()> {
        let inner = self.inner_mut();

        // Set the headers
        if let Some(mut headers) = settings.headers {
            std::mem::swap(&mut inner.headers, &mut headers);
        }

        // Set the headers order if needed
        std::mem::swap(&mut inner.headers_order, &mut settings.headers_order);

        let hyper = &mut inner.hyper;

        // Set the connector
        let connector = BoringTlsConnector::new(settings.tls)?;
        hyper.with_connector(|c| c.set_connector(connector));

        // Set the http2 preference
        hyper.with_http2_builder(|builder| {
            let http2_headers_priority =
                crate::util::convert_headers_priority(settings.http2.headers_priority);

            builder
                .initial_stream_id(settings.http2.initial_stream_id)
                .initial_stream_window_size(settings.http2.initial_stream_window_size)
                .initial_connection_window_size(settings.http2.initial_connection_window_size)
                .max_concurrent_streams(settings.http2.max_concurrent_streams)
                .header_table_size(settings.http2.header_table_size)
                .max_frame_size(settings.http2.max_frame_size)
                .headers_priority(http2_headers_priority)
                .headers_pseudo_order(settings.http2.headers_pseudo_order)
                .settings_order(settings.http2.settings_order);

            if let Some(max_header_list_size) = settings.http2.max_header_list_size {
                builder.max_header_list_size(max_header_list_size);
            }

            if let Some(enable_push) = settings.http2.enable_push {
                builder.enable_push(enable_push);
            }

            if let Some(unknown_setting8) = settings.http2.unknown_setting8 {
                builder.unknown_setting8(unknown_setting8);
            }

            if let Some(unknown_setting9) = settings.http2.unknown_setting9 {
                builder.unknown_setting9(unknown_setting9);
            }
        });

        Ok(())
    }

    /// private mut ref to inner
    fn inner_mut(&mut self) -> &mut ClientRef {
        Arc::make_mut(&mut self.inner)
    }
}

impl tower_service::Service<Request> for Client {
    type Response = Response;
    type Error = crate::Error;
    type Future = Pending;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        self.execute_request(req)
    }
}

impl tower_service::Service<Request> for &'_ Client {
    type Response = Response;
    type Error = crate::Error;
    type Future = Pending;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        self.execute_request(req)
    }
}

impl tower_service::Service<http::Request<Body>> for Client {
    type Response = http::Response<Body>;
    type Error = crate::Error;
    type Future = MappedPending;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        match req.try_into() {
            Ok(req) => MappedPending::new(self.execute_request(req)),
            Err(err) => MappedPending::new(Pending::new_err(err)),
        }
    }
}

pin_project! {
    pub struct MappedPending {
        #[pin]
        inner: Pending,
    }
}

impl MappedPending {
    fn new(inner: Pending) -> MappedPending {
        Self { inner }
    }
}

impl Future for MappedPending {
    type Output = Result<http::Response<Body>, crate::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.project().inner;
        inner.poll(cx).map_ok(Into::into)
    }
}

impl_debug!(
    Config,
    {
        accepts,
        headers,
        headers_order,
        proxies,
        redirect_policy,
        accepts,
        referer,
        timeout,
        connect_timeout,
        https_only,
        nodelay,
        local_address_ipv4,
        local_address_ipv6,
        dns_overrides,
        base_url,
        builder
    }
);

#[derive(Clone)]
struct ClientRef {
    accepts: Accepts,
    #[cfg(feature = "cookies")]
    cookie_store: Option<Arc<dyn cookie::CookieStore>>,
    headers: Cow<'static, HeaderMap>,
    headers_order: Option<Cow<'static, [HeaderName]>>,
    hyper: HyperClient,
    redirect: redirect::Policy,
    referer: bool,
    request_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    https_only: bool,
    proxies_maybe_http_auth: bool,
    base_url: Option<Url>,
    http2_max_retry_count: usize,

    proxies: Vec<Proxy>,
    local_addr_v4: Option<Ipv4Addr>,
    local_addr_v6: Option<Ipv6Addr>,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    interface: Option<std::borrow::Cow<'static, str>>,
}

impl_debug!(
    ClientRef,
    {
        accepts,
        headers,
        headers_order,
        hyper,
        redirect,
        referer,
        request_timeout,
        read_timeout,
        https_only,
        proxies_maybe_http_auth,
        base_url
    }
);

impl ClientRef {
    #[inline]
    fn proxy_auth(&self, dst: &Uri, headers: &mut HeaderMap) {
        if !self.proxies_maybe_http_auth {
            return;
        }

        // Only set the header here if the destination scheme is 'http',
        // since otherwise, the header will be included in the CONNECT tunnel
        // request instead.
        if dst.scheme() != Some(&Scheme::HTTP) || headers.contains_key(PROXY_AUTHORIZATION) {
            return;
        }

        // Find the first proxy that matches the destination URI
        // If a matching proxy provides an HTTP basic auth header, insert it into the headers
        if let Some(header) = self
            .proxies
            .iter()
            .find(|proxy| proxy.maybe_has_http_auth() && proxy.is_match(dst))
            .and_then(|proxy| proxy.http_basic_auth(dst))
        {
            headers.insert(PROXY_AUTHORIZATION, header);
        }
    }

    #[inline]
    fn network_scheme(&self, uri: &Uri, network_scheme: &NetworkScheme) -> NetworkScheme {
        match network_scheme {
            NetworkScheme::None => {
                // Create the NetworkScheme builder based on the target OS
                let builder = {
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    {
                        NetworkScheme::builder().iface((
                            self.interface.clone(),
                            (self.local_addr_v4, self.local_addr_v6),
                        ))
                    }

                    #[cfg(not(any(
                        target_os = "android",
                        target_os = "fuchsia",
                        target_os = "linux"
                    )))]
                    NetworkScheme::builder().iface((self.local_addr_v4, self.local_addr_v6))
                };

                // iterate over the client's proxies and use the first valid one
                for proxy in self.proxies.iter() {
                    if let Some(proxy_scheme) = proxy.intercept(uri) {
                        return builder.proxy(proxy_scheme).build();
                    }
                }

                builder.build()
            }
            _ => network_scheme.clone(),
        }
    }
}

pin_project! {
    pub struct Pending {
        #[pin]
        inner: PendingInner,
    }
}

enum PendingInner {
    Request(PendingRequest),
    Error(Option<crate::Error>),
}

pin_project! {
    struct PendingRequest {
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Option<Bytes>>,

        version: Option<Version>,

        urls: Vec<Url>,

        retry_count: usize,
        max_retry_count: usize,

        redirect: Option<redirect::Policy>,

        cookie_store: CookieStoreOption,

        network_scheme: NetworkScheme,

        client: Arc<ClientRef>,

        #[pin]
        in_flight: ResponseFuture,
        #[pin]
        total_timeout: Option<Pin<Box<Sleep>>>,
        #[pin]
        read_timeout_fut: Option<Pin<Box<Sleep>>>,
        read_timeout: Option<Duration>,
    }
}

enum ResponseFuture {
    Default(HyperResponseFuture),
}

impl PendingRequest {
    fn in_flight(self: Pin<&mut Self>) -> Pin<&mut ResponseFuture> {
        self.project().in_flight
    }

    fn total_timeout(self: Pin<&mut Self>) -> Pin<&mut Option<Pin<Box<Sleep>>>> {
        self.project().total_timeout
    }

    fn read_timeout(self: Pin<&mut Self>) -> Pin<&mut Option<Pin<Box<Sleep>>>> {
        self.project().read_timeout_fut
    }

    fn urls(self: Pin<&mut Self>) -> &mut Vec<Url> {
        self.project().urls
    }

    fn headers(self: Pin<&mut Self>) -> &mut HeaderMap {
        self.project().headers
    }

    fn retry_error(mut self: Pin<&mut Self>, err: &(dyn std::error::Error + 'static)) -> bool {
        if !is_retryable_error(err) {
            return false;
        }

        trace!("can retry {:?}", err);

        let body = match self.body {
            Some(Some(ref body)) => Body::reusable(body.clone()),
            Some(None) => {
                debug!("error was retryable, but body not reusable");
                return false;
            }
            None => Body::empty(),
        };

        if self.retry_count >= self.max_retry_count {
            trace!("retry count too high");
            return false;
        }
        self.retry_count += 1;

        let uri = match try_uri(&self.url) {
            Some(uri) => uri,
            None => {
                debug!("a parsed Url should always be a valid Uri: {}", self.url);
                return false;
            }
        };

        *self.as_mut().in_flight().get_mut() = {
            let req = InnerRequest::<Body>::builder()
                .network_scheme(self.client.network_scheme(&uri, &self.network_scheme))
                .uri(uri)
                .method(self.method.clone())
                .version(self.version)
                .headers(self.headers.clone())
                .headers_order(self.client.headers_order.as_deref())
                .body(body);
            ResponseFuture::Default(self.client.hyper.request(req))
        };

        true
    }
}

fn is_retryable_error(err: &(dyn std::error::Error + 'static)) -> bool {
    use hyper2::h2;

    // pop the legacy::Error
    let err = if let Some(err) = err.source() {
        err
    } else {
        return false;
    };

    if let Some(cause) = err.source() {
        if let Some(err) = cause.downcast_ref::<h2::Error>() {
            // They sent us a graceful shutdown, try with a new connection!
            if err.is_go_away() && err.is_remote() && err.reason() == Some(h2::Reason::NO_ERROR) {
                return true;
            }

            // REFUSED_STREAM was sent from the server, which is safe to retry.
            // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.7-3.2
            if err.is_reset() && err.is_remote() && err.reason() == Some(h2::Reason::REFUSED_STREAM)
            {
                return true;
            }
        }
    }
    false
}

impl Pending {
    pub(super) fn new_err(err: crate::Error) -> Pending {
        Pending {
            inner: PendingInner::Error(Some(err)),
        }
    }

    fn inner(self: Pin<&mut Self>) -> Pin<&mut PendingInner> {
        self.project().inner
    }
}

impl Future for Pending {
    type Output = Result<Response, crate::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.inner();
        match inner.get_mut() {
            PendingInner::Request(ref mut req) => Pin::new(req).poll(cx),
            PendingInner::Error(ref mut err) => Poll::Ready(Err(err
                .take()
                .expect("Pending error polled more than once"))),
        }
    }
}

impl Future for PendingRequest {
    type Output = Result<Response, crate::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(delay) = self.as_mut().total_timeout().as_mut().as_pin_mut() {
            if let Poll::Ready(()) = delay.poll(cx) {
                return Poll::Ready(Err(
                    crate::error::request(crate::error::TimedOut).with_url(self.url.clone())
                ));
            }
        }

        if let Some(delay) = self.as_mut().read_timeout().as_mut().as_pin_mut() {
            if let Poll::Ready(()) = delay.poll(cx) {
                return Poll::Ready(Err(
                    crate::error::request(crate::error::TimedOut).with_url(self.url.clone())
                ));
            }
        }

        loop {
            let res = match self.as_mut().in_flight().get_mut() {
                ResponseFuture::Default(r) => match Pin::new(r).poll(cx) {
                    Poll::Ready(Err(e)) => {
                        if self.as_mut().retry_error(&e) {
                            continue;
                        }
                        return Poll::Ready(Err(
                            crate::error::request(e).with_url(self.url.clone())
                        ));
                    }
                    Poll::Ready(Ok(res)) => res.map(super::body::boxed),
                    Poll::Pending => return Poll::Pending,
                },
            };

            #[cfg(feature = "cookies")]
            let cookie_store = self
                .cookie_store
                .as_ref()
                .or_else(|| self.client.cookie_store.as_ref());

            #[cfg(feature = "cookies")]
            {
                if let Some(ref cookie_store) = cookie_store {
                    let mut cookies =
                        cookie::extract_response_cookie_headers(&res.headers()).peekable();
                    if cookies.peek().is_some() {
                        cookie_store.set_cookies(&mut cookies, &self.url);
                    }
                }
            }

            let previous_method = self.method.clone();

            let should_redirect = match res.status() {
                StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER => {
                    self.body = None;
                    for header in &[
                        TRANSFER_ENCODING,
                        CONTENT_ENCODING,
                        CONTENT_TYPE,
                        CONTENT_LENGTH,
                    ] {
                        self.headers.remove(header);
                    }

                    match self.method {
                        Method::GET | Method::HEAD => {}
                        _ => {
                            self.method = Method::GET;
                        }
                    }
                    true
                }
                StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => {
                    match self.body {
                        Some(Some(_)) | None => true,
                        Some(None) => false,
                    }
                }
                _ => false,
            };

            if should_redirect {
                let loc = res.headers().get(LOCATION).and_then(|val| {
                    let loc = (|| -> Option<Url> {
                        // Some sites may send a utf-8 Location header,
                        // even though we're supposed to treat those bytes
                        // as opaque, we'll check specifically for utf8.
                        self.url.join(str::from_utf8(val.as_bytes()).ok()?).ok()
                    })();

                    // Check that the `url` is also a valid `http::Uri`.
                    //
                    // If not, just log it and skip the redirect.
                    let loc = loc.and_then(|url| {
                        if try_uri(&url).is_some() {
                            Some(url)
                        } else {
                            None
                        }
                    });

                    if loc.is_none() {
                        debug!("Location header had invalid URI: {:?}", val);
                    }
                    loc
                });
                if let Some(loc) = loc {
                    if self.client.referer {
                        if let Some(referer) = make_referer(&loc, &self.url) {
                            self.headers.insert(REFERER, referer);
                        }
                    }
                    let url = self.url.clone();
                    self.as_mut().urls().push(url);
                    let action = self
                        .redirect
                        .as_ref()
                        .unwrap_or(&self.client.redirect)
                        .check(
                            res.status(),
                            &self.method,
                            &loc,
                            &previous_method,
                            &self.urls,
                        );

                    match action {
                        redirect::ActionKind::Follow => {
                            debug!("redirecting '{}' to '{}'", self.url, loc);

                            if loc.scheme() != "http" && loc.scheme() != "https" {
                                return Poll::Ready(Err(error::url_bad_scheme(loc)));
                            }

                            if self.client.https_only && loc.scheme() != "https" {
                                return Poll::Ready(Err(error::redirect(
                                    error::url_bad_scheme(loc.clone()),
                                    loc,
                                )));
                            }

                            self.url = loc;
                            let mut headers =
                                std::mem::replace(self.as_mut().headers(), HeaderMap::new());

                            remove_sensitive_headers(&mut headers, &self.url, &self.urls);
                            let uri = match try_uri(&self.url) {
                                Some(uri) => uri,
                                None => {
                                    return Poll::Ready(Err(error::url_bad_uri(self.url.clone())));
                                }
                            };
                            let body = match self.body {
                                Some(Some(ref body)) => Body::reusable(body.clone()),
                                _ => Body::empty(),
                            };

                            #[cfg(feature = "cookies")]
                            let cookie_store = self
                                .cookie_store
                                .as_ref()
                                .or_else(|| self.client.cookie_store.as_ref());

                            // Add cookies from the cookie store.
                            #[cfg(feature = "cookies")]
                            {
                                if let Some(cookie_store) = cookie_store {
                                    add_cookie_header(&mut headers, &**cookie_store, &self.url);
                                }
                            }

                            self.client.proxy_auth(&uri, &mut headers);

                            *self.as_mut().in_flight().get_mut() = {
                                let req = InnerRequest::<Body>::builder()
                                    .network_scheme(
                                        self.client.network_scheme(&uri, &self.network_scheme),
                                    )
                                    .uri(uri)
                                    .method(self.method.clone())
                                    .version(self.version)
                                    .headers(headers.clone())
                                    .headers_order(self.client.headers_order.as_deref())
                                    .body(body);
                                std::mem::swap(self.as_mut().headers(), &mut headers);
                                ResponseFuture::Default(self.client.hyper.request(req))
                            };

                            continue;
                        }
                        redirect::ActionKind::Stop => {
                            debug!("redirect policy disallowed redirection to '{}'", loc);
                        }
                        redirect::ActionKind::Error(err) => {
                            return Poll::Ready(Err(crate::error::redirect(err, self.url.clone())));
                        }
                    }
                }
            }

            let res = Response::new(
                res,
                self.url.clone(),
                self.client.accepts,
                self.total_timeout.take(),
                self.read_timeout,
            );
            return Poll::Ready(Ok(res));
        }
    }
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.inner {
            PendingInner::Request(ref req) => f
                .debug_struct("Pending")
                .field("method", &req.method)
                .field("url", &req.url)
                .finish(),
            PendingInner::Error(ref err) => f.debug_struct("Pending").field("error", err).finish(),
        }
    }
}

fn make_referer(next: &Url, previous: &Url) -> Option<HeaderValue> {
    if next.scheme() == "http" && previous.scheme() == "https" {
        return None;
    }

    let mut referer = previous.clone();
    let _ = referer.set_username("");
    let _ = referer.set_password(None);
    referer.set_fragment(None);
    referer.as_str().parse().ok()
}

#[cfg(feature = "cookies")]
fn add_cookie_header(headers: &mut HeaderMap, cookie_store: &dyn cookie::CookieStore, url: &Url) {
    if let Some(header) = cookie_store.cookies(url) {
        headers.insert(crate::header::COOKIE, header);
    }
}
