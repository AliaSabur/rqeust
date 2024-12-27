use std::convert::TryFrom;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use http::{request::Parts, Request as HttpRequest, Version};
use serde::Serialize;
#[cfg(feature = "json")]
use serde_json;

use super::body::Body;
use super::http::{Client, Pending};
#[cfg(feature = "multipart")]
use super::multipart;
use super::response::Response;
#[cfg(feature = "cookies")]
use crate::cookie;
use crate::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, HOST};
use crate::proxy::ProxyScheme;
use crate::util::client::NetworkScheme;
use crate::{redirect, IntoUrl, Method, Proxy, Url};
#[cfg(feature = "cookies")]
use std::sync::Arc;

#[cfg(not(feature = "cookies"))]
type PiecesWithCookieStore = (
    Method,
    Url,
    HeaderMap,
    Option<Body>,
    Option<Duration>,
    Option<Version>,
    Option<redirect::Policy>,
    (),
    NetworkScheme,
);

#[cfg(feature = "cookies")]
type PiecesWithCookieStore = (
    Method,
    Url,
    HeaderMap,
    Option<Body>,
    Option<Duration>,
    Option<Version>,
    Option<redirect::Policy>,
    Option<Arc<dyn cookie::CookieStore>>,
    NetworkScheme,
);

/// A request which can be executed with `Client::execute()`.
pub struct Request {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Option<Body>,
    timeout: Option<Duration>,
    version: Option<Version>,
    redirect: Option<redirect::Policy>,
    #[cfg(feature = "cookies")]
    cookie_store: Option<Arc<dyn cookie::CookieStore>>,
    proxy_scheme: Option<ProxyScheme>,
    local_addr_v4: Option<Ipv4Addr>,
    local_addr_v6: Option<Ipv6Addr>,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    interface: Option<std::borrow::Cow<'static, str>>,
}

/// A builder to construct the properties of a `Request`.
///
/// To construct a `RequestBuilder`, refer to the `Client` documentation.
#[must_use = "RequestBuilder does nothing until you 'send' it"]
pub struct RequestBuilder {
    client: Client,
    request: crate::Result<Request>,
}

impl Request {
    /// Constructs a new request.
    #[inline]
    pub fn new(method: Method, url: Url) -> Self {
        Request {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
            timeout: None,
            version: None,
            redirect: None,
            #[cfg(feature = "cookies")]
            cookie_store: None,
            proxy_scheme: None,
            local_addr_v4: None,
            local_addr_v6: None,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            interface: None,
        }
    }

    /// Get the method.
    #[inline]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Get a mutable reference to the method.
    #[inline]
    pub fn method_mut(&mut self) -> &mut Method {
        &mut self.method
    }

    /// Get the url.
    #[inline]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Get a mutable reference to the url.
    #[inline]
    pub fn url_mut(&mut self) -> &mut Url {
        &mut self.url
    }

    /// Get the headers.
    #[inline]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Get a mutable reference to the headers.
    #[inline]
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    /// Get the body.
    #[inline]
    pub fn body(&self) -> Option<&Body> {
        self.body.as_ref()
    }

    /// Get a mutable reference to the body.
    #[inline]
    pub fn body_mut(&mut self) -> &mut Option<Body> {
        &mut self.body
    }

    /// Get the timeout.
    #[inline]
    pub fn timeout(&self) -> Option<&Duration> {
        self.timeout.as_ref()
    }

    /// Get a mutable reference to the timeout.
    #[inline]
    pub fn timeout_mut(&mut self) -> &mut Option<Duration> {
        &mut self.timeout
    }

    /// Get the http version.
    #[inline]
    pub fn version(&self) -> Option<Version> {
        self.version
    }

    /// Get a mutable reference to the http version.
    #[inline]
    pub fn version_mut(&mut self) -> &mut Option<Version> {
        &mut self.version
    }

    /// Attempt to clone the request.
    ///
    /// `None` is returned if the request can not be cloned, i.e. if the body is a stream.
    pub fn try_clone(&self) -> Option<Request> {
        let body = match self.body.as_ref() {
            Some(body) => Some(body.try_clone()?),
            None => None,
        };
        let mut req = Request::new(self.method().clone(), self.url().clone());
        *req.timeout_mut() = self.timeout().copied();
        *req.headers_mut() = self.headers().clone();
        *req.version_mut() = self.version();
        req.body = body;
        Some(req)
    }

    pub(super) fn pieces(self) -> PiecesWithCookieStore {
        // Create the NetworkScheme builder based on the target OS
        let network_scheme = {
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            {
                NetworkScheme::builder()
                    .proxy(self.proxy_scheme)
                    .iface((
                        self.interface.clone(),
                        (self.local_addr_v4, self.local_addr_v6),
                    ))
                    .build()
            }

            #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
            NetworkScheme::builder()
                .proxy(self.proxy_scheme)
                .iface((self.local_addr_v4, self.local_addr_v6))
                .build()
        };
        (
            self.method,
            self.url,
            self.headers,
            self.body,
            self.timeout,
            self.version,
            self.redirect,
            #[cfg(feature = "cookies")]
            self.cookie_store,
            #[cfg(not(feature = "cookies"))]
            (),
            network_scheme,
        )
    }
}

impl RequestBuilder {
    pub(super) fn new(client: Client, request: crate::Result<Request>) -> RequestBuilder {
        let mut builder = RequestBuilder { client, request };

        let auth = builder
            .request
            .as_mut()
            .ok()
            .and_then(|req| extract_authority(&mut req.url));

        if let Some((username, password)) = auth {
            builder.basic_auth(username, password)
        } else {
            builder
        }
    }

    /// Assemble a builder starting from an existing `Client` and a `Request`.
    pub fn from_parts(client: Client, request: Request) -> RequestBuilder {
        RequestBuilder {
            client,
            request: crate::Result::Ok(request),
        }
    }

    /// Add a `Header` to this Request.
    pub fn header<K, V>(self, key: K, value: V) -> RequestBuilder
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.header_sensitive(key, value, false)
    }

    /// Add a `Header` to this Request with ability to define if `header_value` is sensitive.
    fn header_sensitive<K, V>(mut self, key: K, value: V, sensitive: bool) -> RequestBuilder
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        let mut error = None;
        if let Ok(ref mut req) = self.request {
            match <HeaderName as TryFrom<K>>::try_from(key) {
                Ok(key) => match <HeaderValue as TryFrom<V>>::try_from(value) {
                    Ok(mut value) => {
                        // We want to potentially make an unsensitive header
                        // to be sensitive, not the reverse. So, don't turn off
                        // a previously sensitive header.
                        if sensitive {
                            value.set_sensitive(true);
                        }
                        req.headers_mut().append(key, value);
                    }
                    Err(e) => error = Some(crate::error::builder(e.into())),
                },
                Err(e) => error = Some(crate::error::builder(e.into())),
            };
        }
        if let Some(err) = error {
            self.request = Err(err);
        }
        self
    }

    /// Add a set of Headers to the existing ones on this Request.
    ///
    /// The headers will be merged in to any already set.
    pub fn headers(mut self, headers: crate::header::HeaderMap) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            crate::util::replace_headers(req.headers_mut(), headers);
        }
        self
    }

    /// If the URL is not a full URL, this will append the host header to the request.
    ///
    /// This is useful when you want to append the host header to the request
    /// when the URL is not a full URL.
    pub fn with_host_header(mut self) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            let authority = req.url().authority();
            if authority.is_empty() {
                return self;
            }
            if let Ok(host_with_port) = authority.parse::<HeaderValue>() {
                return self.header_sensitive(HOST, host_with_port, false);
            }
        }
        self
    }

    /// Enable HTTP basic authentication.
    ///
    /// ```rust
    /// # use rquest::Error;
    ///
    /// # async fn run() -> Result<(), Error> {
    /// let client = rquest::Client::new();
    /// let resp = client.delete("http://httpbin.org/delete")
    ///     .basic_auth("admin", Some("good password"))
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn basic_auth<U, P>(self, username: U, password: Option<P>) -> RequestBuilder
    where
        U: fmt::Display,
        P: fmt::Display,
    {
        let header_value = crate::util::basic_auth(username, password);
        self.header_sensitive(crate::header::AUTHORIZATION, header_value, true)
    }

    /// Enable HTTP bearer authentication.
    pub fn bearer_auth<T>(self, token: T) -> RequestBuilder
    where
        T: fmt::Display,
    {
        let header_value = format!("Bearer {}", token);
        self.header_sensitive(crate::header::AUTHORIZATION, header_value, true)
    }

    /// Set the request body.
    pub fn body<T: Into<Body>>(mut self, body: T) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            *req.body_mut() = Some(body.into());
        }
        self
    }

    /// Enables a request timeout.
    ///
    /// The timeout is applied from when the request starts connecting until the
    /// response body has finished. It affects only this request and overrides
    /// the timeout configured using `ClientBuilder::timeout()`.
    pub fn timeout(mut self, timeout: Duration) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            *req.timeout_mut() = Some(timeout);
        }
        self
    }

    /// Sends a multipart/form-data body.
    ///
    /// ```
    /// # use rquest::Error;
    ///
    /// # async fn run() -> Result<(), Error> {
    /// let client = rquest::Client::new();
    /// let form = rquest::multipart::Form::new()
    ///     .text("key3", "value3")
    ///     .text("key4", "value4");
    ///
    ///
    /// let response = client.post("your url")
    ///     .multipart(form)
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "multipart")]
    #[cfg_attr(docsrs, doc(cfg(feature = "multipart")))]
    pub fn multipart(self, mut multipart: multipart::Form) -> RequestBuilder {
        let mut builder = self.header(
            CONTENT_TYPE,
            format!("multipart/form-data; boundary={}", multipart.boundary()).as_str(),
        );

        builder = match multipart.compute_length() {
            Some(length) => builder.header(http::header::CONTENT_LENGTH, length),
            None => builder,
        };

        if let Ok(ref mut req) = builder.request {
            *req.body_mut() = Some(multipart.stream())
        }
        builder
    }

    /// Modify the query string of the URL.
    ///
    /// Modifies the URL of this request, adding the parameters provided.
    /// This method appends and does not overwrite. This means that it can
    /// be called multiple times and that existing query parameters are not
    /// overwritten if the same key is used. The key will simply show up
    /// twice in the query string.
    /// Calling `.query(&[("foo", "a"), ("foo", "b")])` gives `"foo=a&foo=b"`.
    ///
    /// # Note
    /// This method does not support serializing a single key-value
    /// pair. Instead of using `.query(("key", "val"))`, use a sequence, such
    /// as `.query(&[("key", "val")])`. It's also possible to serialize structs
    /// and maps into a key-value pair.
    ///
    /// # Errors
    /// This method will fail if the object you provide cannot be serialized
    /// into a query string.
    pub fn query<T: Serialize + ?Sized>(mut self, query: &T) -> RequestBuilder {
        let mut error = None;
        if let Ok(ref mut req) = self.request {
            let url = req.url_mut();
            let mut pairs = url.query_pairs_mut();
            let serializer = serde_urlencoded::Serializer::new(&mut pairs);

            if let Err(err) = query.serialize(serializer) {
                error = Some(crate::error::builder(err));
            }
        }
        if let Ok(ref mut req) = self.request {
            if let Some("") = req.url().query() {
                req.url_mut().set_query(None);
            }
        }
        if let Some(err) = error {
            self.request = Err(err);
        }
        self
    }

    /// Set HTTP version
    pub fn version(mut self, version: Version) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            req.version = Some(version);
        }
        self
    }

    /// Set the redirect policy for this request.
    pub fn redirect(mut self, policy: redirect::Policy) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            req.redirect = Some(policy)
        }
        self
    }

    /// Set the proxy for this request.
    pub fn proxy(mut self, proxy: impl IntoUrl) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            if let Some(err) = proxy
                .into_url()
                .and_then(Proxy::all)
                .map(|proxy| req.proxy_scheme = proxy.intercept(req.url()))
                .err()
            {
                self.request = Err(crate::error::builder(err));
            }
        }
        self
    }

    /// Set the local address for this request.
    pub fn local_address(mut self, local_address: impl Into<IpAddr>) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            match local_address.into() {
                IpAddr::V4(addr) => req.local_addr_v4 = Some(addr),
                IpAddr::V6(addr) => req.local_addr_v6 = Some(addr),
            }
        }
        self
    }

    /// Set the local addresses for this request.
    pub fn local_addresses(
        mut self,
        ipv4: impl Into<Ipv4Addr>,
        ipv6: impl Into<Ipv6Addr>,
    ) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            req.local_addr_v4 = Some(ipv4.into());
            req.local_addr_v6 = Some(ipv6.into());
        }
        self
    }

    /// Set the interface for this request.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn interface(
        mut self,
        interface: impl Into<std::borrow::Cow<'static, str>>,
    ) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            req.interface = Some(interface.into());
        }
        self
    }

    /// Set the cookie store for this request.
    #[cfg(feature = "cookies")]
    pub fn cookie_store(mut self, cookie_store: Arc<dyn cookie::CookieStore>) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            req.cookie_store = Some(cookie_store);
        }
        self
    }

    /// Send a form body.
    ///
    /// Sets the body to the url encoded serialization of the passed value,
    /// and also sets the `Content-Type: application/x-www-form-urlencoded`
    /// header.
    ///
    /// ```rust
    /// # use rquest::Error;
    /// # use std::collections::HashMap;
    /// #
    /// # async fn run() -> Result<(), Error> {
    /// let mut params = HashMap::new();
    /// params.insert("lang", "rust");
    ///
    /// let client = rquest::Client::new();
    /// let res = client.post("http://httpbin.org")
    ///     .form(&params)
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// This method fails if the passed value cannot be serialized into
    /// url encoded format
    pub fn form<T: Serialize + ?Sized>(mut self, form: &T) -> RequestBuilder {
        let mut error = None;
        if let Ok(ref mut req) = self.request {
            match serde_urlencoded::to_string(form) {
                Ok(body) => {
                    req.headers_mut().insert(
                        CONTENT_TYPE,
                        HeaderValue::from_static("application/x-www-form-urlencoded"),
                    );
                    *req.body_mut() = Some(body.into());
                }
                Err(err) => error = Some(crate::error::builder(err)),
            }
        }
        if let Some(err) = error {
            self.request = Err(err);
        }
        self
    }

    /// Send a JSON body.
    ///
    /// # Optional
    ///
    /// This requires the optional `json` feature enabled.
    ///
    /// # Errors
    ///
    /// Serialization can fail if `T`'s implementation of `Serialize` decides to
    /// fail, or if `T` contains a map with non-string keys.
    #[cfg(feature = "json")]
    #[cfg_attr(docsrs, doc(cfg(feature = "json")))]
    pub fn json<T: Serialize + ?Sized>(mut self, json: &T) -> RequestBuilder {
        let mut error = None;
        if let Ok(ref mut req) = self.request {
            match serde_json::to_vec(json) {
                Ok(body) => {
                    if !req.headers().contains_key(CONTENT_TYPE) {
                        req.headers_mut()
                            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                    }
                    *req.body_mut() = Some(body.into());
                }
                Err(err) => error = Some(crate::error::builder(err)),
            }
        }
        if let Some(err) = error {
            self.request = Err(err);
        }
        self
    }

    /// Build a `Request`, which can be inspected, modified and executed with
    /// `Client::execute()`.
    pub fn build(self) -> crate::Result<Request> {
        self.request
    }

    /// Build a `Request`, which can be inspected, modified and executed with
    /// `Client::execute()`.
    ///
    /// This is similar to [`RequestBuilder::build()`], but also returns the
    /// embedded `Client`.
    pub fn build_split(self) -> (Client, crate::Result<Request>) {
        (self.client, self.request)
    }

    /// Constructs the Request and sends it to the target URL, returning a
    /// future Response.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while sending request,
    /// redirect loop was detected or redirect limit was exhausted.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rquest::Error;
    /// #
    /// # async fn run() -> Result<(), Error> {
    /// let response = rquest::Client::new()
    ///     .get("https://hyper.rs")
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send(self) -> impl Future<Output = Result<Response, crate::Error>> {
        match self.request {
            Ok(req) => self.client.execute_request(req),
            Err(err) => Pending::new_err(err),
        }
    }

    /// Attempt to clone the RequestBuilder.
    ///
    /// `None` is returned if the RequestBuilder can not be cloned,
    /// i.e. if the request body is a stream.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rquest::Error;
    /// #
    /// # fn run() -> Result<(), Error> {
    /// let client = rquest::Client::new();
    /// let builder = client.post("http://httpbin.org/post")
    ///     .body("from a &str!");
    /// let clone = builder.try_clone();
    /// assert!(clone.is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_clone(&self) -> Option<RequestBuilder> {
        self.request
            .as_ref()
            .ok()
            .and_then(|req| req.try_clone())
            .map(|req| RequestBuilder {
                client: self.client.clone(),
                request: Ok(req),
            })
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt_request_fields(&mut f.debug_struct("Request"), self).finish()
    }
}

impl fmt::Debug for RequestBuilder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = f.debug_struct("RequestBuilder");
        match self.request {
            Ok(ref req) => fmt_request_fields(&mut builder, req).finish(),
            Err(ref err) => builder.field("error", err).finish(),
        }
    }
}

fn fmt_request_fields<'a, 'b>(
    f: &'a mut fmt::DebugStruct<'a, 'b>,
    req: &Request,
) -> &'a mut fmt::DebugStruct<'a, 'b> {
    f.field("method", &req.method)
        .field("url", &req.url)
        .field("headers", &req.headers)
}

/// Check the request URL for a "username:password" type authority, and if
/// found, remove it from the URL and return it.
pub(crate) fn extract_authority(url: &mut Url) -> Option<(String, Option<String>)> {
    use percent_encoding::percent_decode;

    if url.has_authority() {
        let username: String = percent_decode(url.username().as_bytes())
            .decode_utf8()
            .ok()?
            .into();
        let password = url.password().and_then(|pass| {
            percent_decode(pass.as_bytes())
                .decode_utf8()
                .ok()
                .map(String::from)
        });
        if !username.is_empty() || password.is_some() {
            url.set_username("")
                .expect("has_authority means set_username shouldn't fail");
            url.set_password(None)
                .expect("has_authority means set_password shouldn't fail");
            return Some((username, password));
        }
    }

    None
}

impl<T> TryFrom<HttpRequest<T>> for Request
where
    T: Into<Body>,
{
    type Error = crate::Error;

    fn try_from(req: HttpRequest<T>) -> crate::Result<Self> {
        let (parts, body) = req.into_parts();
        let Parts {
            method,
            uri,
            headers,
            ..
        } = parts;
        let url = crate::into_url::IntoUrlSealed::into_url(uri.to_string())?;
        Ok(Request {
            method,
            url,
            headers,
            body: Some(body.into()),
            timeout: None,
            // TODO: Add version
            version: None,
            redirect: None,
            #[cfg(feature = "cookies")]
            cookie_store: None,
            proxy_scheme: None,
            local_addr_v4: None,
            local_addr_v6: None,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            interface: None,
        })
    }
}

impl TryFrom<Request> for HttpRequest<Body> {
    type Error = crate::Error;

    fn try_from(req: Request) -> crate::Result<Self> {
        let Request {
            method,
            url,
            headers,
            body,
            version,
            ..
        } = req;

        let mut builder = HttpRequest::builder();

        if let Some(version) = version {
            builder = builder.version(version);
        }

        let mut req = builder
            .method(method)
            .uri(url.as_str())
            .body(body.unwrap_or_else(Body::empty))
            .map_err(crate::error::builder)?;

        *req.headers_mut() = headers;
        Ok(req)
    }
}
