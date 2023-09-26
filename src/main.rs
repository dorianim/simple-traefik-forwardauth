use accept_header::Accept;
use axum::extract::{FromRef, Query};
use axum::extract::{Host, State};
use axum::http::header::ACCEPT;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::response::{Redirect, Response};
use axum::routing::get;
use axum::{Extension, Router, ServiceExt};
use axum_extra::extract::cookie::{Cookie, Key, PrivateCookieJar};
use mime::Mime;
use oauth2::reqwest::async_http_client;
use oauth2::{PkceCodeVerifier, RefreshToken};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, RedirectUrl, Scope,
};
use openidconnect::{OAuth2TokenResponse, TokenResponse};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;
use tower_layer::Layer;
use tracing::Span;

const COOKIE_NAME: &'static str = "simlpe-traefik-forward-auth-state";

#[derive(Clone, Default)]
enum PathFilterStrategy {
    #[default]
    Whitelist,
    Balacklist,
}

#[derive(Clone)]
struct AppState {
    secret_key: Key,
    oidc_client: CoreClient,
    oidc_scopes: Vec<Scope>,
    path_filter_regex: Option<Regex>,
    path_filter_strategy: PathFilterStrategy,
}

// this impl tells `SignedCookieJar` how to access the key from our state
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.secret_key.clone()
    }
}

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let state = AppState::new().await;

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        .route("/*key", get(root))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .route("/_oauth", get(oauth))
        .layer(
            TraceLayer::new_for_http()
                .on_request(|request: &Request<_>, _span: &Span| {
                    println!("Request {} {}", request.method(), request.uri());
                })
                .on_response(|_response: &Response, _latency: Duration, _span: &Span| {
                    println!(
                        "Response {}, {}ms",
                        _response.status(),
                        _latency.as_millis()
                    );
                }),
        )
        .layer(CatchPanicLayer::new())
        .with_state(state);

    let forwarded_uri_middleware = middleware::from_fn(use_forwarded_uri);
    let app_with_forwarded_uri = forwarded_uri_middleware.layer(app);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3759));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app_with_forwarded_uri.into_make_service())
        .await
        .unwrap();
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Claims {
    pub id: String,
    pub exp: usize,
    pub iss: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct User {
    username: String,
    name: Option<String>,
    email: Option<String>,
    oidc_token_expires_after: u64,
    oidc_refresh_token: Option<RefreshToken>,
}

#[derive(Serialize, Deserialize)]
struct OidcState {
    pkce_verifier: PkceCodeVerifier,
    nonce: Nonce,
    redirect_url: RedirectUrl,
    csrf_token: CsrfToken,
    post_login_redirect_uri: String,
}

#[derive(Serialize, Deserialize, Clone)]
enum LoggedInState {
    User(User),
    Whitelisted,
}

#[derive(Serialize, Deserialize)]
enum UserState {
    LoggedIn(User),
    LoggedOut(OidcState),
}

#[derive(Deserialize)]
struct OauthParameters {
    state: String,
    code: String,
}

#[axum_macros::debug_handler]
async fn root(Extension(user_state): Extension<LoggedInState>) -> impl IntoResponse {
    let headers = match user_state {
        LoggedInState::User(current_user) => {
            let mut headers = HeaderMap::new();
            headers.append(
                "x-forwarded-username",
                HeaderValue::from_str(&current_user.username).unwrap(),
            );
            headers.append(
                "x-forwarded-name",
                HeaderValue::from_str(&current_user.name.unwrap_or("".to_owned())).unwrap(),
            );
            headers.append(
                "x-forwarded-email",
                HeaderValue::from_str(&current_user.email.unwrap_or("".to_owned())).unwrap(),
            );
            headers
        }
        LoggedInState::Whitelisted => HeaderMap::new(),
    };

    (headers, "Login OK")
}

async fn use_forwarded_uri<B>(
    Host(host): Host,
    mut request: Request<B>,
    next: Next<B>,
) -> Response {
    let uri = request.headers().get("x-forwarded-uri").map(|h| {
        Uri::from_str(h.to_str().unwrap()).expect("Error decoding value of x-forwarded-uri")
    });

    if uri.is_none() {
        return next.run(request).await;
    }

    let uri = uri.unwrap();

    let proto = request
        .headers()
        .get("x-forwarded-proto")
        .map(|h| h.to_str().unwrap_or("http"))
        .unwrap_or("http")
        .to_owned();

    request.uri_mut().clone_from(
        &Uri::from_str(&format!(
            "{proto}://{host}{}",
            uri.path_and_query().map(|p| p.as_str()).unwrap_or("")
        ))
        .unwrap(),
    );

    next.run(request).await
}

#[axum_macros::debug_handler]
async fn oauth(
    jar: PrivateCookieJar,
    State(state): State<AppState>,
    Query(oauth_parameters): Query<OauthParameters>,
) -> Result<(PrivateCookieJar, Redirect), StatusCode> {
    let state_cookie = jar
        .get(COOKIE_NAME)
        .expect("state cookie missing")
        .value()
        .to_string();

    let user_state: UserState = serde_json::from_str(&state_cookie).expect("state cookie invalid");

    let oidc_state = match user_state {
        UserState::LoggedIn(_) => return Err(StatusCode::OK),
        UserState::LoggedOut(s) => s,
    };

    if !oauth_parameters.state.eq(oidc_state.csrf_token.secret()) {
        panic!("Invalid state!");
    }

    let oidc_client = state.oidc_client.set_redirect_uri(oidc_state.redirect_url);

    let token_response = oidc_client
        .exchange_code(AuthorizationCode::new(oauth_parameters.code.to_owned()))
        // Set the PKCE code verifier.
        .set_pkce_verifier(oidc_state.pkce_verifier)
        .request_async(async_http_client)
        .await
        .expect("Error getting token response");

    // Extract the ID token claims after verifying its authenticity and nonce.
    let id_token = token_response.id_token().expect("ID token error");

    let claims = id_token
        .claims(&oidc_client.id_token_verifier(), &oidc_state.nonce)
        .expect("Error getting claims");

    // Verify the access token hash to ensure that the access token hasn't been substituted for
    // another user's.
    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            token_response.access_token(),
            &id_token
                .signing_alg()
                .expect("signing alg missing in id token"),
        )
        .expect("Error calculating access token hash");
        if actual_access_token_hash != *expected_access_token_hash {
            panic!("Invalid access token");
        }
    }

    let oidc_token_expires_after = SystemTime::now()
        .checked_add(
            token_response
                .expires_in()
                .unwrap_or(Duration::new(60 * 30, 0)),
        )
        .expect("Error calculating time of token expiry")
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Error calculating time of token expiry")
        .as_secs();

    let logged_in_user = User {
        username: claims
            .preferred_username()
            .expect("Error: The preferred_username claim is missing from the token")
            .to_string(),
        name: claims
            .name()
            .map(|n| n.get(None).map(|n| n.as_str().to_string()))
            .flatten(),
        email: claims.email().map(|e| e.to_string()),
        oidc_token_expires_after,
        oidc_refresh_token: token_response.refresh_token().map(|t| t.to_owned()),
    };

    println!("User {} logged in successfully!", logged_in_user.username);

    Ok((
        set_state_cookie(jar, &UserState::LoggedIn(logged_in_user)),
        Redirect::to(&oidc_state.post_login_redirect_uri),
    ))
}

async fn auth_middleware<B>(
    cookie_jar: PrivateCookieJar,
    State(state): State<AppState>,
    Host(host): Host,
    mut request: Request<B>,
    next: Next<B>,
) -> Result<(PrivateCookieJar, Response), Result<(PrivateCookieJar, Redirect), StatusCode>> {
    if path_is_whitelisted(&state, request.uri().path()) {
        request.extensions_mut().insert(LoggedInState::Whitelisted);
        return Ok((cookie_jar, next.run(request).await));
    }

    let logged_in_user = get_logged_in_user(&cookie_jar).await;
    if logged_in_user.is_none() {
        return Err(handle_unauthorized_request(state, request, cookie_jar, host).await);
    }

    let mut logged_in_user = logged_in_user.unwrap();

    let token_valid_for = i128::from(logged_in_user.oidc_token_expires_after)
        - i128::from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Error getting system time")
                .as_secs(),
        );

    if token_valid_for < 0 {
        println!("Token of user {} is expired!", logged_in_user.username);
        let updated_user = handle_expired_token(&state, logged_in_user).await;
        if updated_user.is_none() {
            return Err(handle_unauthorized_request(state, request, cookie_jar, host).await);
        }

        logged_in_user = updated_user.unwrap();
        println!("Got new token for user {}!", logged_in_user.username);
    } else {
        println!(
            "Token of user {} is valid for {}s",
            logged_in_user.username, token_valid_for
        );
    }

    let user_state = UserState::LoggedIn(logged_in_user.to_owned());
    let cookie_jar = set_state_cookie(cookie_jar, &user_state);
    request
        .extensions_mut()
        .insert(LoggedInState::User(logged_in_user));

    return Ok((cookie_jar, next.run(request).await));
}

fn path_is_whitelisted(state: &AppState, path: &str) -> bool {
    if state.path_filter_regex.is_none() {
        return false;
    }

    let regex_matches = state.path_filter_regex.clone().unwrap().is_match(path);

    match state.path_filter_strategy {
        PathFilterStrategy::Balacklist => !regex_matches,
        PathFilterStrategy::Whitelist => regex_matches,
    }
}

async fn get_logged_in_user(cookie_jar: &PrivateCookieJar) -> Option<User> {
    let state_cookie = cookie_jar.get(COOKIE_NAME);

    if state_cookie.is_none() {
        return None;
    }

    let user_state = serde_json::from_str::<UserState>(state_cookie.unwrap().value());

    if user_state.is_err() {
        return None;
    }

    match user_state.unwrap() {
        UserState::LoggedOut(_) => return None,
        UserState::LoggedIn(s) => Some(s),
    }
}

async fn handle_unauthorized_request<B>(
    state: AppState,
    request: Request<B>,
    cookie_jar: PrivateCookieJar,
    host: String,
) -> Result<(PrivateCookieJar, Redirect), StatusCode> {
    let accept_header = request
        .headers()
        .get(ACCEPT)
        .map(|v| v.to_str().unwrap())
        .unwrap_or("");

    let accept_header: Accept = accept_header.parse().unwrap_or(Accept {
        wildcard: None,
        types: Vec::new(),
    });

    let accept_types_to_redirect = vec![Mime::from_str("text/html").unwrap()];
    let should_redirect = accept_header.negotiate(&accept_types_to_redirect).is_ok();

    if !should_redirect {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let proto = request
        .headers()
        .get("x-forwarded-proto")
        .map(|h| h.to_str().unwrap_or("http"))
        .unwrap_or("http");

    let redirect_url = format!("{proto}://{host}/_oauth");

    let (redirect, oidc_state) = create_oidc_redirect(
        state.oidc_client,
        state.oidc_scopes,
        RedirectUrl::new(redirect_url).expect("Error parsing redirect_url"),
        request.uri().to_string(),
    );

    let updated_jar = set_state_cookie(cookie_jar, &UserState::LoggedOut(oidc_state));

    return Ok((updated_jar, redirect));
}

async fn handle_expired_token(state: &AppState, logged_in_user: User) -> Option<User> {
    if logged_in_user.oidc_refresh_token.is_none() {
        return None;
    }

    let token_response = state
        .oidc_client
        .exchange_refresh_token(&logged_in_user.oidc_refresh_token.unwrap())
        .request_async(async_http_client)
        .await;

    if let Err(e) = token_response {
        println!("Error exchanging refresh token: {e}");
        return None;
    }

    let token_response = token_response.unwrap();

    let oidc_token_expires_after = SystemTime::now()
        .checked_add(
            token_response
                .expires_in()
                .unwrap_or(Duration::new(60 * 30, 0)),
        )
        .expect("Error calculating time of token expiry")
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Error calculating time of token expiry")
        .as_secs();

    Some(User {
        oidc_token_expires_after,
        oidc_refresh_token: token_response.refresh_token().map(|t| t.to_owned()),
        ..logged_in_user
    })
}

fn create_oidc_redirect(
    client: CoreClient,
    scopes: Vec<Scope>,
    redirect_url: RedirectUrl,
    post_login_redirect_uri: String,
) -> (Redirect, OidcState) {
    let client = client.set_redirect_uri(redirect_url.to_owned());

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    pkce_verifier.secret();

    // Generate the full authorization URL.
    let mut auth_request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge);

    for scope in scopes {
        auth_request = auth_request
            // Set the desired scopes.
            .add_scope(scope);
    }

    let (auth_url, csrf_token, nonce) = auth_request.url();

    (
        Redirect::to(auth_url.as_str()),
        OidcState {
            pkce_verifier,
            nonce,
            redirect_url,
            csrf_token,
            post_login_redirect_uri,
        },
    )
}

impl AppState {
    async fn new() -> Self {
        let secret_key_data: &[u8] =
            &hex::decode(env::var("SECRET_KEY").expect("SECRET_KEY must be set"))
                .expect("Invalid SECRET_KEY format");
        let secret_key = Key::try_from(secret_key_data).expect("Invalid SECRET_KEY format");

        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(env::var("OIDC_ISSUER_URL").expect("OIDC_ISSUER_URL must be set"))
                .expect("OIDC_ISSUER_URL is invalid"),
            async_http_client,
        )
        .await
        .unwrap();

        let oidc_client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(env::var("OIDC_CLIENT_ID").expect("OIDC_CLIENT_ID must be set")),
            env::var("OIDC_CLIENT_SECRET")
                .map(|s| Some(ClientSecret::new(s)))
                .unwrap_or(None),
        );

        let oidc_scopes = env::var("OIDC_SCOPES")
            .unwrap_or("profile,email".to_owned())
            .to_string()
            .split(",")
            .map(|s| Scope::new(s.to_owned()))
            .collect::<Vec<Scope>>();

        let path_filter_regex = env::var("PATH_FILTER_REGEX")
            .map(|r| Some(Regex::new(r.as_str()).expect("Invalid PATH_FILTER_REGEX")))
            .unwrap_or(None);

        let path_filter_strategy = match env::var("PATH_FILTER_STRATEGY")
            .unwrap_or("Whitelist".to_owned())
            .as_str()
        {
            "Whitelist" => PathFilterStrategy::Whitelist,
            "Blacklist" => PathFilterStrategy::Balacklist,
            _ => panic!("Invalid PATH_FILTER_STRATEGY: use Whitelist or Blacklist"),
        };

        AppState {
            secret_key,
            oidc_client,
            oidc_scopes,
            path_filter_regex,
            path_filter_strategy,
        }
    }
}

fn set_state_cookie(cookie_jar: PrivateCookieJar, user_state: &UserState) -> PrivateCookieJar {
    let mut new_cookie = Cookie::new(
        COOKIE_NAME,
        serde_json::to_string(user_state).expect("Error encoding oidc_state"),
    );
    new_cookie.set_http_only(true);
    new_cookie.set_path("/");
    cookie_jar.add(new_cookie)
}
