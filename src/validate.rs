use crate::{
    error::Error,
    jwks::JWKS,
    oauth::AuthenticationResponse,
};

pub struct Response {
    pub refresh_token: String,
    pub valid: bool,
}

pub async fn validate<
    S: AsRef<str>,
    C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
>(
    hyper_client: &hyper::client::Client<C, hyper::body::Body>,
    jwks: &JWKS,
    refresh_token: &str,
    client_id: &str,
    mut characters: impl Iterator<Item = S>,
) -> Result<Response, Error> {
    let oauth_rep = AuthenticationResponse::new(
        hyper_client,
        refresh_token,
        client_id,
    )
        .await?;
    let name = jwks.get_name(&oauth_rep.jwt)?;
    Ok(Response {
        refresh_token: oauth_rep.refresh_token,
        valid: characters.find(|c| c.as_ref() == &name).is_some(),
    })
}
