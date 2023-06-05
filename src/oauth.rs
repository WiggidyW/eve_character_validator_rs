use crate::{
    error::{OAuthParseError, Error},
    util::send,
};

use serde::Deserialize;

#[derive(Deserialize)]
pub struct AuthenticationResponse {
    pub jwt: String,
    pub refresh_token: String,
}

impl AuthenticationResponse {
    pub async fn new<
        C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    >(
        hyper_client: &hyper::client::Client<C, hyper::body::Body>,
        refresh_token: &str,
        client_id: &str,
    ) -> Result<Self, Error> {
        // Build the request
        let req = hyper::Request::builder()
            .method("POST")
            .uri("https://login.eveonline.com/v2/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Host", "login.eveonline.com")
            .body(hyper::Body::from(
                format!(
                    "grant_type=refresh_token&refresh_token={}&client_id={}",
                    refresh_token, client_id
                )
                .as_bytes()
                .to_vec(),
            ))
            .map_err(|e| Error::ParametersError(e))?;

        // Send the request and get the response body
        let rep = send(hyper_client, req)
            .await
            .map_err(|e| e.as_oauth_error())?;

        // Parse the response body into Self
        let parsed = serde_json::from_slice(&rep).map_err(|e| {
            OAuthParseError::new(e)
        })?;

        // Return Self
        Ok(parsed)
    }
}
