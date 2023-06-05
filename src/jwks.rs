use crate::{
    error::{JwksParseError, ParseError, Error},
    util::send,
};

use serde::Deserialize;

pub struct JWKS {
    key: jsonwebtoken::DecodingKey,
    alg: jsonwebtoken::Algorithm,
}

#[derive(Deserialize)]
struct JWTName {
    name: String,
}

impl JWKS {
    pub async fn new<
        C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    >(
        hyper_client: &hyper::client::Client<C, hyper::body::Body>,
    ) -> Result<Self, Error> {
        let jwks_response = JWKSResponse::new(hyper_client).await?;
        Ok(Self::try_from(jwks_response)?)
    }

    pub (crate) fn get_name(&self, jwt: &str) -> Result<String, Error> {
        let mut validation = jsonwebtoken::Validation::new(self.alg);
        validation.set_required_spec_claims(&["name", "iss", "exp", "aud"]);
        validation.set_audience(&["EVE Online"]);
        validation.set_issuer(&["login.eveonline.com"]);

        let token_data = jsonwebtoken::decode::<JWTName>(
            jwt,
            &self.key,
            &validation,
        )
            .map_err(|e| Error::JkwsDecodeError(e))?;

        Ok(token_data.claims.name)
    }
}

impl TryFrom<JWKSResponse> for JWKS {
    type Error = JwksParseError;
    fn try_from(mut value: JWKSResponse) -> Result<Self, Self::Error> {
        if value.keys.len() < 1 {
            return Err(JwksParseError::MissingKeyError);
        }
        let raw_key = value.keys.remove(0);
        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(raw_key)
            .map_err(|e| ParseError::new(e))?;
        let algorithm = jwk.common.algorithm.ok_or(
            JwksParseError::MissingKeyError,
        )?;
        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(&jwk)
            .map_err(|e| JwksParseError::InvalidKeyError(e))?;
        Ok(Self {
            key: decoding_key,
            alg: algorithm,
        })
    }
}

#[derive(Deserialize)]
struct JWKSResponse {
    keys: Vec<serde_json::Value>,
}

impl JWKSResponse {
    async fn new<
        C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    >(
        hyper_client: &hyper::client::Client<C, hyper::body::Body>,
    ) -> Result<Self, Error> {
        // Build the request
        let req = hyper::Request::builder()
            .method("GET")
            .uri("https://login.eveonline.com/oauth/jwks")
            .body(hyper::Body::empty())
            .unwrap();

        // Send the request and get the response body
        let rep_body = send(hyper_client, req)
            .await
            .map_err(|e| e.as_jwk_error())?;

        // Parse the response body into Self
        let parsed = serde_json::from_slice(&rep_body).map_err(|e| {
            JwksParseError::ParseError(ParseError::new(e))
        })?;

        // Return Self
        Ok(parsed)
    }
}
