pub enum Error {
    ParametersError(hyper::http::Error),
    JwksKeyError(jsonwebtoken::errors::Error),
    JwksParseError(JwksParseError),
    JkwsDecodeError(jsonwebtoken::errors::Error),
    OAuthParseError(OAuthParseError),
    OAuthGetResponseError(OAuthGetResponseError),
    JwksGetResponseError(JwksGetResponseError),
    OAuthStatusError(OAuthStatusError),
    JwksStatusError(JwksStatusError),
}

impl From<JwksStatusError> for Error {
    fn from(value: JwksStatusError) -> Self {
        Self::JwksStatusError(value)
    }
}

impl From<OAuthStatusError> for Error {
    fn from(value: OAuthStatusError) -> Self {
        Self::OAuthStatusError(value)
    }
}

impl From<OAuthGetResponseError> for Error {
    fn from(value: OAuthGetResponseError) -> Self {
        Self::OAuthGetResponseError(value)
    }
}

impl From<JwksGetResponseError> for Error {
    fn from(value: JwksGetResponseError) -> Self {
        Self::JwksGetResponseError(value)
    }
}

impl From<JwksParseError> for Error {
    fn from(value: JwksParseError) -> Self {
        Self::JwksParseError(value)
    }
}

impl From<OAuthParseError> for Error {
    fn from(value: OAuthParseError) -> Self {
        Self::OAuthParseError(value)
    }
}

pub struct JwksStatusError(StatusError);

pub struct OAuthStatusError(StatusError);

pub struct StatusError(hyper::StatusCode);

impl StatusError {
    pub fn try_new(status: hyper::StatusCode) -> Result<(), Self> {
        if status == hyper::StatusCode::OK {
            Ok(())
        } else {
            Err(Self(status))
        }
    }
}

pub struct JwksGetResponseError(GetResponseError);

pub struct OAuthGetResponseError(GetResponseError);

pub struct GetResponseError(hyper::Error);

impl GetResponseError {
    pub fn new(e: hyper::Error) -> Self {
        Self(e)
    }
}

pub enum JwksParseError {
    ParseError(ParseError),
    InvalidKeyError(jsonwebtoken::errors::Error),
    MissingKeyError,
}

impl From<ParseError> for JwksParseError {
    fn from(value: ParseError) -> Self {
        Self::ParseError(value)
    }
}

pub struct OAuthParseError(ParseError);

impl OAuthParseError {
    pub fn new(e: serde_json::Error) -> Self {
        Self(ParseError::new(e))
    }
}

pub struct ParseError(serde_json::Error);

impl ParseError {
    pub fn new(e: serde_json::Error) -> Self {
        Self(e)
    }
}

pub enum SendError {
    GetResponseError(GetResponseError),
    StatusError(StatusError),
}

impl SendError {
    pub fn as_jwk_error(self) -> Error {
        match self {
            Self::GetResponseError(e) => Error::JwksGetResponseError(
                JwksGetResponseError(e)
            ),
            Self::StatusError(e) => Error::JwksStatusError(
                JwksStatusError(e)
            ),
        }
    }

    pub fn as_oauth_error(self) -> Error {
        match self {
            Self::GetResponseError(e) => Error::OAuthGetResponseError(
                OAuthGetResponseError(e),
            ),
            Self::StatusError(e) => Error::OAuthStatusError(
                OAuthStatusError(e),
            ),
        }
    }
}
