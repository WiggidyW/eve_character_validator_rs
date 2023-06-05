use crate::error::{SendError, StatusError, GetResponseError};

pub async fn send<
    C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
>(
    hyper_client: &hyper::client::Client<C, hyper::body::Body>,
    req: hyper::Request<hyper::Body>,
) -> Result<hyper::body::Bytes, SendError> {
    
    // Get the response from the server
    let (rep_parts, rep_body) = hyper_client
        .request(req)
        .await
        .map_err(|e| {
            SendError::GetResponseError(GetResponseError::new(e))
        })?
        .into_parts();

    // Throw a status error if the response status is not OK
    StatusError::try_new(rep_parts.status)
        .map_err(|e| SendError::StatusError(e))?;

    // Return the response body as bytes
    hyper::body::to_bytes(rep_body)
        .await
        .map_err(|e| {
            SendError::GetResponseError(GetResponseError::new(e))
        })
}
