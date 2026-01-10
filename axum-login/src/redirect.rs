use axum::http::{self, Uri};

fn update_query(uri: &Uri, new_query: String) -> Result<Uri, http::Error> {
    let query = form_urlencoded::parse(uri.query().map(|q| q.as_bytes()).unwrap_or_default());
    let updated_query = form_urlencoded::Serializer::new(new_query)
        .extend_pairs(query)
        .finish();

    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(format!("{}?{}", uri.path(), updated_query).parse()?);

    Ok(Uri::from_parts(parts)?)
}

/// This is intended for internal use only and subject to change in the future
/// without warning!
#[doc(hidden)]
pub fn url_with_redirect_query(
    url: &str,
    redirect_field: &str,
    redirect_uri: Uri,
) -> Result<Uri, http::Error> {
    let uri = url.parse::<Uri>()?;

    if uri.query().is_some_and(|q| q.contains(redirect_field)) {
        return Ok(uri);
    };

    let redirect_uri_string = redirect_uri.to_string();
    let redirect_uri_encoded = urlencoding::encode(&redirect_uri_string);
    let redirect_query = format!("{redirect_field}={redirect_uri_encoded}");

    update_query(&uri, redirect_query)
}
