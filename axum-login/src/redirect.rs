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

    if let Some(query) = uri.query() {
        let has_redirect =
            form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == redirect_field);
        if has_redirect {
            return Ok(uri);
        }
    }

    let redirect_uri_string = redirect_uri.to_string();
    let redirect_uri_encoded = urlencoding::encode(&redirect_uri_string);
    let redirect_query = format!("{redirect_field}={redirect_uri_encoded}");

    update_query(&uri, redirect_query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_redirect_when_query_contains_substring() {
        let redirect = "/dashboard".parse::<Uri>().unwrap();
        let uri = url_with_redirect_query("/login?context=1", "next", redirect).unwrap();

        assert_eq!(uri.to_string(), "/login?next=%2Fdashboard&context=1");
    }

    #[test]
    fn preserves_existing_redirect_param() {
        let redirect = "/dashboard".parse::<Uri>().unwrap();
        let uri =
            url_with_redirect_query("/login?next=%2Fkeep&context=1", "next", redirect).unwrap();

        assert_eq!(uri.to_string(), "/login?next=%2Fkeep&context=1");
    }
}
