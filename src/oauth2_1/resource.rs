use url::Url;

use crate::error::Error;

/// RFC 8707 resource indicator. The value MUST be an absolute URI and MUST NOT
/// contain a fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource(Url);

impl Resource {
    /// Parse and validate an RFC 8707 resource indicator.
    pub fn parse(value: &str) -> Result<Self, Error> {
        let url = Url::parse(value).map_err(|_| Error::InvalidResource {
            value: value.to_string(),
        })?;

        if !url.has_host() && url.cannot_be_a_base() {
            // Reject relative or otherwise non-absolute URIs.
            return Err(Error::InvalidResource {
                value: value.to_string(),
            });
        }

        if url.fragment().is_some() {
            return Err(Error::InvalidResource {
                value: value.to_string(),
            });
        }

        Ok(Resource(url))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_url(self) -> Url {
        self.0
    }
}

impl std::fmt::Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_absolute_https_uri() {
        let r = Resource::parse("https://api.example.com/").unwrap();
        assert_eq!(r.as_str(), "https://api.example.com/");
    }

    #[test]
    fn parses_absolute_uri_with_path() {
        let r = Resource::parse("https://api.example.com/v1").unwrap();
        assert_eq!(r.as_str(), "https://api.example.com/v1");
    }

    #[test]
    fn rejects_relative_uri() {
        let err = Resource::parse("/relative/path").unwrap_err();
        assert!(matches!(err, Error::InvalidResource { .. }));
    }

    #[test]
    fn rejects_uri_with_fragment() {
        let err = Resource::parse("https://api.example.com/v1#frag").unwrap_err();
        assert!(matches!(err, Error::InvalidResource { .. }));
    }

    #[test]
    fn rejects_garbage() {
        let err = Resource::parse("not a url at all").unwrap_err();
        assert!(matches!(err, Error::InvalidResource { .. }));
    }
}
