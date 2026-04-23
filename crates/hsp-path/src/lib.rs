use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    InvalidPercentEncoding,
    DoublePercentDecodingForbidden,
}

impl Display for PathError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPercentEncoding => f.write_str("invalid percent encoding"),
            Self::DoublePercentDecodingForbidden => {
                f.write_str("double percent decoding is forbidden")
            }
        }
    }
}

impl std::error::Error for PathError {}

pub fn canonical_segments(path: &str) -> Result<Vec<String>, PathError> {
    let decoded = percent_decode_once(path)?;
    if contains_nested_percent_encoding(&decoded) {
        return Err(PathError::DoublePercentDecodingForbidden);
    }

    Ok(decoded.split('/').map(ToString::to_string).collect())
}

pub fn canonical_path(path: &str) -> Result<String, PathError> {
    Ok(canonical_segments(path)?.join("/"))
}

pub fn segment_prefix_matches(prefix: &str, candidate: &str) -> bool {
    let prefix_segments = match canonical_segments(prefix) {
        Ok(segments) => segments,
        Err(_) => return false,
    };
    let candidate_segments = match canonical_segments(candidate) {
        Ok(segments) => segments,
        Err(_) => return false,
    };

    if prefix_segments.len() > candidate_segments.len() {
        return false;
    }

    prefix_segments
        .iter()
        .zip(candidate_segments.iter())
        .all(|(left, right)| left == right)
}

fn percent_decode_once(input: &str) -> Result<String, PathError> {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.as_bytes().iter().copied().peekable();

    while let Some(byte) = chars.next() {
        if byte != b'%' {
            output.push(byte as char);
            continue;
        }

        let high = chars.next().ok_or(PathError::InvalidPercentEncoding)?;
        let low = chars.next().ok_or(PathError::InvalidPercentEncoding)?;
        let decoded = (decode_hex(high)? << 4) | decode_hex(low)?;
        output.push(decoded as char);
    }

    Ok(output)
}

fn decode_hex(byte: u8) -> Result<u8, PathError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(PathError::InvalidPercentEncoding),
    }
}

fn contains_nested_percent_encoding(input: &str) -> bool {
    input.as_bytes().windows(3).any(|window| {
        window[0] == b'%' && window[1].is_ascii_hexdigit() && window[2].is_ascii_hexdigit()
    })
}

#[cfg(test)]
mod tests {
    use super::{canonical_path, canonical_segments, segment_prefix_matches, PathError};

    #[test]
    fn matches_identical_path() {
        assert!(segment_prefix_matches("tenant/a", "tenant/a"));
    }

    #[test]
    fn matches_nested_child_segment() {
        assert!(segment_prefix_matches("tenant/a", "tenant/a/object.txt"));
    }

    #[test]
    fn rejects_prefix_confusion() {
        assert!(!segment_prefix_matches("tenant/a", "tenant/alpha"));
    }

    #[test]
    fn rejects_shorter_candidate() {
        assert!(!segment_prefix_matches("tenant/a/object.txt", "tenant/a"));
    }

    #[test]
    fn percent_decodes_once() {
        assert_eq!(canonical_path("tenant%2Fa"), Ok("tenant/a".to_string()));
        assert_eq!(
            canonical_segments("tenant/a%2Fb").unwrap(),
            vec!["tenant".to_string(), "a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn rejects_double_percent_decoding() {
        assert_eq!(
            canonical_path("tenant/%252Fsecret"),
            Err(PathError::DoublePercentDecodingForbidden)
        );
    }

    #[test]
    fn retains_empty_segments_without_posix_normalization() {
        assert_eq!(
            canonical_segments("tenant//a/.").unwrap(),
            vec![
                "tenant".to_string(),
                "".to_string(),
                "a".to_string(),
                ".".to_string()
            ]
        );
    }
}
