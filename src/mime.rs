/// Returns the MIME type string for a given file extension.
/// Falls back to `application/octet-stream` for unknown types.
pub fn from_ext(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        // Text
        "html" | "htm" => "text/html; charset=utf-8",
        "css"          => "text/css; charset=utf-8",
        "js" | "mjs"   => "application/javascript",
        "json"         => "application/json",
        "xml"          => "application/xml",
        "txt"          => "text/plain; charset=utf-8",
        "csv"          => "text/csv; charset=utf-8",
        "md"           => "text/markdown; charset=utf-8",

        // Images
        "png"          => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif"          => "image/gif",
        "svg"          => "image/svg+xml",
        "ico"          => "image/x-icon",
        "webp"         => "image/webp",
        "bmp"          => "image/bmp",
        "tiff" | "tif" => "image/tiff",
        "avif"         => "image/avif",

        // Fonts
        "woff"         => "font/woff",
        "woff2"        => "font/woff2",
        "ttf"          => "font/ttf",
        "otf"          => "font/otf",

        // Audio / Video
        "mp3"          => "audio/mpeg",
        "ogg"          => "audio/ogg",
        "wav"          => "audio/wav",
        "mp4"          => "video/mp4",
        "webm"         => "video/webm",

        // Documents / Archives
        "pdf"          => "application/pdf",
        "zip"          => "application/zip",
        "gz"           => "application/gzip",
        "tar"          => "application/x-tar",
        "wasm"         => "application/wasm",

        // Fallback
        _              => "application/octet-stream",
    }
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_and_variants() {
        assert_eq!(from_ext("html"), "text/html; charset=utf-8");
        assert_eq!(from_ext("HTML"), "text/html; charset=utf-8"); // case-insensitive
        assert_eq!(from_ext("htm"),  "text/html; charset=utf-8");
    }

    #[test]
    fn css_and_js() {
        assert_eq!(from_ext("css"), "text/css; charset=utf-8");
        assert_eq!(from_ext("js"),  "application/javascript");
        assert_eq!(from_ext("mjs"), "application/javascript");
    }

    #[test]
    fn images() {
        assert_eq!(from_ext("png"),  "image/png");
        assert_eq!(from_ext("jpg"),  "image/jpeg");
        assert_eq!(from_ext("jpeg"), "image/jpeg");
        assert_eq!(from_ext("svg"),  "image/svg+xml");
        assert_eq!(from_ext("ico"),  "image/x-icon");
    }

    #[test]
    fn fonts() {
        assert_eq!(from_ext("woff"),  "font/woff");
        assert_eq!(from_ext("woff2"), "font/woff2");
    }

    #[test]
    fn unknown_falls_back() {
        assert_eq!(from_ext("xyz"),  "application/octet-stream");
        assert_eq!(from_ext(""),     "application/octet-stream");
        assert_eq!(from_ext("rust"), "application/octet-stream");
    }
}
