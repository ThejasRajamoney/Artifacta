#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PackagingError {
    #[error("packaging tool not found: {0}")]
    ToolNotFound(String),
    #[error("packaging failed: {0}")]
    Failed(String),
}

#[derive(Debug, Clone)]
pub enum PackageFormat {
    Nsis,
    Msi,
    Msix,
}

impl PackageFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nsis => "nsis",
            Self::Msi => "msi",
            Self::Msix => "msix",
        }
    }
}

pub struct Packager;

impl Packager {
    pub fn build_package(
        _format: PackageFormat,
        _version: &str,
        _output_dir: &str,
    ) -> Result<String, PackagingError> {
        Ok("Package build delegated to release tooling".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_as_str() {
        assert_eq!(PackageFormat::Nsis.as_str(), "nsis");
        assert_eq!(PackageFormat::Msi.as_str(), "msi");
        assert_eq!(PackageFormat::Msix.as_str(), "msix");
    }
}
