//! DirectoryValidator and PathAllowList for validating symlinked packs and world files
//! against `allowed_symlinks.txt`.
use horizon_client_core::pattern::Pattern;
use std::{
    fs,
    io::BufRead,
    path::{Path, PathBuf},
};

/// ForbiddenSymlinkInfo: a symlink whose target is not in the allow list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForbiddenSymlinkInfo {
    pub link: PathBuf,
    pub target: PathBuf,
}

#[derive(Clone, Debug)]
pub enum EntryType {
    Prefix,
    Glob,
    Regex,
}

#[derive(Clone, Debug)]
enum CompiledMatcher {
    Prefix(String),
    Glob(String),
    Regex(Pattern),
}

/// A parsed entry from `allowed_symlinks.txt`.
#[derive(Clone, Debug)]
pub struct ConfigEntry {
    pub entry_type: EntryType,
    pub pattern: String,
    matcher: CompiledMatcher,
}

/// PathAllowList: symlink target allowlist read from allowed_symlinks.txt.
#[derive(Clone, Debug, Default)]
pub struct PathAllowList {
    entries: Vec<ConfigEntry>,
}

impl PathAllowList {
    /// PathAllowList.readPlain: parses allowed symlink entries from a reader.
    pub fn read_plain<R: BufRead>(reader: R) -> Result<PathAllowList, String> {
        let mut entries = Vec::new();
        for (i, line) in reader.lines().enumerate() {
            let l = line.map_err(|e| e.to_string())?;
            // `ConfigEntry.parse`: the line as written, blank or `#` lines skipped.
            let s = l.as_str();
            if s.trim().is_empty() || s.starts_with('#') {
                continue;
            }
            if !s.starts_with('[') {
                let norm = s.replace('\\', "/");
                entries.push(ConfigEntry {
                    entry_type: EntryType::Prefix,
                    pattern: s.into(),
                    matcher: CompiledMatcher::Prefix(norm),
                });
            } else {
                let Some(close) = s.find(']') else {
                    return Err(format!("line {}: missing ']'", i + 1));
                };
                let (kind, pat) = (&s[1..close], &s[close + 1..]);
                let norm = pat.replace('\\', "/");
                let (entry_type, matcher) = match kind {
                    "prefix" => (EntryType::Prefix, CompiledMatcher::Prefix(norm)),
                    "glob" => (EntryType::Glob, CompiledMatcher::Glob(norm)),
                    "regex" => {
                        let anc =
                            format!("^{}$", pat.trim_start_matches('^').trim_end_matches('$'));
                        let p = Pattern::new(&anc)
                            .ok_or_else(|| format!("line {}: bad regex: {pat}", i + 1))?;
                        (EntryType::Regex, CompiledMatcher::Regex(p))
                    }
                    other => return Err(format!("line {}: unknown type [{other}]", i + 1)),
                };
                entries.push(ConfigEntry {
                    entry_type,
                    pattern: pat.into(),
                    matcher,
                });
            }
        }
        Ok(PathAllowList { entries })
    }

    /// PathAllowList.matches: returns whether the target path matches any allowlist entry.
    pub fn matches(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy().replace('\\', "/");
        for entry in &self.entries {
            match &entry.matcher {
                CompiledMatcher::Prefix(prefix) => {
                    if matches_prefix(prefix, &path_str) {
                        return true;
                    }
                }
                CompiledMatcher::Glob(glob) => {
                    if match_glob(glob, &path_str) {
                        return true;
                    }
                }
                CompiledMatcher::Regex(pat) => {
                    if pat.is_match(&path_str) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// `EntryType.PREFIX`: `path.toString().startsWith(pattern)`.
fn matches_prefix(prefix: &str, target: &str) -> bool {
    target.starts_with(prefix)
}

fn match_glob(p: &str, t: &str) -> bool {
    glob_rec(p.as_bytes(), t.as_bytes())
}

fn glob_rec(mut p: &[u8], mut t: &[u8]) -> bool {
    while !p.is_empty() {
        if p.starts_with(b"**") {
            let rest = &p[2..];
            let rest_after_slash = rest.strip_prefix(b"/").unwrap_or(rest);
            if glob_rec(rest_after_slash, t) {
                return true;
            }
            for i in 0..t.len() {
                if t[i] == b'/' && glob_rec(rest_after_slash, &t[i + 1..]) {
                    return true;
                }
            }
            return false;
        } else if p[0] == b'*' {
            let rest = &p[1..];
            for i in 0..=t.len() {
                if i > 0 && t[i - 1] == b'/' {
                    break;
                }
                if glob_rec(rest, &t[i..]) {
                    return true;
                }
            }
            return false;
        } else if p[0] == b'?' {
            if t.is_empty() || t[0] == b'/' {
                return false;
            }
            p = &p[1..];
            t = &t[1..];
        } else {
            let (ch, advance) = if p[0] == b'\\' && p.len() > 1 {
                (p[1], 2)
            } else {
                (p[0], 1)
            };
            if t.is_empty() || t[0] != ch {
                return false;
            }
            p = &p[advance..];
            t = &t[1..];
        }
    }
    t.is_empty()
}

/// DirectoryValidator: validates directories and symlink targets against the allow list.
#[derive(Clone, Debug, Default)]
pub struct DirectoryValidator {
    allow_list: PathAllowList,
}

impl DirectoryValidator {
    pub fn new(allow_list: PathAllowList) -> Self {
        Self { allow_list }
    }

    pub fn no_symlinks_allowed() -> Self {
        Self {
            allow_list: PathAllowList::default(),
        }
    }

    /// DirectoryValidator.validateSymlink: validates that a symlink's target is allowed.
    pub fn validate_symlink(&self, path: &Path, issues: &mut Vec<ForbiddenSymlinkInfo>) {
        match fs::read_link(path) {
            // The link's own target, as written (`Files.readSymbolicLink`), not resolved.
            Ok(target) => {
                if !self.allow_list.matches(&target) {
                    issues.push(ForbiddenSymlinkInfo {
                        link: path.to_path_buf(),
                        target,
                    });
                }
            }
            Err(_) => issues.push(ForbiddenSymlinkInfo {
                link: path.to_path_buf(),
                target: PathBuf::new(),
            }),
        }
    }

    /// DirectoryValidator.validateKnownDirectory: walks a directory and validates all symlinks inside.
    pub fn validate_known_directory(
        &self,
        directory: &Path,
        issues: &mut Vec<ForbiddenSymlinkInfo>,
    ) {
        let mut stack = vec![directory.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if entry.file_type().is_ok_and(|ft| ft.is_symlink()) {
                    self.validate_symlink(&path, issues);
                } else if path.is_dir() {
                    stack.push(path);
                }
            }
        }
    }

    /// DirectoryValidator.validateDirectory: validates a directory and its symlinks.
    pub fn validate_directory(
        &self,
        directory: &Path,
        allow_top_symlink: bool,
    ) -> Vec<ForbiddenSymlinkInfo> {
        let mut issues = Vec::new();
        let is_symlink = directory.is_symlink();
        if allow_top_symlink && is_symlink {
            self.validate_symlink(directory, &mut issues);
            if issues.is_empty()
                && let Ok(target) = fs::canonicalize(directory)
                && target.is_dir()
            {
                self.validate_known_directory(&target, &mut issues);
            }
        } else if !allow_top_symlink && is_symlink {
            self.validate_symlink(directory, &mut issues);
        } else if directory.is_dir() {
            self.validate_known_directory(directory, &mut issues);
        }
        issues
    }
}

/// LevelStorageSource.parseValidator: reads allowed_symlinks.txt or defaults to rejecting all symlinks.
pub fn parse_validator(config_path: &Path) -> DirectoryValidator {
    let Ok(file) = fs::File::open(config_path) else {
        return DirectoryValidator::no_symlinks_allowed();
    };
    match PathAllowList::read_plain(std::io::BufReader::new(file)) {
        Ok(allow_list) => DirectoryValidator::new(allow_list),
        Err(e) => {
            log::warn!("Failed to parse {}: {e}", config_path.display());
            DirectoryValidator::no_symlinks_allowed()
        }
    }
}

/// `Minecraft.directoryValidator`: `allowed_symlinks.txt` in the game folder, which is the
/// working directory (`--game-dir` moves into it), and nowhere else.
pub fn game_dir_validator() -> DirectoryValidator {
    let dir = std::env::current_dir().unwrap_or_default();
    parse_validator(&dir.join("allowed_symlinks.txt"))
}

/// The detected source of a pack on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveredPackSource {
    Dir(PathBuf),
    Zip(PathBuf),
}

/// PackDetector.detectPackResources: detects pack resources from path while checking for forbidden symlinks.
pub fn detect_pack_resources(
    content: &Path,
    validator: &DirectoryValidator,
    issues: &mut Vec<ForbiddenSymlinkInfo>,
) -> Option<DiscoveredPackSource> {
    let Ok(symlink_meta) = fs::symlink_metadata(content) else {
        return None;
    };
    let file_type = symlink_meta.file_type();
    let name = content.file_name()?.to_string_lossy();
    let (is_dir, is_file) = if file_type.is_symlink() {
        validator.validate_symlink(content, issues);
        if !issues.is_empty() {
            log::warn!(
                "Ignored pack at {}: forbidden symlink target {}",
                content.display(),
                issues[0].target.display()
            );
            return None;
        }
        let Ok(m) = fs::metadata(content) else {
            return None;
        };
        (m.is_dir(), m.is_file())
    } else {
        (file_type.is_dir(), file_type.is_file())
    };
    if is_dir {
        validator.validate_known_directory(content, issues);
        if !issues.is_empty() {
            log::warn!(
                "Ignored pack at {}: forbidden symlink inside {}",
                content.display(),
                issues[0].link.display()
            );
            return None;
        }
        Some(DiscoveredPackSource::Dir(content.to_path_buf()))
    } else if is_file && name.ends_with(".zip") {
        Some(DiscoveredPackSource::Zip(content.to_path_buf()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symlink_validator_allowlist() {
        let text = "# comment\n[prefix]/allowed/prefix\n[glob]**/*.zip\n[regex].*\\.mod\n";
        let list = PathAllowList::read_plain(text.as_bytes()).unwrap();
        assert!(list.matches(Path::new("/allowed/prefix/pack")));
        // `startsWith` on the path's text, as vanilla's PREFIX entry compares.
        assert!(list.matches(Path::new("/allowed/prefixed")));
        assert!(list.matches(Path::new("deep/folder/pack.zip")));
        assert!(list.matches(Path::new("pack.zip")));
        assert!(list.matches(Path::new("/mods/custom.mod")));
        assert!(!list.matches(Path::new("/forbidden/pack")));

        // `**` must match at slash boundaries, not arbitrary substrings
        assert!(!match_glob("**/foo", "afoo"));
        assert!(match_glob("**/foo", "foo"));
        assert!(match_glob("**/foo", "bar/foo"));
        assert!(match_glob("**/foo", "a/b/foo"));

        let no_symlinks = PathAllowList::default();
        assert!(!no_symlinks.matches(Path::new("/any/path")));

        let validator = DirectoryValidator::new(list);
        let mut issues = Vec::new();
        let tmp = std::env::temp_dir().join(format!("mc_symlink_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let link = tmp.join("test_link");
        let _ = std::fs::remove_file(&link);
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(Path::new("/forbidden/pack"), &link);
            validator.validate_symlink(&link, &mut issues);
            assert_eq!(issues.len(), 1);
            let _ = std::fs::remove_file(&link);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
