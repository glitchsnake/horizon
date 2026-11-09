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
            let s = l.trim();
            if s.is_empty() || s.starts_with('#') {
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

fn matches_prefix(prefix: &str, target: &str) -> bool {
    let (p, t) = (prefix.trim_end_matches('/'), target.trim_end_matches('/'));
    t == p
        || target.starts_with(prefix)
        || target.strip_prefix(p).is_some_and(|r| r.starts_with('/'))
}

fn match_glob(p: &str, t: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (p.chars().collect(), t.chars().collect());
    glob_slice(&p, &t)
}

fn glob_slice(mut p: &[char], mut t: &[char]) -> bool {
    while !p.is_empty() {
        if p.starts_with(&['*', '*']) {
            let rest = &p[2..];
            if let Some(&'/') = rest.first() {
                if glob_slice(&rest[1..], t) {
                    return true;
                }
                for i in 0..t.len() {
                    if t[i] == '/' && glob_slice(&rest[1..], &t[i + 1..]) {
                        return true;
                    }
                }
                return false;
            }
            return (0..=t.len()).any(|i| glob_slice(rest, &t[i..]));
        } else if p[0] == '*' {
            let rest = &p[1..];
            for i in 0..=t.len() {
                if i > 0 && t[i - 1] == '/' {
                    break;
                }
                if glob_slice(rest, &t[i..]) {
                    return true;
                }
            }
            return false;
        } else if p[0] == '?' {
            if t.is_empty() || t[0] == '/' {
                return false;
            }
            p = &p[1..];
            t = &t[1..];
        } else if p[0] == '[' {
            let Some(close) = p.iter().position(|&c| c == ']') else {
                return false;
            };
            if t.is_empty() || t[0] == '/' {
                return false;
            }
            let (neg, content) = if p.get(1) == Some(&'!') || p.get(1) == Some(&'^') {
                (true, &p[2..close])
            } else {
                (false, &p[1..close])
            };
            let mut matched = false;
            let mut i = 0;
            while i < content.len() {
                if i + 2 < content.len() && content[i + 1] == '-' {
                    if t[0] >= content[i] && t[0] <= content[i + 2] {
                        matched = true;
                        break;
                    }
                    i += 3;
                } else {
                    if t[0] == content[i] {
                        matched = true;
                        break;
                    }
                    i += 1;
                }
            }
            if matched == neg {
                return false;
            }
            p = &p[close + 1..];
            t = &t[1..];
        } else if p[0] == '{' {
            let (mut depth, mut close, mut alts, mut start) = (0, 0, Vec::new(), 1);
            for (idx, &c) in p.iter().enumerate() {
                if c == '{' {
                    depth += 1;
                } else if c == '}' {
                    depth -= 1;
                    if depth == 0 {
                        close = idx;
                        alts.push(&p[start..idx]);
                        break;
                    }
                } else if c == ',' && depth == 1 {
                    alts.push(&p[start..idx]);
                    start = idx + 1;
                }
            }
            if close == 0 {
                return false;
            }
            let after = &p[close + 1..];
            return alts.into_iter().any(|alt| {
                let mut c = alt.to_vec();
                c.extend_from_slice(after);
                glob_slice(&c, t)
            });
        } else {
            let (ch, advance) = if p[0] == '\\' && p.len() > 1 {
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

fn clean_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            c => out.push(c.as_os_str()),
        }
    }
    out
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
            Ok(target) => {
                let resolved = path
                    .parent()
                    .map(|p| p.join(&target))
                    .unwrap_or_else(|| target.clone());
                let (ct, cr) = (clean_path(&target), clean_path(&resolved));
                if !self.allow_list.matches(&target)
                    && !self.allow_list.matches(&ct)
                    && !self.allow_list.matches(&resolved)
                    && !self.allow_list.matches(&cr)
                {
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

/// Returns the default DirectoryValidator by searching for allowed_symlinks.txt
/// in standard locations (dir parent, player_dir, game_home, current dir).
pub fn default_validator_for(dir: Option<&Path>) -> DirectoryValidator {
    let mut candidates = Vec::new();
    if let Some(d) = dir {
        candidates.push(d.join("allowed_symlinks.txt"));
        if let Some(p) = d.parent() {
            candidates.push(p.join("allowed_symlinks.txt"));
            if let Some(gp) = p.parent() {
                candidates.push(gp.join("allowed_symlinks.txt"));
            }
        }
    }
    candidates.push(crate::logging::player_dir().join("allowed_symlinks.txt"));
    candidates.push(crate::logging::game_home().join("allowed_symlinks.txt"));
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("allowed_symlinks.txt"));
    }
    candidates
        .into_iter()
        .find(|c| c.is_file())
        .map_or_else(DirectoryValidator::no_symlinks_allowed, |c| {
            parse_validator(&c)
        })
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
        let text = "# comment\n[prefix]/allowed/prefix\n[glob]**/*.zip\n";
        let list = PathAllowList::read_plain(text.as_bytes()).unwrap();
        assert!(list.matches(Path::new("/allowed/prefix/pack")));
        assert!(list.matches(Path::new("deep/folder/pack.zip")));
        assert!(!list.matches(Path::new("/forbidden/pack")));
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
