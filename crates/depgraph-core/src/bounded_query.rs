use std::{
    fmt,
    fs::{self, File, Metadata},
    io::Read,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

#[cfg(not(unix))]
use std::fs::OpenOptions;

pub const BOUNDED_QUERY_CONTRACT_VERSION: &str = "bounded-graph-query-v1";
pub const BOUNDED_QUERY_CREDENTIAL_POLICY_VERSION: &str = "release-redaction-shapes-v1";
pub const MAX_QUERY_BYTES: usize = 64 * 1024;
pub const MAX_QUERY_TOKENS: usize = 4_096;
pub const MAX_QUERY_AST_NODES: usize = 512;
pub const MAX_QUERY_EXPRESSION_NESTING: usize = 16;
pub const MAX_QUERY_EXISTENTIAL_PREDICATES: usize = 16;
pub const MAX_QUERY_LIST_LITERALS: usize = 64;
pub const MAX_QUERY_PROJECTIONS: usize = 32;
pub const MAX_QUERY_DEPTH: u8 = 8;
pub const MAX_QUERY_LIMIT: u32 = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryFailureClass {
    Input,
    Security,
    Syntax,
    Limit,
    Binding,
    Type,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct QueryOrigin {
    pub line: usize,
    pub column: usize,
    pub byte_offset: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryDiagnostic {
    pub code: &'static str,
    pub class: QueryFailureClass,
    pub clause: &'static str,
    pub token_class: &'static str,
    pub origin: QueryOrigin,
    #[serde(skip)]
    message: &'static str,
}

impl QueryDiagnostic {
    fn new(
        code: &'static str,
        class: QueryFailureClass,
        clause: &'static str,
        token_class: &'static str,
        origin: QueryOrigin,
        message: &'static str,
    ) -> Self {
        Self {
            code,
            class,
            clause,
            token_class,
            origin,
            message,
        }
    }

    fn input(code: &'static str, class: QueryFailureClass, message: &'static str) -> Self {
        Self::new(
            code,
            class,
            "input",
            "query_input",
            QueryOrigin {
                line: 1,
                column: 1,
                byte_offset: 0,
            },
            message,
        )
    }

    pub(crate) fn semantic(
        code: &'static str,
        class: QueryFailureClass,
        clause: &'static str,
        token_class: &'static str,
        message: &'static str,
    ) -> Self {
        Self::new(
            code,
            class,
            clause,
            token_class,
            QueryOrigin {
                line: 1,
                column: 1,
                byte_offset: 0,
            },
            message,
        )
    }

    pub(crate) fn service_input_limit() -> Self {
        Self::input(
            "query_input_bytes_exceeded",
            QueryFailureClass::Limit,
            "query input exceeds the byte limit",
        )
    }
}

impl fmt::Display for QueryDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}; clause={}; token={}; line={}; column={}; byte={}",
            self.code,
            self.message,
            self.clause,
            self.token_class,
            self.origin.line,
            self.origin.column,
            self.origin.byte_offset
        )
    }
}

impl std::error::Error for QueryDiagnostic {}

pub type QueryResult<T> = Result<T, QueryDiagnostic>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueryAst {
    pub contract_version: String,
    pub match_clause: MatchClause,
    pub where_clause: Option<Expression>,
    pub return_clause: ReturnClause,
    pub order_by: Vec<OrderItem>,
    pub limit: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MatchClause {
    pub path_binding: String,
    pub source: NodePattern,
    pub relationship: RelationshipPattern,
    pub target: NodePattern,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodePattern {
    pub binding: String,
    pub kind: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryDirection {
    Forward,
    Reverse,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelationshipPattern {
    pub direction: QueryDirection,
    pub kinds: Vec<String>,
    pub min_depth: u8,
    pub max_depth: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Expression {
    Or(Vec<Expression>),
    And(Vec<Expression>),
    Not(Box<Expression>),
    Scalar(ScalarPredicate),
    Quantifier(QuantifierPredicate),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScalarPredicate {
    pub field: FieldReference,
    pub operator: ScalarOperator,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ScalarOperator {
    Equal(Literal),
    NotEqual(Literal),
    Less(Literal),
    LessOrEqual(Literal),
    Greater(Literal),
    GreaterOrEqual(Literal),
    StartsWith(Literal),
    In(Vec<Literal>),
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Literal {
    String(String),
    Unsigned(u64),
    Boolean(bool),
    Null,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FieldReference {
    pub binding: String,
    pub field: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantifierKind {
    EveryEdge,
    SomeSite,
    SomeEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuantifierPredicate {
    pub kind: QuantifierKind,
    pub binding: String,
    pub path_binding: String,
    pub expression: EntityExpression,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum EntityExpression {
    Or(Vec<EntityExpression>),
    And(Vec<EntityExpression>),
    Not(Box<EntityExpression>),
    Scalar(ScalarPredicate),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReturnClause {
    pub distinct: bool,
    pub projections: Vec<Projection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Projection {
    Binding(String),
    Field(FieldReference),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SortDirection {
    Ascending,
    Descending,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrderItem {
    pub projection: Projection,
    pub direction: SortDirection,
}

pub fn parse_bounded_query(query: &str) -> QueryResult<QueryAst> {
    parse_bounded_query_bytes(query.as_bytes())
}

pub fn parse_bounded_query_bytes(query: &[u8]) -> QueryResult<QueryAst> {
    if query.len() > MAX_QUERY_BYTES {
        return Err(QueryDiagnostic::input(
            "query_input_bytes_exceeded",
            QueryFailureClass::Limit,
            "query input exceeds the byte limit",
        ));
    }
    let query = std::str::from_utf8(query).map_err(|_| {
        QueryDiagnostic::input(
            "query_input_invalid_utf8",
            QueryFailureClass::Security,
            "query input is not valid UTF-8",
        )
    })?;
    let tokens = Lexer::new(query).lex()?;
    Parser::new(tokens).parse()
}

pub fn read_bounded_query_file(repository_root: &Path, query_file: &Path) -> QueryResult<String> {
    let bytes = read_bounded_repository_file(repository_root, query_file, MAX_QUERY_BYTES)?;
    String::from_utf8(bytes).map_err(|_| {
        QueryDiagnostic::input(
            "query_file_invalid_utf8",
            QueryFailureClass::Security,
            "query file is not valid UTF-8",
        )
    })
}

pub(crate) fn read_bounded_repository_file(
    repository_root: &Path,
    file: &Path,
    max_bytes: usize,
) -> QueryResult<Vec<u8>> {
    let max_bytes = u64::try_from(max_bytes).map_err(|_| {
        QueryDiagnostic::input(
            "query_file_size_or_type_invalid",
            QueryFailureClass::Security,
            "query file byte limit is invalid",
        )
    })?;
    let read_limit = max_bytes.checked_add(1).ok_or_else(|| {
        QueryDiagnostic::input(
            "query_file_size_or_type_invalid",
            QueryFailureClass::Security,
            "query file byte limit is invalid",
        )
    })?;
    let root = fs::canonicalize(repository_root).map_err(|_| {
        QueryDiagnostic::input(
            "query_file_repository_boundary_unavailable",
            QueryFailureClass::Security,
            "query file repository boundary is unavailable",
        )
    })?;
    let candidate = confined_candidate(repository_root, &root, file)?;
    reject_symlink_components(&root, &candidate)?;
    let canonical = fs::canonicalize(&candidate).map_err(|_| {
        QueryDiagnostic::input(
            "query_file_unavailable",
            QueryFailureClass::Security,
            "query file is unavailable",
        )
    })?;
    if !canonical.starts_with(&root) {
        return Err(QueryDiagnostic::input(
            "query_file_outside_repository",
            QueryFailureClass::Security,
            "query file is outside the repository boundary",
        ));
    }

    let path_before = fs::symlink_metadata(&candidate).map_err(|_| {
        QueryDiagnostic::input(
            "query_file_unavailable",
            QueryFailureClass::Security,
            "query file is unavailable",
        )
    })?;
    if path_before.file_type().is_symlink() || !path_before.file_type().is_file() {
        return Err(QueryDiagnostic::input(
            "query_file_not_regular",
            QueryFailureClass::Security,
            "query file must be a non-symlink regular file",
        ));
    }

    let mut opened = open_query_file(&root, &candidate)?;
    let before = opened.file.metadata().map_err(|_| {
        QueryDiagnostic::input(
            "query_file_metadata_unavailable",
            QueryFailureClass::Security,
            "query file metadata is unavailable",
        )
    })?;
    if !before.file_type().is_file() || before.len() > max_bytes {
        return Err(QueryDiagnostic::input(
            "query_file_size_or_type_invalid",
            QueryFailureClass::Security,
            "query file type or size is invalid",
        ));
    }
    if !same_file_identity(&path_before, &before) {
        return Err(QueryDiagnostic::input(
            "query_file_changed_during_open",
            QueryFailureClass::Security,
            "query file changed while it was opened",
        ));
    }

    let capacity = usize::try_from(before.len()).map_err(|_| {
        QueryDiagnostic::input(
            "query_file_size_or_type_invalid",
            QueryFailureClass::Security,
            "query file type or size is invalid",
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    opened
        .file
        .by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            QueryDiagnostic::input(
                "query_file_read_failed",
                QueryFailureClass::Security,
                "query file could not be read safely",
            )
        })?;
    let after = opened.file.metadata().map_err(|_| {
        QueryDiagnostic::input(
            "query_file_metadata_unavailable",
            QueryFailureClass::Security,
            "query file metadata is unavailable",
        )
    })?;
    let path_after = fs::symlink_metadata(&candidate).map_err(|_| {
        QueryDiagnostic::input(
            "query_file_changed_during_read",
            QueryFailureClass::Security,
            "query file changed while it was read",
        )
    })?;
    if !bounded_file_snapshot_is_stable(&before, &after, &path_after, bytes.len(), max_bytes) {
        return Err(QueryDiagnostic::input(
            "query_file_changed_during_read",
            QueryFailureClass::Security,
            "query file changed while it was read",
        ));
    }

    Ok(bytes)
}

pub fn parse_bounded_query_file(
    repository_root: &Path,
    query_file: &Path,
) -> QueryResult<QueryAst> {
    let query = read_bounded_query_file(repository_root, query_file)?;
    parse_bounded_query(&query)
}

fn confined_candidate(
    requested_root: &Path,
    canonical_root: &Path,
    query_file: &Path,
) -> QueryResult<PathBuf> {
    if query_file
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(QueryDiagnostic::input(
            "query_file_parent_traversal",
            QueryFailureClass::Security,
            "query file path contains parent traversal",
        ));
    }
    let candidate = if query_file.is_absolute() {
        query_file
            .strip_prefix(requested_root)
            .map(|relative| canonical_root.join(relative))
            .unwrap_or_else(|_| query_file.to_path_buf())
    } else {
        canonical_root.join(query_file)
    };
    if !candidate.starts_with(canonical_root) {
        return Err(QueryDiagnostic::input(
            "query_file_outside_repository",
            QueryFailureClass::Security,
            "query file is outside the repository boundary",
        ));
    }
    Ok(candidate)
}

fn reject_symlink_components(root: &Path, candidate: &Path) -> QueryResult<()> {
    let relative = candidate.strip_prefix(root).map_err(|_| {
        QueryDiagnostic::input(
            "query_file_outside_repository",
            QueryFailureClass::Security,
            "query file is outside the repository boundary",
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        match component {
            Component::Normal(name) => current.push(name),
            Component::CurDir => continue,
            _ => {
                return Err(QueryDiagnostic::input(
                    "query_file_path_invalid",
                    QueryFailureClass::Security,
                    "query file path is invalid",
                ));
            }
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| {
            QueryDiagnostic::input(
                "query_file_unavailable",
                QueryFailureClass::Security,
                "query file is unavailable",
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(QueryDiagnostic::input(
                "query_file_symlink_rejected",
                QueryFailureClass::Security,
                "query file path contains a symlink",
            ));
        }
    }
    Ok(())
}

struct OpenedQueryFile {
    file: File,
    #[cfg(windows)]
    _parent_directories: Vec<File>,
}

#[cfg(unix)]
fn open_query_file(root: &Path, path: &Path) -> QueryResult<OpenedQueryFile> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd as _, FromRawFd as _},
            unix::ffi::OsStrExt as _,
        },
    };

    let relative = path.strip_prefix(root).map_err(|_| {
        QueryDiagnostic::input(
            "query_file_outside_repository",
            QueryFailureClass::Security,
            "query file is outside the repository boundary",
        )
    })?;
    let names = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name),
            Component::CurDir => None,
            _ => None,
        })
        .collect::<Vec<_>>();
    if names.is_empty() || names.len() != relative.components().count() {
        return Err(query_file_open_error());
    }

    let root_name =
        CString::new(root.as_os_str().as_bytes()).map_err(|_| query_file_open_error())?;
    // SAFETY: root_name is a valid NUL-terminated path and no ownership is
    // transferred through the open call.
    let root_fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if root_fd < 0 {
        return Err(query_file_open_error());
    }
    // SAFETY: root_fd was returned uniquely by libc::open above.
    let mut directory = unsafe { File::from_raw_fd(root_fd) };
    let root_path_metadata = fs::metadata(root).map_err(|_| query_file_open_error())?;
    let root_handle_metadata = directory.metadata().map_err(|_| query_file_open_error())?;
    if !same_file_identity(&root_path_metadata, &root_handle_metadata) {
        return Err(query_file_open_error());
    }

    for (index, name) in names.iter().enumerate() {
        let name = CString::new(name.as_bytes()).map_err(|_| query_file_open_error())?;
        let is_file = index + 1 == names.len();
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if is_file { 0 } else { libc::O_DIRECTORY };
        // SAFETY: directory remains open for the call, name is NUL-terminated,
        // and openat returns a new owned descriptor on success.
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(query_file_open_error());
        }
        // SAFETY: descriptor was returned uniquely by libc::openat above.
        let opened = unsafe { File::from_raw_fd(descriptor) };
        if is_file {
            return Ok(OpenedQueryFile { file: opened });
        }
        directory = opened;
    }
    Err(query_file_open_error())
}

#[cfg(windows)]
fn open_query_file(root: &Path, path: &Path) -> QueryResult<OpenedQueryFile> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let relative = path.strip_prefix(root).map_err(|_| {
        QueryDiagnostic::input(
            "query_file_outside_repository",
            QueryFailureClass::Security,
            "query file is outside the repository boundary",
        )
    })?;
    let names = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name),
            Component::CurDir => None,
            _ => None,
        })
        .collect::<Vec<_>>();
    if names.is_empty() || names.len() != relative.components().count() {
        return Err(query_file_open_error());
    }

    let mut parent_directories = Vec::with_capacity(names.len());
    let mut current = root.to_path_buf();
    let root_directory = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&current)
        .map_err(|_| query_file_open_error())?;
    let root_metadata = root_directory
        .metadata()
        .map_err(|_| query_file_open_error())?;
    if root_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !root_metadata.is_dir()
    {
        return Err(query_file_open_error());
    }
    // Excluding FILE_SHARE_DELETE pins the repository root while descendants
    // are inspected and the final file is opened.
    parent_directories.push(root_directory);
    for name in &names[..names.len() - 1] {
        current.push(name);
        let directory = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&current)
            .map_err(|_| query_file_open_error())?;
        let metadata = directory.metadata().map_err(|_| query_file_open_error())?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir() {
            return Err(query_file_open_error());
        }
        // Excluding FILE_SHARE_DELETE pins every opened ancestor against
        // rename or replacement until the final file has been opened.
        parent_directories.push(directory);
    }

    let file = OpenOptions::new()
        .read(true)
        .write(false)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| query_file_open_error())?;
    let metadata = file.metadata().map_err(|_| query_file_open_error())?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(query_file_open_error());
    }
    Ok(OpenedQueryFile {
        file,
        _parent_directories: parent_directories,
    })
}

#[cfg(not(any(unix, windows)))]
fn open_query_file(root: &Path, path: &Path) -> QueryResult<OpenedQueryFile> {
    let canonical = fs::canonicalize(path).map_err(|_| query_file_open_error())?;
    if !canonical.starts_with(root) {
        return Err(query_file_open_error());
    }
    OpenOptions::new()
        .read(true)
        .write(false)
        .open(&canonical)
        .map(|file| OpenedQueryFile { file })
        .map_err(|_| query_file_open_error())
}

fn query_file_open_error() -> QueryDiagnostic {
    QueryDiagnostic::input(
        "query_file_open_failed",
        QueryFailureClass::Security,
        "query file could not be opened safely",
    )
}

fn metadata_modified(metadata: &Metadata) -> Option<std::time::SystemTime> {
    metadata.modified().ok()
}

#[cfg(test)]
fn query_file_snapshot_is_stable(
    before: &Metadata,
    after: &Metadata,
    path_after: &Metadata,
    bytes_read: usize,
) -> bool {
    bounded_file_snapshot_is_stable(
        before,
        after,
        path_after,
        bytes_read,
        MAX_QUERY_BYTES as u64,
    )
}

fn bounded_file_snapshot_is_stable(
    before: &Metadata,
    after: &Metadata,
    path_after: &Metadata,
    bytes_read: usize,
    max_bytes: u64,
) -> bool {
    u64::try_from(bytes_read).is_ok_and(|bytes_read| {
        bytes_read <= max_bytes
            && before.len() == after.len()
            && bytes_read == after.len()
            && same_file_identity(before, after)
            && same_file_identity(after, path_after)
            && metadata_modified(before) == metadata_modified(after)
    })
}

#[cfg(unix)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    // Rust 1.93 does not expose by-handle volume serial and file index
    // accessors on stable. Replacement is already prevented by the
    // non-delete-shared root/parent handles and the non-write/delete-shared
    // final handle, so this baseline-stable metadata comparison corroborates
    // the read snapshot without relying on a newer standard library.
    left.file_attributes() == right.file_attributes()
        && left.creation_time() == right.creation_time()
        && left.last_write_time() == right.last_write_time()
        && left.file_size() == right.file_size()
}

#[cfg(not(any(unix, windows)))]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && metadata_modified(left) == metadata_modified(right)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TokenKind {
    Identifier(String),
    String(String),
    Unsigned(u64),
    LeftParen,
    RightParen,
    LeftBracket,
    RightBracket,
    Comma,
    Colon,
    Dot,
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
    Pipe,
    Star,
    Range,
    Dash,
    ArrowRight,
    ArrowLeft,
    Semicolon,
    End,
}

impl TokenKind {
    fn class(&self) -> &'static str {
        match self {
            Self::Identifier(_) => "identifier",
            Self::String(_) => "string",
            Self::Unsigned(_) => "unsigned_integer",
            Self::LeftParen => "left_parenthesis",
            Self::RightParen => "right_parenthesis",
            Self::LeftBracket => "left_bracket",
            Self::RightBracket => "right_bracket",
            Self::Comma => "comma",
            Self::Colon => "colon",
            Self::Dot => "dot",
            Self::Equal => "equal",
            Self::NotEqual => "not_equal",
            Self::Less => "less",
            Self::LessOrEqual => "less_or_equal",
            Self::Greater => "greater",
            Self::GreaterOrEqual => "greater_or_equal",
            Self::Pipe => "pipe",
            Self::Star => "star",
            Self::Range => "range",
            Self::Dash => "dash",
            Self::ArrowRight => "right_arrow",
            Self::ArrowLeft => "left_arrow",
            Self::Semicolon => "semicolon",
            Self::End => "end_of_input",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Token {
    kind: TokenKind,
    origin: QueryOrigin,
}

struct Lexer<'a> {
    input: &'a str,
    bytes: &'a [u8],
    offset: usize,
    line: usize,
    column: usize,
    tokens: Vec<Token>,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            bytes: input.as_bytes(),
            offset: 0,
            line: 1,
            column: 1,
            tokens: Vec::new(),
        }
    }

    fn lex(mut self) -> QueryResult<Vec<Token>> {
        while self.offset < self.bytes.len() {
            match self.bytes[self.offset] {
                b' ' | b'\t' | b'\r' => self.advance_ascii(),
                b'\n' => self.advance_newline(),
                b'A'..=b'Z' | b'a'..=b'z' | b'_' => self.lex_identifier()?,
                b'0'..=b'9' => self.lex_unsigned()?,
                b'"' => self.lex_string()?,
                b'(' => self.single(TokenKind::LeftParen)?,
                b')' => self.single(TokenKind::RightParen)?,
                b'[' => self.single(TokenKind::LeftBracket)?,
                b']' => self.single(TokenKind::RightBracket)?,
                b',' => self.single(TokenKind::Comma)?,
                b':' => self.single(TokenKind::Colon)?,
                b';' => self.single(TokenKind::Semicolon)?,
                b'|' => self.single(TokenKind::Pipe)?,
                b'*' => self.single(TokenKind::Star)?,
                b'=' => self.single(TokenKind::Equal)?,
                b'!' if self.peek(1) == Some(b'=') => self.double(TokenKind::NotEqual)?,
                b'<' if self.peek(1) == Some(b'=') => self.double(TokenKind::LessOrEqual)?,
                b'<' if self.peek(1) == Some(b'-') => self.double(TokenKind::ArrowLeft)?,
                b'<' => self.single(TokenKind::Less)?,
                b'>' if self.peek(1) == Some(b'=') => self.double(TokenKind::GreaterOrEqual)?,
                b'>' => self.single(TokenKind::Greater)?,
                b'-' if self.peek(1) == Some(b'>') => self.double(TokenKind::ArrowRight)?,
                b'-' => self.single(TokenKind::Dash)?,
                b'.' if self.peek(1) == Some(b'.') => self.double(TokenKind::Range)?,
                b'.' => self.single(TokenKind::Dot)?,
                _ => {
                    return Err(self.diagnostic(
                        "query_lex_invalid_character",
                        QueryFailureClass::Syntax,
                        "lexer",
                        "invalid_character",
                        "query contains a character outside the grammar",
                    ));
                }
            }
        }
        self.tokens.push(Token {
            kind: TokenKind::End,
            origin: self.origin(),
        });
        Ok(self.tokens)
    }

    fn lex_identifier(&mut self) -> QueryResult<()> {
        let origin = self.origin();
        let start = self.offset;
        while self
            .bytes
            .get(self.offset)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            self.advance_ascii();
        }
        let value = &self.input[start..self.offset];
        if value.len() > 64 {
            return Err(QueryDiagnostic::new(
                "query_identifier_too_long",
                QueryFailureClass::Limit,
                "lexer",
                "identifier",
                origin,
                "identifier exceeds its length limit",
            ));
        }
        self.push(TokenKind::Identifier(value.to_owned()), origin)
    }

    fn lex_unsigned(&mut self) -> QueryResult<()> {
        let origin = self.origin();
        let start = self.offset;
        while self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
            self.advance_ascii();
        }
        let raw = &self.input[start..self.offset];
        if raw.len() > 1 && raw.starts_with('0') {
            return Err(QueryDiagnostic::new(
                "query_integer_not_canonical",
                QueryFailureClass::Syntax,
                "lexer",
                "unsigned_integer",
                origin,
                "unsigned integer is not canonical",
            ));
        }
        let value = raw.parse::<u64>().map_err(|_| {
            QueryDiagnostic::new(
                "query_integer_out_of_range",
                QueryFailureClass::Limit,
                "lexer",
                "unsigned_integer",
                origin,
                "unsigned integer exceeds its range",
            )
        })?;
        self.push(TokenKind::Unsigned(value), origin)
    }

    fn lex_string(&mut self) -> QueryResult<()> {
        let origin = self.origin();
        let start = self.offset;
        self.advance_ascii();
        let mut escaped = false;
        while self.offset < self.bytes.len() {
            let byte = self.bytes[self.offset];
            if !escaped && byte == b'"' {
                self.advance_ascii();
                let raw = &self.input[start..self.offset];
                let value = serde_json::from_str::<String>(raw).map_err(|_| {
                    QueryDiagnostic::new(
                        "query_string_invalid",
                        QueryFailureClass::Syntax,
                        "lexer",
                        "string",
                        origin,
                        "string literal is not valid JSON string syntax",
                    )
                })?;
                if looks_like_query_credential(&value) {
                    return Err(QueryDiagnostic::new(
                        "query_literal_credential_shape",
                        QueryFailureClass::Security,
                        "lexer",
                        "string",
                        origin,
                        "string literal matches the credential-shape policy",
                    ));
                }
                return self.push(TokenKind::String(value), origin);
            }
            if byte == b'\n' || byte == b'\r' || byte < 0x20 {
                return Err(QueryDiagnostic::new(
                    "query_string_invalid",
                    QueryFailureClass::Syntax,
                    "lexer",
                    "string",
                    origin,
                    "string literal is not valid JSON string syntax",
                ));
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            }
            if byte.is_ascii() {
                self.advance_ascii();
            } else {
                let character = self.input[self.offset..].chars().next().ok_or_else(|| {
                    self.diagnostic(
                        "query_string_invalid",
                        QueryFailureClass::Syntax,
                        "lexer",
                        "string",
                        "string literal is not valid UTF-8",
                    )
                })?;
                self.offset += character.len_utf8();
                self.column += 1;
            }
        }
        Err(QueryDiagnostic::new(
            "query_string_unterminated",
            QueryFailureClass::Syntax,
            "lexer",
            "string",
            origin,
            "string literal is unterminated",
        ))
    }

    fn single(&mut self, kind: TokenKind) -> QueryResult<()> {
        let origin = self.origin();
        self.advance_ascii();
        self.push(kind, origin)
    }

    fn double(&mut self, kind: TokenKind) -> QueryResult<()> {
        let origin = self.origin();
        self.advance_ascii();
        self.advance_ascii();
        self.push(kind, origin)
    }

    fn push(&mut self, kind: TokenKind, origin: QueryOrigin) -> QueryResult<()> {
        if self.tokens.len() >= MAX_QUERY_TOKENS {
            return Err(QueryDiagnostic::new(
                "query_token_limit_exceeded",
                QueryFailureClass::Limit,
                "lexer",
                kind.class(),
                origin,
                "query exceeds the token limit",
            ));
        }
        self.tokens.push(Token { kind, origin });
        Ok(())
    }

    fn peek(&self, ahead: usize) -> Option<u8> {
        self.bytes.get(self.offset + ahead).copied()
    }

    fn origin(&self) -> QueryOrigin {
        QueryOrigin {
            line: self.line,
            column: self.column,
            byte_offset: self.offset,
        }
    }

    fn diagnostic(
        &self,
        code: &'static str,
        class: QueryFailureClass,
        clause: &'static str,
        token_class: &'static str,
        message: &'static str,
    ) -> QueryDiagnostic {
        QueryDiagnostic::new(code, class, clause, token_class, self.origin(), message)
    }

    fn advance_ascii(&mut self) {
        self.offset += 1;
        self.column += 1;
    }

    fn advance_newline(&mut self) {
        self.offset += 1;
        self.line += 1;
        self.column = 1;
    }
}

fn looks_like_query_credential(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("bearer ")
        || lower.starts_with("basic ")
        || lower.starts_with("ghp_")
        || lower.starts_with("github_pat_")
        || lower.starts_with("sk-")
        || lower.starts_with("xoxb-")
        || lower.starts_with("xoxp-")
        || lower.starts_with("xoxa-")
        || lower.starts_with("xoxr-")
        || value.starts_with("AKIA")
        || value.starts_with("AIza")
        || (value.starts_with("eyJ") && value.matches('.').count() == 2)
        || (lower.contains("-----begin ") && lower.contains("private key-----"))
        || ["token=", "secret=", "password=", "api_key=", "apikey="]
            .iter()
            .any(|marker| lower.contains(marker))
        || url_authority_has_userinfo(value)
}

fn url_authority_has_userinfo(value: &str) -> bool {
    let Some(scheme_end) = value.find("://") else {
        return false;
    };
    if scheme_end == 0
        || !value[..scheme_end]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return false;
    }
    value[scheme_end + 3..]
        .split(['/', '?', '#'])
        .next()
        .is_some_and(|authority| authority.contains('@'))
}

struct Parser {
    tokens: Vec<Token>,
    index: usize,
    existential_predicates: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            index: 0,
            existential_predicates: 0,
        }
    }

    fn parse(mut self) -> QueryResult<QueryAst> {
        self.expect_keyword("MATCH", "match")?;
        let path_binding = self.expect_identifier("match")?;
        self.expect_simple(TokenKind::Equal, "match")?;
        let source = self.parse_node("match")?;
        let relationship = self.parse_relationship()?;
        let target = self.parse_node("match")?;
        let match_clause = MatchClause {
            path_binding,
            source,
            relationship,
            target,
        };

        let where_clause = if self.consume_keyword("WHERE") {
            Some(self.parse_expression(0)?)
        } else {
            None
        };

        self.expect_keyword("RETURN", "return")?;
        let distinct = self.consume_keyword("DISTINCT");
        let mut projections = vec![self.parse_projection("return")?];
        while self.consume_simple(&TokenKind::Comma) {
            if projections.len() >= MAX_QUERY_PROJECTIONS {
                return Err(self.error(
                    "query_projection_limit_exceeded",
                    QueryFailureClass::Limit,
                    "return",
                    "query exceeds the projection limit",
                ));
            }
            projections.push(self.parse_projection("return")?);
        }
        let return_clause = ReturnClause {
            distinct,
            projections,
        };

        let order_by = if self.consume_keyword("ORDER") {
            self.expect_keyword("BY", "order_by")?;
            let mut items = vec![self.parse_order_item()?];
            while self.consume_simple(&TokenKind::Comma) {
                if items.len() >= MAX_QUERY_PROJECTIONS {
                    return Err(self.error(
                        "query_order_limit_exceeded",
                        QueryFailureClass::Limit,
                        "order_by",
                        "query exceeds the order item limit",
                    ));
                }
                items.push(self.parse_order_item()?);
            }
            items
        } else {
            Vec::new()
        };

        self.expect_keyword("LIMIT", "limit")?;
        let (limit, origin) = self.expect_unsigned("limit")?;
        let limit = u32::try_from(limit)
            .ok()
            .filter(|value| *value > 0 && *value <= MAX_QUERY_LIMIT);
        let Some(limit) = limit else {
            return Err(QueryDiagnostic::new(
                "query_limit_out_of_range",
                QueryFailureClass::Limit,
                "limit",
                "unsigned_integer",
                origin,
                "LIMIT must be within the bounded range",
            ));
        };

        self.consume_simple(&TokenKind::Semicolon);
        if !matches!(self.current().kind, TokenKind::End) {
            return Err(self.error(
                "query_trailing_tokens",
                QueryFailureClass::Syntax,
                "query",
                "query contains trailing tokens or multiple statements",
            ));
        }

        let ast = QueryAst {
            contract_version: BOUNDED_QUERY_CONTRACT_VERSION.to_owned(),
            match_clause,
            where_clause,
            return_clause,
            order_by,
            limit,
        };
        if ast_node_count(&ast) > MAX_QUERY_AST_NODES {
            return Err(self.error(
                "query_ast_node_limit_exceeded",
                QueryFailureClass::Limit,
                "query",
                "query exceeds the AST node limit",
            ));
        }
        Ok(ast)
    }

    fn parse_node(&mut self, clause: &'static str) -> QueryResult<NodePattern> {
        self.expect_simple(TokenKind::LeftParen, clause)?;
        let binding = self.expect_identifier(clause)?;
        let kind = if self.consume_simple(&TokenKind::Colon) {
            Some(self.expect_string(clause)?)
        } else {
            None
        };
        self.expect_simple(TokenKind::RightParen, clause)?;
        Ok(NodePattern { binding, kind })
    }

    fn parse_relationship(&mut self) -> QueryResult<RelationshipPattern> {
        let direction = if self.consume_simple(&TokenKind::ArrowLeft) {
            QueryDirection::Reverse
        } else {
            self.expect_simple(TokenKind::Dash, "match")?;
            QueryDirection::Forward
        };
        self.expect_simple(TokenKind::LeftBracket, "match")?;
        let mut kinds = vec![self.expect_string("match")?];
        while self.consume_simple(&TokenKind::Pipe) {
            kinds.push(self.expect_string("match")?);
        }
        kinds.sort();
        if kinds.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(self.error(
                "query_duplicate_relationship_kind",
                QueryFailureClass::Syntax,
                "match",
                "relationship kind set contains a duplicate",
            ));
        }
        self.expect_simple(TokenKind::Star, "match")?;
        let (min_depth, min_origin) = self.expect_unsigned("match")?;
        self.expect_simple(TokenKind::Range, "match")?;
        let (max_depth, max_origin) = self.expect_unsigned("match")?;
        self.expect_simple(TokenKind::RightBracket, "match")?;
        match direction {
            QueryDirection::Forward => self.expect_simple(TokenKind::ArrowRight, "match")?,
            QueryDirection::Reverse => self.expect_simple(TokenKind::Dash, "match")?,
        }
        let min_depth = u8::try_from(min_depth)
            .ok()
            .filter(|depth| (1..=MAX_QUERY_DEPTH).contains(depth))
            .ok_or_else(|| {
                QueryDiagnostic::new(
                    "query_depth_out_of_range",
                    QueryFailureClass::Limit,
                    "match",
                    "unsigned_integer",
                    min_origin,
                    "minimum depth is outside the bounded range",
                )
            })?;
        let max_depth = u8::try_from(max_depth)
            .ok()
            .filter(|depth| (1..=MAX_QUERY_DEPTH).contains(depth))
            .ok_or_else(|| {
                QueryDiagnostic::new(
                    "query_depth_out_of_range",
                    QueryFailureClass::Limit,
                    "match",
                    "unsigned_integer",
                    max_origin,
                    "maximum depth is outside the bounded range",
                )
            })?;
        if min_depth > max_depth {
            return Err(QueryDiagnostic::new(
                "query_depth_range_invalid",
                QueryFailureClass::Syntax,
                "match",
                "unsigned_integer",
                min_origin,
                "minimum depth exceeds maximum depth",
            ));
        }
        Ok(RelationshipPattern {
            direction,
            kinds,
            min_depth,
            max_depth,
        })
    }

    fn parse_expression(&mut self, nesting: usize) -> QueryResult<Expression> {
        self.ensure_nesting(nesting, "where")?;
        let mut terms = vec![self.parse_and_expression(nesting)?];
        while self.consume_keyword("OR") {
            terms.push(self.parse_and_expression(nesting)?);
        }
        Ok(canonical_expression_or(terms))
    }

    fn parse_and_expression(&mut self, nesting: usize) -> QueryResult<Expression> {
        let mut terms = vec![self.parse_not_expression(nesting)?];
        while self.consume_keyword("AND") {
            terms.push(self.parse_not_expression(nesting)?);
        }
        Ok(canonical_expression_and(terms))
    }

    fn parse_not_expression(&mut self, nesting: usize) -> QueryResult<Expression> {
        let negated = self.consume_keyword("NOT");
        let expression = self.parse_primary_expression(nesting)?;
        Ok(if negated {
            Expression::Not(Box::new(expression))
        } else {
            expression
        })
    }

    fn parse_primary_expression(&mut self, nesting: usize) -> QueryResult<Expression> {
        if self.consume_simple(&TokenKind::LeftParen) {
            self.ensure_nesting(nesting + 1, "where")?;
            let expression = self.parse_expression(nesting + 1)?;
            self.expect_simple(TokenKind::RightParen, "where")?;
            return Ok(expression);
        }
        if self.current_keyword("EVERY") || self.current_keyword("SOME") {
            return self
                .parse_quantifier(nesting + 1)
                .map(Expression::Quantifier);
        }
        self.parse_scalar_predicate("where").map(Expression::Scalar)
    }

    fn parse_quantifier(&mut self, nesting: usize) -> QueryResult<QuantifierPredicate> {
        self.ensure_nesting(nesting, "where")?;
        let every = self.consume_keyword("EVERY");
        if !every {
            self.expect_keyword("SOME", "where")?;
            self.existential_predicates += 1;
            if self.existential_predicates > MAX_QUERY_EXISTENTIAL_PREDICATES {
                return Err(self.error(
                    "query_existential_limit_exceeded",
                    QueryFailureClass::Limit,
                    "where",
                    "query exceeds the existential predicate limit",
                ));
            }
        }
        let binding = self.expect_identifier("where")?;
        self.expect_keyword("IN", "where")?;
        let kind = if every {
            self.expect_keyword("EDGES", "where")?;
            QuantifierKind::EveryEdge
        } else if self.consume_keyword("SITES") {
            QuantifierKind::SomeSite
        } else if self.consume_keyword("EVIDENCE") {
            QuantifierKind::SomeEvidence
        } else {
            return Err(self.error(
                "query_quantifier_collection_invalid",
                QueryFailureClass::Syntax,
                "where",
                "quantifier collection is outside the grammar",
            ));
        };
        self.expect_simple(TokenKind::LeftParen, "where")?;
        let path_binding = self.expect_identifier("where")?;
        self.expect_simple(TokenKind::RightParen, "where")?;
        self.expect_keyword("SATISFIES", "where")?;
        let expression = self.parse_entity_expression(nesting, &binding)?;
        Ok(QuantifierPredicate {
            kind,
            binding,
            path_binding,
            expression,
        })
    }

    fn parse_entity_expression(
        &mut self,
        nesting: usize,
        binding: &str,
    ) -> QueryResult<EntityExpression> {
        self.ensure_nesting(nesting, "where")?;
        let mut terms = vec![self.parse_entity_and_expression(nesting, binding)?];
        while self.current_keyword("OR") && self.entity_term_starts_at(self.index + 1, binding) {
            self.index += 1;
            terms.push(self.parse_entity_and_expression(nesting, binding)?);
        }
        Ok(canonical_entity_or(terms))
    }

    fn parse_entity_and_expression(
        &mut self,
        nesting: usize,
        binding: &str,
    ) -> QueryResult<EntityExpression> {
        let mut terms = vec![self.parse_entity_term(nesting, binding)?];
        while self.current_keyword("AND") && self.entity_term_starts_at(self.index + 1, binding) {
            self.index += 1;
            terms.push(self.parse_entity_term(nesting, binding)?);
        }
        Ok(canonical_entity_and(terms))
    }

    fn parse_entity_term(
        &mut self,
        nesting: usize,
        binding: &str,
    ) -> QueryResult<EntityExpression> {
        let negated = self.consume_keyword("NOT");
        let expression = if self.consume_simple(&TokenKind::LeftParen) {
            self.ensure_nesting(nesting + 1, "where")?;
            let expression = self.parse_entity_expression(nesting + 1, binding)?;
            self.expect_simple(TokenKind::RightParen, "where")?;
            expression
        } else {
            EntityExpression::Scalar(self.parse_scalar_predicate("where")?)
        };
        Ok(if negated {
            EntityExpression::Not(Box::new(expression))
        } else {
            expression
        })
    }

    fn parse_scalar_predicate(&mut self, clause: &'static str) -> QueryResult<ScalarPredicate> {
        let field = self.parse_field(clause)?;
        let operator = if self.consume_simple(&TokenKind::Equal) {
            ScalarOperator::Equal(self.parse_literal(clause)?)
        } else if self.consume_simple(&TokenKind::NotEqual) {
            ScalarOperator::NotEqual(self.parse_literal(clause)?)
        } else if self.consume_simple(&TokenKind::Less) {
            ScalarOperator::Less(self.parse_literal(clause)?)
        } else if self.consume_simple(&TokenKind::LessOrEqual) {
            ScalarOperator::LessOrEqual(self.parse_literal(clause)?)
        } else if self.consume_simple(&TokenKind::Greater) {
            ScalarOperator::Greater(self.parse_literal(clause)?)
        } else if self.consume_simple(&TokenKind::GreaterOrEqual) {
            ScalarOperator::GreaterOrEqual(self.parse_literal(clause)?)
        } else if self.consume_keyword("STARTS") {
            self.expect_keyword("WITH", clause)?;
            ScalarOperator::StartsWith(self.parse_literal(clause)?)
        } else if self.consume_keyword("IN") {
            self.expect_simple(TokenKind::LeftBracket, clause)?;
            let mut literals = vec![self.parse_literal(clause)?];
            while self.consume_simple(&TokenKind::Comma) {
                if literals.len() >= MAX_QUERY_LIST_LITERALS {
                    return Err(self.error(
                        "query_list_literal_limit_exceeded",
                        QueryFailureClass::Limit,
                        clause,
                        "query exceeds the list literal limit",
                    ));
                }
                literals.push(self.parse_literal(clause)?);
            }
            self.expect_simple(TokenKind::RightBracket, clause)?;
            literals.sort();
            if literals.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(self.error(
                    "query_duplicate_list_literal",
                    QueryFailureClass::Syntax,
                    clause,
                    "IN list contains a duplicate literal",
                ));
            }
            ScalarOperator::In(literals)
        } else {
            return Err(self.error(
                "query_scalar_operator_expected",
                QueryFailureClass::Syntax,
                clause,
                "scalar operator is missing or outside the grammar",
            ));
        };
        Ok(ScalarPredicate { field, operator })
    }

    fn parse_field(&mut self, clause: &'static str) -> QueryResult<FieldReference> {
        let binding = self.expect_identifier(clause)?;
        self.expect_simple(TokenKind::Dot, clause)?;
        let field = self.expect_identifier(clause)?;
        Ok(FieldReference { binding, field })
    }

    fn parse_literal(&mut self, clause: &'static str) -> QueryResult<Literal> {
        match self.current().kind.clone() {
            TokenKind::String(value) => {
                self.index += 1;
                Ok(Literal::String(value))
            }
            TokenKind::Unsigned(value) => {
                self.index += 1;
                Ok(Literal::Unsigned(value))
            }
            TokenKind::Identifier(value) if value.eq_ignore_ascii_case("true") => {
                self.index += 1;
                Ok(Literal::Boolean(true))
            }
            TokenKind::Identifier(value) if value.eq_ignore_ascii_case("false") => {
                self.index += 1;
                Ok(Literal::Boolean(false))
            }
            TokenKind::Identifier(value) if value.eq_ignore_ascii_case("null") => {
                self.index += 1;
                Ok(Literal::Null)
            }
            _ => Err(self.error(
                "query_literal_expected",
                QueryFailureClass::Syntax,
                clause,
                "literal is missing or outside the grammar",
            )),
        }
    }

    fn parse_projection(&mut self, clause: &'static str) -> QueryResult<Projection> {
        let binding = self.expect_identifier(clause)?;
        if self.consume_simple(&TokenKind::Dot) {
            let field = self.expect_identifier(clause)?;
            Ok(Projection::Field(FieldReference { binding, field }))
        } else {
            Ok(Projection::Binding(binding))
        }
    }

    fn parse_order_item(&mut self) -> QueryResult<OrderItem> {
        let projection = self.parse_projection("order_by")?;
        let direction = if self.consume_keyword("DESC") {
            SortDirection::Descending
        } else {
            self.consume_keyword("ASC");
            SortDirection::Ascending
        };
        Ok(OrderItem {
            projection,
            direction,
        })
    }

    fn ensure_nesting(&self, nesting: usize, clause: &'static str) -> QueryResult<()> {
        if nesting > MAX_QUERY_EXPRESSION_NESTING {
            return Err(self.error(
                "query_expression_nesting_exceeded",
                QueryFailureClass::Limit,
                clause,
                "query exceeds the expression nesting limit",
            ));
        }
        Ok(())
    }

    fn entity_term_starts_at(&self, mut index: usize, binding: &str) -> bool {
        if self.tokens.get(index).is_some_and(|token| {
            matches!(
                &token.kind,
                TokenKind::Identifier(value) if value.eq_ignore_ascii_case("NOT")
            )
        }) {
            index += 1;
        }
        while matches!(
            self.tokens.get(index).map(|token| &token.kind),
            Some(TokenKind::LeftParen)
        ) {
            index += 1;
            if self.tokens.get(index).is_some_and(|token| {
                matches!(
                    &token.kind,
                    TokenKind::Identifier(value) if value.eq_ignore_ascii_case("NOT")
                )
            }) {
                index += 1;
            }
        }
        matches!(
            (
                self.tokens.get(index).map(|token| &token.kind),
                self.tokens.get(index + 1).map(|token| &token.kind),
            ),
            (
                Some(TokenKind::Identifier(candidate)),
                Some(TokenKind::Dot)
            ) if candidate == binding
        )
    }

    fn current(&self) -> &Token {
        &self.tokens[self.index]
    }

    fn current_keyword(&self, keyword: &str) -> bool {
        matches!(
            &self.current().kind,
            TokenKind::Identifier(value) if value.eq_ignore_ascii_case(keyword)
        )
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        if self.current_keyword(keyword) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect_keyword(&mut self, keyword: &str, clause: &'static str) -> QueryResult<()> {
        if self.consume_keyword(keyword) {
            Ok(())
        } else {
            Err(self.error(
                "query_keyword_expected",
                QueryFailureClass::Syntax,
                clause,
                "required keyword is missing",
            ))
        }
    }

    fn expect_identifier(&mut self, clause: &'static str) -> QueryResult<String> {
        match self.current().kind.clone() {
            TokenKind::Identifier(value) => {
                self.index += 1;
                Ok(value)
            }
            _ => Err(self.error(
                "query_identifier_expected",
                QueryFailureClass::Syntax,
                clause,
                "identifier is missing",
            )),
        }
    }

    fn expect_string(&mut self, clause: &'static str) -> QueryResult<String> {
        match self.current().kind.clone() {
            TokenKind::String(value) => {
                self.index += 1;
                Ok(value)
            }
            _ => Err(self.error(
                "query_string_expected",
                QueryFailureClass::Syntax,
                clause,
                "string literal is missing",
            )),
        }
    }

    fn expect_unsigned(&mut self, clause: &'static str) -> QueryResult<(u64, QueryOrigin)> {
        match self.current().kind.clone() {
            TokenKind::Unsigned(value) => {
                let origin = self.current().origin;
                self.index += 1;
                Ok((value, origin))
            }
            _ => Err(self.error(
                "query_unsigned_expected",
                QueryFailureClass::Syntax,
                clause,
                "unsigned integer is missing",
            )),
        }
    }

    fn consume_simple(&mut self, expected: &TokenKind) -> bool {
        if std::mem::discriminant(&self.current().kind) == std::mem::discriminant(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect_simple(&mut self, expected: TokenKind, clause: &'static str) -> QueryResult<()> {
        if self.consume_simple(&expected) {
            Ok(())
        } else {
            Err(self.error(
                "query_token_expected",
                QueryFailureClass::Syntax,
                clause,
                "required grammar token is missing",
            ))
        }
    }

    fn error(
        &self,
        code: &'static str,
        class: QueryFailureClass,
        clause: &'static str,
        message: &'static str,
    ) -> QueryDiagnostic {
        QueryDiagnostic::new(
            code,
            class,
            clause,
            self.current().kind.class(),
            self.current().origin,
            message,
        )
    }
}

fn canonical_expression_or(terms: Vec<Expression>) -> Expression {
    let mut flattened = Vec::new();
    for term in terms {
        match term {
            Expression::Or(children) => flattened.extend(children),
            term => flattened.push(term),
        }
    }
    canonical_sort(&mut flattened);
    if flattened.len() == 1 {
        flattened.pop().expect("one expression")
    } else {
        Expression::Or(flattened)
    }
}

fn canonical_expression_and(terms: Vec<Expression>) -> Expression {
    let mut flattened = Vec::new();
    for term in terms {
        match term {
            Expression::And(children) => flattened.extend(children),
            term => flattened.push(term),
        }
    }
    canonical_sort(&mut flattened);
    if flattened.len() == 1 {
        flattened.pop().expect("one expression")
    } else {
        Expression::And(flattened)
    }
}

fn canonical_entity_or(terms: Vec<EntityExpression>) -> EntityExpression {
    let mut flattened = Vec::new();
    for term in terms {
        match term {
            EntityExpression::Or(children) => flattened.extend(children),
            term => flattened.push(term),
        }
    }
    canonical_sort(&mut flattened);
    if flattened.len() == 1 {
        flattened.pop().expect("one entity expression")
    } else {
        EntityExpression::Or(flattened)
    }
}

fn canonical_entity_and(terms: Vec<EntityExpression>) -> EntityExpression {
    let mut flattened = Vec::new();
    for term in terms {
        match term {
            EntityExpression::And(children) => flattened.extend(children),
            term => flattened.push(term),
        }
    }
    canonical_sort(&mut flattened);
    if flattened.len() == 1 {
        flattened.pop().expect("one entity expression")
    } else {
        EntityExpression::And(flattened)
    }
}

fn canonical_sort<T: Serialize>(values: &mut [T]) {
    values.sort_by_cached_key(|value| {
        serde_json::to_vec(value).expect("bounded query AST serialization cannot fail")
    });
}

fn ast_node_count(ast: &QueryAst) -> usize {
    1 + 1
        + node_pattern_count(&ast.match_clause.source)
        + relationship_count(&ast.match_clause.relationship)
        + node_pattern_count(&ast.match_clause.target)
        + ast
            .where_clause
            .as_ref()
            .map(expression_count)
            .unwrap_or_default()
        + 1
        + ast
            .return_clause
            .projections
            .iter()
            .map(projection_count)
            .sum::<usize>()
        + ast.order_by.iter().map(order_item_count).sum::<usize>()
        + 1
}

fn node_pattern_count(pattern: &NodePattern) -> usize {
    1 + usize::from(pattern.kind.is_some())
}

fn relationship_count(pattern: &RelationshipPattern) -> usize {
    1 + pattern.kinds.len() + 2
}

fn expression_count(expression: &Expression) -> usize {
    1 + match expression {
        Expression::Or(terms) | Expression::And(terms) => terms.iter().map(expression_count).sum(),
        Expression::Not(expression) => expression_count(expression),
        Expression::Scalar(predicate) => scalar_predicate_count(predicate),
        Expression::Quantifier(predicate) => 1 + entity_expression_count(&predicate.expression),
    }
}

fn entity_expression_count(expression: &EntityExpression) -> usize {
    1 + match expression {
        EntityExpression::Or(terms) | EntityExpression::And(terms) => {
            terms.iter().map(entity_expression_count).sum()
        }
        EntityExpression::Not(expression) => entity_expression_count(expression),
        EntityExpression::Scalar(predicate) => scalar_predicate_count(predicate),
    }
}

fn scalar_predicate_count(predicate: &ScalarPredicate) -> usize {
    2 + match &predicate.operator {
        ScalarOperator::Equal(_)
        | ScalarOperator::NotEqual(_)
        | ScalarOperator::Less(_)
        | ScalarOperator::LessOrEqual(_)
        | ScalarOperator::Greater(_)
        | ScalarOperator::GreaterOrEqual(_)
        | ScalarOperator::StartsWith(_) => 1,
        ScalarOperator::In(literals) => 1 + literals.len(),
    }
}

fn projection_count(projection: &Projection) -> usize {
    match projection {
        Projection::Binding(_) => 1,
        Projection::Field(_) => 2,
    }
}

fn order_item_count(item: &OrderItem) -> usize {
    1 + projection_count(&item.projection)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::{
        BOUNDED_QUERY_CONTRACT_VERSION, Expression, Literal, MAX_QUERY_BYTES, QueryDirection,
        QueryFailureClass, ScalarOperator, bounded_file_snapshot_is_stable, parse_bounded_query,
        parse_bounded_query_bytes, parse_bounded_query_file, query_file_snapshot_is_stable,
        read_bounded_query_file, read_bounded_repository_file,
    };

    const MINIMAL_QUERY: &str = r#"MATCH p = (source:"route")-["calls"*1..1]->(target:"external") RETURN source.id LIMIT 1"#;

    #[test]
    fn parses_the_normative_single_statement_into_a_closed_canonical_ast() {
        let ast = parse_bounded_query(
            r#"
            match p = (source:"route")-["renders"|"calls"|"imports"*1..4]->(target:"external_system")
            where source.locator starts with "route:"
              and every edge in edges(p) satisfies
                  edge.phase in ["semantic", "build", "runtime"]
                  and edge.profile_id in ["profile-b", "profile-a"]
              and some evidence in evidence(p) satisfies
                  evidence.kind in ["runtime", "build"]
                  and evidence.path starts with "apps/web/"
              and some site in sites(p) satisfies site.kind = "call"
            return distinct source.id, target.id, p
            order by source.id, target.id, p desc
            limit 200;
            "#,
        )
        .expect("normative query parses");
        assert_eq!(ast.contract_version, BOUNDED_QUERY_CONTRACT_VERSION);
        assert_eq!(
            ast.match_clause.relationship.direction,
            QueryDirection::Forward
        );
        assert_eq!(
            ast.match_clause.relationship.kinds,
            ["calls", "imports", "renders"]
        );
        assert_eq!(ast.match_clause.relationship.min_depth, 1);
        assert_eq!(ast.match_clause.relationship.max_depth, 4);
        assert_eq!(ast.return_clause.projections.len(), 3);
        assert_eq!(ast.order_by.len(), 3);
        assert_eq!(ast.limit, 200);
        let Expression::And(terms) = ast.where_clause.expect("where") else {
            panic!("top-level expression must be canonical AND");
        };
        assert_eq!(terms.len(), 4);
    }

    #[test]
    fn canonicalizes_keyword_case_json_escapes_and_set_order() {
        let first = parse_bounded_query(
            r#"MATCH p=(s:"route")-["z"|"a"*1..2]->(t:"external") WHERE s.kind IN ["z","\u0061"] RETURN s.id LIMIT 2"#,
        )
        .unwrap();
        let second = parse_bounded_query(
            r#"match p = (s:"route") - ["a"|"z" * 1..2] -> (t:"external") where s.kind in ["a","z"] return s.id limit 2;"#,
        )
        .unwrap();
        assert_eq!(first, second);
        let Expression::Scalar(predicate) = first.where_clause.unwrap() else {
            panic!("scalar predicate expected");
        };
        assert_eq!(
            predicate.operator,
            ScalarOperator::In(vec![
                Literal::String("a".to_owned()),
                Literal::String("z".to_owned())
            ])
        );

        let grouped = parse_bounded_query(
            r#"MATCH p=(s)-["x"*1..1]->(t) WHERE s.a=1 AND (s.b=2 AND s.c=3) RETURN p LIMIT 1"#,
        )
        .unwrap();
        let reordered = parse_bounded_query(
            r#"MATCH p=(s)-["x"*1..1]->(t) WHERE s.c=3 AND s.a=1 AND s.b=2 RETURN p LIMIT 1"#,
        )
        .unwrap();
        assert_eq!(grouped, reordered);
    }

    #[test]
    fn reverse_relationship_and_boolean_precedence_are_explicit() {
        let ast = parse_bounded_query(
            r#"MATCH p=(s)<-["calls"*2..8]-(t) WHERE NOT s.kind = "x" OR s.id = "a" AND t.id != "b" RETURN p LIMIT 3"#,
        )
        .unwrap();
        assert_eq!(
            ast.match_clause.relationship.direction,
            QueryDirection::Reverse
        );
        let Expression::Or(terms) = ast.where_clause.unwrap() else {
            panic!("OR expression expected");
        };
        assert_eq!(terms.len(), 2);
        assert!(terms.iter().any(|term| matches!(term, Expression::Not(_))));
        assert!(terms.iter().any(|term| matches!(term, Expression::And(_))));
    }

    #[test]
    fn quantifier_body_stops_before_outer_predicates() {
        for outer in [
            r#"source.kind = "route""#,
            r#"(source.kind = "route")"#,
            r#"NOT source.kind = "route""#,
        ] {
            let query = format!(
                r#"MATCH p = (source:"route")-["calls"*1..2]->(target:"external")
                   WHERE EVERY edge IN EDGES(p) SATISFIES edge.phase = "runtime"
                     AND {outer}
                   RETURN source.id LIMIT 10"#
            );
            let ast = parse_bounded_query(&query).unwrap();
            let Expression::And(terms) = ast.where_clause.unwrap() else {
                panic!("outer predicate must remain outside the quantifier");
            };
            assert_eq!(terms.len(), 2);
            let quantifier = terms.iter().find_map(|term| match term {
                Expression::Quantifier(predicate) => Some(predicate),
                _ => None,
            });
            let quantifier = quantifier.expect("quantifier remains an outer AND term");
            assert!(matches!(
                quantifier.expression,
                super::EntityExpression::Scalar(_)
            ));
        }
    }

    #[test]
    fn rejects_multiple_statements_comments_and_grammar_extensions() {
        for query in [
            format!("{MINIMAL_QUERY}; {MINIMAL_QUERY}"),
            format!("{MINIMAL_QUERY} // comment"),
            format!("{MINIMAL_QUERY} UNION RETURN p LIMIT 1"),
            "MATCH p=(s)-[\"x\"*1..1]->(t) RETURN p".to_owned(),
            "MATCH p=(s)-[\"x\"]->(t) RETURN p LIMIT 1".to_owned(),
            "MATCH p=(s)-[\"x\"*1..1]->(t), q=(t)-[\"y\"*1..1]->(u) RETURN p LIMIT 1".to_owned(),
        ] {
            assert!(parse_bounded_query(&query).is_err(), "{query}");
        }
    }

    #[test]
    fn depth_limit_projection_list_nesting_token_and_ast_caps_fail_closed() {
        for query in [
            r#"MATCH p=(s)-["x"*0..1]->(t) RETURN p LIMIT 1"#.to_owned(),
            r#"MATCH p=(s)-["x"*1..9]->(t) RETURN p LIMIT 1"#.to_owned(),
            r#"MATCH p=(s)-["x"*2..1]->(t) RETURN p LIMIT 1"#.to_owned(),
            r#"MATCH p=(s)-["x"*1..1]->(t) RETURN p LIMIT 0"#.to_owned(),
            r#"MATCH p=(s)-["x"*1..1]->(t) RETURN p LIMIT 10001"#.to_owned(),
            format!(
                r#"MATCH p=(s)-["x"*1..1]->(t) WHERE s.id IN [{}] RETURN p LIMIT 1"#,
                (0..65)
                    .map(|value| value.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            format!(
                r#"MATCH p=(s)-["x"*1..1]->(t) RETURN {} LIMIT 1"#,
                (0..33)
                    .map(|value| format!("s.f{value}"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            format!(
                r#"MATCH p=(s)-["x"*1..1]->(t) WHERE {}s.id="x"{} RETURN p LIMIT 1"#,
                "(".repeat(17),
                ")".repeat(17)
            ),
            format!("{}{}", ";".repeat(4_097), MINIMAL_QUERY),
            format!(
                r#"MATCH p=(s)-["x"*1..1]->(t) WHERE {} RETURN p LIMIT 1"#,
                (0..140)
                    .map(|value| format!("s.f{value}={value}"))
                    .collect::<Vec<_>>()
                    .join(" OR ")
            ),
        ] {
            let error = parse_bounded_query(&query).expect_err("limit must reject");
            assert!(
                matches!(
                    error.class,
                    QueryFailureClass::Limit | QueryFailureClass::Syntax
                ),
                "{error}"
            );
        }
    }

    #[test]
    fn exact_parser_boundaries_are_admitted_and_the_next_value_is_rejected() {
        let projections = (0..32)
            .map(|value| format!("s.f{value}"))
            .collect::<Vec<_>>()
            .join(",");
        let literals = (0..64)
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let boundary = format!(
            r#"MATCH p=(s)-["x"*1..8]->(t) WHERE s.id IN [{literals}] RETURN {projections} LIMIT 10000"#
        );
        parse_bounded_query(&boundary).expect("exact parser boundaries must pass");

        let padded = format!(
            "{MINIMAL_QUERY}{}",
            " ".repeat(MAX_QUERY_BYTES - MINIMAL_QUERY.len())
        );
        assert_eq!(padded.len(), MAX_QUERY_BYTES);
        parse_bounded_query(&padded).expect("exact byte boundary must pass");
        assert!(parse_bounded_query(&format!("{padded} ")).is_err());

        let quantified = (0..16)
            .map(|value| {
                format!("(SOME evidence{value} IN EVIDENCE(p) SATISFIES evidence{value}.id=\"x\")")
            })
            .collect::<Vec<_>>();
        let admitted = MINIMAL_QUERY.replace(
            "RETURN source.id",
            &format!("WHERE {} RETURN source.id", quantified.join(" AND ")),
        );
        parse_bounded_query(&admitted).expect("exact existential boundary must pass");
        let rejected = MINIMAL_QUERY.replace(
            "RETURN source.id",
            &format!(
                "WHERE {} AND (SOME overflow IN EVIDENCE(p) SATISFIES overflow.id=\"x\") RETURN source.id",
                quantified.join(" AND ")
            ),
        );
        let error = parse_bounded_query(&rejected).expect_err("next existential must reject");
        assert_eq!(error.code, "query_existential_limit_exceeded");
    }

    #[test]
    fn byte_utf8_integer_identifier_duplicate_and_secret_inputs_are_rejected_without_echo() {
        assert!(parse_bounded_query_bytes(&vec![b' '; MAX_QUERY_BYTES + 1]).is_err());
        assert!(parse_bounded_query_bytes(&[0xff]).is_err());
        assert!(parse_bounded_query(&MINIMAL_QUERY.replace("LIMIT 1", "LIMIT 01")).is_err());
        assert!(parse_bounded_query(&MINIMAL_QUERY.replace("source", &"s".repeat(65))).is_err());
        assert!(
            parse_bounded_query(&MINIMAL_QUERY.replace(r#"["calls"*"#, r#"["calls"|"calls"*"#,))
                .is_err()
        );
        let duplicate = MINIMAL_QUERY.replace(
            "RETURN source.id",
            r#"WHERE source.kind IN ["route","route"] RETURN source.id"#,
        );
        assert!(parse_bounded_query(&duplicate).is_err());

        for secret in [
            "ghp_0123456789",
            "github_pat_0123456789",
            "sk-example",
            "AKIAEXAMPLE",
            "Bearer example",
            "token=example",
            "https://user:password@example.test/path",
            "-----BEGIN PRIVATE KEY----- example -----END PRIVATE KEY-----",
        ] {
            let query = MINIMAL_QUERY.replace(
                "RETURN source.id",
                &format!("WHERE source.id = {secret:?} RETURN source.id"),
            );
            let error = parse_bounded_query(&query).expect_err("secret shape must reject");
            assert_eq!(error.class, QueryFailureClass::Security);
            let rendered = error.to_string();
            assert!(!rendered.contains(secret));
            assert!(!rendered.contains(&query));
            assert!(rendered.contains("query_literal_credential_shape"));
        }
    }

    #[test]
    fn malformed_hostile_corpus_never_panics_or_accepts_a_prefix() {
        let corpus = [
            "",
            "\0",
            "MATCH",
            "MATCH p =",
            "MATCH p=(s)",
            r#"MATCH p=(s)-["x"*1..1]->(t) WHERE"#,
            r#"MATCH p=(s)-["x"*1..1]->(t) WHERE NOT NOT s.id="x" RETURN p LIMIT 1"#,
            r#"MATCH p=(s)-["x"*1..1]->(t) WHERE EVERY e IN SITES(p) SATISFIES e.id="x" RETURN p LIMIT 1"#,
            r#"MATCH p=(s)-["x"*1..1]->(t) WHERE SOME e IN EDGES(p) SATISFIES e.id="x" RETURN p LIMIT 1"#,
            r#"MATCH p=(s)-["x"*1..1]->(t) RETURN `p` LIMIT 1"#,
            r#"MATCH p=(s)-["x"*1..1]->(t) RETURN $p LIMIT 1"#,
            r#"MATCH p=(s)-["x"*1..1]->(t) RETURN p LIMIT -1"#,
            r#"MATCH p=(s)-["x"*1..1]->(t) RETURN p LIMIT 18446744073709551616"#,
            r#"MATCH p=(s)-["x"*1..1]->(t) WHERE s.id="\uD800" RETURN p LIMIT 1"#,
            r#"MATCH p=(s)-["x"*1..1]->(t) WHERE s.id="unterminated RETURN p LIMIT 1"#,
        ];
        for query in corpus {
            assert!(parse_bounded_query(query).is_err(), "{query:?}");
        }
    }

    #[test]
    fn generated_byte_corpus_is_deterministic_and_bounded() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for length in 0..512 {
            let mut bytes = Vec::with_capacity(length);
            for _ in 0..length {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                bytes.push(state as u8);
            }
            let first = parse_bounded_query_bytes(&bytes);
            let second = parse_bounded_query_bytes(&bytes);
            assert_eq!(first, second);
        }
    }

    #[test]
    fn bounded_file_reader_accepts_only_confined_stable_utf8_regular_files() {
        let repository = tempfile::tempdir().unwrap();
        let query_path = repository.path().join("query.depgraph");
        fs::write(&query_path, MINIMAL_QUERY).unwrap();
        assert_eq!(
            read_bounded_query_file(repository.path(), Path::new("query.depgraph")).unwrap(),
            MINIMAL_QUERY
        );
        parse_bounded_query_file(repository.path(), &query_path).unwrap();

        let outside = tempfile::NamedTempFile::new().unwrap();
        let error = read_bounded_query_file(repository.path(), outside.path()).unwrap_err();
        assert_eq!(error.class, QueryFailureClass::Security);
        assert!(
            !error
                .to_string()
                .contains(&outside.path().display().to_string())
        );

        let invalid = repository.path().join("invalid.depgraph");
        fs::write(&invalid, [0xff]).unwrap();
        assert!(read_bounded_query_file(repository.path(), &invalid).is_err());

        let oversized = repository.path().join("oversized.depgraph");
        fs::write(&oversized, vec![b'x'; MAX_QUERY_BYTES + 1]).unwrap();
        assert!(read_bounded_query_file(repository.path(), &oversized).is_err());

        assert!(
            read_bounded_query_file(repository.path(), Path::new("../query.depgraph")).is_err()
        );
    }

    #[test]
    fn query_file_ast_is_checkout_independent_and_snapshot_change_is_detected() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        fs::write(first.path().join("query.depgraph"), MINIMAL_QUERY).unwrap();
        fs::write(second.path().join("query.depgraph"), MINIMAL_QUERY).unwrap();
        assert_eq!(
            parse_bounded_query_file(first.path(), Path::new("query.depgraph")).unwrap(),
            parse_bounded_query_file(second.path(), Path::new("query.depgraph")).unwrap()
        );

        let file = first.path().join("race.depgraph");
        fs::write(&file, b"before").unwrap();
        let handle = fs::File::open(&file).unwrap();
        let before = handle.metadata().unwrap();
        handle
            .set_times(fs::FileTimes::new().set_modified(
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1),
            ))
            .unwrap();
        let after = handle.metadata().unwrap();
        assert!(!query_file_snapshot_is_stable(
            &before,
            &after,
            &after,
            after.len() as usize
        ));

        let replacement = first.path().join("replacement.depgraph");
        fs::write(&replacement, b"before").unwrap();
        let replacement_metadata = fs::metadata(&replacement).unwrap();
        assert!(!query_file_snapshot_is_stable(
            &after,
            &after,
            &replacement_metadata,
            after.len() as usize
        ));

        let growing = first.path().join("growing.depgraph");
        fs::write(&growing, b"before").unwrap();
        let handle = fs::File::open(&growing).unwrap();
        let before_growth = handle.metadata().unwrap();
        let mut append = fs::OpenOptions::new().append(true).open(&growing).unwrap();
        std::io::Write::write_all(&mut append, b"-after").unwrap();
        let after_growth = handle.metadata().unwrap();
        let path_after_growth = fs::metadata(&growing).unwrap();
        assert!(!bounded_file_snapshot_is_stable(
            &before_growth,
            &after_growth,
            &path_after_growth,
            before_growth.len() as usize,
            MAX_QUERY_BYTES as u64,
        ));
    }

    #[test]
    fn repository_file_reader_enforces_the_caller_byte_limit() {
        let repository = tempfile::tempdir().unwrap();
        let file = repository.path().join("bounded.bin");
        fs::write(&file, b"12345").unwrap();
        assert!(
            read_bounded_repository_file(repository.path(), Path::new("bounded.bin"), 4).is_err()
        );
        assert_eq!(
            read_bounded_repository_file(repository.path(), Path::new("bounded.bin"), 5).unwrap(),
            b"12345"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_file_reader_rejects_final_and_parent_symlinks() {
        use std::os::unix::fs::symlink;

        let repository = tempfile::tempdir().unwrap();
        let query_path = repository.path().join("query.depgraph");
        fs::write(&query_path, MINIMAL_QUERY).unwrap();
        symlink(&query_path, repository.path().join("linked.depgraph")).unwrap();
        assert!(read_bounded_query_file(repository.path(), Path::new("linked.depgraph")).is_err());

        let directory = repository.path().join("queries");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("nested.depgraph"), MINIMAL_QUERY).unwrap();
        symlink(&directory, repository.path().join("linked-queries")).unwrap();
        assert!(
            read_bounded_query_file(
                repository.path(),
                Path::new("linked-queries/nested.depgraph")
            )
            .is_err()
        );

        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("outside.depgraph"), MINIMAL_QUERY).unwrap();
        symlink(outside.path(), repository.path().join("swapped-parent")).unwrap();
        assert!(
            super::open_query_file(
                repository.path(),
                &repository.path().join("swapped-parent/outside.depgraph")
            )
            .is_err()
        );
    }
}
