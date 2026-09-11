//! Bounded lexical discovery of static JavaScript/TypeScript imports.
//!
//! This is not a compiler or a name resolver. It keeps quoted examples and
//! comments out of the dependency plan while retaining multiline declarations,
//! literal loader calls, template expressions, and JSDoc import types.

use anyhow::{Result, bail};

#[derive(Debug)]
enum Token<'a> {
    Word(&'a str),
    Literal(String),
    Punct(u8),
}

impl Token<'_> {
    fn word(&self, value: &str) -> bool {
        matches!(self, Self::Word(word) if *word == value)
    }
    fn punct(&self, value: u8) -> bool {
        matches!(self, Self::Punct(punct) if *punct == value)
    }
}

pub(super) fn extract(text: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut imports = Vec::new();
    code_tokens(text, &mut 0, false, 0, &mut tokens, &mut imports)?;
    collect(&tokens, false, &mut imports);
    imports.sort();
    imports.dedup();
    if imports.len() > super::MAX_IMPORTS_PER_FILE {
        bail!("source import count exceeds the analysis planning limit");
    }
    Ok(imports)
}

fn collect(tokens: &[Token<'_>], jsdoc: bool, imports: &mut Vec<String>) {
    for (index, token) in tokens.iter().enumerate() {
        if index > 0 && tokens[index - 1].punct(b'.') {
            continue;
        }
        let rest = &tokens[index + 1..];
        let import = token.word("import");
        let loader = import || (!jsdoc && (token.word("require") || token.word("dynamic")));
        if loader && rest.first().is_some_and(|token| token.punct(b'(')) {
            if let Some(Token::Literal(value)) = rest.get(1)
                && rest
                    .get(2)
                    .is_some_and(|token| token.punct(b')') || token.punct(b','))
            {
                imports.push(value.clone());
            }
            continue;
        }
        if jsdoc {
            continue;
        }
        if import && let Some(Token::Literal(value)) = rest.first() {
            imports.push(value.clone());
            continue;
        }
        let export = token.word("export")
            && rest
                .first()
                .is_some_and(|token| token.punct(b'{') || token.punct(b'*') || token.word("type"));
        if !import && !export {
            continue;
        }
        if rest
            .first()
            .is_some_and(|token| token.punct(b'.') || token.punct(b':'))
        {
            continue;
        }
        // Only declaration-shaped tokens can precede `from`. In particular,
        // a method called `from` or a later quoted argument is not an import.
        let mut braces = 0_usize;
        for (offset, token) in rest.iter().enumerate() {
            if token.word("from") && braces == 0 {
                if let Some(Token::Literal(value)) = rest.get(offset + 1) {
                    imports.push(value.clone());
                }
                break;
            }
            match token {
                Token::Word(word)
                    if matches!(*word, "import" | "export" | "const" | "function") =>
                {
                    break;
                }
                Token::Word(_) => {}
                Token::Punct(b'{') => braces += 1,
                Token::Punct(b'}') if braces > 0 => braces -= 1,
                Token::Punct(b',' | b'*') => {}
                _ => break,
            }
        }
    }
}

fn code_tokens<'a>(
    text: &'a str,
    at: &mut usize,
    stop_at_brace: bool,
    depth: usize,
    tokens: &mut Vec<Token<'a>>,
    imports: &mut Vec<String>,
) -> Result<()> {
    if depth > 128 {
        bail!("template nesting exceeds the analysis planning limit");
    }
    let bytes = text.as_bytes();
    let mut braces = 0_usize;
    while *at < bytes.len() {
        let start = *at;
        let byte = bytes[*at];
        *at += 1;
        match byte {
            b' ' | b'\t' | b'\r' | b'\n' => {}
            b'/' if bytes.get(*at) == Some(&b'/') => {
                while *at < bytes.len() && bytes[*at] != b'\n' {
                    *at += 1;
                }
            }
            b'/' if bytes.get(*at) == Some(&b'*') => {
                *at += 1;
                let end = text[*at..].find("*/").map_or(bytes.len(), |end| *at + end);
                if bytes.get(*at) == Some(&b'*') {
                    let mut comment_tokens = Vec::new();
                    let comment = &text[*at..end];
                    code_tokens(
                        comment,
                        &mut 0,
                        false,
                        depth + 1,
                        &mut comment_tokens,
                        imports,
                    )?;
                    collect(&comment_tokens, true, imports);
                }
                *at = (end + 2).min(bytes.len());
            }
            b'\'' | b'"' => {
                if let Some(value) = literal(text, at, byte) {
                    tokens.push(Token::Literal(value));
                }
            }
            b'`' => {
                let mut value = String::new();
                let mut interpolated = false;
                while *at < bytes.len() {
                    if bytes[*at] == b'`' {
                        *at += 1;
                        break;
                    }
                    if bytes[*at] == b'$' && bytes.get(*at + 1) == Some(&b'{') {
                        interpolated = true;
                        tokens.push(Token::Punct(b'`'));
                        *at += 2;
                        code_tokens(text, at, true, depth + 1, tokens, imports)?;
                    } else if bytes[*at] == b'\\' {
                        *at += 1;
                        if let Some(ch) = escaped(text, at) {
                            value.push(ch);
                        }
                    } else {
                        let ch = text[*at..].chars().next().expect("character boundary");
                        *at += ch.len_utf8();
                        value.push(ch);
                    }
                }
                tokens.push(if interpolated {
                    Token::Punct(b'`')
                } else {
                    Token::Literal(value)
                });
            }
            b'/' if regex_can_start(tokens.last()) => {
                let mut class = false;
                while *at < bytes.len() {
                    let ch = bytes[*at];
                    *at += 1;
                    if ch == b'\\' {
                        *at = (*at + 1).min(bytes.len());
                    } else if ch == b'[' {
                        class = true;
                    } else if ch == b']' {
                        class = false;
                    } else if (ch == b'/' && !class) || ch == b'\n' {
                        break;
                    }
                }
                tokens.push(Token::Punct(b'/'));
            }
            b'{' => {
                braces += 1;
                tokens.push(Token::Punct(byte));
            }
            b'}' if stop_at_brace && braces == 0 => return Ok(()),
            b'}' => {
                braces = braces.saturating_sub(1);
                tokens.push(Token::Punct(byte));
            }
            byte if byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$') || byte >= 128 => {
                *at = start;
                while let Some(ch) = text[*at..].chars().next() {
                    if (ch.is_whitespace() || ch.is_ascii())
                        && !matches!(ch, '_' | '$')
                        && !ch.is_alphanumeric()
                    {
                        break;
                    }
                    *at += ch.len_utf8();
                }
                if *at == start {
                    *at += text[start..]
                        .chars()
                        .next()
                        .expect("character boundary")
                        .len_utf8();
                }
                tokens.push(Token::Word(&text[start..*at]));
            }
            _ => tokens.push(Token::Punct(byte)),
        }
    }
    Ok(())
}

fn regex_can_start(previous: Option<&Token<'_>>) -> bool {
    match previous {
        None => true,
        Some(Token::Punct(byte)) => matches!(
            byte,
            b'=' | b'('
                | b'['
                | b'{'
                | b','
                | b':'
                | b';'
                | b'!'
                | b'?'
                | b'&'
                | b'|'
                | b'+'
                | b'-'
                | b'*'
        ),
        Some(Token::Word(word)) => matches!(
            *word,
            "return" | "throw" | "case" | "yield" | "void" | "typeof" | "delete"
        ),
        _ => false,
    }
}

fn literal(text: &str, at: &mut usize, quote: u8) -> Option<String> {
    let mut value = String::new();
    while *at < text.len() {
        let ch = text[*at..].chars().next()?;
        *at += ch.len_utf8();
        if ch as u32 == quote as u32 {
            return Some(value);
        }
        if ch == '\\' {
            if let Some(ch) = escaped(text, at) {
                value.push(ch);
            }
        } else {
            value.push(ch);
        }
    }
    None
}

fn escaped(text: &str, at: &mut usize) -> Option<char> {
    let ch = text[*at..].chars().next()?;
    *at += ch.len_utf8();
    match ch {
        '\n' => None,
        '\r' => {
            if text.as_bytes().get(*at) == Some(&b'\n') {
                *at += 1;
            }
            None
        }
        'n' => Some('\n'),
        'r' => Some('\r'),
        't' => Some('\t'),
        'u' | 'x' => {
            let len = if ch == 'u' { 4 } else { 2 };
            let digits = text.get(*at..*at + len)?;
            let value = u32::from_str_radix(digits, 16).ok()?;
            *at += len;
            char::from_u32(value)
        }
        _ => Some(ch),
    }
}

pub(super) fn node_builtin(specifier: &str) -> bool {
    // Node's prefixed-only modules are handled by the node: namespace. The
    // unprefixed set is the shipped Node 24 baseline, not arbitrary subpaths.
    specifier.starts_with("node:")
        || matches!(
            specifier,
            "_http_agent"
                | "_http_client"
                | "_http_common"
                | "_http_incoming"
                | "_http_outgoing"
                | "_http_server"
                | "_stream_duplex"
                | "_stream_passthrough"
                | "_stream_readable"
                | "_stream_transform"
                | "_stream_wrap"
                | "_stream_writable"
                | "_tls_common"
                | "_tls_wrap"
                | "assert"
                | "assert/strict"
                | "async_hooks"
                | "buffer"
                | "child_process"
                | "cluster"
                | "console"
                | "constants"
                | "crypto"
                | "dgram"
                | "diagnostics_channel"
                | "dns"
                | "dns/promises"
                | "domain"
                | "events"
                | "fs"
                | "fs/promises"
                | "http"
                | "http2"
                | "https"
                | "inspector"
                | "inspector/promises"
                | "module"
                | "net"
                | "os"
                | "path"
                | "path/posix"
                | "path/win32"
                | "perf_hooks"
                | "process"
                | "punycode"
                | "querystring"
                | "readline"
                | "readline/promises"
                | "repl"
                | "stream"
                | "stream/consumers"
                | "stream/promises"
                | "stream/web"
                | "string_decoder"
                | "sys"
                | "timers"
                | "timers/promises"
                | "tls"
                | "trace_events"
                | "tty"
                | "url"
                | "util"
                | "util/types"
                | "v8"
                | "vm"
                | "wasi"
                | "worker_threads"
                | "zlib"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_import_syntax_from_examples_and_method_names() -> Result<()> {
        let imports = extract(
            r#"
            // import missing from 'comment-only';
            const example = "import missing from 'string-only'";
            const template = `import missing from 'template-only'`;
            const pattern = /import\("regex-only"\)/;
            dayjs.from(value).format('YYYY/MM/DD');
            object.require('method-only');
            import {
                first,
                second as renamed
            } from
                'actual-package';
            export { third }
                from './re-export';
            import './side-effect';
            const lazy = import('./lazy', { with: { type: 'json' } });
            const cjs = require('./commonjs');
            const nested = `${(await import('./template-expression')).value}`;
            const staticTemplate = import(`./static-template`);
            /** @type {import('type-package').Config} */
            const config = {};
        "#,
        )?;
        assert_eq!(
            imports,
            [
                "./commonjs",
                "./lazy",
                "./re-export",
                "./side-effect",
                "./static-template",
                "./template-expression",
                "actual-package",
                "type-package"
            ]
        );
        Ok(())
    }

    #[test]
    fn preserves_escaped_specifiers_and_does_not_invent_builtin_subpaths() -> Result<()> {
        assert_eq!(
            extract(r#"import '\u0040example/shared'; export * from "./a\u002fb";"#)?,
            ["./a/b", "@example/shared"]
        );
        assert_eq!(
            extract("import 日本語 from 'unicode-binding';")?,
            ["unicode-binding"]
        );
        assert!(node_builtin("fs/promises"));
        assert!(node_builtin("child_process"));
        assert!(!node_builtin("fs/missing"));
        assert!(!node_builtin("node_module_lookalike"));
        Ok(())
    }
}
