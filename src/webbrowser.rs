//! Text-based web browser for telnet sessions.
//!
//! Fetches HTTP(S) pages, converts HTML to wrapped plain text with numbered
//! link references, and supports page-by-page navigation. Designed to work
//! within the 40-column PETSCII constraint as well as wider ANSI/ASCII terminals.

use html2text::render::{RichAnnotation, TaggedLine, TaggedLineElement};
use html2text::{config, Element, Handle, RcDom};
use std::io::Read;
use ureq::ResponseExt;

/// Bookmarks file, stored next to the binary.
const BOOKMARKS_FILE: &str = "bookmarks.txt";
/// Maximum number of bookmarks.
const MAX_BOOKMARKS: usize = 100;

/// Maximum HTTP response body size (1 MB).
const MAX_BODY_SIZE: usize = 1024 * 1024;
/// Maximum rendered lines to keep (prevents memory bloat on huge pages).
const MAX_RENDERED_LINES: usize = 5000;
/// HTTP request timeout in seconds.
const HTTP_TIMEOUT_SECS: u64 = 15;

/// Result of fetching and rendering a web page.
pub(crate) struct WebPage {
    /// Page title extracted from <title>, if any.
    pub title: Option<String>,
    /// Rendered text lines (plain text, already wrapped to target width).
    pub lines: Vec<String>,
    /// Extracted link URLs, indexed starting at 1 (links[0] = link [1]).
    pub links: Vec<String>,
    /// Final URL after redirects.
    pub url: String,
    /// HTML forms found on the page.
    pub forms: Vec<WebForm>,
}

/// A single field within an HTML form.
#[derive(Clone, Debug)]
pub(crate) enum FormField {
    /// Text-like input (text, search, email, url, tel, number, password, etc.)
    Text {
        name: String,
        value: String,
        label: String,
        input_type: String,
    },
    /// Hidden input — not displayed but included in submission.
    Hidden { name: String, value: String },
    /// Textarea element.
    TextArea { name: String, value: String, label: String },
    /// Select dropdown with options.
    Select {
        name: String,
        options: Vec<(String, String)>, // (value, display_text)
        selected: usize,
        label: String,
    },
    /// Checkbox input.
    Checkbox {
        name: String,
        value: String,
        checked: bool,
        label: String,
    },
    /// Radio button input.
    Radio {
        name: String,
        value: String,
        checked: bool,
        label: String,
    },
}

/// A parsed HTML form.
#[derive(Clone, Debug)]
pub(crate) struct WebForm {
    /// Form action URL (may be relative).
    pub action: String,
    /// HTTP method: "get" or "post" (lowercase).
    pub method: String,
    /// Human-readable label for the form.
    pub label: String,
    /// Fields in document order.
    pub fields: Vec<FormField>,
}

/// Map a 1-based display number (which skips Hidden fields) to the real index.
pub(crate) fn visible_field_index(fields: &[FormField], display_num: usize) -> Option<usize> {
    let mut count = 0;
    for (i, f) in fields.iter().enumerate() {
        if matches!(f, FormField::Hidden { .. }) {
            continue;
        }
        count += 1;
        if count == display_num {
            return Some(i);
        }
    }
    None
}

/// Check whether a ureq error indicates the server doesn't speak TLS at all
/// (e.g. responds with plain HTTP to a TLS ClientHello).  Does NOT match
/// certificate validation errors — those mean TLS is working but the cert is bad.
fn is_tls_error(e: &ureq::Error) -> bool {
    let msg = e.to_string();
    msg.contains("corrupt message") || msg.contains("InvalidContentType")
}

/// Fetch a URL and render it as wrapped plain text with numbered links.
///
/// This is a blocking call (uses ureq) and should be run via `spawn_blocking`.
/// `width` is the target column count for word-wrapping (33 for PETSCII, 73 for ANSI).
pub(crate) fn fetch_and_render(url: &str, width: usize) -> Result<WebPage, String> {
    let agent = ureq::Agent::new_with_config(
        ureq::config::Config::builder()
            .timeout_global(Some(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS)))
            .build(),
    );

    // Try the request; if HTTPS fails with a TLS error, retry with HTTP
    let response = match agent
        .get(url)
        .header("User-Agent", "XmodemGateway/1.0 (text-mode browser)")
        .header("Accept", "text/html, text/plain;q=0.9, */*;q=0.1")
        .call()
    {
        Ok(r) => r,
        Err(e) if url.starts_with("https://") && is_tls_error(&e) => {
            let http_url = format!("http://{}", &url["https://".len()..]);
            agent
                .get(&http_url)
                .header("User-Agent", "XmodemGateway/1.0 (text-mode browser)")
                .header("Accept", "text/html, text/plain;q=0.9, */*;q=0.1")
                .call()
                .map_err(|e2| format!("{}", e2))?
        }
        Err(e) => return Err(format!("{}", e)),
    };

    let final_url = response.get_uri().to_string();

    // Check content type
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    // Read body with size limit
    let mut body_bytes = Vec::new();
    response
        .into_body()
        .as_reader()
        .take(MAX_BODY_SIZE as u64)
        .read_to_end(&mut body_bytes)
        .map_err(|e| format!("Read error: {}", e))?;

    if content_type.contains("text/plain") {
        // Plain text: just split into lines and wrap
        let text = String::from_utf8_lossy(&body_bytes);
        let lines: Vec<String> = text
            .lines()
            .flat_map(|line| wrap_line(line, width))
            .take(MAX_RENDERED_LINES)
            .collect();
        return Ok(WebPage {
            title: None,
            lines,
            links: Vec::new(),
            url: final_url,
            forms: Vec::new(),
        });
    }

    render_html_body(&body_bytes, final_url, width)
}

/// Submit a form (GET or POST) and return the resulting page.
///
/// Blocking call — run via `spawn_blocking`.
pub(crate) fn submit_form(base_url: &str, form: &WebForm, width: usize) -> Result<WebPage, String> {
    // Collect name/value pairs from form fields
    let mut pairs: Vec<(String, String)> = Vec::new();
    for field in &form.fields {
        match field {
            FormField::Text { name, value, .. }
            | FormField::Hidden { name, value }
            | FormField::TextArea { name, value, .. } => {
                pairs.push((name.clone(), value.clone()));
            }
            FormField::Select { name, options, selected, .. } => {
                if let Some((val, _)) = options.get(*selected) {
                    pairs.push((name.clone(), val.clone()));
                }
            }
            FormField::Checkbox { name, value, checked, .. } => {
                if *checked {
                    pairs.push((name.clone(), value.clone()));
                }
            }
            FormField::Radio { name, value, checked, .. } => {
                if *checked {
                    pairs.push((name.clone(), value.clone()));
                }
            }
        }
    }

    let action_url = if form.action.is_empty() {
        base_url.to_string()
    } else {
        resolve_url(base_url, &form.action)
    };

    let agent = ureq::Agent::new_with_config(
        ureq::config::Config::builder()
            .timeout_global(Some(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS)))
            .build(),
    );

    if form.method == "post" {
        let response = match agent
            .post(&action_url)
            .header("User-Agent", "XmodemGateway/1.0 (text-mode browser)")
            .send_form(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        {
            Ok(r) => r,
            Err(e) if action_url.starts_with("https://") && is_tls_error(&e) => {
                let http_url = format!("http://{}", &action_url["https://".len()..]);
                agent
                    .post(&http_url)
                    .header("User-Agent", "XmodemGateway/1.0 (text-mode browser)")
                    .send_form(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                    .map_err(|e2| format!("{}", e2))?
            }
            Err(e) => return Err(format!("{}", e)),
        };

        let final_url = response.get_uri().to_string();
        let mut body_bytes = Vec::new();
        response
            .into_body()
            .as_reader()
            .take(MAX_BODY_SIZE as u64)
            .read_to_end(&mut body_bytes)
            .map_err(|e| format!("Read error: {}", e))?;

        render_html_body(&body_bytes, final_url, width)
    } else {
        // GET: append query string to URL
        let mut url = url::Url::parse(&action_url)
            .map_err(|e| format!("Bad URL: {}", e))?;
        {
            let mut query = url.query_pairs_mut();
            query.clear();
            for (k, v) in &pairs {
                query.append_pair(k, v);
            }
        }
        fetch_and_render(url.as_str(), width)
    }
}

/// Parse an HTML body into a rendered WebPage with title, links, and forms.
fn render_html_body(body_bytes: &[u8], final_url: String, width: usize) -> Result<WebPage, String> {
    let cfg = config::rich();
    let dom = cfg.parse_html(body_bytes)
        .map_err(|e| format!("Parse error: {}", e))?;

    let title = extract_title_from_dom(&dom);
    let forms = extract_forms_from_dom(&dom);

    let render_tree = cfg.dom_to_render_tree(&dom)
        .map_err(|e| format!("Render error: {}", e))?;
    let tagged_lines: Vec<TaggedLine<Vec<RichAnnotation>>> = cfg.render_to_lines(render_tree, width)
        .map_err(|e| format!("Render error: {}", e))?;

    // Extract links and build numbered text.
    let mut links: Vec<String> = Vec::new();
    let mut rendered_lines: Vec<String> = Vec::new();

    for tagged_line in &tagged_lines {
        let mut line_text = String::new();
        let elements: Vec<_> = tagged_line.iter().collect();
        for (idx, element) in elements.iter().enumerate() {
            if let TaggedLineElement::Str(tagged_str) = *element as &TaggedLineElement<Vec<RichAnnotation>> {
                let seg_link = tagged_str.tag.iter().find_map(|ann| {
                    if let RichAnnotation::Link(url) = ann { Some(url.clone()) } else { None }
                });

                line_text.push_str(&tagged_str.s);

                if let Some(ref href) = seg_link {
                    let next_link = elements.get(idx + 1).and_then(|next| {
                        if let TaggedLineElement::Str(ns) = *next as &TaggedLineElement<Vec<RichAnnotation>> {
                            ns.tag.iter().find_map(|ann| {
                                if let RichAnnotation::Link(u) = ann { Some(u.clone()) } else { None }
                            })
                        } else {
                            None
                        }
                    });

                    let link_ending = match &next_link {
                        Some(next_href) => next_href != href,
                        None => true,
                    };

                    if link_ending && !href.is_empty() && !href.starts_with('#') {
                        let link_num = if let Some(pos) = links.iter().position(|l| l == href) {
                            pos + 1
                        } else {
                            links.push(href.clone());
                            links.len()
                        };
                        line_text.push_str(&format!("[{}]", link_num));
                    }
                }
            }
        }
        rendered_lines.push(line_text);
        if rendered_lines.len() >= MAX_RENDERED_LINES {
            break;
        }
    }

    Ok(WebPage {
        title,
        lines: rendered_lines,
        links,
        url: final_url,
        forms,
    })
}

/// Resolve a potentially relative URL against a base URL.
/// Also unwraps DuckDuckGo redirect URLs (`/l/?uddg=<actual_url>`) so that
/// search-result links navigate directly to the target site.
pub(crate) fn resolve_url(base: &str, relative: &str) -> String {
    let resolved = if relative.starts_with("http://") || relative.starts_with("https://") {
        relative.to_string()
    } else {
        match url::Url::parse(base) {
            Ok(base_url) => match base_url.join(relative) {
                Ok(r) => r.to_string(),
                Err(_) => relative.to_string(),
            },
            Err(_) => relative.to_string(),
        }
    };

    // Unwrap DuckDuckGo redirect links: extract the real URL from the uddg parameter
    unwrap_ddg_redirect(&resolved)
}

/// If `url` is a DuckDuckGo `/l/?uddg=<encoded_url>` redirect, return the
/// decoded target URL.  Otherwise return the input unchanged.
fn unwrap_ddg_redirect(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url)
        && parsed.host_str() == Some("duckduckgo.com")
        && parsed.path() == "/l/"
        && let Some(target) = parsed.query_pairs().find_map(|(k, v)| {
            if k == "uddg" { Some(v.into_owned()) } else { None }
        })
        && (target.starts_with("http://") || target.starts_with("https://"))
    {
        return target;
    }
    url.to_string()
}

/// Ensure a URL has a scheme, defaulting to https://.
/// If the input has no dots and no scheme, treat it as a search query.
pub(crate) fn normalize_url(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    // If no dots, treat as a search query (DuckDuckGo Lite for text browsers)
    if !trimmed.contains('.') {
        let encoded: String = trimmed
            .bytes()
            .flat_map(|b| {
                if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' {
                    vec![b as char]
                } else if b == b' ' {
                    vec!['+']
                } else {
                    format!("%{:02X}", b).chars().collect()
                }
            })
            .collect();
        return format!("https://lite.duckduckgo.com/lite/?q={}", encoded);
    }
    format!("https://{}", trimmed)
}

/// Truncate a string to fit within `max_width` columns, appending "..." if truncated.
/// Safe for multi-byte UTF-8: always truncates on a char boundary.
pub(crate) fn truncate_to_width(s: &str, max_width: usize) -> String {
    if s.len() <= max_width {
        return s.to_string();
    }
    if max_width <= 3 {
        return ".".repeat(max_width);
    }
    let target = max_width - 3;
    let mut trunc = 0;
    for (i, c) in s.char_indices() {
        let end = i + c.len_utf8();
        if end > target {
            break;
        }
        trunc = end;
    }
    format!("{}...", &s[..trunc])
}

/// Extract the `<title>` text by walking the parsed DOM tree.
fn extract_title_from_dom(dom: &RcDom) -> Option<String> {
    fn find_title(node: &Handle) -> Option<String> {
        if let Element { ref name, .. } = node.data
            && name.local.as_ref() == "title" {
                let rendered = RcDom::node_as_dom_string(node);
                let text: String = rendered
                    .lines()
                    .filter_map(|line| line.trim().strip_prefix("Text:"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let trimmed = text.trim().to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        for child in node.children.borrow().iter() {
            if let Some(title) = find_title(child) {
                return Some(title);
            }
        }
        None
    }
    find_title(&dom.document)
}

/// Get an attribute value from an element node.
fn get_attr(node: &Handle, attr_name: &str) -> Option<String> {
    if let Element { ref attrs, .. } = node.data {
        attrs.borrow().iter().find_map(|a| {
            if a.name.local.as_ref() == attr_name {
                Some(a.value.to_string())
            } else {
                None
            }
        })
    } else {
        None
    }
}

/// Extract text content from a node's subtree using RcDom's debug rendering.
fn get_text_content(node: &Handle) -> String {
    let rendered = RcDom::node_as_dom_string(node);
    rendered
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Text:"))
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

/// Extract all `<form>` elements from the DOM.
fn extract_forms_from_dom(dom: &RcDom) -> Vec<WebForm> {
    let mut forms = Vec::new();
    find_forms(&dom.document, &mut forms);
    forms
}

fn find_forms(node: &Handle, forms: &mut Vec<WebForm>) {
    if let Element { ref name, .. } = node.data
        && name.local.as_ref() == "form" {
            let action = get_attr(node, "action").unwrap_or_default();
            let method = get_attr(node, "method")
                .unwrap_or_else(|| "get".to_string())
                .to_lowercase();

            let mut fields = Vec::new();
            let mut submit_label = None;
            extract_form_fields(node, &mut fields, &mut submit_label, node);

            let label = submit_label.unwrap_or_else(|| {
                format!("Form {}", forms.len() + 1)
            });

            forms.push(WebForm { action, method, label, fields });
            return; // don't recurse into nested forms
        }
    for child in node.children.borrow().iter() {
        find_forms(child, forms);
    }
}

/// Try to find a human-readable label for a form field, checking (in order):
/// placeholder, aria-label, title, associated <label> element, then field name.
fn get_field_label(node: &Handle, field_name: &str, form_root: &Handle) -> String {
    get_attr(node, "placeholder")
        .or_else(|| get_attr(node, "aria-label"))
        .or_else(|| get_attr(node, "title"))
        .or_else(|| {
            // Look for <label for="id"> in the form
            let id = get_attr(node, "id")?;
            find_label_for_id(form_root, &id)
        })
        .unwrap_or_else(|| field_name.to_string())
}

/// Search the DOM subtree for a `<label for="target_id">` and return its text.
fn find_label_for_id(node: &Handle, target_id: &str) -> Option<String> {
    if let Element { ref name, .. } = node.data
        && name.local.as_ref() == "label"
        && let Some(for_attr) = get_attr(node, "for")
        && for_attr == target_id
    {
        let text = get_text_content(node);
        if !text.is_empty() {
            return Some(text);
        }
    }
    for child in node.children.borrow().iter() {
        if let Some(label) = find_label_for_id(child, target_id) {
            return Some(label);
        }
    }
    None
}

fn extract_form_fields(node: &Handle, fields: &mut Vec<FormField>, submit_label: &mut Option<String>, form_root: &Handle) {
    if let Element { ref name, .. } = node.data {
        let tag = name.local.as_ref();
        match tag {
            "input" => {
                let input_type = get_attr(node, "type")
                    .unwrap_or_else(|| "text".to_string())
                    .to_lowercase();
                let field_name = get_attr(node, "name").unwrap_or_default();
                let value = get_attr(node, "value").unwrap_or_default();

                match input_type.as_str() {
                    "hidden" => {
                        if !field_name.is_empty() {
                            fields.push(FormField::Hidden { name: field_name, value });
                        }
                    }
                    "submit" => {
                        if submit_label.is_none() && !value.is_empty() {
                            *submit_label = Some(value.clone());
                        }
                        if !field_name.is_empty() {
                            fields.push(FormField::Hidden { name: field_name, value });
                        }
                    }
                    "checkbox" => {
                        if !field_name.is_empty() {
                            let label = get_field_label(node, &field_name, form_root);
                            let val = if value.is_empty() { "on".to_string() } else { value };
                            let checked = get_attr(node, "checked").is_some();
                            fields.push(FormField::Checkbox { name: field_name, value: val, checked, label });
                        }
                    }
                    "radio" => {
                        if !field_name.is_empty() {
                            let label = get_attr(node, "aria-label")
                                .unwrap_or_else(|| value.clone());
                            let checked = get_attr(node, "checked").is_some();
                            fields.push(FormField::Radio { name: field_name, value, checked, label });
                        }
                    }
                    "image" | "button" | "reset" | "file" => {} // skip
                    _ => {
                        if !field_name.is_empty() {
                            let label = get_field_label(node, &field_name, form_root);
                            fields.push(FormField::Text {
                                name: field_name, value, label, input_type,
                            });
                        }
                    }
                }
            }
            "textarea" => {
                let field_name = get_attr(node, "name").unwrap_or_default();
                if !field_name.is_empty() {
                    let value = get_text_content(node);
                    let label = get_field_label(node, &field_name, form_root);
                    fields.push(FormField::TextArea { name: field_name, value, label });
                }
            }
            "select" => {
                let field_name = get_attr(node, "name").unwrap_or_default();
                if !field_name.is_empty() {
                    let mut options = Vec::new();
                    let mut selected = 0;
                    extract_select_options(node, &mut options, &mut selected);
                    let label = get_field_label(node, &field_name, form_root);
                    fields.push(FormField::Select { name: field_name, options, selected, label });
                }
            }
            "button" => {
                let btn_type = get_attr(node, "type").unwrap_or_else(|| "submit".to_string());
                if btn_type == "submit" && submit_label.is_none() {
                    let text = get_text_content(node);
                    if !text.is_empty() {
                        *submit_label = Some(text);
                    }
                }
            }
            _ => {}
        }
    }
    for child in node.children.borrow().iter() {
        if let Element { ref name, .. } = child.data
            && name.local.as_ref() == "form" {
                continue;
            }
        extract_form_fields(child, fields, submit_label, form_root);
    }
}

fn extract_select_options(node: &Handle, options: &mut Vec<(String, String)>, selected: &mut usize) {
    for child in node.children.borrow().iter() {
        if let Element { ref name, .. } = child.data {
            if name.local.as_ref() == "option" {
                let value = get_attr(child, "value")
                    .unwrap_or_else(|| get_text_content(child));
                let display = get_text_content(child);
                if get_attr(child, "selected").is_some() {
                    *selected = options.len();
                }
                options.push((value, display));
            } else if name.local.as_ref() == "optgroup" {
                extract_select_options(child, options, selected);
            }
        }
    }
}

// ─── Bookmarks ────────────────────────────────────────────────

/// A single bookmark entry.
#[derive(Clone, Debug)]
pub(crate) struct Bookmark {
    pub title: String,
    pub url: String,
}

/// Load bookmarks from the bookmarks file. Returns an empty list on any error.
pub(crate) fn load_bookmarks() -> Vec<Bookmark> {
    let content = match std::fs::read_to_string(BOOKMARKS_FILE) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut bookmarks = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((url, title)) = trimmed.split_once(' ') {
            bookmarks.push(Bookmark {
                url: url.to_string(),
                title: title.to_string(),
            });
        } else {
            bookmarks.push(Bookmark {
                url: trimmed.to_string(),
                title: trimmed.to_string(),
            });
        }
    }
    bookmarks
}

/// Save bookmarks to the bookmarks file.
fn save_bookmarks(bookmarks: &[Bookmark]) {
    let content: String = bookmarks
        .iter()
        .map(|b| {
            // Sanitize title: collapse whitespace, strip newlines
            let safe_title: String = b.title.split_whitespace().collect::<Vec<_>>().join(" ");
            format!("{} {}", b.url, safe_title)
        })
        .collect::<Vec<_>>()
        .join("\n");
    let _ = std::fs::write(BOOKMARKS_FILE, content);
}

/// Add a bookmark. Returns true if added, false if duplicate or at capacity.
pub(crate) fn add_bookmark(url: &str, title: &str) -> bool {
    let mut bookmarks = load_bookmarks();
    if bookmarks.iter().any(|b| b.url == url) {
        return false; // duplicate
    }
    if bookmarks.len() >= MAX_BOOKMARKS {
        return false; // at capacity
    }
    bookmarks.push(Bookmark {
        url: url.to_string(),
        title: title.to_string(),
    });
    save_bookmarks(&bookmarks);
    true
}

/// Remove a bookmark by index (0-based). Returns true if removed.
pub(crate) fn remove_bookmark(index: usize) -> bool {
    let mut bookmarks = load_bookmarks();
    if index >= bookmarks.len() {
        return false;
    }
    bookmarks.remove(index);
    save_bookmarks(&bookmarks);
    true
}

/// Word-wrap a single line to a given width.
/// Safe for multi-byte UTF-8: always breaks on a char boundary.
fn wrap_line(line: &str, width: usize) -> Vec<String> {
    if line.is_empty() {
        return vec![String::new()];
    }
    if line.len() <= width {
        return vec![line.to_string()];
    }
    let mut result = Vec::new();
    let mut remaining = line;
    while !remaining.is_empty() {
        if remaining.len() <= width {
            result.push(remaining.to_string());
            break;
        }
        let boundary = remaining
            .char_indices()
            .take_while(|&(i, _)| i <= width)
            .last()
            .map_or(width.min(remaining.len()), |(i, _)| i);
        let boundary = if boundary == 0 {
            remaining.char_indices().nth(1).map_or(remaining.len(), |(i, _)| i)
        } else {
            boundary
        };
        let break_at = remaining[..boundary]
            .rfind(' ')
            .unwrap_or(boundary);
        let break_at = if break_at == 0 { boundary } else { break_at };
        result.push(remaining[..break_at].to_string());
        remaining = remaining[break_at..].trim_start();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url_adds_https() {
        assert_eq!(normalize_url("example.com"), "https://example.com");
        assert_eq!(normalize_url("http://example.com"), "http://example.com");
        assert_eq!(normalize_url("https://example.com"), "https://example.com");
    }

    #[test]
    fn test_normalize_url_trims_whitespace() {
        assert_eq!(normalize_url("  example.com  "), "https://example.com");
    }

    #[test]
    fn test_resolve_url_absolute() {
        assert_eq!(
            resolve_url("https://example.com/page", "https://other.com/foo"),
            "https://other.com/foo"
        );
    }

    #[test]
    fn test_resolve_url_relative() {
        assert_eq!(
            resolve_url("https://example.com/dir/page", "other.html"),
            "https://example.com/dir/other.html"
        );
    }

    #[test]
    fn test_resolve_url_absolute_path() {
        assert_eq!(
            resolve_url("https://example.com/dir/page", "/foo/bar"),
            "https://example.com/foo/bar"
        );
    }

    /// Helper: parse HTML and extract title via DOM.
    fn title_from_html(html: &[u8]) -> Option<String> {
        let cfg = config::rich();
        let dom = cfg.parse_html(html).unwrap();
        extract_title_from_dom(&dom)
    }

    #[test]
    fn test_extract_title() {
        let html = b"<html><head><title>Hello World</title></head><body></body></html>";
        assert_eq!(title_from_html(html), Some("Hello World".to_string()));
    }

    #[test]
    fn test_extract_title_none() {
        let html = b"<html><body>No title here</body></html>";
        assert_eq!(title_from_html(html), None);
    }

    #[test]
    fn test_extract_title_empty() {
        let html = b"<html><head><title>  </title></head></html>";
        assert_eq!(title_from_html(html), None);
    }

    #[test]
    fn test_wrap_line_short() {
        assert_eq!(wrap_line("hello", 40), vec!["hello"]);
    }

    #[test]
    fn test_wrap_line_long() {
        let lines = wrap_line("the quick brown fox jumps over the lazy dog", 20);
        assert!(lines.len() > 1);
        for line in &lines {
            assert!(line.len() <= 20, "line too long: '{}'", line);
        }
    }

    #[test]
    fn test_wrap_line_empty() {
        assert_eq!(wrap_line("", 40), vec![""]);
    }

    #[test]
    fn test_wrap_line_multibyte() {
        let s = "caf\u{e9} caf\u{e9} caf\u{e9} caf\u{e9}";
        let lines = wrap_line(s, 10);
        assert!(!lines.is_empty());
        for line in &lines {
            assert!(line.len() <= 12, "line too long: '{}' ({} bytes)", line, line.len());
        }
    }

    #[test]
    fn test_web_browser_menu_fits_petscii() {
        let line = "  B  Simple Browser";
        assert!(line.len() <= 40, "menu line too long: {}", line.len());
    }

    #[test]
    fn test_web_browser_footer_fits_petscii() {
        let footer = "  P=Pv N=Nx R=Re G=Go L=Lk B=Bk Q=X";
        assert!(footer.len() <= 40, "footer too long: {} chars", footer.len());
    }

    #[test]
    fn test_web_browser_home_lines_fit_petscii() {
        let lines = [
            "  WEB BROWSER",
            "  G=Go to URL",
            "  R=Refresh Q=Back",
        ];
        for line in &lines {
            assert!(line.len() <= 40, "line too long: '{}' = {} chars", line, line.len());
        }
    }

    #[test]
    fn test_web_browser_status_line_fits_petscii() {
        let status = format!("  ({}-{} of {})", 4983, 5000, 5000);
        assert!(status.len() <= 40, "status too long: '{}' = {} chars", status, status.len());
    }

    #[test]
    fn test_truncate_to_width_multibyte() {
        let s = "caf\u{e9} latt\u{e9}";
        let result = truncate_to_width(s, 6);
        assert!(result.len() <= 9);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_truncate_to_width_ascii() {
        assert_eq!(truncate_to_width("hello", 10), "hello");
        assert_eq!(truncate_to_width("hello world", 8), "hello...");
        assert_eq!(truncate_to_width("hi", 2), "hi");
        assert_eq!(truncate_to_width("hello", 3), "...");
    }

    #[test]
    fn test_is_tls_error_corrupt_message() {
        let e = ureq::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "received corrupt message of type InvalidContentType",
        ));
        assert!(is_tls_error(&e));
    }

    #[test]
    fn test_is_tls_error_invalid_content_type() {
        let e = ureq::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "InvalidContentType",
        ));
        assert!(is_tls_error(&e));
    }

    #[test]
    fn test_is_tls_error_not_tls() {
        let e = ureq::Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ));
        assert!(!is_tls_error(&e));
    }

    #[test]
    fn test_is_tls_error_not_certificate() {
        let e = ureq::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "certificate verify failed",
        ));
        assert!(!is_tls_error(&e));
    }

    #[test]
    fn test_is_tls_error_timeout() {
        let e = ureq::Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        ));
        assert!(!is_tls_error(&e));
    }

    #[test]
    fn test_constants_sanity() {
        assert!(MAX_BODY_SIZE > 0);
        assert!(MAX_BODY_SIZE <= 10 * 1024 * 1024, "body limit should be reasonable");
        assert!(MAX_RENDERED_LINES > 0);
        assert!(HTTP_TIMEOUT_SECS > 0);
        assert!(HTTP_TIMEOUT_SECS <= 60, "timeout should not be excessive");
    }

    #[test]
    fn test_extract_title_with_attributes() {
        let html = b"<html><head><title lang=\"en\">Attributed</title></head></html>";
        assert_eq!(title_from_html(html), Some("Attributed".to_string()));
    }

    #[test]
    fn test_extract_title_mixed_case_tag() {
        let html = b"<html><head><TITLE>Upper</TITLE></head></html>";
        assert_eq!(title_from_html(html), Some("Upper".to_string()));
    }

    #[test]
    fn test_extract_title_whitespace_trimmed() {
        let html = b"<title>  spaced out  </title>";
        assert_eq!(title_from_html(html), Some("spaced out".to_string()));
    }

    #[test]
    fn test_extract_title_ignores_comment() {
        let html = b"<html><head><!-- <title>Fake</title> --><title>Real</title></head></html>";
        assert_eq!(title_from_html(html), Some("Real".to_string()));
    }

    #[test]
    fn test_extract_title_ignores_script() {
        let html = b"<html><head><script>var t = '<title>Fake</title>';</script><title>Real</title></head></html>";
        assert_eq!(title_from_html(html), Some("Real".to_string()));
    }

    #[test]
    fn test_normalize_url_search_no_dots() {
        let result = normalize_url("rust programming");
        assert!(result.starts_with("https://lite.duckduckgo.com/lite/?q="));
        assert!(result.contains("rust+programming"));
    }

    #[test]
    fn test_normalize_url_search_single_word() {
        let result = normalize_url("wikipedia");
        assert!(result.starts_with("https://lite.duckduckgo.com/lite/?q="));
    }

    #[test]
    fn test_normalize_url_with_dot_is_url() {
        assert_eq!(normalize_url("example.com"), "https://example.com");
    }

    #[test]
    fn test_normalize_url_empty() {
        // Empty input has no dots, treated as a search query
        let result = normalize_url("");
        assert!(result.starts_with("https://lite.duckduckgo.com/lite/?q="));
    }

    #[test]
    fn test_normalize_url_preserves_path() {
        assert_eq!(normalize_url("example.com/page?q=1"), "https://example.com/page?q=1");
    }

    #[test]
    fn test_resolve_url_unwraps_ddg_redirect() {
        // DuckDuckGo Lite result links go through //duckduckgo.com/l/?uddg=<encoded_url>
        let base = "https://lite.duckduckgo.com/lite/?q=test";
        let relative = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage&rut=abc123";
        assert_eq!(resolve_url(base, relative), "https://example.com/page");
    }

    #[test]
    fn test_resolve_url_unwraps_ddg_absolute() {
        let base = "https://lite.duckduckgo.com/lite/?q=test";
        let absolute = "https://duckduckgo.com/l/?uddg=https%3A%2F%2Frust-lang.org&rut=xyz";
        assert_eq!(resolve_url(base, absolute), "https://rust-lang.org");
    }

    #[test]
    fn test_resolve_url_no_unwrap_for_non_ddg() {
        // Regular redirect-style URLs should not be unwrapped
        let base = "https://example.com";
        let relative = "/redirect?url=https%3A%2F%2Fother.com";
        let result = resolve_url(base, relative);
        assert!(result.contains("redirect?url="), "should not unwrap non-DDG redirects");
    }

    #[test]
    fn test_unwrap_ddg_redirect_direct() {
        assert_eq!(
            unwrap_ddg_redirect("https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com&rut=abc"),
            "https://example.com"
        );
        // Non-DDG URL passes through
        assert_eq!(
            unwrap_ddg_redirect("https://example.com/page"),
            "https://example.com/page"
        );
        // DDG URL without uddg param passes through
        assert_eq!(
            unwrap_ddg_redirect("https://duckduckgo.com/l/?other=value"),
            "https://duckduckgo.com/l/?other=value"
        );
    }

    #[test]
    fn test_resolve_url_fragment_only() {
        let result = resolve_url("https://example.com/page", "#section");
        assert!(result.contains("example.com"), "fragment should resolve against base");
    }

    #[test]
    fn test_resolve_url_empty_relative() {
        let result = resolve_url("https://example.com/page", "");
        assert!(result.contains("example.com"));
    }

    #[test]
    fn test_visible_field_index_skips_hidden() {
        let fields = vec![
            FormField::Hidden { name: "h".into(), value: "1".into() },
            FormField::Text { name: "q".into(), value: "".into(), label: "Query".into(), input_type: "text".into() },
            FormField::Hidden { name: "h2".into(), value: "2".into() },
            FormField::Text { name: "n".into(), value: "".into(), label: "Name".into(), input_type: "text".into() },
        ];
        assert_eq!(visible_field_index(&fields, 1), Some(1));
        assert_eq!(visible_field_index(&fields, 2), Some(3));
        assert_eq!(visible_field_index(&fields, 3), None);
    }

    // ─── Bookmarks ──────────────────────────────────────────

    /// Bookmark tests use set_current_dir which is process-global, so they
    /// must be combined into a single test to avoid races with parallel tests.
    #[test]
    fn test_bookmarks() {
        let dir = std::env::temp_dir().join("xmodem_test_bookmarks_all");
        let _ = std::fs::create_dir_all(&dir);
        let saved_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        // Clean slate
        let _ = std::fs::remove_file(BOOKMARKS_FILE);

        // Round trip
        assert!(load_bookmarks().is_empty());
        assert!(add_bookmark("https://example.com", "Example"));
        assert!(add_bookmark("https://rust-lang.org", "Rust"));
        assert!(!add_bookmark("https://example.com", "Dup")); // duplicate

        let bm = load_bookmarks();
        assert_eq!(bm.len(), 2);
        assert_eq!(bm[0].url, "https://example.com");
        assert_eq!(bm[1].title, "Rust");

        assert!(remove_bookmark(0));
        let bm2 = load_bookmarks();
        assert_eq!(bm2.len(), 1);
        assert_eq!(bm2[0].url, "https://rust-lang.org");

        // Title sanitization
        let _ = std::fs::remove_file(BOOKMARKS_FILE);
        assert!(add_bookmark("https://sanitize.com", "Title\nWith\nNewlines"));
        let bm3 = load_bookmarks();
        assert_eq!(bm3.len(), 1);
        assert_eq!(bm3[0].title, "Title With Newlines");

        // Remove out of bounds
        assert!(!remove_bookmark(999));

        // Capacity test
        let _ = std::fs::remove_file(BOOKMARKS_FILE);
        for i in 0..MAX_BOOKMARKS {
            assert!(add_bookmark(&format!("https://site{}.com", i), &format!("Site {}", i)));
        }
        assert!(!add_bookmark("https://overflow.com", "Overflow"));

        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_current_dir(&saved_dir).unwrap();
    }

    #[test]
    fn test_bookmark_constants() {
        assert!(MAX_BOOKMARKS >= 10);
        assert!(MAX_BOOKMARKS <= 500);
    }
}
