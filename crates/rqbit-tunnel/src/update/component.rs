/// Validates a filename component for portability across supported filesystems.
pub(crate) fn validate_portable_component(component: &str) -> Result<(), &'static str> {
    let reason = if component.is_empty() {
        Some("it contains an empty path component")
    } else if !component.is_ascii() {
        Some("it contains non-ASCII characters")
    } else if component == "." || component == ".." {
        Some("it contains a non-normal path component")
    } else if component.starts_with(" ")
        || component.starts_with(".")
        || component.ends_with(" ")
        || component.ends_with(".")
    {
        Some("it begins or ends with a space or period")
    } else if component.bytes().any(|byte| byte.is_ascii_control()) {
        Some("it contains an ASCII control character")
    } else if component.contains('~') {
        Some("it contains a tilde, which could collide with a Windows short name")
    } else if component.bytes().any(|byte| {
        matches!(
            byte,
            b'<' | b'>' | b':' | b'"' | b'/' | b'\\' | b'|' | b'?' | b'*'
        )
    }) {
        Some("it contains a character forbidden on Windows")
    } else if has_windows_reserved_device_basename(component) {
        Some("it has a Windows reserved device basename")
    } else {
        None
    };

    reason.map_or(Ok(()), Err)
}

fn has_windows_reserved_device_basename(component: &str) -> bool {
    let basename = component
        .split_once('.')
        .map_or(component, |(basename, _)| basename)
        .trim_end_matches(|character| matches!(character, ' ' | '.'));
    [
        "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$", "COM1", "COM2", "COM3", "COM4",
        "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6",
        "LPT7", "LPT8", "LPT9",
    ]
    .into_iter()
    .any(|reserved| basename.eq_ignore_ascii_case(reserved))
}
