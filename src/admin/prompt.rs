use std::io::{BufRead, Write};

/// Prints `"{prompt} [y/N] "` and reads one line from `reader`.
pub fn confirm(prompt: &str, assume_yes: bool, reader: &mut impl BufRead) -> bool {
    if assume_yes {
        return true;
    }
    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return false;
    }
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_accepts_y_variants() {
        for input in ["y\n", "Y\n", "yes\n", "YES\n", "  yes  \n"] {
            let mut reader = input.as_bytes();
            assert!(
                confirm("proceed?", false, &mut reader),
                "expected {input:?} to confirm"
            );
        }
    }

    #[test]
    fn confirm_rejects_everything_else() {
        for input in ["n\n", "no\n", "\n", "garbage\n"] {
            let mut reader = input.as_bytes();
            assert!(
                !confirm("proceed?", false, &mut reader),
                "expected {input:?} to reject"
            );
        }
    }

    #[test]
    fn confirm_rejects_eof() {
        let mut reader: &[u8] = &[];
        assert!(!confirm("proceed?", false, &mut reader));
    }

    #[test]
    fn confirm_assume_yes_skips_reading() {
        let mut reader: &[u8] = &[];
        assert!(confirm("proceed?", true, &mut reader));
    }
}
