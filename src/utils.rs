use colored::Colorize;

pub fn check_mark(result: bool) -> colored::ColoredString {
    if result {
        "✓".green()
    } else {
        "✗".red()
    }
}
