use std::fmt;

pub trait StringWrap {
    fn wrap(&self, width: usize) -> StringWrapper;
    fn hex_pp(&self, width: usize) -> StringWrapper;
}

impl<T: AsRef<str>> StringWrap for T {
    fn wrap(&self, width: usize) -> StringWrapper {
        StringWrapper {
            string: self.as_ref(),
            width: width,
            hex_pp: false,
        }
    }

    fn hex_pp(&self, width: usize) -> StringWrapper {
        if width % 2 != 0 {
            panic!("Can't pretty-print odd-length string as hex");
        }

        StringWrapper {
            string: self.as_ref(),
            width: width,
            hex_pp: true,
        }
    }
}

pub struct StringWrapper<'a> {
    string: &'a str,
    width: usize,
    hex_pp: bool,
}

impl<'a> fmt::Display for StringWrapper<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut remaining_string = self.string;

        while remaining_string.len() > 0 {
            let end = remaining_string.len().min(self.width);

            if self.hex_pp {
                write!(f, "{}", &remaining_string[..2])?;

                for start in (2..end).step_by(2) {
                    write!(f, " {}", &remaining_string[start..start + 2])?;
                }

                write!(f, "\n")?;
            } else {
                writeln!(f, "{}", &remaining_string[..end])?;
            }

            remaining_string = if remaining_string.len() - end > 0 {
                &remaining_string[end..]
            } else {
                ""
            };
        }

        Ok(())
    }
}
