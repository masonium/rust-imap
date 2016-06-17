use std::net::{TcpStream, ToSocketAddrs};
use openssl::ssl::{SslContext, SslStream};
use std::io::{Error, ErrorKind, Read, Result, Write, BufReader, BufRead};
use std::{str};
use regex::Regex;

enum IMAPStreamTypes {
    Basic(TcpStream),
    Ssl(SslStream<TcpStream>),
}

pub struct IMAPStream {
    stream: BufReader<IMAPStreamTypes>,
    tag: u32,
    tag_prefix: &'static str
}

impl Read for IMAPStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.stream.read(buf)
    }
}

impl Read for IMAPStreamTypes {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            &mut IMAPStreamTypes::Ssl(ref mut stream) => stream.read(buf),
            &mut IMAPStreamTypes::Basic(ref mut stream) => stream.read(buf),
        }
    }
}

pub struct IMAPMailbox {
    pub flags: String,
    pub exists: u32,
    pub recent: u32,
    pub unseen: Option<u32>,
    pub permanent_flags: Option<String>,
    pub uid_next: Option<u32>,
    pub uid_validity: Option<u32>,
}

impl IMAPStream {
    pub fn connect<A: ToSocketAddrs>(addr: A,
                                     ssl_context: Option<SslContext>)
                                     -> Result<IMAPStream> {
        match TcpStream::connect(addr) {
            Ok(stream) => {
                let stream = match ssl_context {
                    Some(context) =>
                        BufReader::new(IMAPStreamTypes::Ssl(SslStream::connect(&context, stream).unwrap())),
                        None => BufReader::new(IMAPStreamTypes::Basic(stream))
                };

                let mut socket = IMAPStream {
                    stream: stream,
                    tag: 1,
                    tag_prefix: "a",
                };

                try!(socket.read_greeting());
                Ok(socket)
            }
            Err(e) => Err(e),
        }
    }

    // LOGIN
    pub fn login(&mut self, username: &str, password: &str) -> Result<()> {
        self.run_command_and_check_ok(&format!("LOGIN {} {}", username, password).to_string())
    }

    // SELECT
    pub fn select(&mut self, mailbox_name: &str) -> Result<IMAPMailbox> {
        match self.run_command_with_response(&format!("SELECT {}", mailbox_name).to_string()) {
            Ok(lines) => IMAPStream::parse_select_or_examine(lines),
            Err(e) => Err(e),
        }
    }

    fn parse_select_or_examine(lines: Vec<String>) -> Result<IMAPMailbox> {
        let exists_regex = match Regex::new(r"^\* (\d+) EXISTS\r\n") {
            Ok(re) => re,
            Err(err) => panic!("{}", err),
        };

        let recent_regex = match Regex::new(r"^\* (\d+) RECENT\r\n") {
            Ok(re) => re,
            Err(err) => panic!("{}", err),
        };

        let flags_regex = match Regex::new(r"^\* FLAGS (.+)\r\n") {
            Ok(re) => re,
            Err(err) => panic!("{}", err),
        };

        let unseen_regex = match Regex::new(r"^OK \[UNSEEN (\d+)\](.*)\r\n") {
            Ok(re) => re,
            Err(err) => panic!("{}", err),
        };

        let uid_validity_regex = match Regex::new(r"^OK \[UIDVALIDITY (\d+)\](.*)\r\n") {
            Ok(re) => re,
            Err(err) => panic!("{}", err),
        };

        let uid_next_regex = match Regex::new(r"^OK \[UIDNEXT (\d+)\](.*)\r\n") {
            Ok(re) => re,
            Err(err) => panic!("{}", err),
        };

        let permanent_flags_regex = match Regex::new(r"^OK \[PERMANENTFLAGS (.+)\]\r\n") {
            Ok(re) => re,
            Err(err) => panic!("{}", err),
        };

        // Check Ok
        match IMAPStream::parse_response_ok(lines.clone()) {
            Ok(_) => (),
            Err(e) => return Err(e),
        };

        let mut mailbox = IMAPMailbox {
            flags: "".to_string(),
            exists: 0,
            recent: 0,
            unseen: None,
            permanent_flags: None,
            uid_next: None,
            uid_validity: None,
        };

        for line in lines.iter() {
            if exists_regex.is_match(line) {
                let cap = exists_regex.captures(line).unwrap();
                mailbox.exists = cap.at(1).unwrap().parse::<u32>().unwrap();
            } else if recent_regex.is_match(line) {
                let cap = recent_regex.captures(line).unwrap();
                mailbox.recent = cap.at(1).unwrap().parse::<u32>().unwrap();
            } else if flags_regex.is_match(line) {
                let cap = flags_regex.captures(line).unwrap();
                mailbox.flags = cap.at(1).unwrap().to_string();
            } else if unseen_regex.is_match(line) {
                let cap = unseen_regex.captures(line).unwrap();
                mailbox.unseen = Some(cap.at(1).unwrap().parse::<u32>().unwrap());
            } else if uid_validity_regex.is_match(line) {
                let cap = uid_validity_regex.captures(line).unwrap();
                mailbox.uid_validity = Some(cap.at(1).unwrap().parse::<u32>().unwrap());
            } else if uid_next_regex.is_match(line) {
                let cap = uid_next_regex.captures(line).unwrap();
                mailbox.uid_next = Some(cap.at(1).unwrap().parse::<u32>().unwrap());
            } else if permanent_flags_regex.is_match(line) {
                let cap = permanent_flags_regex.captures(line).unwrap();
                mailbox.permanent_flags = Some(cap.at(1).unwrap().to_string());
            }
        }

        return Ok(mailbox);
    }

    // EXAMINE
    pub fn examine(&mut self, mailbox_name: &str) -> Result<IMAPMailbox> {
        match self.run_command_with_response(&format!("EXAMINE {}", mailbox_name).to_string()) {
            Ok(lines) => IMAPStream::parse_select_or_examine(lines),
            Err(e) => Err(e),
        }
    }

    // FETCH
    pub fn fetch(&mut self, sequence_set: &str, query: &str) -> Result<Vec<String>> {
        if let Err(e) = self.run_command(&format!("FETCH {} {}", sequence_set, query).to_string()) {
            return Err(e);
        }

        self.read_fetch_rfc822_response();
        Ok(vec![])
    }

    // NOOP
    pub fn noop(&mut self) -> Result<()> {
        self.run_command_and_check_ok("NOOP")
    }

    // LOGOUT
    pub fn logout(&mut self) -> Result<()> {
        self.run_command_and_check_ok("LOGOUT")
    }

    // CREATE
    pub fn create(&mut self, mailbox_name: &str) -> Result<()> {
        self.run_command_and_check_ok(&format!("CREATE {}", mailbox_name).to_string())
    }

    // DELETE
    pub fn delete(&mut self, mailbox_name: &str) -> Result<()> {
        self.run_command_and_check_ok(&format!("DELETE {}", mailbox_name).to_string())
    }

    // RENAME
    pub fn rename(&mut self, current_mailbox_name: &str, new_mailbox_name: &str) -> Result<()> {
        self.run_command_and_check_ok(&format!("RENAME {} {}",
                                               current_mailbox_name,
                                               new_mailbox_name)
                                      .to_string())
    }

    // SUBSCRIBE
    pub fn subscribe(&mut self, mailbox: &str) -> Result<()> {
        self.run_command_and_check_ok(&format!("SUBSCRIBE {}", mailbox).to_string())
    }

    // UNSUBSCRIBE
    pub fn unsubscribe(&mut self, mailbox: &str) -> Result<()> {
        self.run_command_and_check_ok(&format!("UNSUBSCRIBE {}", mailbox).to_string())
    }

    // CAPABILITY
    pub fn capability(&mut self) -> Result<Vec<String>> {
        match self.run_command_with_response(&format!("CAPABILITY").to_string()) {
            Ok(lines) => IMAPStream::parse_capability(lines),
            Err(e) => Err(e),
        }
    }

    fn parse_capability(lines: Vec<String>) -> Result<Vec<String>> {
        let capability_regex = match Regex::new(r"^\* CAPABILITY (.*)\r\n") {
            Ok(re) => re,
            Err(err) => panic!("{}", err),
        };

        // Check Ok
        match IMAPStream::parse_response_ok(lines.clone()) {
            Ok(_) => (),
            Err(e) => return Err(e),
        };

        for line in lines.iter() {
            if capability_regex.is_match(line) {
                let cap = capability_regex.captures(line).unwrap();
                let capabilities_str = cap.at(1).unwrap();
                return Ok(capabilities_str.split(' ').map(|x| x.to_string()).collect());
            }
        }

        Err(Error::new(ErrorKind::Other, "Error parsing capabilities response"))
    }

    // COPY
    pub fn copy(&mut self, sequence_set: &str, mailbox_name: &str) -> Result<()> {
        self.run_command_and_check_ok(&format!("COPY {} {}", sequence_set, mailbox_name)
                                      .to_string())
    }

    pub fn run_command_and_check_ok(&mut self, command: &str) -> Result<()> {
        match self.run_command_with_response(command) {
            Ok(lines) => IMAPStream::parse_response_ok(lines),
            Err(e) => Err(e),
        }
    }

    pub fn run_command(&mut self, untagged_command: &str) -> Result<()> {
        let command = self.create_command(untagged_command.to_string());

        self.write_str(&*command)
    }

    pub fn run_command_with_response(&mut self, untagged_command: &str) -> Result<Vec<String>> {
        if let Err(e) = self.run_command(untagged_command) {
            return Err(e);
        }

        let ret = match self.read_response() {
            Ok(lines) => Ok(lines),
            Err(_) => Err(Error::new(ErrorKind::Other, "Failed to read")),
        };

        self.tag += 1;

        return ret;
    }

    fn parse_response_ok(lines: Vec<String>) -> Result<()> {
        let ok_regex = match Regex::new(r"^([a-zA-Z0-9]+) ([a-zA-Z0-9]+)(.*)") {
            Ok(re) => re,
            Err(err) => panic!("{}", err),
        };
        let last_line = lines.last().unwrap();

        for cap in ok_regex.captures_iter(last_line) {
            let response_type = cap.at(2).unwrap_or("");
            if response_type == "OK" {
                return Ok(());
            }
        }

        return Err(Error::new(ErrorKind::Other,
                              format!("Invalid Response: {}", last_line).to_string()));
    }

    fn write_str(&mut self, s: &str) -> Result<()> {
        match self.stream.get_mut() {
            &mut IMAPStreamTypes::Ssl(ref mut stream) => stream.write_fmt(format_args!("{}", s)),
            &mut IMAPStreamTypes::Basic(ref mut stream) => stream.write_fmt(format_args!("{}", s)),
        }
    }

    fn read_fetch_rfc822_response(&mut self) -> Result<()> {
        let mut fetch_line = String::new();
        self.stream.read_line(&mut fetch_line);
        println!("{}", fetch_line);
        lazy_static! {
            // static ref FETCH_REGEX: Regex = Regex::new(r"\*\s+[0-9]+\s+FETCH\s+\(RFC822\s+([0-9]+)").unwrap();
            static ref FETCH_REGEX: Regex = Regex::new(r"\*\s+[0-9]+\s+FETCH\s+\(RFC822\s+\{([0-9]+)\}").unwrap();

        }
        let mut response = vec![];
        for cap in FETCH_REGEX.captures_iter(&fetch_line) {
            if let Some(resp_size) = cap.at(1) {
                let response_size = resp_size.parse::<usize>().unwrap();
                // read the full response
                response.resize(response_size, 0);
                if let Ok(()) = self.stream.read_exact(&mut response) {
                    print!("Read {} bytes from stream\n {}", response_size, str::from_utf8(&response).unwrap());
                }
            }
            else {
                println!("no match found");
            }
        }
        fetch_line = String::new();
        self.stream.read_line(&mut fetch_line);
        println!("{}", fetch_line);
        fetch_line = String::new();
        self.stream.read_line(&mut fetch_line);
        println!("{}", fetch_line);

        Ok(())
    }

    fn read_response(&mut self) -> Result<Vec<String>> {
        let mut lines = Vec::new();
        let tag = format!("a{}", self.tag);
        let mut found_end = false;
        loop {
            let mut line = String::new();
            let num_read = self.stream.read_line(&mut line);
            match num_read {
                Ok(_) => {
                    if (&*line).starts_with(&*tag) {
                        found_end = true;
                    }
                    lines.push(line);
                },
                Err(_) => break
            }
            if found_end {
                break;
            }
        }
        Ok(lines)
    }

    fn read_greeting(&mut self) -> Result<()> {
        // Carriage return
        let cr = 0x0d;
        // Line Feed
        let lf = 0x0a;

        let mut line_buffer: Vec<u8> = Vec::new();
        while line_buffer.len() < 2 ||
            (line_buffer[line_buffer.len() - 1] != lf &&
             line_buffer[line_buffer.len() - 2] != cr) {
                let byte_buffer: &mut [u8] = &mut [0];
                match self.read(byte_buffer) {
                    Ok(_) => {}
                    Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to read the response")),
                }
                line_buffer.push(byte_buffer[0]);
            }

        Ok(())
    }

    fn create_command(&mut self, command: String) -> String {
        let command = format!("{}{} {}\r\n", self.tag_prefix, self.tag, command);
        return command;
    }
}

#[test]
fn connect() {
    let imap = IMAPStream::connect(("this-is-not-an-imap-server", 143), None);
    assert!(imap.is_err());
}
