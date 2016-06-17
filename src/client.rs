use std::net::{TcpStream, ToSocketAddrs};
use openssl::ssl::{SslContext, SslStream};
use std::io::{Error, ErrorKind, Read, Result, Write, BufReader, BufRead};
use std::collections::HashMap;
use std::{str};
use regex::Regex;
use email::{MimeMessage};

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

impl Write for IMAPStreamTypes {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self {
            &mut IMAPStreamTypes::Ssl(ref mut stream) => stream.write(buf),
            &mut IMAPStreamTypes::Basic(ref mut stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> Result<()> {
        match self {
            &mut IMAPStreamTypes::Ssl(ref mut stream) => stream.flush(),
            &mut IMAPStreamTypes::Basic(ref mut stream) => stream.flush(),
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
        lazy_static! {
            static ref EXISTS_REGEX: Regex = Regex::new(r"^\* (\d+) EXISTS\r\n").unwrap();
            static ref RECENT_REGEX: Regex = Regex::new(r"^\* (\d+) RECENT\r\n").unwrap();
            static ref FLAGS_REGEX: Regex = Regex::new(r"^\* FLAGS (.+)\r\n").unwrap();
            static ref UNSEEN_REGEX: Regex = Regex::new(r"^OK \[UNSEEN (\d+)\](.*)\r\n").unwrap();
            static ref UID_VALIDITY_REGEX: Regex = Regex::new(r"^OK \[UIDVALIDITY (\d+)\](.*)\r\n").unwrap();
            static ref UID_NEXT_REGEX: Regex =  Regex::new(r"^OK \[UIDNEXT (\d+)\](.*)\r\n").unwrap();
            static ref PERMANENT_FLAGS_REGEX: Regex =  Regex::new(r"^OK \[PERMANENTFLAGS (.+)\]\r\n").unwrap();
        }


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
            if EXISTS_REGEX.is_match(line) {
                let cap = EXISTS_REGEX.captures(line).unwrap();
                mailbox.exists = cap.at(1).unwrap().parse::<u32>().unwrap();
            } else if RECENT_REGEX.is_match(line) {
                let cap = RECENT_REGEX.captures(line).unwrap();
                mailbox.recent = cap.at(1).unwrap().parse::<u32>().unwrap();
            } else if FLAGS_REGEX.is_match(line) {
                let cap = FLAGS_REGEX.captures(line).unwrap();
                mailbox.flags = cap.at(1).unwrap().to_string();
            } else if UNSEEN_REGEX.is_match(line) {
                let cap = UNSEEN_REGEX.captures(line).unwrap();
                mailbox.unseen = Some(cap.at(1).unwrap().parse::<u32>().unwrap());
            } else if UID_VALIDITY_REGEX.is_match(line) {
                let cap = UID_VALIDITY_REGEX.captures(line).unwrap();
                mailbox.uid_validity = Some(cap.at(1).unwrap().parse::<u32>().unwrap());
            } else if UID_NEXT_REGEX.is_match(line) {
                let cap = UID_NEXT_REGEX.captures(line).unwrap();
                mailbox.uid_next = Some(cap.at(1).unwrap().parse::<u32>().unwrap());
            } else if PERMANENT_FLAGS_REGEX.is_match(line) {
                let cap = PERMANENT_FLAGS_REGEX.captures(line).unwrap();
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
        self.run_command_with_response(&format!("FETCH {} {}", sequence_set, query).to_string())
    }


    /// Return a list of messages corresponding to a sequence of message-ids
    pub fn fetch_messages(&mut self, sequence_set: &str) -> Result<HashMap<u32, MimeMessage>> {
        if let Err(e) = self.send_command(&format!("FETCH {} RFC822", sequence_set).to_string()) {
            return Err(e);
        }

        let messages = self.read_fetch_rfc822_response();
        messages
    }

    pub fn fetch_message(&mut self, message_id: u32) -> Result<Option<MimeMessage>> {
        self.fetch_messages(&format!("{}", message_id)).map(|ref mut v| { v.remove(&message_id) })
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

    // Send a command to the IMAP server, returning the tag that the
    // command was sent with.
    pub fn send_command(&mut self, untagged_command: &str) -> Result<String> {
        let (command, command_tag) = self.create_command(untagged_command.to_string());

        self.stream.get_mut().write(command.as_bytes()).map(|_| { command_tag })
    }

    /// Run the specified command, and read the response from the stream.
    pub fn run_command_with_response(&mut self, untagged_command: &str) -> Result<Vec<String>> {
        let tag = self.send_command(untagged_command);
        if let Err(e) = tag {
            return Err(e);
        }

        let ret = match self.read_response(&tag.unwrap()) {
            Ok(lines) => Ok(lines),
            Err(_) => Err(Error::new(ErrorKind::Other, "Failed to read")),
        };

        return ret;
    }

    pub fn run_command_and_check_ok(&mut self, command: &str) -> Result<()> {
        match self.run_command_with_response(command) {
            Ok(lines) => IMAPStream::parse_response_ok(lines),
            Err(e) => Err(e),
        }
    }


    fn parse_response_ok(lines: Vec<String>) -> Result<()> {
        lazy_static! {
            static ref OK_REGEX: Regex = Regex::new(r"^([a-zA-Z0-9]+) ([a-zA-Z0-9]+)(.*)").unwrap();
        }

        let last_line = lines.last().unwrap();

        for cap in OK_REGEX.captures_iter(last_line) {
            let response_type = cap.at(2).unwrap_or("");
            if response_type == "OK" {
                return Ok(());
            }
        }

        return Err(Error::new(ErrorKind::Other,
                              format!("Invalid Response: {}", last_line).to_string()));
    }

    /// Return a list of MimeMessages, read from the stream after a
    /// FETCH RFC822 call.
    fn read_fetch_rfc822_response(&mut self) -> Result<HashMap<u32, MimeMessage>> {
        lazy_static! {
            static ref FETCH_REGEX: Regex = Regex::new(r"\*\s+([0-9]+)\s+FETCH\s+\(RFC822\s+\{([0-9]+)\}").unwrap();
        }

        let mut messages = HashMap::new();
        loop {
            let mut message_bytes = vec![];
            let mut fetch_line = String::new();

            // Read the first line to get the size of the message.
            try!(self.stream.read_line(&mut fetch_line));

            if let Some(m) = FETCH_REGEX.captures(&fetch_line) {
                if let Some(resp_size) = m.at(2) {
                    // Read the full email message
                    let response_size = resp_size.parse::<usize>().unwrap();
                    message_bytes.resize(response_size, 0);

                    if let Ok(()) = self.stream.read_exact(&mut message_bytes) {
                        // parse the full message and add to the message list.
                        let message = MimeMessage::parse(&String::from_utf8_lossy(&message_bytes).to_string()).unwrap();
                        messages.insert(m.at(1).unwrap().parse::<u32>().unwrap(), message);
                    }
                }
            }
            else {
                break;
            }

            fetch_line = String::new();
            try!(self.stream.read_line(&mut fetch_line));
        };

        Ok(messages)
    }

    /// Read from the stream, collecting lines as strings, until we
    /// find the string containing the message tag.
    fn read_response(&mut self, tag: &str) -> Result<Vec<String>> {
        let mut lines = Vec::new();
        let mut found_end = false;
        loop {
            let mut line = String::new();
            let num_read = self.stream.read_line(&mut line);
            match num_read {
                Ok(_) => {
                    if (&*line).starts_with(tag) {
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

    /// Return a command with a unique tag and the tag itself.
    fn create_command(&mut self, command: String) -> (String, String) {
        let command_tag = format!("{}{}", self.tag_prefix, self.tag);
        let command = format!("{} {}\r\n", command_tag, command);
        self.tag += 1;
        return (command, command_tag);
    }
}

#[test]
fn connect() {
    let imap = IMAPStream::connect(("this-is-not-an-imap-server", 143), None);
    assert!(imap.is_err());
}
