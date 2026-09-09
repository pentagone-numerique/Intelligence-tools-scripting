//! `salomon-corpusd` exposes the native corpus scheduler through a small,
//! versioned line protocol. It is intentionally not a network daemon: the
//! Python side starts it as a local child process and communicates over pipes.

use salomon_core::{CorpusEntry, CoverageDelta};
use salomon_corpus::{CorpusLimits, CorpusScheduler, SchedulerConfig, SchedulerStrategy};
use std::env;
use std::io::{self, BufRead, Write};

const PROTOCOL_VERSION: &str = "1";
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_BATCH_SIZE: usize = 1_024;

struct Options {
    limits: CorpusLimits,
    scheduler: SchedulerConfig,
}

fn main() {
    let options = match parse_options() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("salomon-corpusd: {message}");
            std::process::exit(2);
        }
    };

    let mut scheduler = CorpusScheduler::new(options.limits, options.scheduler);
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout());

    for line_result in stdin.lock().lines() {
        let line = match line_result {
            Ok(line) => line,
            Err(error) => {
                let _ = write_response(&mut stdout, &error_response("io", &error.to_string()));
                break;
            }
        };
        if line.len() > MAX_FRAME_BYTES {
            let _ = write_response(
                &mut stdout,
                &error_response("frame", "request exceeds the frame limit"),
            );
            continue;
        }
        let (responses, should_stop) = match handle_command(&line, &mut scheduler) {
            Ok(result) => result,
            Err(message) => (vec![error_response("request", &message)], false),
        };
        let mut write_failed = false;
        for response in responses {
            if write_response(&mut stdout, &response).is_err() {
                write_failed = true;
                break;
            }
        }
        if write_failed || should_stop {
            break;
        }
    }
}

fn parse_options() -> Result<Options, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut limits = CorpusLimits::default();
    let mut scheduler = SchedulerConfig::default();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        if flag == "--help" || flag == "-h" {
            println!(
                "salomon-corpusd [--strategy random|feedback] [--seed N] [--max-entries N] [--max-bytes N] [--max-input-bytes N]"
            );
            std::process::exit(0);
        }
        match flag {
            "--strategy" => {
                scheduler.strategy = match option_value(&args, index, flag)? {
                    "random" => SchedulerStrategy::Random,
                    "feedback" => SchedulerStrategy::Feedback,
                    other => return Err(format!("unknown scheduler strategy: {other}")),
                };
            }
            "--seed" => {
                scheduler.seed = option_value(&args, index, flag)?
                    .parse()
                    .map_err(|_| "invalid --seed".to_string())?;
            }
            "--max-entries" => {
                limits.max_entries = parse_positive(
                    option_value(&args, index, flag)?,
                    "--max-entries",
                )?;
            }
            "--max-bytes" => {
                limits.max_bytes = parse_positive(
                    option_value(&args, index, flag)?,
                    "--max-bytes",
                )?;
            }
            "--max-input-bytes" => {
                limits.max_input_bytes = parse_positive(
                    option_value(&args, index, flag)?,
                    "--max-input-bytes",
                )?;
            }
            other => return Err(format!("unknown option: {other}")),
        }
        index += 2;
    }
    Ok(Options { limits, scheduler })
}

fn option_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_positive(value: &str, flag: &str) -> Result<usize, String> {
    let parsed: usize = value.parse().map_err(|_| format!("invalid {flag}"))?;
    if parsed == 0 {
        return Err(format!("{flag} must be greater than zero"));
    }
    Ok(parsed)
}

fn handle_command(
    line: &str,
    scheduler: &mut CorpusScheduler,
) -> Result<(Vec<String>, bool), String> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let command = fields.first().copied().ok_or_else(|| "empty request".to_string())?;
    match command {
        "HELLO" => {
            if fields.len() != 2 || fields[1] != PROTOCOL_VERSION {
                return Err(format!(
                    "unsupported protocol; expected version {PROTOCOL_VERSION}"
                ));
            }
            Ok((single("HELLO 1 salomon-corpusd"), false))
        }
        "PING" if fields.len() == 1 => Ok((single("PONG"), false)),
        "ADD" if fields.len() == 3 => {
            let parent_id = parse_parent(fields[1])?;
            let bytes = decode_base64(fields[2])?;
            let result = scheduler
                .add_seed(bytes, parent_id)
                .map_err(|error| error.to_string())?;
            Ok((single(format_entry(&result.entry)), false))
        }
        "ADD_BATCH" => handle_add_batch(&fields, scheduler),
        "NEXT" if fields.len() == 1 => match scheduler.next_entry() {
            Some(entry) => Ok((single(format_entry(&entry)), false)),
            None => Ok((single("NONE"), false)),
        },
        "NEXT_BATCH" if fields.len() == 2 => {
            let count = parse_batch_count(fields[1])?;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                if let Some(entry) = scheduler.next_entry() {
                    entries.push(entry);
                } else {
                    break;
                }
            }
            Ok((batch_response(entries), false))
        }
        "FEEDBACK" if fields.len() == 7 => {
            handle_feedback(&fields, scheduler)?;
            Ok((single("OK FEEDBACK"), false))
        }
        "FEEDBACK_BATCH" => {
            handle_feedback_batch(&fields, scheduler)?;
            Ok((single("OK FEEDBACK_BATCH"), false))
        }
        "STATS" if fields.len() == 1 => {
            let stats = scheduler.corpus().stats();
            Ok((
                single(format!(
                    "STATS {} {} {} {}",
                    stats.entries, stats.bytes, stats.max_entries, stats.max_bytes
                )),
                false,
            ))
        }
        "QUIT" if fields.len() == 1 => Ok((single("BYE"), true)),
        _ => Err("invalid command or argument count".to_string()),
    }
}

fn handle_add_batch(
    fields: &[&str],
    scheduler: &mut CorpusScheduler,
) -> Result<(Vec<String>, bool), String> {
    if fields.len() < 3 {
        return Err("ADD_BATCH requires a count".to_string());
    }
    let count = parse_batch_count(fields[1])?;
    if fields.len() != 2 + count * 2 {
        return Err("ADD_BATCH has an invalid number of fields".to_string());
    }
    let mut entries = Vec::with_capacity(count);
    for item in 0..count {
        let parent = parse_parent(fields[2 + item * 2])?;
        let bytes = decode_base64(fields[3 + item * 2])?;
        let result = scheduler
            .add_seed(bytes, parent)
            .map_err(|error| error.to_string())?;
        entries.push(result.entry);
    }
    Ok((batch_response(entries), false))
}

fn handle_feedback(fields: &[&str], scheduler: &mut CorpusScheduler) -> Result<(), String> {
    let id: u64 = fields[1]
        .parse()
        .map_err(|_| "invalid input id".to_string())?;
    let energy: u32 = fields[2]
        .parse()
        .map_err(|_| "invalid energy".to_string())?;
    let favored = parse_bool(fields[3])?;
    let new_edges: u32 = fields[4]
        .parse()
        .map_err(|_| "invalid new edge count".to_string())?;
    let interesting = parse_bool(fields[5])?;
    let bitmap_hash = if fields[6] == "-" {
        None
    } else {
        let hash = decode_base64(fields[6])?;
        if hash.len() != 32 {
            return Err("bitmap hash must contain 32 bytes".to_string());
        }
        let mut value = [0u8; 32];
        value.copy_from_slice(&hash);
        Some(value)
    };
    let mut entry = scheduler
        .corpus()
        .get(id)
        .cloned()
        .ok_or_else(|| "unknown input id".to_string())?;
    entry.energy = entry.energy.max(energy);
    entry.favored |= favored;
    if bitmap_hash.is_some() || new_edges > 0 || interesting {
        entry.coverage = Some(CoverageDelta {
            new_edges,
            bitmap_hash: bitmap_hash.unwrap_or([0; 32]),
            interesting,
        });
    }
    scheduler
        .try_promote(entry)
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn handle_feedback_batch(
    fields: &[&str],
    scheduler: &mut CorpusScheduler,
) -> Result<(), String> {
    if fields.len() < 3 {
        return Err("FEEDBACK_BATCH requires a count".to_string());
    }
    let count = parse_batch_count(fields[1])?;
    if fields.len() != 2 + count * 6 {
        return Err("FEEDBACK_BATCH has an invalid number of fields".to_string());
    }
    for item in 0..count {
        let start = 2 + item * 6;
        let feedback_fields = [
            "FEEDBACK",
            fields[start],
            fields[start + 1],
            fields[start + 2],
            fields[start + 3],
            fields[start + 4],
            fields[start + 5],
        ];
        handle_feedback(&feedback_fields, scheduler)?;
    }
    Ok(())
}

fn parse_batch_count(value: &str) -> Result<usize, String> {
    let count: usize = value.parse().map_err(|_| "invalid batch count".to_string())?;
    if count == 0 || count > MAX_BATCH_SIZE {
        return Err(format!("batch count must be between 1 and {MAX_BATCH_SIZE}"));
    }
    Ok(count)
}

fn batch_response(entries: Vec<CorpusEntry>) -> Vec<String> {
    let mut responses = Vec::with_capacity(entries.len() + 2);
    responses.push(format!("BATCH {}", entries.len()));
    responses.extend(entries.iter().map(format_entry));
    responses.push("END BATCH".to_string());
    responses
}

fn single(response: impl Into<String>) -> Vec<String> {
    vec![response.into()]
}

fn parse_parent(value: &str) -> Result<Option<u64>, String> {
    if value == "-" {
        Ok(None)
    } else {
        value
            .parse()
            .map(Some)
            .map_err(|_| "invalid parent id".to_string())
    }
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err("boolean fields must be 0 or 1".to_string()),
    }
}

fn format_entry(entry: &CorpusEntry) -> String {
    let parent = entry
        .input
        .parent_id
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string());
    let (new_edges, interesting, bitmap_hash) = match &entry.coverage {
        Some(coverage) => (
            coverage.new_edges.to_string(),
            if coverage.interesting { "1" } else { "0" }.to_string(),
            encode_base64(&coverage.bitmap_hash),
        ),
        None => ("0".to_string(), "0".to_string(), "-".to_string()),
    };
    format!(
        "ENTRY {} {} {} {} {} {} {} {}",
        entry.input.id,
        parent,
        entry.energy,
        if entry.favored { "1" } else { "0" },
        encode_base64(&entry.input.bytes),
        new_edges,
        interesting,
        bitmap_hash
    )
}

fn write_response<W: Write>(writer: &mut W, response: &str) -> io::Result<()> {
    writer.write_all(response.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn error_response(code: &str, message: &str) -> String {
    format!("ERR {code} {}", encode_base64(message.as_bytes()))
}

const BASE64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode_base64(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "~".to_string();
    }
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied();
        let third = chunk.get(2).copied();
        output.push(BASE64[(first >> 2) as usize] as char);
        output.push(
            BASE64[(((first & 0x03) << 4) | (second.unwrap_or(0) >> 4)) as usize] as char,
        );
        output.push(match second {
            Some(value) => {
                BASE64[(((value & 0x0f) << 2) | (third.unwrap_or(0) >> 6)) as usize] as char
            },
            None => '=',
        });
        output.push(match third {
            Some(value) => BASE64[(value & 0x3f) as usize] as char,
            None => '=',
        });
    }
    output
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    if value == "~" {
        return Ok(Vec::new());
    }
    let bytes = value.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err("invalid base64 length".to_string());
    }
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    for (chunk_index, chunk) in bytes.chunks(4).enumerate() {
        let last = chunk_index + 1 == bytes.len() / 4;
        let first = base64_value(chunk[0]).ok_or_else(|| "invalid base64".to_string())?;
        let second = base64_value(chunk[1]).ok_or_else(|| "invalid base64".to_string())?;
        let third = if chunk[2] == b'=' {
            if chunk[3] != b'=' || !last {
                return Err("invalid base64 padding".to_string());
            }
            0
        } else {
            base64_value(chunk[2]).ok_or_else(|| "invalid base64".to_string())?
        };
        let fourth = if chunk[3] == b'=' {
            if !last {
                return Err("invalid base64 padding".to_string());
            }
            0
        } else {
            base64_value(chunk[3]).ok_or_else(|| "invalid base64".to_string())?
        };
        output.push((first << 2) | (second >> 4));
        if chunk[2] != b'=' {
            output.push((second << 4) | (third >> 2));
        }
        if chunk[3] != b'=' {
            output.push((third << 6) | fourth);
        }
    }
    Ok(output)
}

fn base64_value(value: u8) -> Option<u8> {
    match value {
        b'A'..=b'Z' => Some(value - b'A'),
        b'a'..=b'z' => Some(value - b'a' + 26),
        b'0'..=b'9' => Some(value - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip_handles_empty_and_binary_values() {
        for value in [b"".as_slice(), b"seed".as_slice(), &[0, 1, 2, 253, 254, 255]] {
            assert_eq!(decode_base64(&encode_base64(value)).unwrap(), value);
        }
    }

    #[test]
    fn protocol_formats_a_hello_and_ping() {
        let mut scheduler = CorpusScheduler::with_default_limits(SchedulerConfig::default());
        assert_eq!(
            handle_command("HELLO 1", &mut scheduler).unwrap().0[0],
            "HELLO 1 salomon-corpusd"
        );
        assert_eq!(handle_command("PING", &mut scheduler).unwrap().0[0], "PONG");
    }

    #[test]
    fn batch_protocol_returns_a_framed_response() {
        let mut scheduler = CorpusScheduler::with_default_limits(SchedulerConfig::default());
        let responses = handle_command("ADD_BATCH 2 - YQ== - Yg==", &mut scheduler)
            .unwrap()
            .0;
        assert_eq!(responses.first().map(String::as_str), Some("BATCH 2"));
        assert_eq!(responses.last().map(String::as_str), Some("END BATCH"));
        assert_eq!(responses.len(), 4);
    }
}
