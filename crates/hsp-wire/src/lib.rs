use std::collections::{BTreeMap, HashSet};
use std::fmt::{Display, Formatter};
use std::io::Cursor;

use ciborium::value::Value;
use hsp_core::{
    AuthFrame, EventRecord, GoAwayFrame, NoticeFrame, ReqHeader, ResHeader, SettingsFrame,
    WireErrorFrame,
};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const FRAME_HEADER_LEN: usize = 5;
const MAX_CONTROL_FRAME_LEN: usize = 8 * 1024 * 1024;
/// Protocol DATA frame cap aligned with the advertised public beta max_chunk_size.
pub const MAX_DATA_FRAME_LEN: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Settings = 0x01,
    Error = 0x02,
    Notice = 0x03,
    ReqHeader = 0x10,
    ResHeader = 0x11,
    Data = 0x12,
    End = 0x13,
    Event = 0x14,
    Ack = 0x15,
    Auth = 0x16,
    GoAway = 0x17,
}

impl TryFrom<u8> for FrameType {
    type Error = WireCodecError;

    fn try_from(value: u8) -> Result<Self, WireCodecError> {
        match value {
            0x01 => Ok(Self::Settings),
            0x02 => Ok(Self::Error),
            0x03 => Ok(Self::Notice),
            0x10 => Ok(Self::ReqHeader),
            0x11 => Ok(Self::ResHeader),
            0x12 => Ok(Self::Data),
            0x13 => Ok(Self::End),
            0x14 => Ok(Self::Event),
            0x15 => Ok(Self::Ack),
            0x16 => Ok(Self::Auth),
            0x17 => Ok(Self::GoAway),
            _ => Err(WireCodecError::InvalidFrameType(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    Settings(SettingsFrame),
    Error(WireErrorFrame),
    Notice(NoticeFrame),
    ReqHeader(ReqHeader),
    ResHeader(ResHeader),
    Data(Vec<u8>),
    End,
    Event(EventRecord),
    Auth(AuthFrame),
    GoAway(GoAwayFrame),
}

impl Frame {
    pub fn frame_type(&self) -> FrameType {
        match self {
            Self::Settings(_) => FrameType::Settings,
            Self::Error(_) => FrameType::Error,
            Self::Notice(_) => FrameType::Notice,
            Self::ReqHeader(_) => FrameType::ReqHeader,
            Self::ResHeader(_) => FrameType::ResHeader,
            Self::Data(_) => FrameType::Data,
            Self::End => FrameType::End,
            Self::Event(_) => FrameType::Event,
            Self::Auth(_) => FrameType::Auth,
            Self::GoAway(_) => FrameType::GoAway,
        }
    }
}

#[derive(Debug)]
pub enum WireCodecError {
    Io(std::io::Error),
    InvalidFrameType(u8),
    InvalidFrame(String),
    OversizedFrame {
        frame_type: FrameType,
        length: usize,
    },
}

impl Display for WireCodecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::InvalidFrameType(frame_type) => {
                write!(f, "invalid frame type 0x{frame_type:02x}")
            }
            Self::InvalidFrame(message) => f.write_str(message),
            Self::OversizedFrame { frame_type, length } => {
                write!(f, "oversized {:?} frame ({length} bytes)", frame_type)
            }
        }
    }
}

impl std::error::Error for WireCodecError {}

impl From<std::io::Error> for WireCodecError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
) -> Result<(), WireCodecError> {
    let frame_type = frame.frame_type();
    let payload = encode_frame_payload(frame)?;
    enforce_frame_len(frame_type, payload.len())?;
    let mut header = [0u8; FRAME_HEADER_LEN];
    header[0] = frame_type as u8;
    header[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    writer.write_all(&header).await?;
    if !payload.is_empty() {
        writer.write_all(&payload).await?;
    }
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame, WireCodecError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let frame_type = FrameType::try_from(header[0])?;
    let length = u32::from_be_bytes(header[1..].try_into().expect("header length")) as usize;

    enforce_frame_len(frame_type, length)?;

    let mut payload = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut payload).await?;
    }
    decode_frame_payload(frame_type, &payload)
}

fn enforce_frame_len(frame_type: FrameType, length: usize) -> Result<(), WireCodecError> {
    let max_len = match frame_type {
        FrameType::Data => MAX_DATA_FRAME_LEN,
        _ => MAX_CONTROL_FRAME_LEN,
    };
    if length > max_len {
        return Err(WireCodecError::OversizedFrame { frame_type, length });
    }
    Ok(())
}

fn encode_frame_payload(frame: &Frame) -> Result<Vec<u8>, WireCodecError> {
    match frame {
        Frame::Settings(settings) => encode_cbor(settings),
        Frame::Error(error) => encode_cbor(error),
        Frame::Notice(notice) => encode_cbor(notice),
        Frame::ReqHeader(header) => encode_cbor(header),
        Frame::ResHeader(header) => encode_cbor(header),
        Frame::Data(bytes) => Ok(bytes.clone()),
        Frame::End => Ok(Vec::new()),
        Frame::Event(event) => encode_cbor(event),
        Frame::Auth(auth) => encode_cbor(auth),
        Frame::GoAway(go_away) => encode_cbor(go_away),
    }
}

fn decode_frame_payload(frame_type: FrameType, payload: &[u8]) -> Result<Frame, WireCodecError> {
    match frame_type {
        FrameType::Settings => Ok(Frame::Settings(decode_settings_frame(payload)?)),
        FrameType::Error => Ok(Frame::Error(decode_cbor(payload)?)),
        FrameType::Notice => Ok(Frame::Notice(decode_cbor(payload)?)),
        FrameType::ReqHeader => Ok(Frame::ReqHeader(decode_cbor(payload)?)),
        FrameType::ResHeader => Ok(Frame::ResHeader(decode_cbor(payload)?)),
        FrameType::Data => Ok(Frame::Data(payload.to_vec())),
        FrameType::End => {
            if !payload.is_empty() {
                return Err(WireCodecError::InvalidFrame(
                    "END frame must not carry payload".to_string(),
                ));
            }
            Ok(Frame::End)
        }
        FrameType::Event => Ok(Frame::Event(decode_cbor(payload)?)),
        FrameType::Auth => Ok(Frame::Auth(decode_cbor(payload)?)),
        FrameType::GoAway => Ok(Frame::GoAway(decode_cbor(payload)?)),
        FrameType::Ack => Err(WireCodecError::InvalidFrame(
            "Ack is reserved in beta runtime".to_string(),
        )),
    }
}

fn encode_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, WireCodecError> {
    let mut output = Vec::new();
    ciborium::into_writer(value, &mut output)
        .map_err(|error| WireCodecError::InvalidFrame(error.to_string()))?;
    Ok(output)
}

fn decode_cbor<T: serde::de::DeserializeOwned>(payload: &[u8]) -> Result<T, WireCodecError> {
    ciborium::from_reader(Cursor::new(payload))
        .map_err(|error| WireCodecError::InvalidFrame(error.to_string()))
}

fn decode_settings_frame(payload: &[u8]) -> Result<SettingsFrame, WireCodecError> {
    let value: Value = ciborium::from_reader(Cursor::new(payload))
        .map_err(|error| WireCodecError::InvalidFrame(error.to_string()))?;
    let map = match value {
        Value::Map(entries) => entries,
        _ => {
            return Err(WireCodecError::InvalidFrame(
                "SETTINGS payload must be a CBOR map".to_string(),
            ))
        }
    };

    let mut seen = HashSet::new();
    let mut entries = BTreeMap::new();
    for (key, value) in map {
        let key = match key {
            Value::Text(text) => text,
            _ => {
                return Err(WireCodecError::InvalidFrame(
                    "SETTINGS keys must be text".to_string(),
                ))
            }
        };
        if !seen.insert(key.clone()) {
            return Err(WireCodecError::InvalidFrame(format!(
                "duplicate SETTINGS key: {key}"
            )));
        }
        entries.insert(key, value);
    }

    Ok(SettingsFrame {
        max_chunk_size: required_u64(&entries, "max_chunk_size")?,
        max_manifest_size: required_u64(&entries, "max_manifest_size")?,
        max_object_size: required_u64(&entries, "max_object_size")?,
        max_parallel_streams: required_u64(&entries, "max_parallel_streams")? as u16,
        supported_chunkers: required_text_array(&entries, "supported_chunkers")?,
        supported_content_encodings: required_text_array(&entries, "supported_content_encodings")?,
        supported_token_profiles: required_text_array(&entries, "supported_token_profiles")?,
        supported_extensions: required_text_array(&entries, "supported_extensions")?,
        server_instance_id: required_text(&entries, "server_instance_id")?,
        event_replay_window_sec: required_u64(&entries, "event_replay_window_sec")?,
        limits_revision: required_u64(&entries, "limits_revision")?,
    })
}

fn required_u64(entries: &BTreeMap<String, Value>, key: &str) -> Result<u64, WireCodecError> {
    match entries.get(key) {
        Some(Value::Integer(value)) => {
            let converted: i128 = (*value).into();
            u64::try_from(converted).map_err(|_| {
                WireCodecError::InvalidFrame(format!("SETTINGS {key} must be unsigned"))
            })
        }
        _ => Err(WireCodecError::InvalidFrame(format!(
            "SETTINGS {key} is missing or not an integer"
        ))),
    }
}

fn required_text(entries: &BTreeMap<String, Value>, key: &str) -> Result<String, WireCodecError> {
    match entries.get(key) {
        Some(Value::Text(value)) if !value.is_empty() => Ok(value.clone()),
        _ => Err(WireCodecError::InvalidFrame(format!(
            "SETTINGS {key} is missing or not a text string"
        ))),
    }
}

fn required_text_array(
    entries: &BTreeMap<String, Value>,
    key: &str,
) -> Result<Vec<String>, WireCodecError> {
    match entries.get(key) {
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| match value {
                Value::Text(text) => Ok(text.clone()),
                _ => Err(WireCodecError::InvalidFrame(format!(
                    "SETTINGS {key} must contain only text values"
                ))),
            })
            .collect(),
        _ => Err(WireCodecError::InvalidFrame(format!(
            "SETTINGS {key} is missing or not an array"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hsp_core::{
        public_multitenant_settings_frame, ApiErrorCategory, AuthFrame, ChannelBindingProof,
        EventRecord, EventType, GoAwayFrame, NoticeFrame, OperationName, PayloadMode, ReqHeader,
        ResHeader, WireErrorFrame,
    };

    fn req_header() -> ReqHeader {
        ReqHeader {
            version: 1,
            operation: OperationName::Info,
            request_id: Some(7),
            payload_mode: Some(PayloadMode::Json),
            payload_length: Some(0),
            params: BTreeMap::new(),
            extensions: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn roundtrip_req_header_frame() {
        let frame = Frame::ReqHeader(req_header());
        let (mut client, mut server) = tokio::io::duplex(4096);
        write_frame(&mut client, &frame).await.unwrap();
        let decoded = read_frame(&mut server).await.unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn settings_decoder_rejects_duplicate_keys() {
        let mut payload = Vec::new();
        ciborium::into_writer(
            &Value::Map(vec![
                (
                    Value::Text("max_chunk_size".to_string()),
                    Value::Integer(1u64.into()),
                ),
                (
                    Value::Text("max_chunk_size".to_string()),
                    Value::Integer(2u64.into()),
                ),
            ]),
            &mut payload,
        )
        .unwrap();
        let error = decode_settings_frame(&payload).unwrap_err();
        assert!(error.to_string().contains("duplicate SETTINGS key"));
    }

    #[tokio::test]
    async fn end_frame_rejects_payload() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client
            .write_all(&[FrameType::End as u8, 0, 0, 0, 1, 0xff])
            .await
            .unwrap();
        let error = read_frame(&mut server).await.unwrap_err();
        assert!(error.to_string().contains("END frame"));
    }

    #[tokio::test]
    async fn data_frame_rejects_oversized_length_before_payload_read() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let oversized_len = MAX_DATA_FRAME_LEN + 1;
        let mut header = [0u8; FRAME_HEADER_LEN];
        header[0] = FrameType::Data as u8;
        header[1..].copy_from_slice(&(oversized_len as u32).to_be_bytes());
        client.write_all(&header).await.unwrap();

        let error = read_frame(&mut server).await.unwrap_err();
        assert!(matches!(
            error,
            WireCodecError::OversizedFrame {
                frame_type: FrameType::Data,
                length
            } if length == oversized_len
        ));
    }

    #[test]
    fn settings_roundtrip_is_valid() {
        let settings = public_multitenant_settings_frame("server-1");
        let encoded = encode_frame_payload(&Frame::Settings(settings.clone())).unwrap();
        let decoded = decode_settings_frame(&encoded).unwrap();
        assert_eq!(decoded, settings);
    }

    #[test]
    fn data_frame_keeps_raw_bytes() {
        let frame = Frame::Data(vec![1, 2, 3, 4]);
        let encoded = encode_frame_payload(&frame).unwrap();
        let decoded = decode_frame_payload(FrameType::Data, &encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn reserved_frame_type_is_not_supported() {
        let error = decode_frame_payload(FrameType::Ack, &[]).unwrap_err();
        assert!(error.to_string().contains("reserved"));
    }

    #[test]
    fn error_and_auth_frames_encode() {
        let error = Frame::Error(WireErrorFrame {
            category: ApiErrorCategory::Auth,
            code: "invalid_token_signature".to_string(),
            message: "bad token".to_string(),
        });
        let notice = Frame::Notice(NoticeFrame {
            kind: "heartbeat".to_string(),
            message: None,
            cursor: Some("cursor".to_string()),
        });
        let auth = Frame::Auth(AuthFrame {
            token_b64: "token".to_string(),
            channel_binding: ChannelBindingProof {
                binding_kind: "tls-exporter".to_string(),
                proof_b64: "proof".to_string(),
                nonce: "nonce".to_string(),
            },
        });
        let event = Frame::Event(EventRecord {
            version: 1,
            seq: 1,
            at_ms: 1,
            event_type: EventType::ObjectCommitted,
            subject_kind: "object".to_string(),
            namespace: None,
            path: None,
            cid: Some("cid".to_string()),
            revision: None,
            trace_id: None,
            payload: BTreeMap::new(),
        });
        let go_away = Frame::GoAway(GoAwayFrame {
            reason: "shutdown".to_string(),
        });
        let res = Frame::ResHeader(ResHeader {
            version: 1,
            status_code: 200,
            request_id: Some(1),
            payload_mode: Some(PayloadMode::Json),
            payload_length: Some(0),
            meta: BTreeMap::new(),
            extensions: BTreeMap::new(),
        });

        assert!(!encode_frame_payload(&error).unwrap().is_empty());
        assert!(!encode_frame_payload(&notice).unwrap().is_empty());
        assert!(!encode_frame_payload(&auth).unwrap().is_empty());
        assert!(!encode_frame_payload(&event).unwrap().is_empty());
        assert!(!encode_frame_payload(&go_away).unwrap().is_empty());
        assert!(!encode_frame_payload(&res).unwrap().is_empty());
    }
}
