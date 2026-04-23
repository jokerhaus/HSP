package gatewaybeta

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"

	"github.com/loxar/hsp/sdk/go/protocol"
)

type ChunkStreamReader struct {
	body     io.ReadCloser
	scanner  *bufio.Scanner
	meta     protocol.GetResponseMeta
	metaRead bool
}

type chunkStreamLine struct {
	Type       string                       `json:"type"`
	Meta       *protocol.GetResponseMeta    `json:"meta,omitempty"`
	Descriptor *protocol.GetChunkDescriptor `json:"descriptor,omitempty"`
	DataBase64 string                       `json:"data_b64,omitempty"`
}

type EventStreamReader struct {
	body    io.ReadCloser
	scanner *bufio.Scanner
}

func NewChunkStreamReader(body io.ReadCloser) *ChunkStreamReader {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	return &ChunkStreamReader{
		body:    body,
		scanner: scanner,
	}
}

func NewEventStreamReader(body io.ReadCloser) *EventStreamReader {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	return &EventStreamReader{
		body:    body,
		scanner: scanner,
	}
}

func (r *ChunkStreamReader) Meta() (protocol.GetResponseMeta, error) {
	if r.metaRead {
		return r.meta, nil
	}

	line, err := r.nextLine()
	if err != nil {
		return protocol.GetResponseMeta{}, err
	}
	if line.Type != "meta" || line.Meta == nil {
		return protocol.GetResponseMeta{}, &protocol.APIError{
			Category: protocol.ErrorCategoryValidation,
			Code:     "invalid_chunk_stream_meta",
			Message:  "first chunk-stream record must be meta",
		}
	}

	r.meta = *line.Meta
	r.metaRead = true
	return r.meta, nil
}

func (r *ChunkStreamReader) Next() (*protocol.GetChunk, error) {
	if _, err := r.Meta(); err != nil {
		return nil, err
	}

	line, err := r.nextLine()
	if err != nil {
		return nil, err
	}
	if line.Type != "chunk" || line.Descriptor == nil {
		return nil, &protocol.APIError{
			Category: protocol.ErrorCategoryValidation,
			Code:     "invalid_chunk_stream_record",
			Message:  "chunk-stream record must include descriptor and data",
		}
	}

	bytes, err := base64.RawURLEncoding.DecodeString(line.DataBase64)
	if err != nil {
		return nil, err
	}
	return &protocol.GetChunk{
		Descriptor: *line.Descriptor,
		Bytes:      bytes,
	}, nil
}

func (r *ChunkStreamReader) Close() error {
	if r.body == nil {
		return nil
	}
	return r.body.Close()
}

func (r *ChunkStreamReader) nextLine() (*chunkStreamLine, error) {
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}

	var line chunkStreamLine
	if err := json.Unmarshal(r.scanner.Bytes(), &line); err != nil {
		return nil, err
	}
	return &line, nil
}

func (r *EventStreamReader) Next() (*protocol.SubscribeEnvelope, error) {
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}

	var line protocol.SubscribeEnvelope
	if err := json.Unmarshal(r.scanner.Bytes(), &line); err != nil {
		return nil, err
	}
	return &line, nil
}

func (r *EventStreamReader) Close() error {
	if r.body == nil {
		return nil
	}
	return r.body.Close()
}
