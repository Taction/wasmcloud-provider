package sqldb

import (
	"database/sql"

	wcsql "github.com/wasmcloud/interfaces/sqldb/tinygo"
	cbor "github.com/wasmcloud/tinygo-cbor"
	msgpack "github.com/wasmcloud/tinygo-msgpack"
)

type Operation string

const (
	EXECUTE_OPERATION Operation = "SqlDb.Execute"
	QUERY_OPERATION   Operation = "SqlDb.Query"
	PING_OPERATION    Operation = "SqlDb.Ping"
)

func (o Operation) String() string {
	return string(o)
}

func DecodeStatement(statement []byte) (*wcsql.Statement, error) {
	d := msgpack.NewDecoder(statement)
	state, err := wcsql.MDecodeStatement(&d)
	if err != nil {
		return nil, err
	}
	return &state, nil
}

func EncodeExecuteResponse(er *wcsql.ExecuteResult) []byte {
	var sizer msgpack.Sizer
	size_enc := &sizer
	er.MEncode(size_enc)
	buf := make([]byte, sizer.Len())
	encoder := msgpack.NewEncoder(buf)
	enc := &encoder
	er.MEncode(enc)
	return buf
}

func EncodeQueryResponse(qr *wcsql.QueryResult) []byte {
	var sizer msgpack.Sizer
	size_enc := &sizer
	qr.MEncode(size_enc)
	buf := make([]byte, sizer.Len())
	encoder := msgpack.NewEncoder(buf)
	enc := &encoder
	qr.MEncode(enc)
	return buf
}

func EncodePingResponse(pr *wcsql.PingResult) []byte {
	var sizer msgpack.Sizer
	size_enc := &sizer
	pr.MEncode(size_enc)
	buf := make([]byte, sizer.Len())
	encoder := msgpack.NewEncoder(buf)
	enc := &encoder
	pr.MEncode(enc)
	return buf
}

func EncodeRows(rows [][]interface{}, cols []*sql.ColumnType) ([]byte, error) {
	var sizer cbor.Sizer
	size_enc := &sizer

	rowCount := len(rows)
	size_enc.WriteArraySize(uint32(rowCount))
	for _, r := range rows {
		size_enc.WriteArraySize(uint32(len(r)))
		for i, c := range cols {
			err := encodeSizer(size_enc, r, *c, i)
			if err != nil {
				return nil, err
			}
		}
	}

	buffer := make([]byte, sizer.Len())
	encoder := cbor.NewEncoder(buffer)
	enc := &encoder

	enc.WriteArraySize(uint32(rowCount))
	for _, r := range rows {
		enc.WriteArraySize(uint32(len(r)))
		for i, c := range cols {
			err := encodeValues(enc, r, *c, i)
			if err != nil {
				return nil, err
			}
		}
	}

	return buffer, nil
}

func encodeValues(enc *cbor.Encoder, row []interface{}, ty sql.ColumnType, i int) error {
	switch ty.DatabaseTypeName() {
	case "BOOL":
		enc.WriteBool(row[i].(bool))
	case "INT":
		enc.WriteInt8(row[i].(int8))
	case "TEXT":
		enc.WriteString(row[i].(string))
	default:
		enc.WriteByteArray(row[i].([]byte))
	}
	return nil
}

func encodeSizer(enc *cbor.Sizer, row []interface{}, ty sql.ColumnType, i int) error {
	switch ty.DatabaseTypeName() {
	case "BOOL":
		enc.WriteBool(row[i].(bool))
	case "INT":
		enc.WriteInt8(row[i].(int8))
	case "TEXT":
		enc.WriteString(row[i].(string))
	default:
		enc.WriteByteArray(row[i].([]byte))
	}
	return nil
}
