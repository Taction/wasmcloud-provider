package sqldb

import (
	"database/sql"

	cbor "github.com/wasmcloud/tinygo-cbor"
)

func encodeValues(enc *cbor.Encoder, row []interface{}, ty sql.ColumnType, i int) error {
	switch ty.DatabaseTypeName() {
	case "INTEGER":
		enc.WriteInt32(row[i].(int32))
	case "REAL":
		enc.WriteFloat32(row[i].(float32))
	case "TEXT":
		enc.WriteString(row[i].(string))
	default: // BLOB
		enc.WriteByteArray(row[i].([]byte))
	}
	return nil
}

func encodeSizer(enc *cbor.Sizer, row []interface{}, ty sql.ColumnType, i int) error {
	switch ty.DatabaseTypeName() {
	case "INTEGER":
		enc.WriteInt32(row[i].(int32))
	case "REAL":
		enc.WriteFloat32(row[i].(float32))
	case "TEXT":
		enc.WriteString(row[i].(string))
	default: // BLOB
		enc.WriteByteArray(row[i].([]byte))
	}
	return nil
}
