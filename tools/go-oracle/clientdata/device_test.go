package clientdata

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/device"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

// nativeClientDeviceData derives claim order and OS defaults from the compiled public owners.
func nativeClientDeviceData(t *testing.T, out *strings.Builder) {
	t.Helper()
	var data login.ClientData
	value := reflect.ValueOf(&data).Elem()
	for i := range value.NumField() {
		field := value.Field(i)
		if !field.CanSet() || value.Type().Field(i).Tag.Get("json") == "-" {
			continue
		}
		switch field.Kind() {
		case reflect.String:
			field.SetString("fixture")
		case reflect.Bool:
			field.SetBool(true)
		case reflect.Pointer:
			if field.Type().Elem().Kind() == reflect.Bool {
				field.Set(reflect.New(field.Type().Elem()))
				field.Elem().SetBool(true)
			}
		}
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		t.Fatalf("client claims are not an object: %v", err)
	}
	out.WriteString("pub(in crate::login) const CLAIM_ORDER: &[&str] = &[\n")
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(out, "    %s,\n", strconv.Quote(name.(string)))
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			t.Fatal(err)
		}
	}
	out.WriteString("];\n\n")
	out.WriteString("/// Returns the default input mode from the pinned device owner.\n")
	out.WriteString("pub(in crate::login) fn device_input_mode(os: i64) -> i64 {\n    match os {\n")
	fallback := device.DefaultInputMode(protocol.DeviceUnknown)
	for os := protocol.DeviceOS(1); ; os++ {
		if _, known := os.Name(); !known {
			break
		}
		if mode := device.DefaultInputMode(os); mode != fallback {
			fmt.Fprintf(out, "        %d => %d,\n", os, mode)
		}
	}
	fmt.Fprintf(out, "        _ => %d,\n    }\n}\n", fallback)
}
