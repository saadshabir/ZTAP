package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/saadshabir/ZTAP/internal/restartproof"
)

func readEvidence(path string, output any) (err error) {
	const maxEvidenceBytes = 4 << 20
	file, err := openRegularFile(path, "evidence")
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close %s: %w", path, closeErr)
		}
	}()
	data, err := io.ReadAll(io.LimitReader(file, maxEvidenceBytes+1))
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxEvidenceBytes {
		return fmt.Errorf("%s exceeds the 4 MiB evidence limit", path)
	}
	if err := validateStrictJSONKeys(data); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	if err := validateRequiredJSONFields(data, output); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode %s: multiple JSON values", path)
		}
		return fmt.Errorf("decode %s: trailing data: %w", path, err)
	}
	return nil
}

func validateRequiredJSONFields(data []byte, output any) error {
	typeOfOutput := reflect.TypeOf(output)
	if typeOfOutput == nil {
		return errors.New("JSON output type is nil")
	}
	return validateRequiredJSONValue(data, typeOfOutput, "$")
}

func validateRequiredJSONValue(data []byte, typeOfValue reflect.Type, path string) error {
	for typeOfValue.Kind() == reflect.Pointer {
		typeOfValue = typeOfValue.Elem()
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("%s must not be null", path)
	}
	switch typeOfValue.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return fmt.Errorf("%s must be a JSON object: %w", path, err)
		}
		if fields == nil {
			return fmt.Errorf("%s must be a JSON object", path)
		}
		// Restart evidence is a versioned union. Keep every field required
		// within its version, including zero-valued prohibited counters.
		var omittedFields map[string]bool
		if typeOfValue == reflect.TypeFor[restartEvidence]() || typeOfValue == reflect.TypeFor[crashEvidence]() {
			var version int
			if raw, ok := fields["schema_version"]; ok {
				if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
					return fmt.Errorf("%s evidence version must not be null", path)
				}
				if err := json.Unmarshal(raw, &version); err != nil {
					return fmt.Errorf("%s has an invalid evidence version: %w", path, err)
				}
			}
			if version == restartproof.EvidenceVersion {
				omittedFields = map[string]bool{"RestartMS": true, "RestartP95": true, "CrashGapMS": true, "CrashGapP95": true}
				for _, name := range []string{"restart_samples_ms", "restart_p95_ms", "crash_fail_open_samples_ms", "crash_fail_open_p95_ms"} {
					if _, ok := fields[name]; ok {
						return fmt.Errorf("%s continuity evidence contains legacy field %q", path, name)
					}
				}
			} else {
				omittedFields = map[string]bool{"SchemaVersion": true, "Continuity": true}
				if _, ok := fields["continuity_samples"]; ok {
					return fmt.Errorf("%s legacy evidence contains continuity samples", path)
				}
			}
		}
		for fieldIndex := 0; fieldIndex < typeOfValue.NumField(); fieldIndex++ {
			field := typeOfValue.Field(fieldIndex)
			if field.PkgPath != "" || omittedFields[field.Name] {
				continue
			}
			name, required := requiredJSONFieldName(field)
			if !required {
				continue
			}
			value, ok := fields[name]
			if !ok {
				return fmt.Errorf("%s is missing JSON field %q", path, name)
			}
			if err := validateRequiredJSONValue(value, field.Type, path+"."+name); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if err := json.Unmarshal(data, &values); err != nil {
			return fmt.Errorf("%s must be a JSON array: %w", path, err)
		}
		for index, value := range values {
			if err := validateRequiredJSONValue(value, typeOfValue.Elem(), fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func requiredJSONFieldName(field reflect.StructField) (string, bool) {
	tag, hasTag := field.Tag.Lookup("json")
	if !hasTag {
		return field.Name, true
	}
	name := strings.Split(tag, ",")[0]
	if name == "-" {
		return "", false
	}
	if name == "" {
		return field.Name, true
	}
	return name, true
}

func validateStrictJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSONValue(decoder, 0); err != nil {
		return fmt.Errorf("invalid or non-strict JSON: %w", err)
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxEvidenceJSONDepth {
		return fmt.Errorf("JSON nesting exceeds depth %d", maxEvidenceJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if key != strings.ToLower(key) {
				return fmt.Errorf("object key %q is not lowercase", key)
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate object key %q", key)
			}
			keys[key] = struct{}{}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		if closing, err := decoder.Token(); err != nil {
			return err
		} else if closing != json.Delim('}') {
			return errors.New("object is missing closing delimiter")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		if closing, err := decoder.Token(); err != nil {
			return err
		} else if closing != json.Delim(']') {
			return errors.New("array is missing closing delimiter")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}
