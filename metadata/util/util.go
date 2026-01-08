package util

import (
	"fmt"
	"strconv"
	"time"

	"github.com/go-gost/core/metadata"
)

func IsExists(md metadata.Metadata, keys ...string) bool {
	if md == nil {
		return false
	}

	for _, key := range keys {
		if md.IsExists(key) {
			return true
		}
	}
	return false
}

func GetBool(md metadata.Metadata, keys ...string) (v bool) {
	if md == nil {
		return
	}

	for _, key := range keys {
		vv := md.Get(key)
		if vv == nil {
			continue
		}
		switch val := vv.(type) {
		case bool:
			v = val
		case int:
			v = val != 0
		case string:
			v, _ = strconv.ParseBool(val)
		}
		break
	}

	return
}

func GetInt(md metadata.Metadata, keys ...string) (v int) {
	if md == nil {
		return
	}

	for _, key := range keys {
		vv := md.Get(key)
		if vv == nil {
			continue
		}
		switch val := vv.(type) {
		case bool:
			if val {
				v = 1
			}
		case int:
			v = val
		case string:
			v, _ = strconv.Atoi(val)
		}
		break
	}

	return
}

func GetFloat(md metadata.Metadata, keys ...string) (v float64) {
	if md == nil {
		return
	}

	for _, key := range keys {
		vv := md.Get(key)
		if vv == nil {
			continue
		}

		switch val := vv.(type) {
		case float64:
			v = val
		case int:
			v = float64(val)
		case string:
			v, _ = strconv.ParseFloat(val, 64)
		}
		break
	}
	return
}

func GetDuration(md metadata.Metadata, keys ...string) (v time.Duration) {
	if md == nil {
		return
	}

	for _, key := range keys {
		vv := md.Get(key)
		if vv == nil {
			continue
		}

		switch val := vv.(type) {
		case int:
			v = time.Duration(val) * time.Second
		case string:
			v, _ = time.ParseDuration(val)
			if v == 0 {
				n, _ := strconv.Atoi(val)
				v = time.Duration(n) * time.Second
			}
		}
		break
	}
	return
}

func GetString(md metadata.Metadata, keys ...string) (v string) {
	if md == nil {
		return
	}

	for _, key := range keys {
		vv := md.Get(key)
		if vv == nil {
			continue
		}

		switch val := vv.(type) {
		case string:
			v = val
		case int:
			v = strconv.FormatInt(int64(val), 10)
		case int64:
			v = strconv.FormatInt(val, 10)
		case uint:
			v = strconv.FormatUint(uint64(val), 10)
		case uint64:
			v = strconv.FormatUint(uint64(val), 10)
		case bool:
			v = strconv.FormatBool(val)
		case float32:
			v = strconv.FormatFloat(float64(val), 'f', -1, 32)
		case float64:
			v = strconv.FormatFloat(float64(val), 'f', -1, 64)
		}
		break
	}

	return
}

func GetStrings(md metadata.Metadata, keys ...string) (ss []string) {
	if md == nil {
		return
	}

	for _, key := range keys {
		vv := md.Get(key)
		if vv == nil {
			continue
		}

		switch val := vv.(type) {
		case []string:
			ss = val
		case []any:
			for _, v := range val {
				if s, ok := v.(string); ok {
					ss = append(ss, s)
				}
			}
		}
		break
	}
	return
}

func GetStringMap(md metadata.Metadata, keys ...string) (m map[string]any) {
	if md == nil {
		return
	}

	for _, key := range keys {
		vv := md.Get(key)
		if vv == nil {
			continue
		}

		switch val := vv.(type) {
		case map[string]any:
			m = val
		case map[any]any:
			m = make(map[string]any)
			for k, v := range val {
				m[fmt.Sprintf("%v", k)] = v
			}
		}
		break
	}
	return
}

func GetStringMapString(md metadata.Metadata, keys ...string) (m map[string]string) {
	if md == nil {
		return
	}

	for _, key := range keys {
		vv := md.Get(key)
		if vv == nil {
			continue
		}

		switch val := vv.(type) {
		case map[string]any:
			m = make(map[string]string)
			for k, v := range val {
				m[k] = fmt.Sprintf("%v", v)
			}
		case map[any]any:
			m = make(map[string]string)
			for k, v := range val {
				m[fmt.Sprintf("%v", k)] = fmt.Sprintf("%v", v)
			}
		}
		break
	}

	return
}
