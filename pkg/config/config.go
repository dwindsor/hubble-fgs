package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
)

// ConfigObject is a generic config object, where config is the config JSON object
// and Type is the type of the config.
type ConfigObject struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

// ConfigCallback is a function that is mapped to a config type and can be called
// when the config object of that type is refreshed.  An empty ConfigObject will be
// passed if the config does not exist in the ConfigList.
type ConfigCallback func(ConfigObject) error

// ConfigList is a map-like structure of config objects, keyed by config type.
// It enforces that only one config object of each type exists.
type ConfigList struct {
	items     map[string]ConfigObject
	callbacks map[string]ConfigCallback
}

func IsNil(i interface{}) bool {
	if i == nil {
		return true
	}
	vi := reflect.ValueOf(i)
	switch vi.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return vi.IsNil()
	}
	return false
}

// Add adds or replaces a ConfigObject by its Type.
func (cl *ConfigList) Add(obj ConfigObject) {
	if IsNil(cl.items) {
		cl.items = make(map[string]ConfigObject)
	}
	cl.items[obj.Type] = obj
}

// Get returns a ConfigObject by type, and a bool if it exists.
func (cl *ConfigList) Get(typ string) (ConfigObject, bool) {
	if IsNil(cl.items) {
		cl.items = make(map[string]ConfigObject)
	}
	obj, ok := cl.items[typ]
	return obj, ok
}

// Delete removes a ConfigObject by type.
func (cl *ConfigList) Delete(typ string) {
	if IsNil(cl.items) {
		cl.items = make(map[string]ConfigObject)
	}
	delete(cl.items, typ)
}

// All returns all config objects as a slice.
func (cl *ConfigList) All() []ConfigObject {
	if IsNil(cl.items) {
		cl.items = make(map[string]ConfigObject)
	}
	result := make([]ConfigObject, 0, len(cl.items))
	for _, obj := range cl.items {
		result = append(result, obj)
	}
	return result
}

// AddCallback adds or replaces a config refresh callback for a given config type.
func (cl *ConfigList) AddCallback(typ string, cb ConfigCallback) {
	if IsNil(cl.callbacks) {
		cl.callbacks = make(map[string]ConfigCallback)
	}
	cl.callbacks[typ] = cb
}

// DeleteCallback removes a config refresh callback for a given config type.
func (cl *ConfigList) DeleteCallback(typ string) {
	if IsNil(cl.callbacks) {
		return
	}
	delete(cl.callbacks, typ)
}

// GetCallback retrieves a config refresh callback for a given config type.
func (cl *ConfigList) GetCallback(typ string) (ConfigCallback, bool) {
	if IsNil(cl.callbacks) {
		return nil, false
	}
	cb, ok := cl.callbacks[typ]
	return cb, ok
}

// GetAllCallbacks returns a copy of the map of all registered config callbacks.
func (cl *ConfigList) GetAllCallbacks() map[string]ConfigCallback {
	result := make(map[string]ConfigCallback)
	if IsNil(cl.callbacks) {
		return result
	}
	for k, v := range cl.callbacks {
		result[k] = v
	}
	return result
}

// RunCallback runs the callback for a given config type, if it exists.
func (cl *ConfigList) RunCallback(typ string) error {
	cb, ok := cl.GetCallback(typ)
	if !ok {
		return nil
	}
	obj, exists := cl.Get(typ)
	if !exists {
		return nil
	}
	return cb(obj)
}

// HashConfigList returns the sha256 hash (hex encoded) of the JSON encoding of the ConfigList
func HashConfigList(cl ConfigList) (string, error) {
	jsonBytes, err := SerializeConfigList(cl)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(jsonBytes)
	return hex.EncodeToString(hash[:]), nil
}

// SerializeConfigList returns the JSON encoding of the ConfigList
func SerializeConfigList(cl ConfigList) (json.RawMessage, error) {
	jsonBytes, err := json.Marshal(cl.items)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(jsonBytes), nil
}

// DeserializeConfigList returns the ConfigList from the JSON encoding
func DeserializeConfigList(raw json.RawMessage) (ConfigList, error) {
	m := make(map[string]ConfigObject)
	err := json.Unmarshal([]byte(raw), &m)
	if err != nil {
		return ConfigList{}, err
	}
	return ConfigList{items: m}, nil
}
