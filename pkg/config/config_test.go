package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestConfigList_Add(t *testing.T) {
	tests := []struct {
		name string
		cl   *ConfigList
		obj  ConfigObject
		want map[string]ConfigObject
	}{
		{
			name: "add to nil map",
			cl:   &ConfigList{},
			obj:  ConfigObject{Type: "test", Config: json.RawMessage(`{"key":"value"}`)},
			want: map[string]ConfigObject{
				"test": {Type: "test", Config: json.RawMessage(`{"key":"value"}`)},
			},
		},
		{
			name: "add new item",
			cl: &ConfigList{
				items: map[string]ConfigObject{
					"existing": {Type: "existing", Config: json.RawMessage(`{"key":"value"}`)},
				},
			},
			obj: ConfigObject{Type: "new", Config: json.RawMessage(`{"key":"value2"}`)},
			want: map[string]ConfigObject{
				"existing": {Type: "existing", Config: json.RawMessage(`{"key":"value"}`)},
				"new":      {Type: "new", Config: json.RawMessage(`{"key":"value2"}`)},
			},
		},
		{
			name: "replace existing item",
			cl: &ConfigList{
				items: map[string]ConfigObject{
					"test": {Type: "test", Config: json.RawMessage(`{"key":"value"}`)},
				},
			},
			obj: ConfigObject{Type: "test", Config: json.RawMessage(`{"key":"updated"}`)},
			want: map[string]ConfigObject{
				"test": {Type: "test", Config: json.RawMessage(`{"key":"updated"}`)},
			},
		},
		{
			name: "add empty config",
			cl:   &ConfigList{},
			obj:  ConfigObject{Type: "empty", Config: json.RawMessage(`{}`)},
			want: map[string]ConfigObject{
				"empty": {Type: "empty", Config: json.RawMessage(`{}`)},
			},
		},
		{
			name: "add nil config",
			cl:   &ConfigList{},
			obj:  ConfigObject{Type: "nil", Config: nil},
			want: map[string]ConfigObject{
				"nil": {Type: "nil", Config: nil},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cl.Add(tt.obj)
			if !reflect.DeepEqual(tt.cl.items, tt.want) {
				t.Errorf("ConfigList.Add() = %v, want %v", tt.cl.items, tt.want)
			}
		})
	}
}

func TestConfigList_Get(t *testing.T) {
	tests := []struct {
		name      string
		cl        *ConfigList
		typ       string
		wantObj   ConfigObject
		wantFound bool
	}{
		{
			name:      "get from nil map",
			cl:        &ConfigList{},
			typ:       "test",
			wantObj:   ConfigObject{},
			wantFound: false,
		},
		{
			name: "get existing item",
			cl: &ConfigList{
				items: map[string]ConfigObject{
					"test": {Type: "test", Config: json.RawMessage(`{"key":"value"}`)},
				},
			},
			typ:       "test",
			wantObj:   ConfigObject{Type: "test", Config: json.RawMessage(`{"key":"value"}`)},
			wantFound: true,
		},
		{
			name: "get non-existing item",
			cl: &ConfigList{
				items: map[string]ConfigObject{
					"test": {Type: "test", Config: json.RawMessage(`{"key":"value"}`)},
				},
			},
			typ:       "nonexistent",
			wantObj:   ConfigObject{},
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotObj, gotFound := tt.cl.Get(tt.typ)
			if !reflect.DeepEqual(gotObj, tt.wantObj) {
				t.Errorf("ConfigList.Get() gotObj = %v, want %v", gotObj, tt.wantObj)
			}
			if gotFound != tt.wantFound {
				t.Errorf("ConfigList.Get() gotFound = %v, want %v", gotFound, tt.wantFound)
			}
		})
	}
}

func TestConfigList_Delete(t *testing.T) {
	tests := []struct {
		name string
		cl   *ConfigList
		typ  string
		want map[string]ConfigObject
	}{
		{
			name: "delete from nil map",
			cl:   &ConfigList{},
			typ:  "test",
			want: map[string]ConfigObject{},
		},
		{
			name: "delete existing item",
			cl: &ConfigList{
				items: map[string]ConfigObject{
					"test":     {Type: "test", Config: json.RawMessage(`{"key":"value"}`)},
					"preserve": {Type: "preserve", Config: json.RawMessage(`{"key":"value2"}`)},
				},
			},
			typ: "test",
			want: map[string]ConfigObject{
				"preserve": {Type: "preserve", Config: json.RawMessage(`{"key":"value2"}`)},
			},
		},
		{
			name: "delete non-existing item",
			cl: &ConfigList{
				items: map[string]ConfigObject{
					"test": {Type: "test", Config: json.RawMessage(`{"key":"value"}`)},
				},
			},
			typ: "nonexistent",
			want: map[string]ConfigObject{
				"test": {Type: "test", Config: json.RawMessage(`{"key":"value"}`)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cl.Delete(tt.typ)
			if !reflect.DeepEqual(tt.cl.items, tt.want) {
				t.Errorf("ConfigList.Delete() = %v, want %v", tt.cl.items, tt.want)
			}
		})
	}
}

func TestConfigList_All(t *testing.T) {
	tests := []struct {
		name string
		cl   *ConfigList
		want []ConfigObject
	}{
		{
			name: "all from nil map",
			cl:   &ConfigList{},
			want: []ConfigObject{},
		},
		{
			name: "all from empty map",
			cl: &ConfigList{
				items: map[string]ConfigObject{},
			},
			want: []ConfigObject{},
		},
		{
			name: "all from populated map",
			cl: &ConfigList{
				items: map[string]ConfigObject{
					"test1": {Type: "test1", Config: json.RawMessage(`{"key":"value1"}`)},
					"test2": {Type: "test2", Config: json.RawMessage(`{"key":"value2"}`)},
				},
			},
			want: []ConfigObject{
				{Type: "test1", Config: json.RawMessage(`{"key":"value1"}`)},
				{Type: "test2", Config: json.RawMessage(`{"key":"value2"}`)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cl.All()

			// Since map iteration order is not guaranteed, we need to compare differently
			if len(got) != len(tt.want) {
				t.Errorf("ConfigList.All() got %v items, want %v items", len(got), len(tt.want))
				return
			}

			// Convert expected slice to map for easier comparison
			wantMap := make(map[string]ConfigObject)
			for _, obj := range tt.want {
				wantMap[obj.Type] = obj
			}

			// Check each item in the result
			for _, obj := range got {
				wantObj, ok := wantMap[obj.Type]
				if !ok {
					t.Errorf("ConfigList.All() unexpected item %v", obj)
					continue
				}
				if !reflect.DeepEqual(obj, wantObj) {
					t.Errorf("ConfigList.All() item %v = %v, want %v", obj.Type, obj, wantObj)
				}
			}
		})
	}
}

func TestConfigList_AddCallback(t *testing.T) {
	tests := []struct {
		name string
		cl   *ConfigList
		typ  string
	}{
		{
			name: "add callback to nil map",
			cl:   &ConfigList{},
			typ:  "test",
		},
		{
			name: "add new callback",
			cl: &ConfigList{
				callbacks: map[string]ConfigCallback{
					"existing": func(ConfigObject) error { return nil },
				},
			},
			typ: "new",
		},
		{
			name: "replace existing callback",
			cl: &ConfigList{
				callbacks: map[string]ConfigCallback{
					"test": func(ConfigObject) error { return nil },
				},
			},
			typ: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callback := func(ConfigObject) error { return nil }
			tt.cl.AddCallback(tt.typ, callback)

			// Verify callback was added
			if tt.cl.callbacks == nil {
				t.Errorf("ConfigList.AddCallback() callbacks map is nil")
				return
			}

			cb, ok := tt.cl.callbacks[tt.typ]
			if !ok {
				t.Errorf("ConfigList.AddCallback() callback not found for type %s", tt.typ)
				return
			}

			// Compare function pointers (not perfect but checks if non-nil)
			if reflect.ValueOf(cb).Pointer() != reflect.ValueOf(callback).Pointer() {
				t.Errorf("ConfigList.AddCallback() callback pointer mismatch")
			}
		})
	}
}

func TestConfigList_DeleteCallback(t *testing.T) {
	callback := func(ConfigObject) error { return nil }

	tests := []struct {
		name string
		cl   *ConfigList
		typ  string
		want map[string]ConfigCallback
	}{
		{
			name: "delete from nil map",
			cl:   &ConfigList{},
			typ:  "test",
			want: nil,
		},
		{
			name: "delete existing callback",
			cl: &ConfigList{
				callbacks: map[string]ConfigCallback{
					"test":     callback,
					"preserve": callback,
				},
			},
			typ: "test",
			want: map[string]ConfigCallback{
				"preserve": callback,
			},
		},
		{
			name: "delete non-existing callback",
			cl: &ConfigList{
				callbacks: map[string]ConfigCallback{
					"test": callback,
				},
			},
			typ: "nonexistent",
			want: map[string]ConfigCallback{
				"test": callback,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cl.DeleteCallback(tt.typ)

			// Check if callbacks map matches expected state
			if tt.want == nil && tt.cl.callbacks != nil {
				t.Errorf("ConfigList.DeleteCallback() callbacks = %v, want nil", tt.cl.callbacks)
				return
			}

			if tt.want != nil {
				if len(tt.cl.callbacks) != len(tt.want) {
					t.Errorf("ConfigList.DeleteCallback() callbacks count = %d, want %d",
						len(tt.cl.callbacks), len(tt.want))
					return
				}

				for k := range tt.want {
					if _, ok := tt.cl.callbacks[k]; !ok {
						t.Errorf("ConfigList.DeleteCallback() missing callback for %s", k)
					}
				}
			}
		})
	}
}

func TestConfigList_GetCallback(t *testing.T) {
	callback := func(ConfigObject) error { return nil }

	tests := []struct {
		name      string
		cl        *ConfigList
		typ       string
		wantFound bool
	}{
		{
			name:      "get from nil map",
			cl:        &ConfigList{},
			typ:       "test",
			wantFound: false,
		},
		{
			name: "get existing callback",
			cl: &ConfigList{
				callbacks: map[string]ConfigCallback{
					"test": callback,
				},
			},
			typ:       "test",
			wantFound: true,
		},
		{
			name: "get non-existing callback",
			cl: &ConfigList{
				callbacks: map[string]ConfigCallback{
					"test": callback,
				},
			},
			typ:       "nonexistent",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotFound := tt.cl.GetCallback(tt.typ)
			if gotFound != tt.wantFound {
				t.Errorf("ConfigList.GetCallback() gotFound = %v, want %v", gotFound, tt.wantFound)
			}
		})
	}
}

func TestConfigList_GetAllCallbacks(t *testing.T) {
	callback1 := func(ConfigObject) error { return nil }
	callback2 := func(ConfigObject) error { return nil }

	tests := []struct {
		name string
		cl   *ConfigList
		want int // Number of callbacks expected
	}{
		{
			name: "get all from nil map",
			cl:   &ConfigList{},
			want: 0,
		},
		{
			name: "get all from populated map",
			cl: &ConfigList{
				callbacks: map[string]ConfigCallback{
					"test1": callback1,
					"test2": callback2,
				},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cl.GetAllCallbacks()
			if len(got) != tt.want {
				t.Errorf("ConfigList.GetAllCallbacks() got %v items, want %v items", len(got), tt.want)
			}

			// Verify it's a copy, not the original map
			if tt.cl.callbacks != nil {
				// Modify the original map
				tt.cl.callbacks["new"] = callback1
				// Check that the returned map wasn't affected
				if _, ok := got["new"]; ok {
					t.Errorf("ConfigList.GetAllCallbacks() returned a reference, not a copy")
				}
			}
		})
	}
}

func TestConfigList_RunCallback(t *testing.T) {
	var callbackCalled bool
	var callbackObj ConfigObject

	callback := func(obj ConfigObject) error {
		callbackCalled = true
		callbackObj = obj
		return nil
	}

	tests := []struct {
		name            string
		cl              *ConfigList
		typ             string
		wantCalled      bool
		wantCallbackObj ConfigObject
	}{
		{
			name: "run non-existent callback",
			cl: &ConfigList{
				callbacks: map[string]ConfigCallback{
					"other": callback,
				},
				items: map[string]ConfigObject{
					"test": {Type: "test", Config: json.RawMessage(`{"key":"value"}`)},
				},
			},
			typ:        "test",
			wantCalled: false,
		},
		{
			name: "run callback for non-existent config",
			cl: &ConfigList{
				callbacks: map[string]ConfigCallback{
					"test": callback,
				},
				items: map[string]ConfigObject{
					"other": {Type: "other", Config: json.RawMessage(`{"key":"value"}`)},
				},
			},
			typ:        "test",
			wantCalled: false,
		},
		{
			name: "run existing callback for existing config",
			cl: &ConfigList{
				callbacks: map[string]ConfigCallback{
					"test": callback,
				},
				items: map[string]ConfigObject{
					"test": {Type: "test", Config: json.RawMessage(`{"key":"value"}`)},
				},
			},
			typ:             "test",
			wantCalled:      true,
			wantCallbackObj: ConfigObject{Type: "test", Config: json.RawMessage(`{"key":"value"}`)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset callback state
			callbackCalled = false
			callbackObj = ConfigObject{}

			err := tt.cl.RunCallback(tt.typ)
			if err != nil {
				t.Errorf("ConfigList.RunCallback() error = %v", err)
			}

			if callbackCalled != tt.wantCalled {
				t.Errorf("ConfigList.RunCallback() callbackCalled = %v, want %v", callbackCalled, tt.wantCalled)
			}

			if tt.wantCalled && !reflect.DeepEqual(callbackObj, tt.wantCallbackObj) {
				t.Errorf("ConfigList.RunCallback() callbackObj = %v, want %v", callbackObj, tt.wantCallbackObj)
			}
		})
	}
}

func TestHashConfigList(t *testing.T) {
	tests := []struct {
		name    string
		cl      ConfigList
		wantErr bool
	}{
		{
			name:    "hash empty config list",
			cl:      ConfigList{},
			wantErr: false,
		},
		{
			name: "hash populated config list",
			cl: ConfigList{
				items: map[string]ConfigObject{
					"test1": {Type: "test1", Config: json.RawMessage(`{"key":"value1"}`)},
					"test2": {Type: "test2", Config: json.RawMessage(`{"key":"value2"}`)},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HashConfigList(tt.cl)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashConfigList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check that we got a non-empty hash
			if !tt.wantErr && got == "" {
				t.Errorf("HashConfigList() returned empty hash")
			}

			// Verify deterministic behavior - same input should give same hash
			got2, err := HashConfigList(tt.cl)
			if err != nil {
				t.Errorf("HashConfigList() second call error = %v", err)
				return
			}

			if got != got2 {
				t.Errorf("HashConfigList() not deterministic: %v != %v", got, got2)
			}
		})
	}
}

func TestSerializeConfigList(t *testing.T) {
	tests := []struct {
		name    string
		cl      ConfigList
		wantNil bool   // Whether we expect nil/null JSON
		want    string // Only checked if wantNil is false
		wantErr bool
	}{
		{
			name:    "serialize empty config list",
			cl:      ConfigList{},
			wantNil: true,
			wantErr: false,
		},
		{
			name: "serialize populated config list",
			cl: ConfigList{
				items: map[string]ConfigObject{
					"test": {Type: "test", Config: json.RawMessage(`{"key":"value"}`)},
				},
			},
			wantNil: false,
			want:    `{"test":{"type":"test","config":{"key":"value"}}}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SerializeConfigList(tt.cl)
			if (err != nil) != tt.wantErr {
				t.Errorf("SerializeConfigList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if tt.wantNil {
					// For empty ConfigList, the implementation returns null
					if string(got) != "null" {
						t.Errorf("SerializeConfigList() for empty ConfigList = %v, want null", string(got))
					}
					return
				}

				// Compare JSON by unmarshaling to ensure equivalent structure
				var gotMap, wantMap map[string]interface{}
				if err := json.Unmarshal(got, &gotMap); err != nil {
					t.Errorf("Failed to unmarshal result: %v", err)
					return
				}
				if err := json.Unmarshal([]byte(tt.want), &wantMap); err != nil {
					t.Errorf("Failed to unmarshal expected: %v", err)
					return
				}

				if !reflect.DeepEqual(gotMap, wantMap) {
					t.Errorf("SerializeConfigList() = %v, want %v", string(got), tt.want)
				}
			}
		})
	}
}

func TestDeserializeConfigList(t *testing.T) {
	tests := []struct {
		name    string
		raw     json.RawMessage
		want    ConfigList
		wantErr bool
	}{
		{
			name:    "deserialize empty JSON",
			raw:     json.RawMessage(`{}`),
			want:    ConfigList{items: map[string]ConfigObject{}},
			wantErr: false,
		},
		{
			name: "deserialize valid JSON",
			raw:  json.RawMessage(`{"test":{"type":"test","config":{"key":"value"}}}`),
			want: ConfigList{
				items: map[string]ConfigObject{
					"test": {Type: "test", Config: json.RawMessage(`{"key":"value"}`)},
				},
			},
			wantErr: false,
		},
		{
			name:    "deserialize invalid JSON",
			raw:     json.RawMessage(`{invalid}`),
			want:    ConfigList{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeserializeConfigList(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeserializeConfigList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Check that items map has expected entries
				if len(got.items) != len(tt.want.items) {
					t.Errorf("DeserializeConfigList() items count = %d, want %d",
						len(got.items), len(tt.want.items))
					return
				}

				for k, wantObj := range tt.want.items {
					gotObj, ok := got.items[k]
					if !ok {
						t.Errorf("DeserializeConfigList() missing item %s", k)
						continue
					}

					if gotObj.Type != wantObj.Type {
						t.Errorf("DeserializeConfigList() item %s type = %s, want %s",
							k, gotObj.Type, wantObj.Type)
					}

					// Compare Config as JSON
					var gotConfig, wantConfig interface{}
					if err := json.Unmarshal(gotObj.Config, &gotConfig); err != nil {
						t.Errorf("Failed to unmarshal gotConfig: %v", err)
						continue
					}
					if err := json.Unmarshal(wantObj.Config, &wantConfig); err != nil {
						t.Errorf("Failed to unmarshal wantConfig: %v", err)
						continue
					}

					if !reflect.DeepEqual(gotConfig, wantConfig) {
						t.Errorf("DeserializeConfigList() item %s config = %v, want %v",
							k, gotConfig, wantConfig)
					}
				}
			}
		})
	}
}
