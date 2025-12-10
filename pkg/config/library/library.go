package library

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

// ConfigCallback is a function that is mapped to a config type and will be called
// when the config object of that type changes.  The old and new config objects are
// passed on a change, including if the config object does not change.  If a config
// object is added for the first time or deleted, nil will be passed accordingly.
// If a callback function returns an error, the operation will fail.
type ConfigCallback func(*v1alpha.ConfigObject, *v1alpha.ConfigObject) error

// UpdateConfigFunc is a function that modifies a config object in place.
// It receives the existing config (or nil if not found) and returns the updated config.
// If the update function returns an error, the update operation will fail.
type UpdateConfigFunc func(existing *v1alpha.ConfigObject) (*v1alpha.ConfigObject, error)

// ConfigRepository is a repository that stores app configuration as a map of configuration
// objects by their type, which is defined as a ConfigType string.  The repository also stores
// a map of callback functions by their type, which are matched against the types of config
// objects in the repository.  Any time a config object is added or removed, the callback
// function is called as well.  A hash of all configuration objects in the map can be used to
// reconcile the repository across distributed environments.  Thread safe.
type ConfigRepository interface {
	AddConfig(*v1alpha.ConfigObject) error
	DeleteConfig(v1alpha.ConfigType) error
	AddConfigCallback(v1alpha.ConfigType, ConfigCallback)
	DeleteConfigCallback(v1alpha.ConfigType)
	GetConfigObject(v1alpha.ConfigType) (*v1alpha.ConfigObject, bool)
	GetConfigObjects() map[v1alpha.ConfigType]*v1alpha.ConfigObject
	GetConfig(v1alpha.ConfigType, interface{}) error
	GetHash() [sha256.Size]byte
	UpdateConfig(v1alpha.ConfigType, UpdateConfigFunc) error
	// TODO: Add support for persisting the configuration to a file
}

type configRepositoryImpl struct {
	hash      [sha256.Size]byte
	configs   map[v1alpha.ConfigType]*v1alpha.ConfigObject
	callbacks map[v1alpha.ConfigType]ConfigCallback
	mu        sync.RWMutex
}

var (
	repo            *configRepositoryImpl
	initGlobalCache sync.Once
)

func GetRepository() ConfigRepository {
	initGlobalCache.Do(func() {
		repo = &configRepositoryImpl{}
		repo.configs = make(map[v1alpha.ConfigType]*v1alpha.ConfigObject)
		repo.callbacks = make(map[v1alpha.ConfigType]ConfigCallback)
	})
	return repo
}

// AddConfig adds or replaces a config object, calls its callback function if it exists, and recalculates the hash.
func (cr *configRepositoryImpl) AddConfig(obj *v1alpha.ConfigObject) error {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	oldObj, ok := cr.configs[obj.Type]
	if !ok {
		oldObj = nil
	}
	callback, ok := cr.callbacks[obj.Type]
	if ok {
		err := callback(oldObj, obj)
		if err != nil {
			return err
		}
	}
	cr.configs[obj.Type] = obj
	cr.recalculateHash()
	return nil
}

// DeleteConfig removes a config object by type, calls its callback function if it exists, and recalculates the hash.
func (cr *configRepositoryImpl) DeleteConfig(typ v1alpha.ConfigType) error {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	oldObj, ok := cr.configs[typ]
	if !ok {
		oldObj = nil
	}
	callback, ok := cr.callbacks[typ]
	if ok {
		err := callback(oldObj, nil)
		if err != nil {
			return err
		}
	}
	delete(cr.configs, typ)
	cr.recalculateHash()
	return nil
}

// AddConfigCallback adds a callback function to be called when a config object of a specific type is added.
func (cr *configRepositoryImpl) AddConfigCallback(typ v1alpha.ConfigType, callback ConfigCallback) {
	cr.mu.Lock()
	cr.callbacks[typ] = callback
	cr.mu.Unlock()
}

// DeleteConfigCallback removes a callback function that was added with AddConfigCallback.
func (cr *configRepositoryImpl) DeleteConfigCallback(typ v1alpha.ConfigType) {
	cr.mu.Lock()
	delete(cr.callbacks, typ)
	cr.mu.Unlock()
}

// GetConfigObject returns the ConfigObject for a given type.
func (cr *configRepositoryImpl) GetConfigObject(typ v1alpha.ConfigType) (*v1alpha.ConfigObject, bool) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	obj, ok := cr.configs[typ]
	if !ok {
		return nil, false
	}
	return obj, true
}

// GetConfigObjects returns all config objects as a map.
func (cr *configRepositoryImpl) GetConfigObjects() map[v1alpha.ConfigType]*v1alpha.ConfigObject {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.configs
}

// GetConfig extracts the config for the given type into the provided target.
func (cr *configRepositoryImpl) GetConfig(typ v1alpha.ConfigType, target interface{}) error {
	cr.mu.RLock()
	obj, ok := cr.configs[typ]
	cr.mu.RUnlock()
	if !ok {
		return &ConfigNotFoundError{}
	}
	switch obj.GetType() {
	case v1alpha.ConfigType_CONFIG_TYPE_DPU:
		dpuConfig := obj.GetConfigDpu()
		if dpuConfig == nil {
			return fmt.Errorf("config is nil")
		}
		targetPtr, ok := target.(*v1alpha.DpuConfig)
		if ok {
			targetPtr.ServiceIp = dpuConfig.ServiceIp
			targetPtr.ServiceMac = dpuConfig.ServiceMac
			targetPtr.PortLow = dpuConfig.PortLow
			targetPtr.PortHigh = dpuConfig.PortHigh
			return nil
		}
		return fmt.Errorf("unable to cast target of type %T to *v1alpha.DpuConfig", target)
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG:
		logConfig := obj.GetConfigLogSyslog()
		if logConfig == nil {
			return fmt.Errorf("config is nil")
		}
		targetPtr, ok := target.(*v1alpha.LogConfigSyslog)
		if ok {
			targetPtr.Configs = logConfig.Configs
			return nil
		}
		return fmt.Errorf("unable to cast target of type %T to *v1alpha.LogConfigSyslog", target)
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX:
		logConfig := obj.GetConfigLogIpfix()
		if logConfig == nil {
			return fmt.Errorf("config is nil")
		}
		targetPtr, ok := target.(*v1alpha.LogConfigIpfix)
		if ok {
			targetPtr.Configs = logConfig.Configs
			return nil
		}
		return fmt.Errorf("unable to cast target of type %T to *v1alpha.LogConfigIpfix", target)
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE:
		logConfig := obj.GetConfigLogTimescape()
		if logConfig == nil {
			return fmt.Errorf("config is nil")
		}
		targetPtr, ok := target.(*v1alpha.LogConfigTimescape)
		if ok {
			targetPtr.Configs = logConfig.Configs
			return nil
		}
		return fmt.Errorf("unable to cast target of type %T to *v1alpha.LogConfigTimescape", target)
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK:
		logConfig := obj.GetConfigLogSplunk()
		if logConfig == nil {
			return fmt.Errorf("config is nil")
		}
		targetPtr, ok := target.(*v1alpha.LogConfigSplunk)
		if ok {
			targetPtr.Configs = logConfig.Configs
			return nil
		}
		return fmt.Errorf("unable to cast target of type %T to *v1alpha.LogConfigSplunk", target)
	default:
		return fmt.Errorf("unknown config type: %v", obj.GetType())
	}
}

// GetHash returns the current hash of the entire config.
func (cr *configRepositoryImpl) GetHash() [sha256.Size]byte {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.hash
}

// recalculateHash recalculates the hash of the config list.  This function does not
// acquire a lock, so a write lock should be held when it is called.
func (cr *configRepositoryImpl) recalculateHash() {
	jsonBytes, _ := json.Marshal(cr.configs)
	hash := sha256.Sum256(jsonBytes)
	cr.hash = hash
}

// UpdateConfig atomically updates a config by type using the provided updater function.
// The updater receives the current config (or nil if not found) and must return the new config
// or an error.  An error will cancel the update operation and the object will remain unchanged.
// This method holds the lock for the entire read-modify-write cycle, preventing race conditions.
func (cr *configRepositoryImpl) UpdateConfig(typ v1alpha.ConfigType, updater UpdateConfigFunc) error {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	existing, _ := cr.configs[typ]

	newObj, err := updater(existing)
	if err != nil {
		return err
	}

	// Call callback if exists
	callback, ok := cr.callbacks[typ]
	if ok {
		if err := callback(existing, newObj); err != nil {
			return err
		}
	}

	cr.configs[typ] = newObj
	cr.recalculateHash()
	return nil
}
