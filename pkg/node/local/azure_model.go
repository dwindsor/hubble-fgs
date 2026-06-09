// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nocloud

package local

// VMData is following https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux
type VMData struct {
	Compute Compute `json:"compute"`
	Network Network `json:"network"`
}

type Compute struct {
	AdditionalCapabilities     AdditionalCapabilities `json:"additionalCapabilities"`
	AzEnvironment              string                 `json:"azEnvironment"`
	CustomData                 string                 `json:"customData"`
	EvictionPolicy             string                 `json:"evictionPolicy"`
	ExtendedLocation           ExtendedLocation       `json:"extendedLocation"`
	Host                       Host                   `json:"host"`
	HostGroup                  HostGroup              `json:"hostGroup"`
	IsHostCompatibilityLayerVm string                 `json:"isHostCompatibilityLayerVm"`
	IsVmInStandbyPool          string                 `json:"isVmInStandbyPool"`
	LicenseType                string                 `json:"licenseType"`
	Location                   string                 `json:"location"`
	Name                       string                 `json:"name"`
	Offer                      string                 `json:"offer"`
	OsProfile                  OsProfile              `json:"osProfile"`
	OsType                     string                 `json:"osType"`
	PhysicalZone               string                 `json:"physicalZone"`
	PlacementGroupId           string                 `json:"placementGroupId"`
	Plan                       Plan                   `json:"plan"`
	PlatformFaultDomain        string                 `json:"platformFaultDomain"`
	PlatformSubFaultDomain     string                 `json:"platformSubFaultDomain"`
	PlatformUpdateDomain       string                 `json:"platformUpdateDomain"`
	Priority                   string                 `json:"priority"`
	Provider                   string                 `json:"provider"`
	PublicKeys                 []PublicKey            `json:"publicKeys"`
	Publisher                  string                 `json:"publisher"`
	ResourceGroupName          string                 `json:"resourceGroupName"`
	ResourceId                 string                 `json:"resourceId"`
	SecurityProfile            SecurityProfile        `json:"securityProfile"`
	Sku                        string                 `json:"sku"`
	StorageProfile             StorageProfile         `json:"storageProfile"`
	SubscriptionId             string                 `json:"subscriptionId"`
	SystemFaultDomain          string                 `json:"systemFaultDomain"`
	Tags                       string                 `json:"tags"`
	TagsList                   []Tag                  `json:"tagsList"`
	UserData                   string                 `json:"userData"`
	Version                    string                 `json:"version"`
	VirtualMachineScaleSet     VirtualMachineScaleSet `json:"virtualMachineScaleSet"`
	VmId                       string                 `json:"vmId"`
	VmScaleSetName             string                 `json:"vmScaleSetName"`
	VmSize                     string                 `json:"vmSize"`
	Zone                       string                 `json:"zone"`
}

type AdditionalCapabilities struct {
	HibernationEnabled string `json:"hibernationEnabled"`
}

type ExtendedLocation struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Host struct {
	Id string `json:"id"`
}

type HostGroup struct {
	Id string `json:"id"`
}

type OsProfile struct {
	AdminUsername                 string `json:"adminUsername"`
	ComputerName                  string `json:"computerName"`
	DisablePasswordAuthentication string `json:"disablePasswordAuthentication"`
}

type Plan struct {
	Name      string `json:"name,omitempty"`
	Product   string `json:"product,omitempty"`
	Publisher string `json:"publisher,omitempty"`
}

type PublicKey struct {
	KeyData string `json:"keyData,omitempty"`
	Path    string `json:"path,omitempty"`
}

type SecurityProfile struct {
	SecureBootEnabled string `json:"secureBootEnabled,omitempty"`
	VirtualTpmEnabled string `json:"virtualTpmEnabled,omitempty"`
	EncryptionAtHost  string `json:"encryptionAtHost,omitempty"`
	SecurityType      string `json:"securityType,omitempty"`
}

type StorageProfile struct {
	DataDisks      []DataDisk      `json:"dataDisks,omitempty"`
	ImageReference *ImageReference `json:"imageReference,omitempty"`
	OsDisk         *OsDisk         `json:"osDisk,omitempty"`
	ResourceDisk   *ResourceDisk   `json:"resourceDisk,omitempty"`
}

type DataDisk struct {
	BytesPerSecondThrottle  string      `json:"bytesPerSecondThrottle"`
	Caching                 string      `json:"caching"`
	CreateOption            string      `json:"createOption"`
	DiskCapacityBytes       string      `json:"diskCapacityBytes"`
	DiskSizeGB              string      `json:"diskSizeGB"`
	Image                   Image       `json:"image"`
	IsSharedDisk            string      `json:"isSharedDisk"`
	IsUltraDisk             string      `json:"isUltraDisk"`
	Lun                     string      `json:"lun"`
	ManagedDisk             ManagedDisk `json:"managedDisk"`
	Name                    string      `json:"name"`
	OpsPerSecondThrottle    string      `json:"opsPerSecondThrottle"`
	Vhd                     Vhd         `json:"vhd"`
	WriteAcceleratorEnabled string      `json:"writeAcceleratorEnabled"`
}

type ManagedDisk struct {
	ID                 string `json:"id,omitempty"`
	StorageAccountType string `json:"storageAccountType,omitempty"`
}

type Image struct {
	Uri string `json:"uri"`
}

type Vhd struct {
	Uri string `json:"uri"`
}

type ImageReference struct {
	CommunityGalleryImageId string `json:"communityGalleryImageId"`
	ExactVersion            string `json:"exactVersion"`
	Id                      string `json:"id"`
	Offer                   string `json:"offer"`
	Publisher               string `json:"publisher"`
	SharedGalleryImageId    string `json:"sharedGalleryImageId"`
	Sku                     string `json:"sku"`
	Version                 string `json:"version"`
}

type OsDisk struct {
	Caching                 string             `json:"caching"`
	CreateOption            string             `json:"createOption"`
	DiffDiskSettings        DiffDiskSettings   `json:"diffDiskSettings"`
	DiskSizeGB              string             `json:"diskSizeGB"`
	EncryptionSettings      EncryptionSettings `json:"encryptionSettings"`
	Image                   Image              `json:"image"`
	ManagedDisk             ManagedDisk        `json:"managedDisk"`
	Name                    string             `json:"name"`
	OsType                  string             `json:"osType"`
	Vhd                     Vhd                `json:"vhd"`
	WriteAcceleratorEnabled string             `json:"writeAcceleratorEnabled"`
}

type URIObject struct {
	URI string `json:"uri,omitempty"`
}

type DiffDiskSettings struct {
	Option string `json:"option,omitempty"`
}

type EncryptionSettings struct {
	Enabled           string             `json:"enabled,omitempty"`
	DiskEncryptionKey *DiskEncryptionKey `json:"diskEncryptionKey,omitempty"`
	KeyEncryptionKey  *KeyEncryptionKey  `json:"keyEncryptionKey,omitempty"`
}

type DiskEncryptionKey struct {
	SourceVault *SourceVault `json:"sourceVault,omitempty"`
	SecretUrl   string       `json:"secretUrl,omitempty"`
}

type KeyEncryptionKey struct {
	SourceVault *SourceVault `json:"sourceVault,omitempty"`
	KeyUrl      string       `json:"keyUrl,omitempty"`
}

type SourceVault struct {
	ID string `json:"id,omitempty"`
}

type ResourceDisk struct {
	Size string `json:"size,omitempty"`
}

type Tag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type VirtualMachineScaleSet struct {
	ID string `json:"id,omitempty"`
}

type Network struct {
	Interfaces []NetworkInterface `json:"interface,omitempty"`
}

type NetworkInterface struct {
	IPv4       IPv4   `json:"ipv4"`
	IPv6       IPv6   `json:"ipv6"`
	MacAddress string `json:"macAddress"`
}

type IPv4 struct {
	IPAddress      []IPAddressEntry `json:"ipAddress"`
	IPAddressBlock []IPAddressBlock `json:"ipAddressBlock"`
	Subnet         []Subnet         `json:"subnet"`
}

type IPv6 struct {
	IPAddress      []IPAddressEntry `json:"ipAddress"`
	IPAddressBlock []IPAddressBlock `json:"ipAddressBlock"`
}

type IPAddressEntry struct {
	PrivateIpAddress string `json:"privateIpAddress"`
	PublicIpAddress  string `json:"publicIpAddress"`
}

type IPAddressBlock struct {
	Address string `json:"address"`
	Prefix  string `json:"prefix"`
}

type Subnet struct {
	Address string `json:"address,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
}

func (vm *VMData) GetHostname() string {
	return vm.Compute.Name
}

func (vm *VMData) GetID() string {
	return vm.Compute.VmId
}

func (vm *VMData) GetTags() map[string]string {
	tags := make(map[string]string)
	for _, tag := range vm.Compute.TagsList {
		tags[tag.Name] = tag.Value
	}
	return tags
}

func (vm *VMData) GetInternalIP() string {
	for _, ipAddr := range vm.Network.Interfaces[0].IPv4.IPAddress {
		if ipAddr.PrivateIpAddress != "" {
			return ipAddr.PrivateIpAddress
		}
	}

	for _, ipAddr := range vm.Network.Interfaces[0].IPv6.IPAddress {
		if ipAddr.PrivateIpAddress != "" {
			return ipAddr.PrivateIpAddress
		}
	}
	return ""
}

func (vm *VMData) GetExternalIP() string {
	for _, ipAddr := range vm.Network.Interfaces[0].IPv4.IPAddress {
		if ipAddr.PublicIpAddress != "" {
			return ipAddr.PublicIpAddress
		}
	}

	for _, ipAddr := range vm.Network.Interfaces[0].IPv6.IPAddress {
		if ipAddr.PublicIpAddress != "" {
			return ipAddr.PublicIpAddress
		}
	}
	return ""
}
