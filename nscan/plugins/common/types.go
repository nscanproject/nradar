package common

type Target struct {
	IP           string        `json:"ip"`
	MAC          string        `json:"mac"`
	MACVendor    string        `json:"mac_vendor"`
	DeviceType   string        `json:"device_type"`
	ServiceInfos []ServiceInfo `json:"service_infos"`
	OSInfos      []OSInfo      `json:"os_infos"`
}

type ServiceInfo struct {
	Port    int        `json:"port"`
	State   string     `json:"state"`
	Method  string     `json:"method"`
	Proto   string     `json:"proto"`
	Product string     `json:"product"`
	Service string     `json:"service"`
	Version string     `json:"version"`
	CPEs    []string   `json:"cpes"`
	Banner  string     `json:"banner"`
	Url     string     `json:"url"`
	Vulns   []VulnInfo `json:"vulns"`
	Tags    []string   `json:"tags"`
}

type VulnInfo struct {
	Name        string `json:"name"`
	Descriotion string `json:"description"`
	CVE         string `json:"cve"`
	CNVD        string `json:"cnvd"`
}

type OSInfo struct {
	Name       string   `json:"name"`
	Accuracy   int      `json:"accuracy"`
	CPEs       []string `json:"cpes"`
	DeviceType string   `json:"device_type"`
}
