package handler

type ScanInfo struct {
	Host string `json:"host"`
	Port string `json:"port"`
	Vuln bool   `json:"vuln"`
}
