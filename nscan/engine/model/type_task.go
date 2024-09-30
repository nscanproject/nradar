package model

type Task struct {
	Id          uint64   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Target      string   `json:"target"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	Tags        []string `json:"tags"`
	StartTime   string   `json:"startTime"`
	EndTime     string   `json:"endTime"`
}
