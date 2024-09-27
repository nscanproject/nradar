package model

type Task struct {
	Id          uint64   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Target      string   `json:"target"`
	Description string   `json:"description"`
	Status      uint8    `json:"status"`
	Tags        []string `json:"tags"`
	ScreenShot  string   `json:"screenShot,omitempty"`
}
