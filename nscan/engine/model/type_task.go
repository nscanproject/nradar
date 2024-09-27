package model

type Task struct {
	Id          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Target      string   `json:"target"`
	Description string   `json:"description"`
	Status      int      `json:"status"`
	Tags        []string `json:"tags"`
}
