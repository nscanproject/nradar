package model

type TAwdb struct {
	Country  string
	Province string
	City     string
	District string
	ISP      string
	IP       string
}

func (TAwdb) TableName() string {
	return "t_awdb"
}
