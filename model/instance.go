package model

import "time"

type Instance struct {
	ID        int32     `json:"id" gorm:"primaryKey;autoIncrement"`
	Nama      string    `json:"nama" gorm:"type:varchar(255);not null"`
	Alamat    string    `json:"alamat" gorm:"type:varchar(255);null"`
	Kabupaten string    `json:"kabupaten" gorm:"type:varchar(100);null"`
	Provinsi  string    `json:"provinsi" gorm:"type:varchar(100);not null"`
	Telp      string    `json:"telp" gorm:"type:varchar(20);null"`
	Email     string    `json:"email" gorm:"type:varchar(100);null"`
	Modified  time.Time `json:"modified" gorm:"type:datetime;autoUpdateTime:milli"`
}

type AllInstancesWithTotal struct {
	Instances []Instance `json:"instances"`
	Total     int64      `json:"total"`
}
