package model

type Role struct {
	ID   int32  `json:"id" gorm:"primaryKey;autoIncrement"`
	Nama string `json:"nama" gorm:"type:varchar(100);not null"`
}

type InstancesRoles struct {
	Instances []Instance `json:"instances"`
	Roles     []Role     `json:"roles"`
}
