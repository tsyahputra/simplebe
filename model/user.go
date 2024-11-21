package model

import (
	"time"
)

type User struct {
	ID         int32     `json:"id" gorm:"primaryKey;autoIncrement"`
	Nama       string    `json:"nama" gorm:"type:varchar(255);not null"`
	Email      string    `json:"email" gorm:"type:varchar(250);not null;unique"`
	Password   string    `json:"-" gorm:"type:varchar(100);not null"`
	InstanceID int32     `json:"instance_id" gorm:"not null"`
	RoleID     int32     `json:"role_id" gorm:"not null"`
	HashToken  string    `json:"hash_token" gorm:"type:varchar(15);null"`
	FcmToken   string    `json:"fcm_token" gorm:"type:varchar(255);null"`
	Modified   time.Time `json:"modified" gorm:"type:datetime;autoUpdateTime:milli"`
	Instance   Instance  `json:"instance,omitempty" gorm:"foreignKey:InstanceID"`
	Role       Role      `json:"role,omitempty" gorm:"foreignKey:RoleID"`
}

type UserToken struct {
	User         User   `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type AllUsersWithTotal struct {
	Users []User `json:"users"`
	Total int64  `json:"total"`
}
