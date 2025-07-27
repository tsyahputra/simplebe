package model

import (
	"time"
)

type User struct {
	ID                  int32     `json:"id" gorm:"primaryKey;autoIncrement"`
	Nama                string    `json:"nama" gorm:"type:varchar(255);not null"`
	Email               string    `json:"email" gorm:"type:varchar(250);not null;unique"`
	Password            string    `json:"-" gorm:"type:varchar(100);not null"`
	InstanceID          int32     `json:"instance_id" gorm:"not null"`
	RoleID              int32     `json:"role_id" gorm:"not null"`
	CustomKey           string    `json:"-" gorm:"type:varchar(16);null"`  // Key untuk Refresh Token
	TwoFASecret         string    `json:"-" gorm:"type:varchar(255);null"` // Rahasia untuk Google Authenticator
	TwoFAEnabled        bool      `json:"two_fa_enabled" gorm:"default:false"`
	ResetPasswordToken  string    `json:"-" gorm:"type:varchar(32);null"` // Token unik untuk reset password
	ResetPasswordExpiry int64     `json:"-"`
	FcmToken            string    `json:"fcm_token" gorm:"type:varchar(255);null"`
	Modified            time.Time `json:"modified" gorm:"type:datetime;autoUpdateTime:milli"`
	Instance            Instance  `json:"instance,omitempty" gorm:"foreignKey:InstanceID"`
	Role                Role      `json:"role,omitempty" gorm:"foreignKey:RoleID"`
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
