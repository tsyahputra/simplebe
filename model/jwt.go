package model

import "github.com/golang-jwt/jwt/v5"

type AccessTokenCustomClaims struct {
	jwt.RegisteredClaims
	KeyType    string
	RoleID     int32 `json:"role_id"`
	InstanceID int32 `json:"instance_id"`
}

type RefreshTokenCustomClaims struct {
	jwt.RegisteredClaims
	CustomKey string
	KeyType   string
}
