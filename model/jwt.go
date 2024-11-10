package model

import "github.com/golang-jwt/jwt/v4"

type CustomClaims struct {
	jwt.RegisteredClaims
	RoleID     int32 `json:"role_id"`
	InstanceID int32 `json:"instance_id"`
}
