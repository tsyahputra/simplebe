package controller

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tsyahputra/simplebe/helper"
	"github.com/tsyahputra/simplebe/model"
)

func JwtMiddlewareValidateAccessToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := ExtractToken(r)
		if err != nil {
			helper.ResponseError(w, http.StatusUnauthorized, "Unauthenticated. Invalid token")
			return
		}
		token, err := VerifyAccessToken(tokenString)
		if err != nil {
			helper.ResponseError(w, http.StatusUnauthorized, "Unauhorized")
			return
		}
		_, ok := token.Claims.(*model.AccessTokenCustomClaims)
		if !ok || !token.Valid {
			helper.ResponseError(w, http.StatusUnauthorized, "Unauhorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ExtractToken(r *http.Request) (string, error) {
	authorizationHeader := r.Header.Get("Authorization")
	if !strings.Contains(authorizationHeader, "Bearer") {
		return "", errors.New("token not provided or malformed")
	}
	authHeaderContent := strings.Replace(authorizationHeader, "Bearer ", "", -1)
	return authHeaderContent, nil
}

func VerifyAccessToken(tokenString string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, &model.AccessTokenCustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method in token")
		}
		verifyBytes, err := os.ReadFile("config/simple-access-public.pem")
		if err != nil {
			return nil, err
		}
		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
		if err != nil {
			return nil, err
		}
		return verifyKey, nil
	})
}

func CreateAccessToken(user model.User) string {
	expTime := time.Now().Add(time.Minute * 30)
	claims := &model.AccessTokenCustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    user.Nama,
			Subject:   strconv.Itoa(int(user.ID)),
			Audience:  []string{"SSO"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expTime),
		},
		KeyType:    "access",
		RoleID:     user.RoleID,
		InstanceID: user.InstanceID,
	}
	signBytes, _ := os.ReadFile("config/simple-access-private.key")
	signKey, _ := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	tokenAlg := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	accessToken, _ := tokenAlg.SignedString(signKey)
	return accessToken
}

func ParseAccessToken(r *http.Request) (*model.AccessTokenCustomClaims, string) {
	tokenString, err := ExtractToken(r)
	if err != nil {
		message := "Unauthenticated. Invalid token"
		return &model.AccessTokenCustomClaims{}, message
	}
	token, err := VerifyAccessToken(tokenString)
	claims, ok := token.Claims.(*model.AccessTokenCustomClaims)
	if err != nil {
		message := "Unauthenticated"
		return &model.AccessTokenCustomClaims{}, message
	}
	if !ok || !token.Valid || claims.KeyType != "access" {
		message := "Unauthenticated. Not access token."
		return &model.AccessTokenCustomClaims{}, message
	}
	return claims, ""
}

func GenerateCustomKey(user model.User) string {
	h := hmac.New(sha256.New, []byte(user.CustomKey))
	h.Write([]byte(strconv.Itoa(int(user.ID))))
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}

func CreateRefreshToken(user model.User) string {
	cusKey := GenerateCustomKey(user)
	claims := &model.RefreshTokenCustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   user.Nama,
			Subject:  strconv.Itoa(int(user.ID)),
			Audience: []string{"SSO"},
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		CustomKey: cusKey,
		KeyType:   "refresh",
	}
	signBytes, _ := os.ReadFile("config/simple-refresh-private.key")
	signKey, _ := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	tokenAlg := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	accessToken, _ := tokenAlg.SignedString(signKey)
	return accessToken
}

func VerifyRefreshToken(tokenString string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, &model.RefreshTokenCustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method in token")
		}
		verifyBytes, err := os.ReadFile("config/simple-refresh-public.pem")
		if err != nil {
			return nil, err
		}
		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
		if err != nil {
			return nil, err
		}
		return verifyKey, nil
	})
}

func ParseRefreshToken(r *http.Request) (*model.RefreshTokenCustomClaims, string) {
	tokenString, err := ExtractToken(r)
	if err != nil {
		message := "Unauthenticated. Invalid token"
		return &model.RefreshTokenCustomClaims{}, message
	}
	token, err := VerifyRefreshToken(tokenString)
	claims, ok := token.Claims.(*model.RefreshTokenCustomClaims)
	if err != nil {
		message := "Unauthenticated"
		return &model.RefreshTokenCustomClaims{}, message
	}
	if !ok || !token.Valid || claims.KeyType != "refresh" {
		message := "Unauthenticated. Not refresh token."
		return &model.RefreshTokenCustomClaims{}, message
	}
	return claims, ""
}

func JwtMiddlewareValidateRefreshToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := ExtractToken(r)
		if err != nil {
			helper.ResponseError(w, http.StatusUnauthorized, "Unauthenticated. Invalid token")
			return
		}
		token, err := VerifyRefreshToken(tokenString)
		if err != nil {
			helper.ResponseError(w, http.StatusUnauthorized, "Unauhorized")
			return
		}
		claims, ok := token.Claims.(*model.RefreshTokenCustomClaims)
		if !ok || !token.Valid || claims.KeyType != "refresh" {
			helper.ResponseError(w, http.StatusUnauthorized, "Unauhorized. Not refresh token.")
			return
		}
		next.ServeHTTP(w, r)
	})
}
