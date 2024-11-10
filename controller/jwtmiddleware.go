package controller

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/tsyahputra/simplebe/helper"
	"github.com/tsyahputra/simplebe/model"
)

func JwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := ExtractToken(r)
		if err != nil {
			helper.ResponseError(w, http.StatusUnauthorized, "Unauthenticated. Invalid token")
			return
		}
		token, err := VerifyToken(tokenString)
		if err != nil {
			v, _ := err.(*jwt.ValidationError)
			switch v.Errors {
			case jwt.ValidationErrorSignatureInvalid:
				helper.ResponseError(w, http.StatusUnauthorized, "Unauhorized")
				return
			default:
				helper.ResponseError(w, http.StatusUnauthorized, "Unauhorized")
				return
			}
		}
		_, ok := token.Claims.(*model.CustomClaims)
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

func VerifyToken(tokenString string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, &model.CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method in token")
		}
		verifyBytes, err := os.ReadFile("config/simple-public.pem")
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
	expTime := time.Now().Add(time.Hour * 24 * 3)
	claims := &model.CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    user.Nama,
			Subject:   strconv.Itoa(int(user.ID)),
			Audience:  []string{"SSO"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expTime),
		},
		RoleID:     user.RoleID,
		InstanceID: user.InstanceID,
	}
	signBytes, _ := os.ReadFile("config/simple-private.key")
	signKey, _ := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	tokenAlg := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	accessToken, _ := tokenAlg.SignedString(signKey)
	return accessToken
}

func ParseJwtToken(r *http.Request) (*model.CustomClaims, string) {
	tokenString, err := ExtractToken(r)
	if err != nil {
		message := "Unauthenticated. Invalid token"
		return &model.CustomClaims{}, message
	}
	token, err := VerifyToken(tokenString)
	claims, ok := token.Claims.(*model.CustomClaims)
	if err != nil {
		v, _ := err.(*jwt.ValidationError)
		switch v.Errors {
		case jwt.ValidationErrorSignatureInvalid:
			message := "Unauthenticated. Signature invalid"
			return &model.CustomClaims{}, message
		default:
			message := "Unauthenticated"
			return &model.CustomClaims{}, message
		}
	}
	if !ok || !token.Valid {
		message := "Unauthenticated"
		return &model.CustomClaims{}, message
	}
	if !claims.VerifyAudience("SSO", true) {
		message := "Unauthenticated"
		return &model.CustomClaims{}, message
	}
	return claims, ""
}
