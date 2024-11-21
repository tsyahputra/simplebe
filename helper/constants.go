package helper

import "time"

const (
	authTokenExp       = time.Minute * 10
	refreshTokenExp    = time.Hour * 24 * 30
	blacklistKeyPrefix = "blacklisted:"
	otpKeyPrefix       = "password-reset:"
	otpExp             = time.Minute * 10
	otpCharSet         = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	emailTemplate      = "To: %s\r\n" +
		"Subject: Harmonis Password Reset\r\n" +
		"\r\n" +
		"Your OTP for password reset is %s\r\n"
	OTPLength = 6
)
