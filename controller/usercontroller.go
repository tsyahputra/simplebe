package controller

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/pquerna/otp/totp"
	"github.com/tsyahputra/simplebe/helper"
	"github.com/tsyahputra/simplebe/model"
	"golang.org/x/crypto/bcrypt"
)

func GetUsers(w http.ResponseWriter, r *http.Request) {
	userLoggedIn, err := ParseAccessToken(r)
	if err != "" {
		helper.ResponseMessage(w, http.StatusUnauthorized, err)
		return
	}
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	search := "%" + q.Get("search") + "%"
	var users []model.User
	var totalRecords int64
	if q.Get("search") == "" {
		switch userLoggedIn.RoleID {
		// Administrator
		case 1:
			result := model.DB.Joins("Instance").
				Joins("Role").
				Find(&users)
			totalRecords = result.RowsAffected
			if err := result.Limit(10).Offset(offset).Find(&users).Error; err != nil {
				helper.ResponseMessage(w, http.StatusInternalServerError, err.Error())
				return
			}
		// Non Administrator
		case 2:
			result := model.DB.Where("users.role_id > 1").
				Joins("Instance").
				Joins("Role").
				Find(&users)
			totalRecords = result.RowsAffected
			if err := result.Limit(10).Offset(offset).Find(&users).Error; err != nil {
				helper.ResponseMessage(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	} else {
		switch userLoggedIn.RoleID {
		case 1:
			result := model.DB.Where("users.nama LIKE ?", search).
				Or("users.email LIKE ?", search).
				Or("Role.nama LIKE ?", search).
				Or("Instance.nama LIKE ?", search).
				Joins("Instance").
				Joins("Role").
				Find(&users)
			totalRecords = result.RowsAffected
			if err := result.Limit(10).Offset(offset).Find(&users).Error; err != nil {
				helper.ResponseMessage(w, http.StatusInternalServerError, err.Error())
				return
			}
		case 2:
			result := model.DB.Where(
				model.DB.Where("users.role_id > 1").
					Where(model.DB.Where("users.nama LIKE ?", search).
						Or("users.email LIKE ?", search).
						Or("Role.nama LIKE ?", search).
						Or("Instance.nama LIKE ?", search))).
				Joins("Instance").
				Joins("Role").
				Find(&users)
			totalRecords = result.RowsAffected
			if err := result.Limit(10).Offset(offset).Find(&users).Error; err != nil {
				helper.ResponseMessage(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}
	response := &model.AllUsersWithTotal{
		Users: users,
		Total: totalRecords,
	}
	helper.ResponseJSON(w, http.StatusOK, response)
}

func BeforeAddUser(w http.ResponseWriter, r *http.Request) {
	var instances []model.Instance
	var roles []model.Role
	if err := model.DB.Find(&instances).Error; err != nil {
		helper.ResponseMessage(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := model.DB.Find(&roles).Error; err != nil {
		helper.ResponseMessage(w, http.StatusInternalServerError, err.Error())
		return
	}
	response := &model.InstancesRoles{
		Instances: instances,
		Roles:     roles,
	}
	helper.ResponseJSON(w, http.StatusOK, response)
}

func AddUser(w http.ResponseWriter, r *http.Request) {
	userInput := map[string]string{
		"nama":        "",
		"email":       "",
		"password":    "",
		"role_id":     "",
		"instance_id": "",
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()
	// hash field password
	hashPassword, _ := bcrypt.GenerateFromPassword([]byte(userInput["password"]), bcrypt.DefaultCost)
	customKey, _ := helper.GenerateRandomString(16)
	instanceID, _ := strconv.Atoi(userInput["instance_id"])
	roleID, _ := strconv.Atoi(userInput["role_id"])
	// save to db
	user := model.User{
		Nama:       userInput["nama"],
		Email:      userInput["email"],
		Password:   string(hashPassword),
		InstanceID: int32(instanceID),
		RoleID:     int32(roleID),
		CustomKey:  customKey,
	}
	if err := model.DB.Create(&user).Error; err != nil {
		helper.ResponseMessage(w, http.StatusInternalServerError, err.Error())
		return
	}
	helper.ResponseMessage(w, http.StatusOK, "Sukses")
}

func ViewUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userid"])
	if err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	var user model.User
	if err := model.DB.Where("users.id = ?", userID).
		Joins("Instance").
		Joins("Role").
		First(&user).Error; err != nil {
		helper.ResponseMessage(w, http.StatusNotFound, err.Error())
		return
	}
	helper.ResponseJSON(w, http.StatusOK, user)
}

func EditUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userid"])
	if err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	userInput := map[string]string{
		"nama":        "",
		"email":       "",
		"password":    "",
		"role_id":     "",
		"instance_id": "",
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, "Gagal")
		return
	}
	defer r.Body.Close()
	// hash field password
	hashPassword, _ := bcrypt.GenerateFromPassword([]byte(userInput["password"]), bcrypt.DefaultCost)
	customKey, _ := helper.GenerateRandomString(16)
	instanceID, _ := strconv.Atoi(userInput["instance_id"])
	roleID, _ := strconv.Atoi(userInput["role_id"])
	// save to db
	model.DB.Model(&model.User{}).Where("id = ?", int32(userID)).Updates(map[string]interface{}{
		"nama":                  userInput["nama"],
		"email":                 userInput["email"],
		"password":              string(hashPassword),
		"instance_id":           int32(instanceID),
		"role_id":               int32(roleID),
		"custom_key":            customKey,
		"reset_password_token":  "",
		"reset_password_Expiry": 0,
	})
	helper.ResponseMessage(w, http.StatusOK, "Sukses")
}

func EditUserOnly(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userid"])
	if err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	var user model.User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&user); err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, "Gagal")
		return
	}
	defer r.Body.Close()
	model.DB.Model(&model.User{}).Where("id = ?", int32(userID)).Updates(map[string]interface{}{
		"nama":        user.Nama,
		"email":       user.Email,
		"role_id":     user.RoleID,
		"instance_id": user.InstanceID,
	})
	helper.ResponseMessage(w, http.StatusOK, "Sukses")
}

func ChangePassword(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userid"])
	if err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	userInput := map[string]string{"password": ""}
	if err := json.NewDecoder(r.Body).Decode(&userInput); err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()
	hashPassword, _ := bcrypt.GenerateFromPassword([]byte(userInput["password"]), bcrypt.DefaultCost)
	customKey, _ := helper.GenerateRandomString(16)
	if model.DB.Model(&model.User{}).Where("id = ?", int32(userID)).Updates(map[string]interface{}{
		"password":              string(hashPassword),
		"custom_key":            customKey,
		"reset_password_token":  "",
		"reset_password_Expiry": 0,
	}).RowsAffected == 0 {
		helper.ResponseMessage(w, http.StatusInternalServerError, "Gagal")
		return
	}
	helper.ResponseMessage(w, http.StatusOK, "Sukses")
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	input := map[string]int32{"id": 0}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()
	var user model.User
	if model.DB.Where("id = ?", input["id"]).Delete(&user).RowsAffected == 0 {
		helper.ResponseMessage(w, http.StatusBadRequest, "Gagal")
		return
	}
	helper.ResponseMessage(w, http.StatusOK, "Sukses")
}

func Login(w http.ResponseWriter, r *http.Request) {
	userInput := map[string]string{
		"email":     "",
		"password":  "",
		"fcm_token": "",
		"ip":        "",
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()

	var blockade model.Blockade
	ada := model.DB.Where("blockades.ip = ?", userInput["ip"]).First(&blockade)
	// get email exist
	var user model.User
	if err := model.DB.Where("users.email = ?", userInput["email"]).
		Joins("Instance").
		Joins("Role").
		First(&user).Error; err != nil {
		if ada.RowsAffected == 0 {
			model.DB.Create(&model.Blockade{Ip: userInput["ip"], Count: 1})
		} else {
			if blockade.Count > 3 {
				helper.ResponseMessage(w, http.StatusForbidden, "Silahkan jawab CAPTCHA")
				return
			}
			model.DB.Model(&model.Blockade{}).Where("blockades.ip = ?", userInput["ip"]).Update("count", blockade.Count+1)
		}
		helper.ResponseMessage(w, http.StatusUnauthorized, "email atau password salah")
		return
	}
	// verify user pass
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userInput["password"])); err != nil {
		if ada.RowsAffected == 0 {
			model.DB.Create(&model.Blockade{Ip: userInput["ip"], Count: 1})
		} else {
			if blockade.Count > 3 {
				helper.ResponseMessage(w, http.StatusForbidden, "Silahkan jawab CAPTCHA")
				return
			}
			model.DB.Model(&model.Blockade{}).Where("blockades.ip = ?", userInput["ip"]).Update("count", blockade.Count+1)
		}
		helper.ResponseMessage(w, http.StatusUnauthorized, "email atau password salah")
		return
	}

	if userInput["fcm_token"] != "" {
		model.DB.Model(&model.User{}).
			Where("email = ?", userInput["email"]).
			Update("fcm_token", userInput["fcm_token"])
	}
	if ada.RowsAffected > 0 {
		model.DB.Where("ip = ?", userInput["ip"]).Delete(&blockade)
	}
	// create JWT Access Token
	accessToken := CreateAccessToken(user)
	// create JWT Refresh Token
	refreshToken := CreateRefreshToken(user)
	response := &model.UserToken{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	helper.ResponseJSON(w, http.StatusOK, response)
}

func VerifyCaptcha(w http.ResponseWriter, r *http.Request) {
	userInput := map[string]string{
		"ip": "",
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()
	var blockade model.Blockade
	ada := model.DB.Where("blockades.ip = ? AND blockades.count > 3", userInput["ip"]).First(&blockade)
	if ada.RowsAffected > 0 {
		helper.ResponseMessage(w, http.StatusAlreadyReported, "Silahkan jawab CAPTCHA")
		return
	}
	helper.ResponseMessage(w, http.StatusOK, "Silahkan login terlebih dahulu")
}

func RefreshJWT(w http.ResponseWriter, r *http.Request) {
	userLoggedIn, err := ParseRefreshToken(r)
	if err != "" {
		helper.ResponseMessage(w, http.StatusUnauthorized, err)
		return
	}
	var user model.User
	userID, _ := strconv.Atoi(userLoggedIn.Subject)
	if err := model.DB.First(&user, int32(userID)).Error; err != nil {
		helper.ResponseMessage(w, http.StatusNotFound, err.Error())
		return
	}
	actualCustomKey := generateCustomKey(user)
	if userLoggedIn.CustomKey != actualCustomKey {
		helper.ResponseMessage(w, http.StatusUnauthorized, "Token anda tidak sesuai.")
		return
	}
	accessToken := CreateAccessToken(user)
	refreshToken := CreateRefreshToken(user)
	response := &model.UserToken{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	helper.ResponseJSON(w, http.StatusOK, response)
}

// Generate2FASecretHandler menghasilkan kunci rahasia 2FA baru dan URL QR Code untuk pengguna.
// Secret ini akan disimpan sementara di database sampai diverifikasi.
func Generate2FASecretHandler(w http.ResponseWriter, r *http.Request) {
	userLoggedIn, err := ParseAccessToken(r)
	if err != "" {
		helper.ResponseMessage(w, http.StatusUnauthorized, err)
		return
	}
	userID, _ := strconv.Atoi(userLoggedIn.Subject)
	var user model.User
	if err := model.DB.Where("users.id = ?", int32(userID)).
		Joins("Instance").
		First(&user).Error; err != nil {
		helper.ResponseMessage(w, http.StatusNotFound, err.Error())
		return
	}
	if user.TwoFAEnabled {
		helper.ResponseMessage(w, http.StatusBadRequest, "2FA sudah diaktifkan untuk akun ini")
		return
	}

	// Hasilkan kunci rahasia 2FA dan URL QR Code
	key, notOk := totp.Generate(totp.GenerateOpts{
		Issuer:      "SSO",
		AccountName: user.Email,
	})
	if notOk != nil {
		helper.ResponseMessage(w, http.StatusInternalServerError, "Gagal menghasilkan URL QR Code")
		return
	}
	secret := key.Secret()
	qrCodeURL := key.URL()
	// Simpan secret ke database. Ini penting agar bisa divalidasi nanti.
	// Jika pengguna tidak menyelesaikan proses, secret ini akan tetap ada sampai mereka mencoba lagi atau direset.
	model.DB.Model(&model.User{}).Where("id = ?", int32(userID)).Update("two_fa_secret", secret)
	response := map[string]string{"qr_code_url": qrCodeURL, "secret": secret}
	helper.ResponseJSON(w, http.StatusOK, response)
}

// VerifyAndEnable2FAHandler memverifikasi kode 2FA yang dimasukkan pengguna
// dan mengaktifkan 2FA jika kode valid.
func VerifyAndEnable2FAHandler(w http.ResponseWriter, r *http.Request) {
	userLoggedIn, eror := ParseAccessToken(r)
	if eror != "" {
		helper.ResponseMessage(w, http.StatusUnauthorized, eror)
		return
	}
	userID, _ := strconv.Atoi(userLoggedIn.Subject)
	userInput := map[string]string{"code": ""}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()

	var user model.User
	if err := model.DB.Where("users.ID = ?", int32(userID)).First(&user).Error; err != nil {
		helper.ResponseMessage(w, http.StatusNotFound, "Pengguna tidak ditemukan")
		return
	}
	if user.TwoFASecret == "" {
		helper.ResponseMessage(w, http.StatusBadRequest, "2FA belum diaktifkan.")
		return
	}
	valid := totp.Validate(userInput["code"], user.TwoFASecret)
	if !valid {
		helper.ResponseMessage(w, http.StatusUnauthorized, "Kode 2FA tidak valid.")
		return
	}
	model.DB.Model(&model.User{}).Where("id = ?", int32(userID)).Updates(map[string]any{
		"two_fa_enabled": true,
	})
	helper.ResponseMessage(w, http.StatusOK, "Sukses")
}

// Disable 2FA
func Disable2FAHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userid"])
	if err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	model.DB.Model(&model.User{}).Where("id = ?", int32(userID)).Updates(map[string]any{
		"two_fa_secret":  "",
		"two_fa_enabled": false,
	})
	helper.ResponseMessage(w, http.StatusOK, "Sukses")
}

// Verifikasi kode 2FA untuk reset password
func Verify2FAResetPassword(w http.ResponseWriter, r *http.Request) {
	userInput := map[string]string{"email": "", "code": ""}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()

	var user model.User
	if err := model.DB.Where("users.email = ?", userInput["email"]).First(&user).Error; err != nil {
		helper.ResponseMessage(w, http.StatusNotFound, err.Error())
		return
	}
	if !user.TwoFAEnabled || user.TwoFASecret == "" {
		helper.ResponseMessage(w, http.StatusBadRequest, "2FA belum diaktifkan.")
		return
	}
	valid := totp.Validate(userInput["code"], user.TwoFASecret)
	if !valid {
		helper.ResponseMessage(w, http.StatusUnauthorized, "Kode 2FA tidak valid.")
		return
	}
	// Jika 2FA valid, generate token khusus untuk reset password
	resetToken, _ := helper.GenerateRandomString(32)
	model.DB.Model(&model.User{}).Where("email = ?", userInput["email"]).
		Updates(map[string]any{
			"reset_password_token":  resetToken,
			"reset_password_expiry": time.Now().Add(time.Minute * 30).Unix(),
		})
	response := map[string]string{
		"reset_token": resetToken,
	}
	helper.ResponseJSON(w, http.StatusOK, response)
}

func ResetPassword(w http.ResponseWriter, r *http.Request) {
	userInput := map[string]string{
		"email":       "",
		"password":    "",
		"reset_token": "",
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()

	var user model.User
	if err := model.DB.Where("users.email = ? AND reset_password_token = ?", userInput["email"], userInput["reset_token"]).
		First(&user).Error; err != nil {
		helper.ResponseMessage(w, http.StatusNotFound, "Invalid or expired reset token")
		return
	}
	if time.Now().Unix() > user.ResetPasswordExpiry {
		helper.ResponseMessage(w, http.StatusUnauthorized, "Reset token expired")
		return
	}
	hashPassword, _ := bcrypt.GenerateFromPassword([]byte(userInput["password"]), bcrypt.DefaultCost)
	customKey, _ := helper.GenerateRandomString(16)
	model.DB.Model(&model.User{}).Where("email = ?", userInput["email"]).
		Updates(map[string]any{
			"password":              string(hashPassword),
			"custom_key":            customKey,
			"reset_password_token":  "",
			"reset_password_expiry": 0,
		})
	helper.ResponseMessage(w, http.StatusOK, "Sukses")
}
