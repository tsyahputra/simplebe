package controller

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/tsyahputra/simplebe/helper"
	"github.com/tsyahputra/simplebe/model"
	"golang.org/x/crypto/bcrypt"
)

func GetUsers(w http.ResponseWriter, r *http.Request) {
	userLoggedIn, err := ParseAccessToken(r)
	if err != "" {
		helper.ResponseError(w, http.StatusUnauthorized, err)
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
				helper.ResponseError(w, http.StatusInternalServerError, err.Error())
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
				helper.ResponseError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	} else {
		switch userLoggedIn.RoleID {
		case 1:
			result := model.DB.Where("users.nama LIKE ?", search).
				Or("users.username LIKE ?", search).
				Or("Role.nama LIKE ?", search).
				Or("Instance.nama LIKE ?", search).
				Joins("Instance").
				Joins("Role").
				Find(&users)
			totalRecords = result.RowsAffected
			if err := result.Limit(10).Offset(offset).Find(&users).Error; err != nil {
				helper.ResponseError(w, http.StatusInternalServerError, err.Error())
				return
			}
		case 2:
			result := model.DB.Where(
				model.DB.Where("users.role_id > 1").
					Where(model.DB.Where("users.nama LIKE ?", search).
						Or("users.username LIKE ?", search).
						Or("Role.nama LIKE ?", search).
						Or("Instance.nama LIKE ?", search))).
				Joins("Instance").
				Joins("Role").
				Find(&users)
			totalRecords = result.RowsAffected
			if err := result.Limit(10).Offset(offset).Find(&users).Error; err != nil {
				helper.ResponseError(w, http.StatusInternalServerError, err.Error())
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
		helper.ResponseError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := model.DB.Find(&roles).Error; err != nil {
		helper.ResponseError(w, http.StatusInternalServerError, err.Error())
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
		"username":    "",
		"password":    "",
		"role_id":     "",
		"instance_id": "",
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		helper.ResponseError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()
	// hash field password
	hashPassword, _ := bcrypt.GenerateFromPassword([]byte(userInput["password"]), bcrypt.DefaultCost)
	hashToken := helper.GenerateRandomString(15)
	instanceID, _ := strconv.Atoi(userInput["instance_id"])
	roleID, _ := strconv.Atoi(userInput["role_id"])
	// save to db
	user := model.User{
		Nama:       userInput["nama"],
		Username:   userInput["username"],
		Password:   string(hashPassword),
		HashToken:  hashToken,
		InstanceID: int32(instanceID),
		RoleID:     int32(roleID),
	}
	if err := model.DB.Create(&user).Error; err != nil {
		helper.ResponseError(w, http.StatusInternalServerError, err.Error())
		return
	}
	response := map[string]string{"message": "Sukses"}
	helper.ResponseJSON(w, http.StatusOK, response)
}

func ViewUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userid"])
	if err != nil {
		helper.ResponseError(w, http.StatusBadRequest, err.Error())
		return
	}
	var user model.User
	if err := model.DB.Where("users.id = ?", userID).
		Joins("Instance").
		Joins("Role").
		First(&user).Error; err != nil {
		helper.ResponseError(w, http.StatusNotFound, err.Error())
		return
	}
	helper.ResponseJSON(w, http.StatusOK, user)
}

func EditUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userid"])
	if err != nil {
		helper.ResponseError(w, http.StatusBadRequest, err.Error())
		return
	}
	userInput := map[string]string{
		"nama":        "",
		"username":    "",
		"password":    "",
		"role_id":     "",
		"instance_id": "",
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		helper.ResponseError(w, http.StatusBadRequest, "Gagal")
		return
	}
	defer r.Body.Close()
	// hash field password
	hashPassword, _ := bcrypt.GenerateFromPassword([]byte(userInput["password"]), bcrypt.DefaultCost)
	hashToken := helper.GenerateRandomString(15)
	instanceID, _ := strconv.Atoi(userInput["instance_id"])
	roleID, _ := strconv.Atoi(userInput["role_id"])
	// save to db
	model.DB.Model(&model.User{}).Where("id = ?", int32(userID)).Updates(map[string]interface{}{
		"nama":        userInput["nama"],
		"username":    userInput["username"],
		"password":    string(hashPassword),
		"hash_token":  hashToken,
		"instance_id": int32(instanceID),
		"role_id":     int32(roleID),
	})
	response := map[string]string{"message": "Sukses"}
	helper.ResponseJSON(w, http.StatusOK, response)
}

func EditUserOnly(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userid"])
	if err != nil {
		helper.ResponseError(w, http.StatusBadRequest, err.Error())
		return
	}
	var user model.User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&user); err != nil {
		helper.ResponseError(w, http.StatusBadRequest, "Gagal")
		return
	}
	defer r.Body.Close()
	model.DB.Model(&model.User{}).Where("id = ?", int32(userID)).Updates(map[string]interface{}{
		"nama":        user.Nama,
		"username":    user.Username,
		"role_id":     user.RoleID,
		"instance_id": user.InstanceID,
	})
	response := map[string]string{"message": "Sukses"}
	helper.ResponseJSON(w, http.StatusOK, response)
}

func ChangePassword(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userid"])
	if err != nil {
		helper.ResponseError(w, http.StatusBadRequest, err.Error())
		return
	}
	userInput := map[string]string{"password": ""}
	if err := json.NewDecoder(r.Body).Decode(&userInput); err != nil {
		helper.ResponseError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()
	hashPassword, _ := bcrypt.GenerateFromPassword([]byte(userInput["password"]), bcrypt.DefaultCost)
	hashToken := helper.GenerateRandomString(15)
	if model.DB.Model(&model.User{}).Where("id = ?", int32(userID)).Updates(map[string]interface{}{
		"password":   string(hashPassword),
		"hash_token": hashToken,
	}).RowsAffected == 0 {
		helper.ResponseError(w, http.StatusInternalServerError, "Gagal")
		return
	}
	response := map[string]string{"message": "Sukses"}
	helper.ResponseJSON(w, http.StatusOK, response)
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	input := map[string]int32{"id": 0}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		helper.ResponseError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()
	var user model.User
	if model.DB.Where("id = ?", input["id"]).Delete(&user).RowsAffected == 0 {
		helper.ResponseError(w, http.StatusBadRequest, "Gagal")
		return
	}
	response := map[string]string{"message": "Sukses"}
	helper.ResponseJSON(w, http.StatusOK, response)
}

func Login(w http.ResponseWriter, r *http.Request) {
	userInput := map[string]string{
		"username":  "",
		"password":  "",
		"fcm_token": "",
		"ip":        "",
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		helper.ResponseError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()

	var blockade model.Blockade
	ada := model.DB.Where("blockades.ip = ?", userInput["ip"]).First(&blockade)
	// get username exist
	var user model.User
	if err := model.DB.Where("users.username = ?", userInput["username"]).
		Joins("Instance").
		Joins("Role").
		First(&user).Error; err != nil {
		if ada.RowsAffected == 0 {
			model.DB.Create(&model.Blockade{Ip: userInput["ip"], Count: 1})
		} else {
			if blockade.Count > 3 {
				helper.ResponseError(w, http.StatusForbidden, "Silahkan jawab CAPTCHA")
				return
			}
			model.DB.Model(&model.Blockade{}).Where("blockades.ip = ?", userInput["ip"]).Update("count", blockade.Count+1)
		}
		helper.ResponseError(w, http.StatusUnauthorized, "Username atau password salah")
		return
	}
	// verify user pass
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userInput["password"])); err != nil {
		if ada.RowsAffected == 0 {
			model.DB.Create(&model.Blockade{Ip: userInput["ip"], Count: 1})
		} else {
			if blockade.Count > 3 {
				helper.ResponseError(w, http.StatusForbidden, "Silahkan jawab CAPTCHA")
				return
			}
			model.DB.Model(&model.Blockade{}).Where("blockades.ip = ?", userInput["ip"]).Update("count", blockade.Count+1)
		}
		response := map[string]string{"message": "Username atau password salah"}
		helper.ResponseJSON(w, http.StatusUnauthorized, response)
		return
	}

	if userInput["fcm_token"] != "" {
		model.DB.Model(&model.User{}).
			Where("username = ?", userInput["username"]).
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
		helper.ResponseError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()
	var blockade model.Blockade
	ada := model.DB.Where("blockades.ip = ? AND blockades.count > 3", userInput["ip"]).First(&blockade)
	if ada.RowsAffected == 0 {
		helper.ResponseJSON(w, http.StatusOK, "Silahkan login terlebih dahulu")
		return
	} else {
		helper.ResponseError(w, http.StatusAlreadyReported, "Silahkan jawab CAPTCHA")
		return
	}
}

func RefreshJWT(w http.ResponseWriter, r *http.Request) {
	userLoggedIn, err := ParseRefreshToken(r)
	if err != "" {
		helper.ResponseError(w, http.StatusUnauthorized, err)
		return
	}
	var user model.User
	userID, _ := strconv.Atoi(userLoggedIn.Subject)
	if err := model.DB.First(&user, int32(userID)); err != nil {
		helper.ResponseError(w, http.StatusNotFound, "Sesi anda telah berakhir. Silahkan login kembali.")
		return
	}
	actualCustomKey := generateCustomKey(user)
	if userLoggedIn.CustomKey != actualCustomKey {
		helper.ResponseError(w, http.StatusUnauthorized, "Sesi anda telah berakhir. Silahkan login kembali.")
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
