package controller

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/tsyahputra/simplebe/helper"
	"github.com/tsyahputra/simplebe/model"
)

func GetRoles(w http.ResponseWriter, r *http.Request) {
	var roles []model.Role
	if err := model.DB.Find(&roles).Error; err != nil {
		helper.ResponseMessage(w, http.StatusInternalServerError, err.Error())
		return
	}
	helper.ResponseJSON(w, http.StatusOK, roles)
}

func AddRole(w http.ResponseWriter, r *http.Request) {
	var role model.Role
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&role); err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, "Gagal")
		return
	}
	defer r.Body.Close()
	if err := model.DB.Create(&role).Error; err != nil {
		helper.ResponseMessage(w, http.StatusInternalServerError, err.Error())
		return
	}
	helper.ResponseMessage(w, http.StatusOK, "Sukses")
}

func EditRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleID, err := strconv.Atoi(vars["roleid"])
	if err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	var role model.Role
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&role); err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, "Gagal")
		return
	}
	defer r.Body.Close()
	model.DB.Model(model.Role{}).Where("id = ?", int32(roleID)).Updates(map[string]interface{}{
		"nama": role.Nama,
	})
	helper.ResponseMessage(w, http.StatusOK, "Sukses")
}

func DeleteRole(w http.ResponseWriter, r *http.Request) {
	input := map[string]int32{"id": 0}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		helper.ResponseMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()
	var role model.Role
	if model.DB.Where("id = ?", input["id"]).Delete(&role).RowsAffected == 0 {
		helper.ResponseMessage(w, http.StatusInternalServerError, "Gagal hapus data")
		return
	}
	helper.ResponseMessage(w, http.StatusOK, "Sukses")
}
