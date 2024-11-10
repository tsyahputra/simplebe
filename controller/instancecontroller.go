package controller

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/tsyahputra/simplebe/helper"
	"github.com/tsyahputra/simplebe/model"
)

func GetInstances(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	search := "%" + q.Get("search") + "%"

	var instances []model.Instance
	var totalRecords int64
	if q.Get("search") == "" {
		result := model.DB.Find(&instances)
		totalRecords = result.RowsAffected
		if err := result.Limit(10).Offset(offset).
			Find(&instances).Error; err != nil {
			helper.ResponseError(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else {
		result := model.DB.Where("instances.nama LIKE ?", search).
			Or("instances.alamat LIKE ?", search).
			Or("instances.kabupaten LIKE ?", search).
			Or("instances.email LIKE ?", search).
			Find(&instances)
		totalRecords = result.RowsAffected
		if err := result.Limit(10).Offset(offset).Find(&instances).Error; err != nil {
			helper.ResponseError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	response := &model.AllInstancesWithTotal{
		Instances: instances,
		Total:     totalRecords,
	}
	helper.ResponseJSON(w, http.StatusOK, response)
}

func ViewInstance(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	instanceID, err := strconv.Atoi(vars["instanceid"])
	if err != nil {
		helper.ResponseError(w, http.StatusBadRequest, err.Error())
		return
	}
	var instance model.Instance
	if err := model.DB.Where("instances.id = ?", int32(instanceID)).
		First(&instance).Error; err != nil {
		helper.ResponseError(w, http.StatusNotFound, err.Error())
		return
	}
	helper.ResponseJSON(w, http.StatusOK, instance)
}

func AddInstance(w http.ResponseWriter, r *http.Request) {
	var instance model.Instance
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&instance); err != nil {
		helper.ResponseError(w, http.StatusBadRequest, "Gagal")
		return
	}
	defer r.Body.Close()
	if err := model.DB.Create(&instance).Error; err != nil {
		helper.ResponseError(w, http.StatusInternalServerError, err.Error())
		return
	}
	response := map[string]string{"message": "Sukses"}
	helper.ResponseJSON(w, http.StatusOK, response)
}

func EditInstance(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	instanceID, err := strconv.Atoi(vars["instanceid"])
	if err != nil {
		helper.ResponseError(w, http.StatusBadRequest, err.Error())
		return
	}
	var instance model.Instance
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&instance); err != nil {
		helper.ResponseError(w, http.StatusBadRequest, "Gagal")
		return
	}
	defer r.Body.Close()
	model.DB.Model(model.Instance{}).Where("id = ?", int32(instanceID)).Updates(map[string]interface{}{
		"nama":      instance.Nama,
		"alamat":    instance.Alamat,
		"kabupaten": instance.Kabupaten,
		"telp":      instance.Telp,
		"email":     instance.Email,
	})
	response := map[string]string{"message": "Sukses"}
	helper.ResponseJSON(w, http.StatusOK, response)
}

func DeleteInstance(w http.ResponseWriter, r *http.Request) {
	input := map[string]int32{"id": 0}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		helper.ResponseError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()
	var instance model.Instance
	if model.DB.Model(model.Instance{}).Where("id = ?", input["id"]).Delete(&instance).RowsAffected == 0 {
		helper.ResponseError(w, http.StatusInternalServerError, "Gagal hapus data")
		return
	}
	response := map[string]string{"message": "Sukses"}
	helper.ResponseJSON(w, http.StatusOK, response)
}
