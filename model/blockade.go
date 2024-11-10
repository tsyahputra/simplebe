package model

type Blockade struct {
	ID    int32  `json:"id" gorm:"primaryKey;autoIncrement"`
	Ip    string `json:"ip" gorm:"type:varchar(20);not null"`
	Count int32  `json:"count" gorm:"not null;default 1"`
}
