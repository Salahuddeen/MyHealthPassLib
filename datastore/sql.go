package datastore

import (
	"database/sql"

	"github.com/Salahuddeen/MyHealthPassLib/pkg/auth"
	"github.com/sirupsen/logrus"
)

type SQLiteAdapter struct {
	db     *sql.DB
	logger *logrus.Entry
}

func (adapter *SQLiteAdapter) Initialize() (err error) {
	var db *sql.DB

	db, err = sql.Open("string", "string")

	if err != nil {
		adapter.logger.Error("unable to initialize gorm db")
		return err
	}

	adapter.db = db
	return
}

func (adapter *SQLiteAdapter) getAccount(username string) auth.Account {
	panic("not implemented") // TODO: Implement
}

func (adapter *SQLiteAdapter) createAccount(account *auth.Account) (err error) {
	panic("not implemented") // TODO: Implement
}

func (adapter *SQLiteAdapter) updateAccount(*auth.Account) (updatedAccount *auth.Account, err error) {
	panic("not implemented") // TODO: Implement
}
