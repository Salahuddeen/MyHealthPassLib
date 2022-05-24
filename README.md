# MyHealthPassLib


This Library requires you to bring your own datastore.


The following is the interface required for this library to function.

```go
type DataStore interface {
	getAccount(username string) *Account
	createAccount(account *Account) (err error)
	updateAccount(*Account) (updatedAccount *Account, err error)
}
```
an example for the Datastore implementation can be found in datastore/sql.go

An example for the library implementation can be found in example/example.go
___ 

### Testing: 

This project uses go modules.

run the following commands in the root of the repo to run all tests.

```
go mod tidy
go test ./...
```