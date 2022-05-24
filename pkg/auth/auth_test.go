package auth

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthLib_Login(t *testing.T) {

	testLogger.SetLevel(log.TraceLevel)
	testLogger.SetOutput(os.Stdout)

	password, err := bcrypt.GenerateFromPassword([]byte("f1f1in!s@"), bcrypt.DefaultCost)
	assert.NoError(t, err)

	dataStoreMoq := DataStoreMock{
		getAccountFunc: func(username string) *Account {

			t.Logf("get called with username %s", username)

			switch username {

			case "folley":
				t.Logf("returning folley")
				return &Account{
					Username:            "folley",
					password:            password,
					lastLogin:           "1653364364",
					accountActive:       true,
					failedLoginAttempts: 0,
					firstFailTimestamp:  0,
				}

			case "barney":
				t.Logf("returning barney")
				return &Account{
					Username:            "barney",
					password:            password,
					lastLogin:           "1653364364",
					accountActive:       false,
					failedLoginAttempts: 0,
					firstFailTimestamp:  time.Now().Unix(),
				}

			default:
				return nil
			}
		},
		updateAccountFunc: func(account *Account) (*Account, error) {
			switch account.Username {

			case "folley":
				assert.Equal(t, 1, account.failedLoginAttempts)
				assert.True(t, account.accountActive)
				assert.NotEqual(t, int64(0), account.firstFailTimestamp)
				return account, nil

			case "barney":
				assert.False(t, account.accountActive)
				return account, nil

			default:
				t.Errorf("unexpected call to update account with username %s", account.Username)
				return nil, fmt.Errorf("unexpected call to update account with username %s", account.Username)
			}
		},
	}

	type fields struct {
		logger                     *log.Logger
		dataStore                  DataStore
		lockoutInterval            time.Duration
		loginAttemptsBeforeLockout int
		jwtSecret                  []byte
	}
	type args struct {
		username string
		password string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantToken bool
		wantErr   bool
	}{
		{
			name: "success, valid token",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            5,
				loginAttemptsBeforeLockout: 2,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				username: "folley",
				password: "f1f1in!s@",
			},
			wantToken: true,
			wantErr:   false,
		},
		{
			name: "wrong password",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            5,
				loginAttemptsBeforeLockout: 2,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				username: "folley",
				password: "f1f1in!s@",
			},
			wantToken: true,
			wantErr:   false,
		},
		{
			name: "locked account",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            5,
				loginAttemptsBeforeLockout: 2,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				username: "barney",
				password: "f1f1in!s@",
			},
			wantToken: false,
			wantErr:   true,
		},
		{
			name: "user does not exist",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            5,
				loginAttemptsBeforeLockout: 2,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				username: "marshall",
				password: "f1f1in!s@",
			},
			wantToken: false,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthLib{
				logger:                     tt.fields.logger,
				dataStore:                  tt.fields.dataStore,
				lockoutInterval:            tt.fields.lockoutInterval,
				loginAttemptsBeforeLockout: tt.fields.loginAttemptsBeforeLockout,
				jwtSecret:                  tt.fields.jwtSecret,
			}
			gotToken, err := a.Login(tt.args.username, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthLib.Login() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantToken {
				// check if token is valid
				jwtToken, err := jwt.ParseWithClaims(gotToken, &claims{}, func(t *jwt.Token) (interface{}, error) {
					return tt.fields.jwtSecret, nil
				})

				assert.NoError(t, err)
				if claims, ok := jwtToken.Claims.(*claims); ok && jwtToken.Valid {

					username := claims.Username
					exp := claims.NotBefore

					expiry := time.Unix(exp, 0)

					assert.NotEmpty(t, username)
					assert.NotEmpty(t, expiry)

					assert.Equal(t, tt.args.username, username)

				} else {
					t.Errorf("unable to parse claims on jwt")
				}
			}
		})
	}
}

func TestAuthLib_Register(t *testing.T) {

	// This uses, getAccount, createAccount

	dataStoreMoq := DataStoreMock{
		getAccountFunc: func(username string) *Account {
			switch username {

			case "folley":
				t.Logf("returning folley")
				return &Account{
					Username:            "folley",
					password:            []byte("df"),
					lastLogin:           "1653364364",
					accountActive:       true,
					failedLoginAttempts: 0,
					firstFailTimestamp:  0,
				}

			default:
				return nil
			}
		},
		createAccountFunc: func(account *Account) error {
			assert.Equal(t, "ted", account.Username)
			assert.Equal(t, "", account.lastLogin)
			assert.Equal(t, 0, account.failedLoginAttempts)
			assert.True(t, account.accountActive)
			assert.Equal(t, int64(0), account.firstFailTimestamp)

			err := bcrypt.CompareHashAndPassword(account.password, []byte("password"))
			assert.NoError(t, err)

			return nil
		},
	}

	type fields struct {
		logger                     *log.Logger
		dataStore                  DataStore
		lockoutInterval            time.Duration
		loginAttemptsBeforeLockout int
		jwtSecret                  []byte
	}
	type args struct {
		accountDetails Account
		password       string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Account
		wantErr bool
	}{
		{
			name: "valid account",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            3,
				loginAttemptsBeforeLockout: 3,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				accountDetails: Account{
					Username: "ted",
				},
				password: "password",
			},
			want: &Account{
				Username:            "ted",
				password:            []byte{},
				lastLogin:           "",
				accountActive:       true,
				failedLoginAttempts: 0,
				firstFailTimestamp:  0,
			},
			wantErr: false,
		},
		{
			name: "invalid username",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            3,
				loginAttemptsBeforeLockout: 3,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				accountDetails: Account{
					Username: "",
				},
				password: "password",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid password",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            3,
				loginAttemptsBeforeLockout: 3,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				accountDetails: Account{
					Username: "ted",
				},
				password: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "user already exists",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            3,
				loginAttemptsBeforeLockout: 3,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				accountDetails: Account{
					Username: "folley",
				},
				password: "password",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthLib{
				logger:                     tt.fields.logger,
				dataStore:                  tt.fields.dataStore,
				lockoutInterval:            tt.fields.lockoutInterval,
				loginAttemptsBeforeLockout: tt.fields.loginAttemptsBeforeLockout,
				jwtSecret:                  tt.fields.jwtSecret,
			}
			got, err := a.Register(tt.args.accountDetails, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthLib.Register() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.want != nil {
				assert.Equal(t, tt.want.Username, got.Username)
				assert.Equal(t, tt.want.lastLogin, got.lastLogin)
				assert.Equal(t, tt.want.accountActive, got.accountActive)
				assert.Equal(t, tt.want.failedLoginAttempts, got.failedLoginAttempts)
				assert.Equal(t, tt.want.firstFailTimestamp, got.firstFailTimestamp)
			}
			if tt.want == nil && got != nil {
				t.Errorf("wanted error and no account, got not nil")
			}
		})
	}
}

func TestAuthLib_Authenticate(t *testing.T) {

	testLogger.SetLevel(log.TraceLevel)
	testLogger.SetOutput(os.Stdout)

	dataStoreMoq := DataStoreMock{
		getAccountFunc: func(username string) *Account {
			switch username {
			case "folley":
				return &Account{
					Username:            "folley",
					password:            []byte("spi"),
					lastLogin:           "1653364364",
					accountActive:       true,
					failedLoginAttempts: 0,
					firstFailTimestamp:  0,
				}

			default:
				return nil
			}
		},
	}

	// valid JWT
	expiration := time.Now().Add(time.Duration(10) * time.Minute)
	cl := claims{
		"folley",
		jwt.StandardClaims{
			NotBefore: time.Now().Unix(),
			ExpiresAt: expiration.Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	tk := jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
	validJWT, err := tk.SignedString([]byte("hi"))
	assert.NoError(t, err)

	//signed with another string
	expiration = time.Now().Add(time.Duration(10) * time.Minute)
	cl = claims{
		"folley",
		jwt.StandardClaims{
			NotBefore: time.Now().Unix(),
			ExpiresAt: expiration.Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	tk = jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
	wrongKeyJWT, err := tk.SignedString([]byte("hello"))
	assert.NoError(t, err)

	//expired JWT
	expiration = time.Now().Add(time.Duration(-10) * time.Minute)
	cl = claims{
		"folley",
		jwt.StandardClaims{
			NotBefore: time.Now().Unix(),
			ExpiresAt: expiration.Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	tk = jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
	expiredJWT, err := tk.SignedString([]byte("hi"))
	assert.NoError(t, err)

	type fields struct {
		logger                     *log.Logger
		dataStore                  DataStore
		lockoutInterval            time.Duration
		loginAttemptsBeforeLockout int
		jwtSecret                  []byte
	}
	type args struct {
		token string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "valid JWT",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            1,
				loginAttemptsBeforeLockout: 2,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				token: validJWT,
			},
			want: true,
		},
		{
			name: "invalid JWT",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            1,
				loginAttemptsBeforeLockout: 2,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				token: wrongKeyJWT,
			},
			want: false,
		},
		{
			name: "expired JWT",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            1,
				loginAttemptsBeforeLockout: 2,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				token: expiredJWT,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthLib{
				logger:                     tt.fields.logger,
				dataStore:                  tt.fields.dataStore,
				lockoutInterval:            tt.fields.lockoutInterval,
				loginAttemptsBeforeLockout: tt.fields.loginAttemptsBeforeLockout,
				jwtSecret:                  tt.fields.jwtSecret,
			}
			if got := a.Authenticate(tt.args.token); got != tt.want {
				t.Errorf("AuthLib.Authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}
