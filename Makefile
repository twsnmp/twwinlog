.PHONY: all test clean zip mac docker

### バージョンの定義
VERSION     := "v1.1.0"
COMMIT      := $(shell git rev-parse --short HEAD)
WD          := $(shell pwd)
### コマンドの定義
GO          = go
GO_BUILD    = $(GO) build
GO_TEST     = $(GO) test -v
GO_LDFLAGS  = -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)"
ZIP          = zip

### ターゲットパラメータ
DIST = dist
SRC = ./main.go ./winlog.go ./syslog.go ./logon.go ./monitor.go ./process.go ./task.go ./kerberos.go ./privilege.go ./account.go
TARGETS     = $(DIST)/twwinlog.exe
ROOT  = ./...

### PHONY ターゲットのビルドルール
all: $(TARGETS)
test:
	env GOOS=$(GOOS) $(GO_TEST) $(GO_PKGROOT)
clean:
	rm -rf $(TARGETS) $(DIST)/*.zip
zip: $(TARGETS)
	cd dist && $(ZIP) twwinlog_win.zip twwinlog.exe


### 実行ファイルのビルドルール
$(DIST)/twwinlog.exe: $(SRC)
	env GO111MODULE=on GOOS=windows GOARCH=amd64 $(GO_BUILD) $(GO_LDFLAGS) -o $@
