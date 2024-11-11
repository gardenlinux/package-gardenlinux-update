gardenlinux-update: main.go
	GO111MODULE=on go build -mod=vendor

install:
	install -D -t $(DESTDIR)/sbin/ gardenlinux-update
