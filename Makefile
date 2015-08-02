SHELL := /bin/bash

NAME=gosgp
VERSION=0.1

# Dependencies: golang

.PHONY: all clean clean_all prepare package_deb package_rpm
.SILENT: desc

all: desc

desc:
	echo "usage: please use either 'make package_deb' or 'make package_rpm'"

clean:
	rm -f $(NAME)*.deb
	rm -f $(NAME)*.rpm
	rm -rf ./build

clean_all: clean
	rm -rf /tmp/gosgp

prepare: clean
	mkdir -p ./build/usr/bin/
	GOPATH=/tmp/gosgp go get -d
	GOPATH=/tmp/gosgp go build -o gosgp
	mv gosgp ./build/usr/bin/.

package_deb: prepare
	fpm -s dir \
	    -t deb \
            -n $(NAME) \
            -m "Jochen Breuer <brejoc@gmail.com>" \
            --url "https://github.com/brejoc/gosgp" \
            --license "GPLv2" \
            --description "Command line SuperGenPass password generator written in go." \
            -v $(VERSION) \
            --deb-user root \
            --deb-group root \
            -C ./build \
            usr
	#############################################################
	### Don't forget to 'make clean_all' to delete GOPATH dir ###
	#############################################################

package_rpm: prepare
	fpm -s dir \
            -t rpm \
            -n $(NAME) \
            -m "Jochen Breuer <brejoc@gmail.com>" \
            --url "https://github.com/brejoc/gosgp" \
            --license "GPLv2" \
            --description "Command line SuperGenPass password generator written in go." \
            -v $(VERSION) \
            --rpm-user root \
            --rpm-group root \
            -C ./build \
            usr
	#############################################################
	### Don't forget to 'make clean_all' to delete GOPATH dir ###
	#############################################################
