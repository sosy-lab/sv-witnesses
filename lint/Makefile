.PHONY: build
build:
	mkdir -p build/witnesslint
	rm -rf build/witnesslint/*
	cp README.md build/witnesslint/
	cp ../LICENSE build/witnesslint/
	cp -r ../LICENSES build/witnesslint/LICENSES
	cp witnesslinter.py build/witnesslint/
	cp -r witnesslint build/witnesslint/witnesslint
	zip -r val_witnesslint.zip witnesslint
