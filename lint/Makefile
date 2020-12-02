.PHONY: build
build:
	mkdir -p build/witnesslint
	rm -rf build/witnesslint/*
	rm -f val_witnesslint.zip
	cp README.md build/witnesslint/
	cp ../LICENSE build/witnesslint/
	cp -r ../LICENSES build/witnesslint/LICENSES
	cp witnesslinter.py build/witnesslint/
	cp -r witnesslint build/witnesslint/witnesslint
	echo "$$(git describe --dirty)"
	sed -i "s|__version__ = \"DEV\"|__version__ = \"$$(git describe --dirty)\"|g" build/witnesslint/witnesslint/linter.py
	cd build && zip -r ../val_witnesslint.zip witnesslint
