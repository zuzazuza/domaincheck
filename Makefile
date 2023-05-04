NAME=domaincheck
VERSION=$(shell sed -n -e 's/^VERSION = "\(.*\)"/\1/p' src/${NAME}.py)
PREFIX?=/usr/local
PIP?=pip3

help:
	@echo "The following targets are available:"
	@echo "doc          format man page into .txt"
	@echo "install      install ${NAME} into ${PREFIX}"
	@echo "pip-install  install ${NAME} using ${PIP}"
	@echo "readme       generate the README after a manual page update"
	@echo "uninstall    uninstall ${NAME} from ${PREFIX}"

doc: doc/${NAME}.1.txt

doc/${NAME}.1.txt: doc/${NAME}.1
	mandoc -c -O width=80 $? | col -b >$@

readme: doc
	sed -n -e '/^NAME/!p;//q' README.md >.readme
	sed -n -e '/^NAME/,$$p' -e '/authors/q' doc/${NAME}.1.txt >>.readme
	echo '```' >>.readme
	mv .readme README.md

pip-install:
	cp src/${NAME}.py src/${NAME}
	${PIP} install .
	rm -fr build src/${NAME} src/${NAME}.egg-info

install:
	mkdir -p ${PREFIX}/bin ${PREFIX}/share/man/man1
	install -c -m 0555 src/${NAME}.py ${PREFIX}/bin/${NAME}
	install -c -m 0555 doc/${NAME}.1 ${PREFIX}/share/man/man1/${NAME}.1

uninstall:
	rm -f ${PREFIX}/bin/${NAME} ${PREFIX}/share/man/man1/${NAME}.1
