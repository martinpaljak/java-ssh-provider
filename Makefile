# NOTE: this makefile is not intended for general use
TZ = UTC
export TZ

JAVA_HOME = /Library/Java/JavaVirtualMachines/zulu-21.jdk/Contents/Home
export JAVA_HOME

SOURCES = $(shell find . -name '*.java' -o -name 'pom.xml')

default: today test

today:
	# for a dirty tree, set the date to today
	test -z "$(shell git status --porcelain)" || ./mvnw versions:set -DnewVersion=$(shell date +%y.%m.%d)-SNAPSHOT -DgenerateBackupPoms=false

test: $(SOURCES)
	./mvnw clean verify

fast: $(SOURCES)
	./mvnw package -Dmaven.test.skip=true

soft:
	ssh-agent sh -c 'chmod 600 core/src/test/resources/k/*; ssh-add core/src/test/resources/k/*; ssh-add -l; YAUSA_TEST=true make test'

maven:
	./mvnw clean install
