default: install

tool/target/esteid.jar: $(shell find tool library -name '*.java')
	mvn -Dmaven.javadoc.skip=true -Dmaven.test.skip=true package

dep:
	mvn -Dmaven.javadoc.skip=true -Dmaven.test.skip=true install

install: ~/.apdu4j/plugins/esteid.jar

~/.apdu4j/plugins/esteid.jar: tool/target/esteid.jar
	mkdir -p ~/.apdu4j/plugins
	cp tool/target/esteid.jar ~/.apdu4j/plugins/esteid.jar

clean:
	mvn clean
