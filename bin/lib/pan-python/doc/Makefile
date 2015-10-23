RST2HTML = rst2html
OPTIONS =
SOURCE = panrc.html panxapi.html pan.xapi.html panconf.html panwfapi.html pan.wfapi.html

.SUFFIXES: .rst .html
.rst.html:
	$(RST2HTML) $(OPTIONS) $< $@

all: $(SOURCE)

clean:
	rm -f $(SOURCE)
