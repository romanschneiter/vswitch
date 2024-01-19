instructions = nprj0.pdf nprj1.pdf nprj2.pdf nprj3.pdf faq.pdf kickoff-slides.pdf nprjw.pdf
programs = parser  vswitch #switch arp router hub
tests = test-vswitch #test-switch test-arp test-router test-hub 

all: network-driver $(programs) $(tests)
docs: $(instructions)


CFLAGS = -O0 -g -Wall


network-driver: network-driver.c glab.h
	gcc -g -O0 -Wall -o network-driver network-driver.c

# Try to build instructions, but do not fail hard if this fails:
# The CI doesn't have pdflatex...
$(instructions): %.pdf: %.tex bonus.tex code.tex grading.tex setup.tex testing.tex

	pdflatex $<  || true
	pdflatex $<  || true
	pdflatex $<  || true
# $(instructions): %.pdf: %.tex bonus.tex code.tex grading.tex setup.tex testing.tex
#    pdflatex -interaction=batchmode $<
#    pdflatex -interaction=batchmode $<


clean:
	rm -f network-driver sample-parser $(instructions) *.log *.aux *.out $(programs)

$(programs): %: %.c glab.h loop.c print.c crc.c
	gcc $(CFLAGS) $^ -o $@

#test-hub: test-hub.c harness.c harness.h
#	gcc $(CFLAGS) $^ -o $@
#test-switch: test-switch.c harness.c harness.h
#	gcc $(CFLAGS) $^ -o $@

test-vswitch: test-vswitch.c harness.c harness.h
	gcc $(CFLAGS) $^ -o $@

#test-arp: test-arp.c harness.c harness.h
#	gcc $(CFLAGS) $^ -o $@
#test-router: test-router.c harness.c harness.h
#	gcc $(CFLAGS) $^ -o $@

check: check-vswitch # check-arp check-router check-hub check-switch 

#check-hub: test-hub
#	./test-hub ./hub
#check-switch: test-switch
#	./test-switch ./switch
check-vswitch: test-vswitch
	./test-vswitch ./vswitch
#check-arp: test-arp
#	./test-arp ./arp
#check-router: test-router
#	./test-router ./router
arch.pdf: arch.svg
	rsvg-convert -f pdf -o arch.pdf arch.svg


# tests vswitch
check-vswitch-ref: test-vswitch
	./test-vswitch ./reference-vswitch
check-vswitch-bug1: test-vswitch
	./test-vswitch ./bug1-vswitch
check-vswitch-bug2: test-vswitch
	./test-vswitch ./bug2-vswitch
check-vswitch-bug3: test-vswitch
	./test-vswitch ./bug3-vswitch


.PHONY: clean check check-hub check-switch check-vswitch check-arp check-router check-vswitch-ref check-vswitch-bug1 check-vswitch-bug2 check-vswitch-bug3 

