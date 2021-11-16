# Makefile for src/mod/rust.mod/

MOD_EXT = so


# static: ../rust.o

modules: rust.$(MOD_EXT)

# ../rust.o:
# 	rustc --emit=obj rust.rs

rust.$(MOD_EXT):
	rustc --crate-type cdylib -g rust.rs -o rust.$(MOD_EXT)

clean:
	@rm -f *.$(MOD_EXT)

distclean: clean
