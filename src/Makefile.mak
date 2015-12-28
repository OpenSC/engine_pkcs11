TOPDIR = ..

!INCLUDE $(TOPDIR)\Make.rules.mak
# see make.rules.mak to edit openssl or libp11 path

TARGET                  = engine_pkcs11.dll

OBJECTS			= engine_pkcs11.obj hw_pkcs11.obj

all: $(TARGET)

.c.obj::
	cl $(COPTS) /c $<

$(TARGET): $(OBJECTS) .
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type $*.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) $(OBJECTS) $(OPENSSL_LIB) $(LIBP11_LIB)
	if EXIST $*.dll.manifest mt -manifest $*.dll.manifest -outputresource:$*.dll;2
