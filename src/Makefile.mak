TOPDIR = ..

# see ..\make.rules.mak to edit openssl or libp11 path
!INCLUDE $(TOPDIR)\make.rules.mak

TARGET = pkcs11.dll

OBJECTS = engine_pkcs11.obj hw_pkcs11.obj

all: $(TARGET) versioninfo.res

RSC_PROJ=/l 0x809 /r /fo"versioninfo.res"

versioninfo.res: versioninfo.rc
	rc $(RSC_PROJ) versioninfo.rc

.c.obj::
	cl $(CLFLAGS) /c $<

$(TARGET): $(OBJECTS) versioninfo.res
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type $*.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) \
		$(OBJECTS) $(OPENSSL_LIB) $(LIBP11_LIB) versioninfo.res
	if EXIST $*.dll.manifest mt -manifest $*.dll.manifest -outputresource:$*.dll;2
