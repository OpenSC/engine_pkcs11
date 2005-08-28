# - set the OPENSSL_INCL_DIR below to your openssl include directory, preceded by "/I"
# - set the OPENSSL_LIB below to your openssl lib file
# Note: these instructions obsolete the instructions in opensc.html

OPENSSL_INCL_DIR = /IC:\openssl\include
OPENSSL_LIB = C:\openssl\out32dll\libeay32.lib

COPTS = /Zi /MD /nologo /DHAVE_CONFIG_H $(OPENSSL_INCL_DIR) /D_WIN32_WINNT=0x0400 /DHAVE_OPENSSL
LINKFLAGS = /DEBUG /NOLOGO /INCREMENTAL:NO /MACHINE:IX86


TARGET                  = engine_pkcs11.dll

OBJECTS			= engine_pkcs11.obj hw_pkcs11.obj

all: $(TARGET)

.c.obj::
	cl $(COPTS) /c $<

$(TARGET): $(OBJECTS) ..\libp11\libp11.lib ..\scconf\scconf.lib
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) $(OBJECTS) ..\libp11\libp11.lib ..\scconf\scconf.lib winscard.lib $(OPENSSL_LIB) gdi32.lib
