# - set the OPENSSL_INCL_DIR below to your openssl include directory, preceded by "/I"
# - set the OPENSSL_LIB below to your openssl lib file
# Note: these instructions obsolete the instructions in opensc.html

OPENSSL_INC = /IC:\openssl\include
OPENSSL_LIB = C:\openssl\lib\libeay32.lib
LIBP11_INC = /IC:\libp11\include
LIBP11_LIB = C:\libp11\lib\libp11.lib

COPTS = /Zi /MD /nologo /DHAVE_CONFIG_H $(OPENSSL_INC) $(LIBP11_INC) /D_WIN32_WINNT=0x0400 /DHAVE_OPENSSL
LINKFLAGS = /DEBUG /NOLOGO /INCREMENTAL:NO /MACHINE:IX86


TARGET                  = engine_pkcs11.dll

OBJECTS			= engine_pkcs11.obj hw_pkcs11.obj

all: $(TARGET)

.c.obj::
	cl $(COPTS) /c $<

$(TARGET): $(OBJECTS) .
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) $(OBJECTS) $(OPENSSL_LIB) $(LIBP11_LIB) gdi32.lib
