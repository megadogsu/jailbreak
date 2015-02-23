INCLUDES = ../include
SOURCES = $(TARGET).c

LIBRARIES = syringe usb-1.0 curl z setupapi curldll
LDFLAGS = -L../syringe -L/opt/local/lib -L"C:\MinGW\lib"

include ../common.mk