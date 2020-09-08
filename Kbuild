ccflags-y := -I$(src)/include

obj-m := tifilter.o nfglue.o timatrix.o

tifilter-y = tifilter/core.o \
	     tifilter/tifilter_hook.o \
	     tifilter/tifilter_notifier.o

nfglue-y   = nfglue/core.o

timatrix-y = timatrix/tm_flood.o
