TARGET = route

CFLAGS += -DRTM_GET_SILENT=0x11 -DRTM_GET_EXT=0x15

$(TARGET): route.c network_cmds_lib.c
	$(CC) $(CFLAGS) $^ -o $@


clean:
	$(RM) $@ $(TARGET)
