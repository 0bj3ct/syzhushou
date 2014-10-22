# A simple test for the minimal standard C++ library
#

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_ARM_MODE := arm
LOCAL_MODULE := ppDexLoader
LOCAL_SRC_FILES := DexLoader.c

# for logging
LOCAL_LDLIBS    += -L$(SYSROOT)/usr/lib -llog
LOCAL_LDFLAGS += $(LOCAL_PATH)/libdvm.so -On

include $(BUILD_SHARED_LIBRARY)
