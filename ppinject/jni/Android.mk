# A simple test for the minimal standard C++ library
#

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_ARM_MODE := arm
LOCAL_MODULE := ppinject
LOCAL_SRC_FILES := main.c	\
				   ptrace_func.c \
				   inject.c \
				   shellcode.s
include $(BUILD_EXECUTABLE)
