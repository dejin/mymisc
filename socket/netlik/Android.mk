LOCAL_PATH:= $(call my-dir)


include $(CLEAR_VARS)
LOCAL_SRC_FILES :=  test_msg_server.c msg.c

LOCAL_C_INCLUDES := \
		$(VENDOR_SDK_INCLUDES)

LOCAL_SHARED_LIBRARIES := \
			liblog \
			libcutils \
			libutils

LOCAL_MODULE := qn_server
LOCAL_MODULE_TAGS := optional tests
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := test_msg_client.c msg.c

LOCAL_C_INCLUDES := \
		$(VENDOR_SDK_INCLUDES)

LOCAL_SHARED_LIBRARIES := \
			liblog \
			libcutils \
			libutils

LOCAL_MODULE := qn_client
LOCAL_MODULE_TAGS := optional tests
include $(BUILD_EXECUTABLE)