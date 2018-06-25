define walk
  $(wildcard $(1)) $(foreach e, $(wildcard $(1)/*), $(call walk, $(e)))
endef

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MULTILIB := both
LOCAL_MODULE := maniacd
LOCAL_SRC_FILES := $(filter %.c, $(call walk, $(LOCAL_PATH)))

include $(BUILD_EXECUTABLE)
