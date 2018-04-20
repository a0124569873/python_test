# Copyright 6WIND, 2012, All rights reserved.

include $(S)/fpn-sdk.mk

FILES= $(wildcard $(S)/fpn*.h)

include mk/files.mk

SUBDIR-$(CONFIG_MCORE_FPN_CRYPTO) = crypto
SUBDIR-y += igbuio_modalias
SUBDIR-y += mk

SUBDIR:= $(SUBDIR-y)

include mk/subdir.mk
