TARGET = build/bin/sudo
ORIGINAL_REPO = target/sudo-1.9.15p5
# We don't want to use sudo in certain contexts (e.g., in a Docker container), so we guard it
# behind this. It will simply do nothing if sudo is not present.
SUDO := $(shell which sudo)

SAFE_DIR = target/safe
BACKDOORED_DIR = target/backdoored
GROUND_TRUTH_DIR = target/ground-truth

SAFE_TARGET = $(SAFE_DIR)/$(TARGET)
BACKDOORED_TARGET = $(BACKDOORED_DIR)/$(TARGET)
GROUND_TRUTH_TARGET = $(GROUND_TRUTH_DIR)/$(TARGET)


all: safe backdoored ground-truth


safe: $(SAFE_TARGET)

backdoored: $(BACKDOORED_TARGET)

ground-truth: $(GROUND_TRUTH_TARGET)


$(SAFE_TARGET): $(ORIGINAL_REPO)
	$(SUDO) rm -rf $(SAFE_DIR)/
	cp -r $(ORIGINAL_REPO)/ $(SAFE_DIR)/
	cd $(SAFE_DIR) && \
		patch -p1 < ../../patches/base.patch && \
		./configure --prefix=$(realpath .)/$(SAFE_DIR)/build --without-pam && \
		$(SUDO) $(MAKE) -j$(shell nproc) && \
		$(SUDO) $(MAKE) install


$(BACKDOORED_TARGET): $(ORIGINAL_REPO) patches/backdoored.patch
	$(SUDO) rm -rf $(BACKDOORED_DIR)/
	cp -r $(ORIGINAL_REPO)/ $(BACKDOORED_DIR)/
	cd $(BACKDOORED_DIR) && \
		patch -p1 < ../../patches/base.patch && \
		patch -p1 < ../../patches/backdoored.patch && \
		./configure --prefix=$(realpath .)/$(BACKDOORED_DIR)/build --without-pam && \
		$(SUDO) $(MAKE) -j$(shell nproc) && \
		$(SUDO) $(MAKE) install


$(GROUND_TRUTH_TARGET): $(ORIGINAL_REPO) patches/ground-truth.patch
	$(SUDO) rm -rf $(GROUND_TRUTH_DIR)/
	cp -r $(ORIGINAL_REPO)/ $(GROUND_TRUTH_DIR)/
	cd $(GROUND_TRUTH_DIR) && \
		patch -p1 < ../../patches/base.patch && \
		patch -p1 < ../../patches/ground-truth.patch && \
		./configure --prefix=$(realpath .)/$(GROUND_TRUTH_DIR)/build --without-pam && \
		$(SUDO) $(MAKE) -j$(shell nproc) && \
		$(SUDO) $(MAKE) install


clean:
	$(SUDO) rm -rf $(SAFE_DIR)/ $(BACKDOORED_DIR)/ $(GROUND_TRUTH_DIR)/


.PHONY: clean all safe backdoored ground-truth
