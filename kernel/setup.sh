#!/bin/sh
set -eux

GKI_ROOT=$(pwd)

echo "[+] GKI_ROOT: $GKI_ROOT"

if test -d "$GKI_ROOT/common/drivers"; then
	DRIVER_DIR="$GKI_ROOT/common/drivers"
elif test -d "$GKI_ROOT/drivers"; then
	DRIVER_DIR="$GKI_ROOT/drivers"
else
	echo '[ERROR] "drivers/" directory is not found.'
	echo '[+] You should modify this script by yourself.'
	exit 127
fi

test -d "$GKI_ROOT/qudong" || git clone https://github.com/pfgq/qudong
cd "$GKI_ROOT/qudong"
git stash
git checkout main  # 强制切换到main分支
git pull
cd "$GKI_ROOT"

echo "[+] GKI_ROOT: $GKI_ROOT"
echo "[+] Copy qudong driver to $DRIVER_DIR"

cd "$DRIVER_DIR"
if test -d "$GKI_ROOT/common/drivers"; then
	if test -d "$GKI_ROOT/common/drivers/khack"; then
		echo "[+] Exiting folder exists"
	else
		ln -sf "../qudong/kernel" "khack"
	fi
elif test -d "$GKI_ROOT/drivers"; then
	if test -d "$GKI_ROOT/drivers/khack"; then
		echo "[+] Exiting folder exists"
	else
		ln -sf "../qudong/kernel" "khack"
	fi
fi
cd "$GKI_ROOT"

echo '[+] Add driver to Makefile'

DRIVER_MAKEFILE=$DRIVER_DIR/Makefile
DRIVER_KCONFIG=$DRIVER_DIR/Kconfig
grep -q "khack" "$DRIVER_MAKEFILE" || printf "obj-\$(CONFIG_KERNEL_HACK) += khack/\n" >> "$DRIVER_MAKEFILE"
grep -q "khack" "$DRIVER_KCONFIG" || sed -i "/endmenu/i\\source \"drivers/khack/Kconfig\"" "$DRIVER_KCONFIG"

echo '[+] Done.'