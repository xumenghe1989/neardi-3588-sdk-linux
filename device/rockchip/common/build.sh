#!/bin/bash

export LC_ALL=C
export LD_LIBRARY_PATH=
unset RK_CFG_TOOLCHAIN

err_handler() {
	ret=$?
	[ "$ret" -eq 0 ] && return

	echo "ERROR: Running ${FUNCNAME[1]} failed!"
	echo "ERROR: exit code $ret from line ${BASH_LINENO[0]}:"
	echo "    $BASH_COMMAND"
	exit $ret
}
trap 'err_handler' ERR
set -eE

function finish_build(){
	echo "Running ${FUNCNAME[1]} succeeded."
	cd $TOP_DIR
}

function check_config(){
	unset missing
	for var in $@; do
		eval [ \$$var ] && continue

		missing="$missing $var"
	done

	[ -z "$missing" ] && return 0

	echo "Skipping ${FUNCNAME[1]} for missing configs: $missing."
	return 1
}

function choose_target_board()
{
	echo
	echo "You're building on Linux"
	echo "Lunch menu...pick a combo:"
	echo ""

#	echo "0. default BoardConfig.mk"
	echo ${RK_TARGET_BOARD_ARRAY[@]} | xargs -n 1 | sed "=" | sed "N;s/\n/. /"

	local INDEX
	read -p "Which would you like? [0]: " INDEX
	INDEX=$((${INDEX:-0} - 1))

	if echo $INDEX | grep -vq [^0-9]; then
		RK_BUILD_TARGET_BOARD="${RK_TARGET_BOARD_ARRAY[$INDEX]}"
	else
		echo "Lunching for Default BoardConfig.mk boards..."
		RK_BUILD_TARGET_BOARD=BoardConfig.mk
	fi
}

function build_select_board()
{
	RK_TARGET_BOARD_ARRAY=( $(cd ${TARGET_PRODUCT_DIR}/; ls BoardConfig*.mk | sort) )

	RK_TARGET_BOARD_ARRAY_LEN=${#RK_TARGET_BOARD_ARRAY[@]}
	if [ $RK_TARGET_BOARD_ARRAY_LEN -eq 0 ]; then
		echo "No available Board Config"
		return
	fi

	choose_target_board

        #
        # check the select file exist or not.
        #
        if [ -d $TARGET_PRODUCT_DIR/$RK_BUILD_TARGET_BOARD ]; then
            #
            # the user input invalid index, do nothing and exit.
            #
            echo "No Such Board Config, please select a correct one!"
            return;
        fi

	ln -rfs $TARGET_PRODUCT_DIR/$RK_BUILD_TARGET_BOARD device/rockchip/.BoardConfig.mk
	echo "switching to board: `realpath $BOARD_CONFIG`"
}

function unset_board_config_all()
{
	local tmp_file=`mktemp`
	grep -oh "^export.*RK_.*=" `find device -name "Board*.mk"` > $tmp_file
	source $tmp_file
	rm -f $tmp_file
}

CMD=`realpath $0`
COMMON_DIR=`dirname $CMD`
TOP_DIR=$(realpath $COMMON_DIR/../../..)
cd $TOP_DIR

BOARD_CONFIG=$TOP_DIR/device/rockchip/.BoardConfig.mk
TARGET_PRODUCT="$TOP_DIR/device/rockchip/.target_product"
TARGET_PRODUCT_DIR=$(realpath ${TARGET_PRODUCT})

if [ ! -L "$BOARD_CONFIG" -a  "$1" != "lunch" ]; then
	build_select_board
fi
unset_board_config_all
[ -L "$BOARD_CONFIG" ] && source $BOARD_CONFIG

function prebuild_uboot()
{
	UBOOT_COMPILE_COMMANDS="\
			${RK_TRUST_INI_CONFIG:+../rkbin/RKTRUST/$RK_TRUST_INI_CONFIG} \
			${RK_SPL_INI_CONFIG:+../rkbin/RKBOOT/$RK_SPL_INI_CONFIG} \
			${RK_UBOOT_SIZE_CONFIG:+--sz-uboot $RK_UBOOT_SIZE_CONFIG} \
			${RK_TRUST_SIZE_CONFIG:+--sz-trust $RK_TRUST_SIZE_CONFIG}"
	UBOOT_COMPILE_COMMANDS="$(echo $UBOOT_COMPILE_COMMANDS)"

	if [ "$RK_LOADER_UPDATE_SPL" = "true" ]; then
		UBOOT_COMPILE_COMMANDS="--spl-new $UBOOT_COMPILE_COMMANDS"
		UBOOT_COMPILE_COMMANDS="$(echo $UBOOT_COMPILE_COMMANDS)"
	fi

	if [ "$RK_RAMDISK_SECURITY_BOOTUP" = "true" ];then
		UBOOT_COMPILE_COMMANDS=" \
			$UBOOT_COMPILE_COMMANDS \
			${RK_ROLLBACK_INDEX_BOOT:+--rollback-index-boot $RK_ROLLBACK_INDEX_BOOT} \
			${RK_ROLLBACK_INDEX_UBOOT:+--rollback-index-uboot $RK_ROLLBACK_INDEX_UBOOT} "
	fi
}

function prebuild_security_uboot()
{
	local mode=$1

	if [ "$RK_RAMDISK_SECURITY_BOOTUP" = "true" ];then
		if [ "$RK_SECURITY_OTP_DEBUG" != "true" ]; then
			UBOOT_COMPILE_COMMANDS="$UBOOT_COMPILE_COMMANDS --burn-key-hash"
		fi

		case "${mode:-normal}" in
			uboot)
				;;
			boot)
				UBOOT_COMPILE_COMMANDS=" \
					--boot_img $TOP_DIR/u-boot/boot.img \
					$UBOOT_COMPILE_COMMANDS "
				;;
			recovery)
				UBOOT_COMPILE_COMMANDS=" \
					--recovery_img $TOP_DIR/u-boot/recovery.img
					$UBOOT_COMPILE_COMMANDS "
				;;
			*)
				UBOOT_COMPILE_COMMANDS=" \
					--boot_img $TOP_DIR/u-boot/boot.img \
					$UBOOT_COMPILE_COMMANDS "
				test -z "${RK_PACKAGE_FILE_AB}" && \
					UBOOT_COMPILE_COMMANDS="$UBOOT_COMPILE_COMMANDS --recovery_img $TOP_DIR/u-boot/recovery.img"
				;;
		esac

		UBOOT_COMPILE_COMMANDS="$(echo $UBOOT_COMPILE_COMMANDS)"
	fi
}

function usagekernel()
{
	check_config RK_KERNEL_DTS RK_KERNEL_DEFCONFIG || return 0

	echo "cd kernel"
	echo "make ARCH=$RK_ARCH $RK_KERNEL_DEFCONFIG $RK_KERNEL_DEFCONFIG_FRAGMENT"
	echo "make ARCH=$RK_ARCH $RK_KERNEL_DTS.img -j$RK_JOBS"
}

function usageuboot()
{
	check_config RK_UBOOT_DEFCONFIG || return 0
	prebuild_uboot
	prebuild_security_uboot $1

	cd u-boot
	echo "cd u-boot"
	if [ -n "$RK_UBOOT_DEFCONFIG_FRAGMENT" ]; then
		if [ -f "configs/${RK_UBOOT_DEFCONFIG}_defconfig" ]; then
			echo "make ${RK_UBOOT_DEFCONFIG}_defconfig $RK_UBOOT_DEFCONFIG_FRAGMENT"
		else
			echo "make ${RK_UBOOT_DEFCONFIG}.config $RK_UBOOT_DEFCONFIG_FRAGMENT"
		fi
		echo "./make.sh $UBOOT_COMPILE_COMMANDS"
	else
		echo "./make.sh $RK_UBOOT_DEFCONFIG $UBOOT_COMPILE_COMMANDS"
	fi

	if [ "$RK_IDBLOCK_UPDATE_SPL" = "true" ]; then
		echo "./make.sh --idblock --spl"
	fi

	finish_build
}

function usagerootfs()
{
	check_config RK_ROOTFS_IMG || return 0

	if [ "${RK_CFG_BUILDROOT}x" != "x" ];then
		echo "source envsetup.sh $RK_CFG_BUILDROOT"
	else
		if [ "${RK_CFG_RAMBOOT}x" != "x" ];then
			echo "source envsetup.sh $RK_CFG_RAMBOOT"
		else
			echo "Not found config buildroot. Please Check !!!"
		fi
	fi

	case "${RK_ROOTFS_SYSTEM:-buildroot}" in
		yocto)
			;;
		debian)
			;;
		*)
			echo "make"
			;;
	esac
}

function usagerecovery()
{
	check_config RK_CFG_RECOVERY || return 0

	echo "source envsetup.sh $RK_CFG_RECOVERY"
	echo "$COMMON_DIR/mk-ramdisk.sh recovery.img $RK_CFG_RECOVERY"
}

function usageramboot()
{
	check_config RK_CFG_RAMBOOT || return 0

	echo "source envsetup.sh $RK_CFG_RAMBOOT"
	echo "$COMMON_DIR/mk-ramdisk.sh ramboot.img $RK_CFG_RAMBOOT"
}

function usagemodules()
{
	check_config RK_KERNEL_DEFCONFIG || return 0

	echo "cd kernel"
	echo "make ARCH=$RK_ARCH $RK_KERNEL_DEFCONFIG"
	echo "make ARCH=$RK_ARCH modules -j$RK_JOBS"
}

function usagesecurity()
{
	case "$1" in
		uboot) usageboot $1;;
		boot)
			usageramboot;
			echo "cp buildroot/output/$RK_CFG_RAMBOOT/images/ramboot.img u-boot/boot.img"
			usageuboot $1;;
		recovery)
			usagerecovery;
			echo "cp buildroot/output/$RK_CFG_RECOVERY/images/recovery.img u-boot/recovery.img"
			usageuboot $1;;
		rootfs)
			usagerootfs;
			usagesecurity boot;;
		*);;
	esac
}

function usagesecurity_uboot()
{
	usageuboot uboot
}

function usagesecurity_boot()
{
	usagesecurity boot
}

function usagesecurity_recovery()
{
	usagesecurity recovery
}

function usagesecurity_rootfs()
{
	usagesecurity rootfs
}

function usage()
{
	echo "Usage: build.sh [OPTIONS]"
	echo "Available options:"
	echo "BoardConfig*.mk    -switch to specified board config"
	echo "lunch              -list current SDK boards and switch to specified board config"
	echo "wifibt             -build wifibt"
	echo "uboot              -build uboot"
	echo "uefi		 -build uefi"
	echo "spl                -build spl"
	echo "loader             -build loader"
	echo "kernel             -build kernel"
    echo "kernels            -build kernels"
	echo "modules            -build kernel modules"
	echo "toolchain          -build toolchain"
	echo "rootfs             -build default rootfs, currently build buildroot as default"
	echo "buildroot          -build buildroot rootfs"
	echo "ramboot            -build ramboot image"
	echo "multi-npu_boot     -build boot image for multi-npu board"
	echo "yocto              -build yocto rootfs"
	echo "debian             -build debian rootfs"
	echo "jammy              -build ubuntu jammy rootfs"
	echo "focal              -build ubuntu focal rootfs"
	echo "ubuntu             -build ubuntu focal rootfs"
	echo "pcba               -build pcba"
	echo "recovery           -build recovery"
	echo "all                -build uboot, kernel, rootfs, recovery image"
	echo "cleanall           -clean uboot, kernel, rootfs, recovery"
	echo "firmware           -pack all the image we need to boot up system"
	echo "updateimg          -pack update image"
	echo "otapackage         -pack ab update otapackage image (update_ota.img)"
	echo "sdpackage          -pack update sdcard package image (update_sdcard.img)"
	echo "save               -save images, patches, commands used to debug"
	echo "allsave            -build all & firmware & updateimg & save"
	echo "check              -check the environment of building"
	echo "info               -see the current board building information"
	echo "app/<pkg>          -build packages in the dir of app/*"
	echo "external/<pkg>     -build packages in the dir of external/*"
	echo ""
	echo "createkeys         -create secureboot root keys"
	echo "security_rootfs    -build rootfs and some relevant images with security paramter (just for dm-v)"
	echo "security_boot      -build boot with security paramter"
	echo "security_uboot     -build uboot with security paramter"
	echo "security_recovery  -build recovery with security paramter"
	echo "security_check     -check security paramter if it's good"
	echo ""
	echo "Default option is 'allsave'."
}

function build_info(){
	if [ ! -L $TARGET_PRODUCT_DIR ];then
		echo "No found target product!!!"
	fi
	if [ ! -L $BOARD_CONFIG ];then
		echo "No found target board config!!!"
	fi

	if [ -f .repo/manifest.xml ]; then
		local sdk_ver=""
		sdk_ver=`grep "include name"  .repo/manifest.xml | awk -F\" '{print $2}'`
		sdk_ver=`realpath .repo/manifests/${sdk_ver}`
		echo "Build SDK version: `basename ${sdk_ver}`"
	else
		echo "Not found .repo/manifest.xml [ignore] !!!"
	fi

	echo "Current Building Information:"
	echo "Target Product: $TARGET_PRODUCT_DIR"
	echo "Target BoardConfig: `realpath $BOARD_CONFIG`"
	echo "Target Misc config:"
	echo "`env |grep "^RK_" | grep -v "=$" | sort`"

	local kernel_file_dtb

	if [ "$RK_ARCH" == "arm" ]; then
		kernel_file_dtb="${TOP_DIR}/kernel/arch/arm/boot/dts/${RK_KERNEL_DTS}.dtb"
	else
		kernel_file_dtb="${TOP_DIR}/kernel/arch/arm64/boot/dts/rockchip/${RK_KERNEL_DTS}.dtb"
	fi

	rm -f $kernel_file_dtb

	cd kernel
	make ARCH=$RK_ARCH dtbs -j$RK_JOBS

	build_check_power_domain
}

function build_check_power_domain(){
	local dump_kernel_dtb_file
	local tmp_phandle_file
	local tmp_io_domain_file
	local tmp_regulator_microvolt_file
	local tmp_final_target
	local tmp_none_item
	local kernel_file_dtb_dts

	if [ "$RK_ARCH" == "arm" ]; then
		kernel_file_dtb_dts="${TOP_DIR}/kernel/arch/arm/boot/dts/$RK_KERNEL_DTS"
	else
		kernel_file_dtb_dts="${TOP_DIR}/kernel/arch/arm64/boot/dts/rockchip/$RK_KERNEL_DTS"
	fi

	dump_kernel_dtb_file=${kernel_file_dtb_dts}.dump.dts
	tmp_phandle_file=`mktemp`
	tmp_io_domain_file=`mktemp`
	tmp_regulator_microvolt_file=`mktemp`
	tmp_final_target=`mktemp`
	tmp_grep_file=`mktemp`

	dtc -I dtb -O dts -o ${dump_kernel_dtb_file} ${kernel_file_dtb_dts}.dtb 2>/dev/null

	if [ "$RK_SYSTEM_CHECK_METHOD" = "DM-E" ] ; then
		if ! grep "compatible = \"linaro,optee-tz\";" $dump_kernel_dtb_file > /dev/null 2>&1 ; then
			echo "Please add: "
			echo "        optee: optee {"
			echo "                compatible = \"linaro,optee-tz\";"
			echo "                method = \"smc\";"
			echo "                status = \"okay\";"
			echo "        }"
			echo "To your dts file"
			return -1;
		fi
	fi

	if ! grep -Pzo "io-domains\s*{(\n|\w|-|;|=|<|>|\"|_|\s|,)*};" $dump_kernel_dtb_file 1>$tmp_grep_file 2>/dev/null; then
		echo "Not Found io-domains in ${kernel_file_dtb_dts}.dts"
		rm -f $tmp_grep_file
		return 0
	fi
	grep -a supply $tmp_grep_file > $tmp_io_domain_file
	rm -f $tmp_grep_file
	awk '{print "phandle = " $3}' $tmp_io_domain_file > $tmp_phandle_file


	while IFS= read -r item_phandle && IFS= read -u 3 -r item_domain
	do
		echo "${item_domain% *}" >> $tmp_regulator_microvolt_file
		tmp_none_item=${item_domain% *}
		cmds="grep -Pzo \"{(\\n|\w|-|;|=|<|>|\\\"|_|\s)*"$item_phandle\"

		eval "$cmds $dump_kernel_dtb_file | strings | grep "regulator-m..-microvolt" >> $tmp_regulator_microvolt_file" || \
			eval "sed -i \"/${tmp_none_item}/d\" $tmp_regulator_microvolt_file" && continue

		echo >> $tmp_regulator_microvolt_file
	done < $tmp_phandle_file 3<$tmp_io_domain_file

	while read -r regulator_val
	do
		if echo ${regulator_val} | grep supply &>/dev/null; then
			echo -e "\n\n\e[1;33m${regulator_val%*=}\e[0m" >> $tmp_final_target
		else
			tmp_none_item=${regulator_val##*<}
			tmp_none_item=${tmp_none_item%%>*}
			echo -e "${regulator_val%%<*} \e[1;31m$(( $tmp_none_item / 1000 ))mV\e[0m" >> $tmp_final_target
		fi
	done < $tmp_regulator_microvolt_file

	echo -e "\e[41;1;30m PLEASE CHECK BOARD GPIO POWER DOMAIN CONFIGURATION !!!!!\e[0m"
	echo -e "\e[41;1;30m <<< ESPECIALLY Wi-Fi/Flash/Ethernet IO power domain >>> !!!!!\e[0m"
	echo -e "\e[41;1;30m Check Node [pmu_io_domains] in the file: ${kernel_file_dtb_dts}.dts \e[0m"
	echo
	echo -e "\e[41;1;30m 请再次确认板级的电源域配置！！！！！！\e[0m"
	echo -e "\e[41;1;30m <<< 特别是Wi-Fi，FLASH，以太网这几路IO电源的配置 >>> ！！！！！\e[0m"
	echo -e "\e[41;1;30m 检查内核文件 ${kernel_file_dtb_dts}.dts 的节点 [pmu_io_domains] \e[0m"
	cat $tmp_final_target

	rm -f $tmp_phandle_file
	rm -f $tmp_regulator_microvolt_file
	rm -f $tmp_io_domain_file
	rm -f $tmp_final_target
	rm -f $dump_kernel_dtb_file
}

function build_check_cross_compile(){

	case $RK_ARCH in
	arm|armhf)
		if [ "$RK_TARGET_PRODUCT" = "rv1126_rv1109" ];then
			if [ -d "$TOP_DIR/prebuilts/gcc/linux-x86/arm/gcc-arm-8.3-2019.03-x86_64-arm-linux-gnueabihf" ]; then
				CROSS_COMPILE=$(realpath $TOP_DIR)/prebuilts/gcc/linux-x86/arm/gcc-arm-8.3-2019.03-x86_64-arm-linux-gnueabihf/bin/arm-rockchip830-linux-gnueabihf-
			fi
		else
			if [ -d "$TOP_DIR/prebuilts/gcc/linux-x86/arm/gcc-arm-10.3-2021.07-x86_64-arm-none-linux-gnueabihf" ]; then
				CROSS_COMPILE=$(realpath $TOP_DIR)/prebuilts/gcc/linux-x86/arm/gcc-arm-10.3-2021.07-x86_64-arm-none-linux-gnueabihf/bin/arm-none-linux-gnueabihf-
			fi
		fi
		export CROSS_COMPILE=$CROSS_COMPILE
		;;
	arm64|aarch64)
		if [ -d "$TOP_DIR/prebuilts/gcc/linux-x86/aarch64/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu" ]; then
			CROSS_COMPILE=$(realpath $TOP_DIR)/prebuilts/gcc/linux-x86/aarch64/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu/bin/aarch64-none-linux-gnu-
		export CROSS_COMPILE=$CROSS_COMPILE
		fi
		;;
	*)
		echo "the $RK_ARCH not supported for now, please check it again\n"
		;;
	esac
}

function build_check(){
	local build_depend_cfg="build-depend-tools.txt"
	common_product_build_tools="device/rockchip/common/$build_depend_cfg"
	target_product_build_tools="device/rockchip/$RK_TARGET_PRODUCT/$build_depend_cfg"
	cat $common_product_build_tools $target_product_build_tools 2>/dev/null | while read chk_item
		do
			chk_item=${chk_item###*}
			if [ -z "$chk_item" ]; then
				continue
			fi

			dst=${chk_item%%,*}
			src=${chk_item##*,}
			echo "**************************************"
			if eval $dst &>/dev/null;then
				echo "Check [OK]: $dst"
			else
				echo "Please install ${dst%% *} first"
				echo "    sudo apt-get install $src"
			fi
		done
}

function build_pkg() {
	check_config RK_CFG_BUILDROOT || check_config RK_CFG_RAMBOOT || check_config RK_CFG_RECOVERY || check_config RK_CFG_PCBA || return 0

	local target_pkg=$1
	target_pkg=${target_pkg%*/}

	if [ ! -d $target_pkg ];then
		echo "build pkg: error: not found package $target_pkg"
		return 1
	fi

	if ! eval [ $rk_package_mk_arrry ];then
		rk_package_mk_arrry=( $(find buildroot/package/rockchip/ -name "*.mk" | sort) )
	fi

	local pkg_mk pkg_config_in pkg_br pkg_final_target pkg_final_target_upper pkg_cfg

	for it in ${rk_package_mk_arrry[@]}
	do
		pkg_final_target=$(basename $it)
		pkg_final_target=${pkg_final_target%%.mk*}
		pkg_final_target_upper=${pkg_final_target^^}
		pkg_final_target_upper=${pkg_final_target_upper//-/_}
		if grep "${pkg_final_target_upper}_SITE.*$target_pkg" $it &>/dev/null; then
			pkg_mk=$it
			pkg_config_in=$(dirname $pkg_mk)/Config.in
			pkg_br=BR2_PACKAGE_$pkg_final_target_upper

			for cfg in RK_CFG_BUILDROOT RK_CFG_RAMBOOT RK_CFG_RECOVERY RK_CFG_PCBA
			do
				if eval [ \$$cfg ] ;then
					pkg_cfg=$( eval "echo \$$cfg" )
					if grep -wq ${pkg_br}=y buildroot/output/$pkg_cfg/.config; then
						echo "Found $pkg_br in buildroot/output/$pkg_cfg/.config "
						make -C buildroot/output/$pkg_cfg ${pkg_final_target}-dirclean O=buildroot/output/$pkg_cfg
						make -C buildroot/output/$pkg_cfg ${pkg_final_target}-rebuild O=buildroot/output/$pkg_cfg
					else
						echo "[SKIP BUILD $target_pkg] NOT Found ${pkg_br}=y in buildroot/output/$pkg_cfg/.config"
					fi
				fi
			done
		fi
	done

	finish_build
}

function build_uefi(){
	build_check_cross_compile
	local kernel_file_dtb

	if [ "$RK_ARCH" == "arm" ]; then
		kernel_file_dtb="${TOP_DIR}/kernel/arch/arm/boot/dts/${RK_KERNEL_DTS}.dtb"
	else
		kernel_file_dtb="${TOP_DIR}/kernel/arch/arm64/boot/dts/rockchip/${RK_KERNEL_DTS}.dtb"
	fi

	echo "============Start building uefi============"
	echo "Copy kernel dtb $kernel_file_dtb to uefi/edk2-platforms/Platform/Rockchip/DeviceTree/rk3588.dtb"
	echo "========================================="
	if [ ! -f $kernel_file_dtb ]; then
		echo "Please compile the kernel before"
		return -1
	fi

	cp $kernel_file_dtb uefi/edk2-platforms/Platform/Rockchip/DeviceTree/rk3588.dtb
	cd uefi
	./make.sh $RK_UBOOT_DEFCONFIG
	cd -

	finish_build
}

function build_uboot(){
	check_config RK_UBOOT_DEFCONFIG || return 0
	build_check_cross_compile
	prebuild_uboot
	prebuild_security_uboot $@

	echo "============Start building uboot============"
	echo "TARGET_UBOOT_CONFIG=$RK_UBOOT_DEFCONFIG"
	echo "========================================="

	cd u-boot
	rm -f *_loader_*.bin
	if [ "$RK_LOADER_UPDATE_SPL" = "true" ]; then
		rm -f *spl.bin
	fi

	if [ -n "$RK_UBOOT_DEFCONFIG_FRAGMENT" ]; then
		if [ -f "configs/${RK_UBOOT_DEFCONFIG}_defconfig" ]; then
			make ${RK_UBOOT_DEFCONFIG}_defconfig $RK_UBOOT_DEFCONFIG_FRAGMENT
		else
			make ${RK_UBOOT_DEFCONFIG}.config $RK_UBOOT_DEFCONFIG_FRAGMENT
		fi
		./make.sh $UBOOT_COMPILE_COMMANDS
	elif [ -d "$TOP_DIR/prebuilts/gcc/linux-x86/arm/gcc-arm-10.3-2021.07-x86_64-arm-none-linux-gnueabihf" ]; then
		./make.sh $RK_UBOOT_DEFCONFIG \
			$UBOOT_COMPILE_COMMANDS CROSS_COMPILE=$CROSS_COMPILE
	elif [ -d "$TOP_DIR/prebuilts/gcc/linux-x86/aarch64/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu" ]; then
		./make.sh $RK_UBOOT_DEFCONFIG \
			$UBOOT_COMPILE_COMMANDS CROSS_COMPILE=$CROSS_COMPILE
	else
		./make.sh $RK_UBOOT_DEFCONFIG \
			$UBOOT_COMPILE_COMMANDS
	fi

	if [ "$RK_IDBLOCK_UPDATE_SPL" = "true" ]; then
		./make.sh --idblock --spl
	fi

	if [ "$RK_RAMDISK_SECURITY_BOOTUP" = "true" ];then
		ln -rsf $TOP_DIR/u-boot/boot.img $TOP_DIR/rockdev/
		test -z "${RK_PACKAGE_FILE_AB}" && \
			ln -rsf $TOP_DIR/u-boot/recovery.img $TOP_DIR/rockdev/ || true
	fi

	finish_build
}

# TODO: build_spl can be replaced by build_uboot with define RK_LOADER_UPDATE_SPL
function build_spl(){
	check_config RK_SPL_DEFCONFIG || return 0

	echo "============Start building spl============"
	echo "TARGET_SPL_CONFIG=$RK_SPL_DEFCONFIG"
	echo "========================================="

	cd u-boot
	rm -f *spl.bin
	./make.sh $RK_SPL_DEFCONFIG
	./make.sh --spl

	finish_build
}

function build_loader(){
	check_config RK_LOADER_BUILD_TARGET || return 0

	echo "============Start building loader============"
	echo "RK_LOADER_BUILD_TARGET=$RK_LOADER_BUILD_TARGET"
	echo "=========================================="

	cd loader
	./build.sh $RK_LOADER_BUILD_TARGET

	finish_build
}

function build_kernel(){
	check_config RK_KERNEL_DTS RK_KERNEL_DEFCONFIG || return 0

	echo "============Start building kernel============"
	echo "TARGET_ARCH          =$RK_ARCH"
	echo "TARGET_KERNEL_CONFIG =$RK_KERNEL_DEFCONFIG"
	echo "TARGET_KERNEL_DTS    =$RK_KERNEL_DTS"
	echo "TARGET_KERNEL_CONFIG_FRAGMENT =$RK_KERNEL_DEFCONFIG_FRAGMENT"
	echo "=========================================="

	build_check_cross_compile

	cd kernel
    rm -rf ${TOP_DIR}/kernel/*.dtb 2>/dev/null
	make ARCH=$RK_ARCH $RK_KERNEL_DEFCONFIG $RK_KERNEL_DEFCONFIG_FRAGMENT
	make ARCH=$RK_ARCH $RK_KERNEL_DTS.img -j$RK_JOBS
	if [ -f "$TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$RK_KERNEL_FIT_ITS" ]; then
		$COMMON_DIR/mk-fitimage.sh $TOP_DIR/kernel/$RK_BOOT_IMG \
			$TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$RK_KERNEL_FIT_ITS
	fi

	if [ -f "$TOP_DIR/kernel/$RK_BOOT_IMG" ]; then
		mkdir -p $TOP_DIR/rockdev
		ln -sf  $TOP_DIR/kernel/$RK_BOOT_IMG $TOP_DIR/rockdev/boot.img
	fi

	if [ "$RK_RAMDISK_SECURITY_BOOTUP" = "true" ];then
		cp $TOP_DIR/kernel/$RK_BOOT_IMG \
			$TOP_DIR/u-boot/boot.img
	fi

	build_check_power_domain

	finish_build
}


function build_kernels(){
    check_config RK_KERNEL_DTS RK_KERNEL_DEFCONFIG || return 0

    echo "============Start building kernel============"
    echo "TARGET_ARCH          =$RK_ARCH"
    echo "TARGET_KERNEL_CONFIG =$RK_KERNEL_DEFCONFIG"
    echo "TARGET_KERNEL_DTS    =$RK_KERNEL_DTS"
    echo "TARGET_KERNEL_CONFIG_FRAGMENT =$RK_KERNEL_DEFCONFIG_FRAGMENT"
    echo "=========================================="

    build_check_cross_compile

    cd kernel
    make ARCH=arm64 dtbs
    cp -rf ${TOP_DIR}/kernel/arch/arm64/boot/dts/rockchip/*.dtb  ${TOP_DIR}/kernel
    make ARCH=$RK_ARCH $RK_KERNEL_DEFCONFIG $RK_KERNEL_DEFCONFIG_FRAGMENT
    make ARCH=$RK_ARCH $RK_KERNEL_DTS.img -j$RK_JOBS
    if [ -f "$TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$RK_KERNEL_FIT_ITS" ]; then
        $COMMON_DIR/mk-fitimage.sh $TOP_DIR/kernel/$RK_BOOT_IMG \
            $TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$RK_KERNEL_FIT_ITS
    fi

    if [ -f "$TOP_DIR/kernel/$RK_BOOT_IMG" ]; then
        mkdir -p $TOP_DIR/rockdev
        ln -sf  $TOP_DIR/kernel/$RK_BOOT_IMG $TOP_DIR/rockdev/boot.img
    fi

    if [ "$RK_RAMDISK_SECURITY_BOOTUP" = "true" ];then
        cp $TOP_DIR/kernel/$RK_BOOT_IMG \
            $TOP_DIR/u-boot/boot.img
    fi

    build_check_power_domain

    finish_build
}


function build_wifibt(){
	build_check_cross_compile
	case $RK_ARCH in
	arm|armhf)
		WIFI_ARCH=arm
		RKWIFIBT_APP_GCC=$TOP_DIR/buildroot/output/$RK_CFG_BUILDROOT/host/bin/arm-buildroot-linux-gnueabihf-gcc
		RKWIFIBT_APP_SYSROOT=$TOP_DIR/buildroot/output/$RK_CFG_BUILDROOT/host/arm-buildroot-linux-gnueabihf/sysroot
		;;
	arm64|aarch64)
		WIFI_ARCH=arm64
		RKWIFIBT_APP_GCC=$TOP_DIR/buildroot/output/$RK_CFG_BUILDROOT/host/bin/aarch64-buildroot-linux-gnu-gcc
		RKWIFIBT_APP_SYSROOT=$TOP_DIR/buildroot/output/$RK_CFG_BUILDROOT/host/aarch64-buildroot-linux-gnu/sysroot
		;;
	esac

	if [ -n "$1" ]; then
		WIFI_CHIP=$1
	elif [ -n "$RK_WIFIBT_CHIP" ]; then
		WIFI_CHIP=$RK_WIFIBT_CHIP
	else
		# defile ALL_AP
		echo "=== WARNNING WIFI_CHIP is NULL so default to ALL_AP ==="
		WIFI_CHIP=ALL_AP
	fi

	if [ -n "$2" ]; then
		BT_TTY_DEV=$2
	elif [ -n "$RK_WIFIBT_TTY" ]; then
		BT_TTY_DEV=$RK_WIFIBT_TTY
	else
		echo "=== WARNNING BT_TTY is NULL so default to ttyS0 ==="
		BT_TTY_DEV=ttyS0
	fi

	#check kernel .config
	WIFI_USB=`grep "CONFIG_USB=y" $TOP_DIR/kernel/.config` || true
	WIFI_SDIO=`grep "CONFIG_MMC=y" $TOP_DIR/kernel/.config` || true
	WIFI_PCIE=`grep "CONFIG_PCIE_DW_ROCKCHIP=y" $TOP_DIR/kernel/.config` || true
	WIFI_RFKILL=`grep "CONFIG_RFKILL=y" $TOP_DIR/kernel/.config` || true
	if [ -z "WIFI_SDIO" ]; then
		echo "=== WARNNING CONFIG_MMC not set !!! ==="
	fi
	if [ -z "WIFI_RFKILL" ]; then
		echo "=== WARNNING CONFIG_USB not set !!! ==="
	fi
	if [[ "$WIFI_CHIP" =~ "U" ]];then
		if [ -z "$WIFI_USB" ]; then
			echo "=== WARNNING CONFIG_USB not set so ABORT!!! ==="
			exit 0
		fi
	fi
	echo "kernel config: $WIFI_USB $WIFI_SDIO $WIFI_RFKILL"

	TARGET_CC=${CROSS_COMPILE}gcc
	RKWIFIBT=$TOP_DIR/external/rkwifibt
	RKWIFIBT_APP=$TOP_DIR/external/rkwifibt-app
	TARGET_ROOTFS_DIR=$TOP_DIR/buildroot/output/$RK_CFG_BUILDROOT/target

	echo "========build wifibt info======="
	echo CROSS_COMPILE=$CROSS_COMPILE
	echo WIFI_CHIP=$WIFI_CHIP
	echo BT_TTY_DEV=$BT_TTY_DEV
	echo TARGET_ROOTFS_DIR=$TARGET_ROOTFS_DIR
	echo RKWIFIBT_APP_GCC=$RKWIFIBT_APP_GCC
	echo RKWIFIBT_APP_SYSROOT=$RKWIFIBT_APP_SYSROOT

	if [[ "$WIFI_CHIP" =~ "ALL_AP" ]];then
		echo "building bcmdhd sdio"
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/bcmdhd CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8 CONFIG_BCMDHD=m CONFIG_BCMDHD_SDIO=y CONFIG_BCMDHD_PCIE=
		if [ -n "$WIFI_PCIE" ]; then
			echo "building bcmdhd pcie"
			make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/bcmdhd CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8 CONFIG_BCMDHD=m CONFIG_BCMDHD_PCIE=y CONFIG_BCMDHD_SDIO=
		fi
		if [ -n "$WIFI_USB" ]; then
			echo "building rtl8188fu usb"
			make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8188fu CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j8
		fi
		echo "building rtl8189fs sdio"
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8189fs CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j8
		echo "building rtl8723ds sdio"
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8723ds CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j8
		echo "building rtl8821cs sdio"
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8821cs CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j8
		echo "building rtl8822cs sdio"
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8822cs CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j8
		echo "building rtl8852bs sdio"
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8852bs CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j8 DRV_PATH=$RKWIFIBT/drivers/rtl8852bs
		if [ -n "$WIFI_PCIE" ]; then
			echo "building rtl8852be pcie"
			make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8852be CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j8 DRV_PATH=$RKWIFIBT/drivers/rtl8852be
		fi
	fi

	if [[ "$WIFI_CHIP" =~ "ALL_CY" ]];then
		echo "building CYW4354"
		cp $RKWIFIBT/drivers/infineon/chips/CYW4354_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
		echo "building CYW4373"
		cp $RKWIFIBT/drivers/infineon/chips/CYW4373_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
		echo "building CYW43438"
		cp $RKWIFIBT/drivers/infineon/chips/CYW43438_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
		echo "building CYW43455"
		cp $RKWIFIBT/drivers/infineon/chips/CYW43455_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
		echo "building CYW5557X"
		cp $RKWIFIBT/drivers/infineon/chips/CYW5557X_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
		if [ -n "$WIFI_PCIE" ]; then
			echo "building CYW5557X_PCIE"
			cp $RKWIFIBT/drivers/infineon/chips/CYW5557X_PCIE_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
			make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
			echo "building CYW54591_PCIE"
			cp $RKWIFIBT/drivers/infineon/chips/CYW54591_PCIE_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
			make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
		fi
		echo "building CYW54591"
		cp $RKWIFIBT/drivers/infineon/chips/CYW54591_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8

		if [ -n "$WIFI_USB" ]; then
			echo "building rtl8188fu usb"
			make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8188fu CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j8
		fi
		echo "building rtl8189fs sdio"
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8189fs CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j8
		echo "building rtl8723ds sdio"
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8723ds CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j8
		echo "building rtl8821cs sdio"
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8821cs CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j8
		echo "building rtl8822cs sdio"
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8822cs CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j8
		echo "building rtl8852bs sdio"
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8852bs CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j8 DRV_PATH=$RKWIFIBT/drivers/rtl8852bs
		if [ -n "$WIFI_PCIE" ]; then
			echo "building rtl8852be pcie"
			make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8852be CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j8 DRV_PATH=$RKWIFIBT/drivers/rtl8852be
		fi
	fi

	if [[ "$WIFI_CHIP" =~ "AP6" ]];then
		if [[ "$WIFI_CHIP" = "AP6275_PCIE" ]];then
			echo "building bcmdhd pcie driver"
			make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/bcmdhd CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8 CONFIG_BCMDHD=m CONFIG_BCMDHD_PCIE=y CONFIG_BCMDHD_SDIO=
		else
			echo "building bcmdhd sdio driver"
			make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/bcmdhd CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8 CONFIG_BCMDHD=m CONFIG_BCMDHD_SDIO=y CONFIG_BCMDHD_PCIE=
		fi
	fi

	if [[ "$WIFI_CHIP" = "CYW4354" ]];then
		echo "building CYW4354"
		cp $RKWIFIBT/drivers/infineon/chips/CYW4354_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
	fi

	if [[ "$WIFI_CHIP" = "CYW4373" ]];then
		echo "building CYW4373"
		cp $RKWIFIBT/drivers/infineon/chips/CYW4373_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
	fi

	if [[ "$WIFI_CHIP" = "CYW43438" ]];then
		echo "building CYW43438"
		cp $RKWIFIBT/drivers/infineon/chips/CYW43438_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
	fi

	if [[ "$WIFI_CHIP" = "CYW43455" ]];then
		echo "building CYW43455"
		cp $RKWIFIBT/drivers/infineon/chips/CYW43455_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
	fi

	if [[ "$WIFI_CHIP" = "CYW5557X" ]];then
		echo "building CYW5557X"
		cp $RKWIFIBT/drivers/infineon/chips/CYW5557X_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
	fi

	if [[ "$WIFI_CHIP" = "CYW5557X_PCIE" ]];then
		echo "building CYW5557X_PCIE"
		cp $RKWIFIBT/drivers/infineon/chips/CYW5557X_PCIE_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
	fi

	if [[ "$WIFI_CHIP" = "CYW54591" ]];then
		echo "building CYW54591"
		cp $RKWIFIBT/drivers/infineon/chips/CYW54591_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
	fi

	if [[ "$WIFI_CHIP" = "CYW54591_PCIE" ]];then
		echo "building CYW54591_PCIE"
		cp $RKWIFIBT/drivers/infineon/chips/CYW54591_PCIE_Makefile $RKWIFIBT/drivers/infineon/Makefile -r
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/infineon CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH -j8
	fi

	if [[ "$WIFI_CHIP" = "RTL8188FU" ]];then
		echo "building rtl8188fu driver"
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8188fu CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j32
	fi

	if [[ "$WIFI_CHIP" = "RTL8189FS" ]];then
		echo "building rtl8189fs driver"
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8189fs CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j32
	fi

	if [[ "$WIFI_CHIP" = "RTL8723DS" ]];then
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8723ds CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j32
	fi

	if [[ "$WIFI_CHIP" = "RTL8821CS" ]];then
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8821cs CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j32
	fi

	if [[ "$WIFI_CHIP" = "RTL8822CS" ]];then
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8822cs CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j32
	fi

	if [[ "$WIFI_CHIP" = "RTL8852BS" ]];then
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8852bs CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j32
	fi

	if [[ "$WIFI_CHIP" = "RTL8852BE" ]];then
		make -C $TOP_DIR/kernel M=$RKWIFIBT/drivers/rtl8852be CROSS_COMPILE=$CROSS_COMPILE ARCH=$WIFI_ARCH modules -j32
	fi

	echo "building brcm_tools"
	$TARGET_CC -o $RKWIFIBT/tools/brcm_tools/brcm_patchram_plus1 $RKWIFIBT/tools/brcm_tools/brcm_patchram_plus1.c
	$TARGET_CC -o $RKWIFIBT/tools/brcm_tools/dhd_priv $RKWIFIBT/tools/brcm_tools/dhd_priv.c

	echo "building rk_wifibt_init"
	$TARGET_CC -o $RKWIFIBT/src/rk_wifibt_init $RKWIFIBT/src/rk_wifi_init.c

	echo "building realtek_tools"
	make -C $RKWIFIBT/tools/rtk_hciattach/ CC=$TARGET_CC

	echo "building realtek bt drivers"
	make -C $TOP_DIR/kernel/ M=$RKWIFIBT/drivers/bluetooth_uart_driver ARCH=$WIFI_ARCH CROSS_COMPILE=$CROSS_COMPILE
	if [ -n "$WIFI_USB" ]; then
		make -C $TOP_DIR/kernel/ M=$RKWIFIBT/drivers/bluetooth_usb_driver ARCH=$WIFI_ARCH CROSS_COMPILE=$CROSS_COMPILE
	fi

	if [ "$RK_TARGET_PRODUCT" = "rv1126_rv1109" ];then
		echo "target is rv1126_rv1109, skip $RKWIFIBT_APP"
	else
		echo "building rkwifibt-app"
		make -C $RKWIFIBT_APP CC=$RKWIFIBT_APP_GCC SYSROOT=$RKWIFIBT_APP_SYSROOT ARCH=$RK_ARCH
	fi

	echo "chmod +x tools"
	chmod 755 $RKWIFIBT/tools/brcm_tools/brcm_patchram_plus1
	chmod 755 $RKWIFIBT/tools/brcm_tools/dhd_priv
	chmod 755 $RKWIFIBT/src/rk_wifibt_init
	chmod 755 $RKWIFIBT/tools/rtk_hciattach/rtk_hciattach

	echo "mkdir rootfs dir" $TARGET_ROOTFS_DIR
	rm -rf $TARGET_ROOTFS_DIR/system/lib/modules/
	rm -rf $TARGET_ROOTFS_DIR/system/etc/firmware/
	rm -rf $TARGET_ROOTFS_DIR/vendor/
        rm -rf $TARGET_ROOTFS_DIR/usr/lib/modules/
        mkdir -p $TARGET_ROOTFS_DIR/usr/lib/modules/
	mkdir -p $TARGET_ROOTFS_DIR/system/lib/modules/
	mkdir -p $TARGET_ROOTFS_DIR/system/etc/firmware/
	mkdir -p $TARGET_ROOTFS_DIR/lib/firmware/rtlbt/

	echo "create link system->vendor"
	cd $TARGET_ROOTFS_DIR/
	rm -rf $TARGET_ROOTFS_DIR/vendor
	ln -sf system $TARGET_ROOTFS_DIR/vendor
	cd -

	echo "copy tools/sh to rootfs"
	cp $RKWIFIBT/bin/$WIFI_ARCH/* $TARGET_ROOTFS_DIR/usr/bin/
	cp $RKWIFIBT/sh/wifi_start.sh $TARGET_ROOTFS_DIR/usr/bin/
	cp $RKWIFIBT/sh/wifi_ap6xxx_rftest.sh $TARGET_ROOTFS_DIR/usr/bin/
	cp $RKWIFIBT/conf/wpa_supplicant.conf $TARGET_ROOTFS_DIR/etc/
	cp $RKWIFIBT/conf/dnsmasq.conf $TARGET_ROOTFS_DIR/etc/
	cp $RKWIFIBT/tools/brcm_tools/dhd_priv $TARGET_ROOTFS_DIR/usr/bin/
	cp $RKWIFIBT/tools/brcm_tools/brcm_patchram_plus1 $TARGET_ROOTFS_DIR/usr/bin/
	cp $RKWIFIBT/src/rk_wifibt_init $TARGET_ROOTFS_DIR/usr/bin/

	if [[ "$WIFI_CHIP" = "ALL_CY" ]];then
		echo "copy infineon/realtek firmware/nvram to rootfs"
		cp $RKWIFIBT/drivers/infineon/*.ko $TARGET_ROOTFS_DIR/system/lib/modules/ || true
		cp $RKWIFIBT/firmware/infineon/*/* $TARGET_ROOTFS_DIR/system/etc/firmware/ || true

		#todo rockchip
		#cp $RKWIFIBT/firmware/rockchip/* $TARGET_ROOTFS_DIR/system/etc/firmware/
		cp $RKWIFIBT/sh/bt_load_broadcom_firmware $TARGET_ROOTFS_DIR/usr/bin/
		cp $TARGET_ROOTFS_DIR/usr/bin/bt_load_broadcom_firmware $TARGET_ROOTFS_DIR/usr/bin/bt_init.sh
		cp $TARGET_ROOTFS_DIR/usr/bin/bt_load_broadcom_firmware $TARGET_ROOTFS_DIR/usr/bin/bt_pcba_test

		#reatek
		cp $RKWIFIBT/firmware/realtek/*/* $TARGET_ROOTFS_DIR/lib/firmware/
		cp $RKWIFIBT/firmware/realtek/*/* $TARGET_ROOTFS_DIR/lib/firmware/rtlbt/
		cp $RKWIFIBT/tools/rtk_hciattach/rtk_hciattach $TARGET_ROOTFS_DIR/usr/bin/
		cp $RKWIFIBT/drivers/bluetooth_uart_driver/hci_uart.ko $TARGET_ROOTFS_DIR/usr/lib/modules/
		if [ -n "$WIFI_USB" ]; then
			cp $RKWIFIBT/drivers/bluetooth_usb_driver/rtk_btusb.ko $TARGET_ROOTFS_DIR/usr/lib/modules/
		fi

		rm -rf $TARGET_ROOTFS_DIR/etc/init.d/S36load_wifi_modules
		cp $RKWIFIBT/S36load_all_wifi_modules $TARGET_ROOTFS_DIR/etc/init.d/
		sed -i "s/BT_TTY_DEV/\/dev\/${BT_TTY_DEV}/g" $TARGET_ROOTFS_DIR/etc/init.d/S36load_all_wifi_modules
	fi

	if [[ "$WIFI_CHIP" = "ALL_AP" ]];then
		echo "copy ap6xxx/realtek firmware/nvram to rootfs"
		cp $RKWIFIBT/drivers/bcmdhd/*.ko $TARGET_ROOTFS_DIR/system/lib/modules/
		cp $RKWIFIBT/firmware/broadcom/*/wifi/* $TARGET_ROOTFS_DIR/system/etc/firmware/ || true
		cp $RKWIFIBT/firmware/broadcom/*/bt/* $TARGET_ROOTFS_DIR/system/etc/firmware/ || true

		#todo rockchip
		#cp $RKWIFIBT/firmware/rockchip/* $TARGET_ROOTFS_DIR/system/etc/firmware/
		cp $RKWIFIBT/sh/bt_load_broadcom_firmware $TARGET_ROOTFS_DIR/usr/bin/
		cp $TARGET_ROOTFS_DIR/usr/bin/bt_load_broadcom_firmware $TARGET_ROOTFS_DIR/usr/bin/bt_init.sh
		cp $TARGET_ROOTFS_DIR/usr/bin/bt_load_broadcom_firmware $TARGET_ROOTFS_DIR/usr/bin/bt_pcba_test

		#reatek
		cp -rf $RKWIFIBT/firmware/realtek/*/* $TARGET_ROOTFS_DIR/lib/firmware/
		cp -rf $RKWIFIBT/firmware/realtek/*/* $TARGET_ROOTFS_DIR/lib/firmware/rtlbt/
		cp $RKWIFIBT/tools/rtk_hciattach/rtk_hciattach $TARGET_ROOTFS_DIR/usr/bin/
		cp $RKWIFIBT/drivers/bluetooth_uart_driver/hci_uart.ko $TARGET_ROOTFS_DIR/usr/lib/modules/
		if [ -n "$WIFI_USB" ]; then
			cp $RKWIFIBT/drivers/bluetooth_usb_driver/rtk_btusb.ko $TARGET_ROOTFS_DIR/usr/lib/modules/
		fi

		rm -rf $TARGET_ROOTFS_DIR/etc/init.d/S36load_wifi_modules
		cp $RKWIFIBT/S36load_all_wifi_modules $TARGET_ROOTFS_DIR/etc/init.d/
		sed -i "s/BT_TTY_DEV/\/dev\/${BT_TTY_DEV}/g" $TARGET_ROOTFS_DIR/etc/init.d/S36load_all_wifi_modules
	fi

	if [[ "$WIFI_CHIP" =~ "RTL" ]];then
		echo "Copy RTL file to rootfs"
		if [ -d "$RKWIFIBT/firmware/realtek/$WIFI_CHIP" ]; then
			cp $RKWIFIBT/firmware/realtek/$WIFI_CHIP/* $TARGET_ROOTFS_DIR/lib/firmware/rtlbt/
			cp $RKWIFIBT/firmware/realtek/$WIFI_CHIP/* $TARGET_ROOTFS_DIR/lib/firmware/
		else
			echo "INFO: $WIFI_CHIP isn't bluetooth?"
		fi

		WIFI_KO_DIR=$(echo $WIFI_CHIP | tr '[A-Z]' '[a-z]')

		cp $RKWIFIBT/drivers/$WIFI_KO_DIR/*.ko $TARGET_ROOTFS_DIR/system/lib/modules/

		cp $RKWIFIBT/sh/bt_load_rtk_firmware $TARGET_ROOTFS_DIR/usr/bin/
		sed -i "s/BT_TTY_DEV/\/dev\/${BT_TTY_DEV}/g" $TARGET_ROOTFS_DIR/usr/bin/bt_load_rtk_firmware
		if [ -n "$WIFI_USB" ]; then
			cp $RKWIFIBT/drivers/bluetooth_usb_driver/rtk_btusb.ko $TARGET_ROOTFS_DIR/usr/lib/modules/
			sed -i "s/BT_DRV/rtk_btusb/g" $TARGET_ROOTFS_DIR/usr/bin/bt_load_rtk_firmware
		else
			cp $RKWIFIBT/drivers/bluetooth_uart_driver/hci_uart.ko $TARGET_ROOTFS_DIR/usr/lib/modules/
			sed -i "s/BT_DRV/hci_uart/g" $TARGET_ROOTFS_DIR/usr/bin/bt_load_rtk_firmware
		fi
		cp $TARGET_ROOTFS_DIR/usr/bin/bt_load_rtk_firmware $TARGET_ROOTFS_DIR/usr/bin/bt_init.sh
		cp $TARGET_ROOTFS_DIR/usr/bin/bt_load_rtk_firmware $TARGET_ROOTFS_DIR/usr/bin/bt_pcba_test
		cp $RKWIFIBT/tools/rtk_hciattach/rtk_hciattach $TARGET_ROOTFS_DIR/usr/bin/
		rm -rf $TARGET_ROOTFS_DIR/etc/init.d/S36load_all_wifi_modules
		cp $RKWIFIBT/S36load_wifi_modules $TARGET_ROOTFS_DIR/etc/init.d/
		sed -i "s/WIFI_KO/\/system\/lib\/modules\/$WIFI_CHIP.ko/g" $TARGET_ROOTFS_DIR/etc/init.d/S36load_wifi_modules
	fi

	if [[ "$WIFI_CHIP" =~ "CYW" ]];then
		echo "Copy CYW file to rootfs"
		#tools
		cp $RKWIFIBT/tools/brcm_tools/dhd_priv $TARGET_ROOTFS_DIR/usr/bin/
		cp $RKWIFIBT/tools/brcm_tools/brcm_patchram_plus1 $TARGET_ROOTFS_DIR/usr/bin/
		#firmware
		cp $RKWIFIBT/firmware/infineon/$WIFI_CHIP/* $TARGET_ROOTFS_DIR/system/etc/firmware/
		cp $RKWIFIBT/drivers/infineon/*.ko $TARGET_ROOTFS_DIR/system/lib/modules/
		#bt
		cp $RKWIFIBT/sh/bt_load_broadcom_firmware $TARGET_ROOTFS_DIR/usr/bin/
		sed -i "s/BT_TTY_DEV/\/dev\/${BT_TTY_DEV}/g" $TARGET_ROOTFS_DIR/usr/bin/bt_load_broadcom_firmware
		sed -i "s/BTFIRMWARE_PATH/\/system\/etc\/firmware\//g" $TARGET_ROOTFS_DIR/usr/bin/bt_load_broadcom_firmware
		cp $TARGET_ROOTFS_DIR/usr/bin/bt_load_broadcom_firmware $TARGET_ROOTFS_DIR/usr/bin/bt_init.sh
		cp $TARGET_ROOTFS_DIR/usr/bin/bt_load_broadcom_firmware $TARGET_ROOTFS_DIR/usr/bin/bt_pcba_test
		#wifi
		rm -rf $TARGET_ROOTFS_DIR/etc/init.d/S36load_all_wifi_modules
		cp $RKWIFIBT/S36load_wifi_modules $TARGET_ROOTFS_DIR/etc/init.d/
		sed -i "s/WIFI_KO/\/system\/lib\/modules\/$WIFI_CHIP.ko/g" $TARGET_ROOTFS_DIR/etc/init.d/S36load_wifi_modules
	fi

	if [[ "$WIFI_CHIP" =~ "AP6" ]];then
		echo "Copy AP file to rootfs"
		#tools
		cp $RKWIFIBT/tools/brcm_tools/dhd_priv $TARGET_ROOTFS_DIR/usr/bin/
		cp $RKWIFIBT/tools/brcm_tools/brcm_patchram_plus1 $TARGET_ROOTFS_DIR/usr/bin/
		#firmware
		cp $RKWIFIBT/firmware/broadcom/$WIFI_CHIP/wifi/* $TARGET_ROOTFS_DIR/system/etc/firmware/
		cp $RKWIFIBT/firmware/broadcom/$WIFI_CHIP/bt/* $TARGET_ROOTFS_DIR/system/etc/firmware/
		cp $RKWIFIBT/drivers/bcmdhd/*.ko $TARGET_ROOTFS_DIR/system/lib/modules/
		#bt
		cp $RKWIFIBT/sh/bt_load_broadcom_firmware $TARGET_ROOTFS_DIR/usr/bin/
		sed -i "s/BT_TTY_DEV/\/dev\/${BT_TTY_DEV}/g" $TARGET_ROOTFS_DIR/usr/bin/bt_load_broadcom_firmware
		sed -i "s/BTFIRMWARE_PATH/\/system\/etc\/firmware\//g" $TARGET_ROOTFS_DIR/usr/bin/bt_load_broadcom_firmware
		cp $TARGET_ROOTFS_DIR/usr/bin/bt_load_broadcom_firmware $TARGET_ROOTFS_DIR/usr/bin/bt_init.sh
		cp $TARGET_ROOTFS_DIR/usr/bin/bt_load_broadcom_firmware $TARGET_ROOTFS_DIR/usr/bin/bt_pcba_test
		#wifi
		rm -rf $TARGET_ROOTFS_DIR/etc/init.d/S36load_all_wifi_modules
		cp $RKWIFIBT/S36load_wifi_modules $TARGET_ROOTFS_DIR/etc/init.d/
		if [[ "$WIFI_CHIP" =~ "AP" ]];then
			sed -i "s/WIFI_KO/\/system\/lib\/modules\/bcmdhd.ko/g" $TARGET_ROOTFS_DIR/etc/init.d/S36load_wifi_modules
		else
			sed -i "s/WIFI_KO/\/system\/lib\/modules\/bcmdhd_pcie.ko/g" $TARGET_ROOTFS_DIR/etc/init.d/S36load_wifi_modules
		fi
	fi
	finish_build
	#exit 0
}

function build_modules(){
	check_config RK_KERNEL_DEFCONFIG || return 0

	echo "============Start building kernel modules============"
	echo "TARGET_ARCH          =$RK_ARCH"
	echo "TARGET_KERNEL_CONFIG =$RK_KERNEL_DEFCONFIG"
	echo "TARGET_KERNEL_CONFIG_FRAGMENT =$RK_KERNEL_DEFCONFIG_FRAGMENT"
	echo "=================================================="

	build_check_cross_compile

	cd kernel
	make ARCH=$RK_ARCH $RK_KERNEL_DEFCONFIG $RK_KERNEL_DEFCONFIG_FRAGMENT
	make ARCH=$RK_ARCH modules -j$RK_JOBS

	finish_build
}

function build_toolchain(){
	check_config RK_CFG_TOOLCHAIN || return 0

	echo "==========Start building toolchain =========="
	echo "TARGET_TOOLCHAIN_CONFIG=$RK_CFG_TOOLCHAIN"
	echo "========================================="

	/usr/bin/time -f "you take %E to build toolchain" \
		$COMMON_DIR/mk-toolchain.sh $BOARD_CONFIG

	finish_build
}

function build_buildroot(){
	check_config RK_CFG_BUILDROOT || return 0

	echo "==========Start building buildroot=========="
	echo "TARGET_BUILDROOT_CONFIG=$RK_CFG_BUILDROOT"
	echo "========================================="

	/usr/bin/time -f "you take %E to build builroot" \
		$COMMON_DIR/mk-buildroot.sh $BOARD_CONFIG

	finish_build
}

function build_ramboot(){
	check_config RK_CFG_RAMBOOT || return 0

	echo "=========Start building ramboot========="
	echo "TARGET_RAMBOOT_CONFIG=$RK_CFG_RAMBOOT"
	echo "====================================="

	/usr/bin/time -f "you take %E to build ramboot" \
		$COMMON_DIR/mk-ramdisk.sh ramboot.img $RK_CFG_RAMBOOT

	ln -rsf buildroot/output/$RK_CFG_RAMBOOT/images/ramboot.img \
		rockdev/boot.img

	cp buildroot/output/$RK_CFG_RAMBOOT/images/ramboot.img \
		u-boot/boot.img

	finish_build
}

function build_multi-npu_boot(){
	check_config RK_MULTINPU_BOOT || return 0

	echo "=========Start building multi-npu boot========="
	echo "TARGET_RAMBOOT_CONFIG=$RK_CFG_RAMBOOT"
	echo "====================================="

	/usr/bin/time -f "you take %E to build multi-npu boot" \
		$COMMON_DIR/mk-multi-npu_boot.sh

	finish_build
}

function kernel_version(){
	VERSION_KEYS="VERSION PATCHLEVEL"
	VERSION=""

	for k in $VERSION_KEYS; do
		v=$(grep "^$k = " $1/Makefile | cut -d' ' -f3)
		VERSION=${VERSION:+${VERSION}.}$v
	done
	echo $VERSION
}

function build_yocto(){
	check_config RK_YOCTO_MACHINE || return 0

	echo "=========Start building ramboot========="
	echo "TARGET_MACHINE=$RK_YOCTO_MACHINE"
	echo "====================================="

	KERNEL_VERSION=$(kernel_version kernel/)

	cd yocto
	ln -sf $RK_YOCTO_MACHINE.conf build/conf/local.conf
	source oe-init-build-env
	LANG=en_US.UTF-8 LANGUAGE=en_US.en LC_ALL=en_US.UTF-8 \
		bitbake core-image-minimal -r conf/include/rksdk.conf \
		-r conf/include/kernel-$KERNEL_VERSION.conf

	finish_build
}

function build_debian(){
	ARCH=${RK_DEBIAN_ARCH:-${RK_ARCH}}
	case $ARCH in
		arm|armhf) ARCH=armhf ;;
		*) ARCH=arm64 ;;
	esac

	echo "=========Start building debian for $ARCH========="

	cd debian
	VERSION=debug ARCH=$ARCH ./mk-rootfs-$RK_DEBIAN_VERSION.sh

	finish_build
}

function build_ubuntu() {
	ARCH=${RK_DEBIAN_ARCH:-${RK_ARCH}}
	case $ARCH in
		arm|armhf) ARCH=armhf
		echo "Doesn't support armhf, please use ARCH=arm64 mode..."
		exit 1
		;;
		*) ARCH=arm64 ;;
	esac

	echo "=========Start building ubuntu $1 for $ARCH========="

	cd ubuntu
	if [ ! -e ubuntu.base.$1.tar.gz ]; then
		echo "cannot find ubuntu.base.$1.tar.gz"
		exit 1
	fi

	#
	# Install all kinds of patches...
	#
	VERSION=debug ARCH=$ARCH ./mk-rootfs.sh $1

	finish_build
}

function build_rootfs(){
	check_config RK_ROOTFS_IMG || return 0
    IMAGE_PATH=$TOP_DIR/rockdev

	RK_ROOTFS_DIR=.rootfs
	ROOTFS_IMG=${RK_ROOTFS_IMG##*/}

	rm -rf $RK_ROOTFS_IMG $RK_ROOTFS_DIR
	mkdir -p ${RK_ROOTFS_IMG%/*} $RK_ROOTFS_DIR
	echo "rootfs dir $RK_ROOTFS_DIR"

	case "$1" in
		yocto)
			build_yocto
			ln -rsf yocto/build/latest/rootfs.img \
				$RK_ROOTFS_DIR/rootfs.ext4
			;;
		debian)
			build_debian
			ln -rsf debian/linaro-rootfs.img $RK_ROOTFS_DIR/rootfs.ext4
			ln -rsf debian/linaro-rootfs.img $IMAGE_PATH/rootfs.img
			;;
		jammy)
			build_ubuntu jammy
			ln -rsf  ./ubuntu/ubuntu-base-jammy.img $IMAGE_PATH/rootfs.img
                        ;;
		focal)
			build_ubuntu focal
			ln -rsf  ./ubuntu/ubuntu-base-focal.img $IMAGE_PATH/rootfs.img
			;;
		ubuntu)
			build_ubuntu focal
			ln -rsf  ./ubuntu/ubuntu-base-focal.img $IMAGE_PATH/rootfs.img
                        ;;
		*)
			build_buildroot
			build_wifibt
                        #fixed requires second compilation issue
			build_buildroot
			for f in $(ls buildroot/output/$RK_CFG_BUILDROOT/images/rootfs.*);do
				ln -rsf $f $RK_ROOTFS_DIR/
			done
			ln -rsf buildroot/output/$RK_CFG_BUILDROOT/images/rootfs.ext2 $IMAGE_PATH/rootfs.img
			;;
	esac

	if [ ! -f "$RK_ROOTFS_DIR/$ROOTFS_IMG" ]; then
		#echo "There's no $ROOTFS_IMG generated..."
		exit 1
	fi

	ln -rsf $RK_ROOTFS_DIR/$ROOTFS_IMG $RK_ROOTFS_IMG

	finish_build
}

function build_recovery(){

	if [ "$RK_UPDATE_SDCARD_ENABLE_FOR_AB" = "true" ] ;then
		RK_CFG_RECOVERY=$RK_UPDATE_SDCARD_CFG_RECOVERY
	fi

	if [ ! -z "$RK_PACKAGE_FILE_AB" ]; then
		return 0
	fi

	check_config RK_CFG_RECOVERY || return 0

	echo "==========Start building recovery=========="
	echo "TARGET_RECOVERY_CONFIG=$RK_CFG_RECOVERY"
	echo "========================================"

	/usr/bin/time -f "you take %E to build recovery" \
		$COMMON_DIR/mk-ramdisk.sh recovery.img $RK_CFG_RECOVERY

	ln -rsf buildroot/output/$RK_CFG_RECOVERY/images/recovery.img \
		rockdev/recovery.img

	cp buildroot/output/$RK_CFG_RECOVERY/images/recovery.img \
		u-boot/recovery.img

	finish_build
}

function build_pcba(){
	check_config RK_CFG_PCBA || return 0

	echo "==========Start building pcba=========="
	echo "TARGET_PCBA_CONFIG=$RK_CFG_PCBA"
	echo "===================================="

	/usr/bin/time -f "you take %E to build pcba" \
		$COMMON_DIR/mk-ramdisk.sh pcba.img $RK_CFG_PCBA

	finish_build
}

BOOT_FIXED_CONFIGS="
	CONFIG_BLK_DEV_DM
	CONFIG_DM_CRYPT
	CONFIG_BLK_DEV_CRYPTOLOOP
	CONFIG_DM_VERITY"

BOOT_OPTEE_FIXED_CONFIGS="
	CONFIG_TEE
	CONFIG_OPTEE"

UBOOT_FIXED_CONFIGS="
	CONFIG_FIT_SIGNATURE
	CONFIG_SPL_FIT_SIGNATURE"

UBOOT_AB_FIXED_CONFIGS="
	CONFIG_ANDROID_AB"

ROOTFS_UPDATE_ENGINEBIN_CONFIGS="
	BR2_PACKAGE_RECOVERY
	BR2_PACKAGE_RECOVERY_UPDATEENGINEBIN"

ROOTFS_AB_FIXED_CONFIGS="
	$ROOTFS_UPDATE_ENGINEBIN_CONFIGS
	BR2_PACKAGE_RECOVERY_BOOTCONTROL"

function defconfig_check() {
	# 1. defconfig 2. fixed config
	echo debug-$1
	for i in $2
	do
		echo "look for $i"
		result=$(cat $1 | grep "${i}=y" -w || echo "No found")
		if [ "$result" = "No found" ]; then
			echo -e "\e[41;1;37mSecurity: No found config ${i} in $1 \e[0m"
			echo "make sure your config include this list"
			echo "---------------------------------------"
			echo "$2"
			echo "---------------------------------------"
			return -1;
		fi
	done
	return 0
}

function find_string_in_config(){
	result=$(cat "$2" | grep "$1" || echo "No found")
	if [ "$result" = "No found" ]; then
		echo "Security: No found string $1 in $2"
		return -1;
	fi
	return 0;
}

function check_security_condition(){
	# check security enabled
	test -z "$RK_SYSTEM_CHECK_METHOD" && return 0

	if [ ! -d u-boot/keys ]; then
		echo "ERROR: No root keys(u-boot/keys) found in u-boot"
		echo "       Create it by ./build.sh createkeys or move your key to it"
		return -1
	fi

	if [ "$RK_SYSTEM_CHECK_METHOD" = "DM-E" ]; then
		if [ ! -e u-boot/keys/root_passwd ]; then
			echo "ERROR: No root passwd(u-boot/keys/root_passwd) found in u-boot"
			echo "       echo your root key for sudo to u-boot/keys/root_passwd"
			echo "       some operations need supper user permission when create encrypt image"
			return -1
		fi

		if [ ! -e u-boot/keys/system_enc_key ]; then
			echo "ERROR: No enc key(u-boot/keys/system_enc_key) found in u-boot"
			echo "       Create it by ./build.sh createkeys or move your key to it"
			return -1
		fi

		BOOT_FIXED_CONFIGS="${BOOT_FIXED_CONFIGS}
				    ${BOOT_OPTEE_FIXED_CONFIGS}"
	fi

	echo "check kernel defconfig"
	defconfig_check kernel/arch/$RK_ARCH/configs/$RK_KERNEL_DEFCONFIG "$BOOT_FIXED_CONFIGS"

	if [ ! -z "${RK_PACKAGE_FILE_AB}" ]; then
		UBOOT_FIXED_CONFIGS="${UBOOT_FIXED_CONFIGS}
				     ${UBOOT_AB_FIXED_CONFIGS}"

		defconfig_check buildroot/configs/${RK_CFG_BUILDROOT}_defconfig "$ROOTFS_AB_FIXED_CONFIGS"
	fi
	echo "check uboot defconfig"
	defconfig_check u-boot/configs/${RK_UBOOT_DEFCONFIG}_defconfig "$UBOOT_FIXED_CONFIGS"

	if [ "$RK_SYSTEM_CHECK_METHOD" = "DM-E" ]; then
		echo "check ramdisk defconfig"
		defconfig_check buildroot/configs/${RK_CFG_RAMBOOT}_defconfig "$ROOTFS_UPDATE_ENGINEBIN_CONFIGS"
	fi

	echo "check rootfs defconfig"
	find_string_in_config "BR2_ROOTFS_OVERLAY=\".*board/rockchip/common/security-system-overlay.*" "buildroot/configs/${RK_CFG_BUILDROOT}_defconfig"

	echo "Security: finish check"
}

function build_all(){
	echo "============================================"
	echo "TARGET_ARCH=$RK_ARCH"
	echo "TARGET_PLATFORM=$RK_TARGET_PRODUCT"
	echo "TARGET_UBOOT_CONFIG=$RK_UBOOT_DEFCONFIG"
	echo "TARGET_SPL_CONFIG=$RK_SPL_DEFCONFIG"
	echo "TARGET_KERNEL_CONFIG=$RK_KERNEL_DEFCONFIG"
	echo "TARGET_KERNEL_DTS=$RK_KERNEL_DTS"
	echo "TARGET_TOOLCHAIN_CONFIG=$RK_CFG_TOOLCHAIN"
	echo "TARGET_BUILDROOT_CONFIG=$RK_CFG_BUILDROOT"
	echo "TARGET_RECOVERY_CONFIG=$RK_CFG_RECOVERY"
	echo "TARGET_PCBA_CONFIG=$RK_CFG_PCBA"
	echo "TARGET_RAMBOOT_CONFIG=$RK_CFG_RAMBOOT"
	echo "============================================"

	# NOTE: On secure boot-up world, if the images build with fit(flattened image tree)
	#       we will build kernel and ramboot firstly,
	#       and then copy images into u-boot to sign the images.
	if [ "$RK_RAMDISK_SECURITY_BOOTUP" != "true" ];then
		#note: if build spl, it will delete loader.bin in uboot directory,
		# so can not build uboot and spl at the same time.
		if [ -z $RK_SPL_DEFCONFIG ]; then
			build_uboot
		else
			build_spl
		fi
	fi

	check_security_condition
	build_loader
	build_kernel
	build_toolchain
	build_rootfs ${RK_ROOTFS_SYSTEM:-buildroot}
	build_recovery
	build_ramboot

	if [ "$RK_RAMDISK_SECURITY_BOOTUP" = "true" ];then
		#note: if build spl, it will delete loader.bin in uboot directory,
		# so can not build uboot and spl at the same time.
		if [ -z $RK_SPL_DEFCONFIG ]; then
			build_uboot
		else
			build_spl
		fi
	fi

	finish_build
}

function build_cleanall(){
	echo "clean uboot, kernel, rootfs, recovery"

	cd u-boot
	make distclean
	cd -
	cd kernel
	make distclean
	cd -
	rm -rf buildroot/output
	rm -rf yocto/build/tmp
	rm -rf debian/binary

	finish_build
}

function build_firmware(){
	./mkfirmware.sh $BOARD_CONFIG

	finish_build
}

function build_updateimg(){
	IMAGE_PATH=$TOP_DIR/rockdev
	PACK_TOOL_DIR=$TOP_DIR/tools/linux/Linux_Pack_Firmware

	cd $PACK_TOOL_DIR/rockdev
 	chmod +x ./mkupdate.sh

	if [ -f "$RK_PACKAGE_FILE_AB" ]; then
		build_sdcard_package
		build_otapackage

		cd $PACK_TOOL_DIR/rockdev
		echo "Make Linux a/b update_ab.img."
		source_package_file_name=`ls -lh package-file | awk -F ' ' '{print $NF}'`
		ln -fs "$RK_PACKAGE_FILE_AB" package-file
		./mkupdate.sh
		mv update.img $IMAGE_PATH/update_ab.img
		ln -fs $source_package_file_name package-file
	else
		echo "Make update.img"

		if [ -f "$RK_PACKAGE_FILE" ]; then
			source_package_file_name=`ls -lh package-file | awk -F ' ' '{print $NF}'`
			ln -fs "$RK_PACKAGE_FILE" package-file
			./mkupdate.sh
			ln -fs $source_package_file_name package-file
		else
			ls $IMAGE_PATH
   			./mkupdate.sh
		fi
		mv update.img $IMAGE_PATH
	fi

	finish_build
}

function build_otapackage(){
	IMAGE_PATH=$TOP_DIR/rockdev
	PACK_TOOL_DIR=$TOP_DIR/tools/linux/Linux_Pack_Firmware

	echo "Make ota ab update_ota.img"
	cd $PACK_TOOL_DIR/rockdev
	if [ -f "$RK_PACKAGE_FILE_OTA" ]; then
		source_package_file_name=`ls -lh $PACK_TOOL_DIR/rockdev/package-file | awk -F ' ' '{print $NF}'`
		ln -fs "$RK_PACKAGE_FILE_OTA" package-file
		./mkupdate.sh
		mv update.img $IMAGE_PATH/update_ota.img
		ln -fs $source_package_file_name package-file
	fi

	finish_build
}

function build_sdcard_package(){

	check_config RK_UPDATE_SDCARD_ENABLE_FOR_AB || return 0

	local image_path=$TOP_DIR/rockdev
	local pack_tool_dir=$TOP_DIR/tools/linux/Linux_Pack_Firmware
	local rk_sdupdate_ab_misc=${RK_SDUPDATE_AB_MISC:=sdupdate-ab-misc.img}
	local rk_parameter_sdupdate=${RK_PARAMETER_SDUPDATE:=parameter-sdupdate.txt}
	local rk_package_file_sdcard_update=${RK_PACKAGE_FILE_SDCARD_UPDATE:=sdcard-update-package-file}
	local sdupdate_ab_misc_img=$TOP_DIR/device/rockchip/rockimg/$rk_sdupdate_ab_misc
	local parameter_sdupdate=$TOP_DIR/device/rockchip/rockimg/$rk_parameter_sdupdate
	local recovery_img=$TOP_DIR/buildroot/output/$RK_UPDATE_SDCARD_CFG_RECOVERY/images/recovery.img

	if [ $RK_UPDATE_SDCARD_CFG_RECOVERY ]; then
		if [ -f $recovery_img ]; then
			echo -n "create recovery.img..."
			ln -rsf $recovery_img $image_path/recovery.img
		else
			echo "error: $recovery_img not found!"
			return 1
		fi
	fi


	echo "Make sdcard update update_sdcard.img"
	cd $pack_tool_dir/rockdev
	if [ -f "$rk_package_file_sdcard_update" ]; then

		if [ $rk_parameter_sdupdate ]; then
			if [ -f $parameter_sdupdate ]; then
				echo -n "create sdcard update image parameter..."
				ln -rsf $parameter_sdupdate $image_path/
			fi
		fi

		if [ $rk_sdupdate_ab_misc ]; then
			if [ -f $sdupdate_ab_misc_img ]; then
				echo -n "create sdupdate ab misc.img..."
				ln -rsf $sdupdate_ab_misc_img $image_path/
			fi
		fi

		source_package_file_name=`ls -lh $pack_tool_dir/rockdev/package-file | awk -F ' ' '{print $NF}'`
		ln -fs "$rk_package_file_sdcard_update" package-file
		./mkupdate.sh
		mv update.img $image_path/update_sdcard.img
		ln -fs $source_package_file_name package-file
		rm -f $image_path/$rk_sdupdate_ab_misc $image_path/$rk_parameter_sdupdate $image_path/recovery.img
	fi

	finish_build
}

function build_save(){
	IMAGE_PATH=$TOP_DIR/rockdev
	DATE=$(date  +%Y%m%d.%H%M)
	STUB_PATH=Image/"$RK_KERNEL_DTS"_"$DATE"_RELEASE_TEST
	STUB_PATH="$(echo $STUB_PATH | tr '[:lower:]' '[:upper:]')"
	export STUB_PATH=$TOP_DIR/$STUB_PATH
	export STUB_PATCH_PATH=$STUB_PATH/PATCHES
	mkdir -p $STUB_PATH

	#Generate patches
	#.repo/repo/repo forall -c \
	#	"$TOP_DIR/device/rockchip/common/gen_patches_body.sh"

	#Copy stubs
	#.repo/repo/repo manifest -r -o $STUB_PATH/manifest_${DATE}.xml
	mkdir -p $STUB_PATCH_PATH/kernel
	cp kernel/.config $STUB_PATCH_PATH/kernel
	cp kernel/vmlinux $STUB_PATCH_PATH/kernel
	mkdir -p $STUB_PATH/IMAGES/
	cp $IMAGE_PATH/* $STUB_PATH/IMAGES/

	#Save build command info
	echo "UBOOT:  defconfig: $RK_UBOOT_DEFCONFIG" >> $STUB_PATH/build_cmd_info
	echo "KERNEL: defconfig: $RK_KERNEL_DEFCONFIG, dts: $RK_KERNEL_DTS" >> $STUB_PATH/build_cmd_info
	echo "BUILDROOT: $RK_CFG_BUILDROOT" >> $STUB_PATH/build_cmd_info

	finish_build
}

function build_allsave(){
	rm -fr $TOP_DIR/rockdev
	build_all
	build_firmware
	build_updateimg
	build_save

	build_check_power_domain

	finish_build
}

function create_keys() {
	test -d u-boot/keys && echo "ERROR: u-boot/keys has existed" && return -1

	mkdir u-boot/keys -p
	cd u-boot/keys
	$TOP_DIR/rkbin/tools/rk_sign_tool kk --bits 2048
	cd -

	ln -s private_key.pem u-boot/keys/dev.key
	ln -s public_key.pem u-boot/keys/dev.pubkey
	openssl req -batch -new -x509 -key u-boot/keys/dev.key -out u-boot/keys/dev.crt

	openssl rand -out u-boot/keys/system_enc_key -hex 32
}

function security_is_enabled()
{
	if [ "$RK_RAMDISK_SECURITY_BOOTUP" != "true" ]; then
		echo "No security paramter found in .BoardConfig.mk"
		exit -1
	fi
}


#=========================
# build targets
#=========================

if echo $@|grep -wqE "help|-h"; then
	if [ -n "$2" -a "$(type -t usage$2)" == function ]; then
		echo "###Current SDK Default [ $2 ] Build Command###"
		eval usage$2
	else
		usage
	fi
	exit 0
fi

OPTIONS="${@:-allsave}"

[ -f "device/rockchip/$RK_TARGET_PRODUCT/$RK_BOARD_PRE_BUILD_SCRIPT" ] \
	&& source "device/rockchip/$RK_TARGET_PRODUCT/$RK_BOARD_PRE_BUILD_SCRIPT"  # board hooks

for option in ${OPTIONS}; do
	echo "processing option: $option"
	case $option in
		BoardConfig*.mk)
			option=device/rockchip/$RK_TARGET_PRODUCT/$option
			;&
		*.mk)
			CONF=$(realpath $option)
			echo "switching to board: $CONF"
			if [ ! -f $CONF ]; then
				echo "not exist!"
				exit 1
			fi

			ln -rsf $CONF $BOARD_CONFIG
			;;
		lunch) build_select_board ;;
		all) build_all ;;
		save) build_save ;;
		allsave) build_allsave ;;
		check) build_check ;;
		cleanall) build_cleanall ;;
		firmware) build_firmware ;;
		updateimg) build_updateimg ;;
		otapackage) build_otapackage ;;
		sdpackage) build_sdcard_package ;;
		toolchain) build_toolchain ;;
		spl) build_spl ;;
		uboot) build_uboot ;;
		uefi) build_uefi ;;
		loader) build_loader ;;
		kernel) build_kernel ;;
        kernels) build_kernels ;;
		wifibt)
			build_wifibt $2 $3
			exit 1 ;;
		modules) build_modules ;;
		rootfs|buildroot|debian|ubuntu|jammy|focal|distro|yocto) build_rootfs $option ;;
		pcba) build_pcba ;;
		ramboot) build_ramboot ;;
		recovery) build_recovery ;;
		multi-npu_boot) build_multi-npu_boot ;;
		info) build_info ;;
		app/*|external/*) build_pkg $option ;;
		createkeys) create_keys ;;
		security_boot) security_is_enabled; build_ramboot; build_uboot boot ;;
		security_uboot) security_is_enabled; build_uboot uboot ;;
		security_recovery) security_is_enabled; build_recovery; build_uboot recovery ;;
		security_check) check_security_condition ;;
		security_rootfs)
			security_is_enabled
			build_rootfs
			build_ramboot
			build_uboot
			echo "please update rootfs.img / boot.img"
			;;
		*) usage ;;
	esac
done
