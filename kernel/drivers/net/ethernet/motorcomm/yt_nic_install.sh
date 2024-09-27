#!/bin/bash
# Motorcomm Networks Interface Card driver install

drv_base=yt6801
drv_file=yt6801.ko
dir_cur=`pwd`
KDST=/lib/modules/`uname -r`/kernel/drivers/net/ethernet/motorcomm/
mod_inuse=`lsmod | grep -i yt6 | head -n 1 | cut -d ' ' -f 1`


drv_full_name=`ls *.tar.gz -t | head -n 1`
#echo drv_full_name:$drv_full_name

if [ "$drv_full_name" == "" ]; then
	echo no *.tar.gz file found...exit.
	exit -1
else
	drv_name=`basename ${drv_full_name} .tar.gz`
	#Convert to lowercase
	drv_name=`echo $drv_name | tr A-Z a-z`
	#drv_name  is yt6801_1.0.17
	#echo drv_name:$drv_name
fi

echo tar ball:$drv_full_name, target dir:$drv_name

#if [ ! -d $drv_name ];then
#	echo first run
#else

if [ -d $drv_name ];then
	#echo clean old file
	rm -rf ./$drv_name
	#ls -lh
fi

mkdir -p $drv_name
#tar -xvf  YT6801_1.0.17.tar.gz -C YT6801_1.0.17/
tar -xf  $drv_full_name -C ${drv_name}/


if [ $# -gt 0 ]; then
	if [[ "clean" == "$1" ]]; then
		#echo sudo rm ${KDST}$drv_file
		echo Uninstall Motorcomm NIC driver...
		sudo rm ${KDST}$drv_file > /dev/null 2>&1
		cd $drv_name
		make clean > /dev/null 2>&1
		cd $dir_cur
		echo Done.
		exit 0
	fi
	echo Do nothing and quit.
	exit 1
fi

if [[ -f $KDST$drv_file ]];then
	echo Driver has been installed before, press 'y' to continue and other to quit...
	read -rsN1 keyy
	#echo $keyy
	if [[ "$keyy" != "y" ]]; then
		exit 0
	fi
fi

cd $drv_name
if [[ ! -f $drv_file ]];then
	echo No driver file,try make it	and pls wait...
	make > /dev/null 2>&1
	if [[ -f $drv_file ]];then
		echo Successful make and install now...; echo
		make install > /dev/null 2>&1
		echo Done.
	else
		echo Fail to make and pls check manually.
	fi
else
	echo Driver file exists,install...;echo
	make install > /dev/null 2>&1

	echo Done.
fi

if [[ "$mod_inuse" == "" ]];then
	#echo yt6801 driver module is NOT in use...
	sudo insmod $drv_file
else
	#echo yt6801 driver module is in use...
	sudo rmmod $mod_inuse
	sudo insmod $drv_file
fi

cd $dir_cur

