#!/bin/bash
echo "start to make update.img..."
if [ ! -f "Image/parameter" -a ! -f "Image/parameter.txt" ]; then
	echo "Error:No found parameter!"
	exit 11
fi
if [ ! -f "package-file" ]; then
	echo "Error:No found package-file!"
	exit 22
fi
./afptool -pack ./ Image/update.img || pause
./rkImageMaker -RK3588 Image/MiniLoaderAll.bin Image/update.img update.img -os_type:androidos
echo "Making ./Image/update.img OK."
#echo "Press any key to quit:"
#read -n1 -s key
exit 
