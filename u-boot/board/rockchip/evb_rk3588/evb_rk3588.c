/*
 * SPDX-License-Identifier:     GPL-2.0+
 *
 * (C) Copyright 2021 Rockchip Electronics Co., Ltd
 */

#include <common.h>
#include <dwc3-uboot.h>
#include <usb.h>
#include <asm/gpio.h>
DECLARE_GLOBAL_DATA_PTR;

#ifdef CONFIG_USB_DWC3
static struct dwc3_device dwc3_device_data = {
	.maximum_speed = USB_SPEED_HIGH,
	.base = 0xfc000000,
	.dr_mode = USB_DR_MODE_PERIPHERAL,
	.index = 0,
	.dis_u2_susphy_quirk = 1,
	.usb2_phyif_utmi_width = 16,
};

int usb_gadget_handle_interrupts(void)
{
	dwc3_uboot_handle_interrupt(0);
	return 0;
}

int board_usb_init(int index, enum usb_init_type init)
{
	return dwc3_uboot_init(&dwc3_device_data);
}


static void ec20_init(void)
{
#define EC20_PWREN              (120)           //3d0
#define EC20_RESET              (119)           //3c7

        gpio_request(EC20_PWREN, "4g_pwren");
        gpio_request(EC20_RESET, "4g_reset");
		gpio_direction_output(EC20_PWREN, 0);	 //pwren
		udelay(5000);
		gpio_direction_output(EC20_PWREN, 1);   //pwren
	    udelay(1000);
	    gpio_direction_output(EC20_RESET, 0);   //reset
		udelay(1000);
}


int rk_board_late_init(void)
{
 	ec20_init();
        return 0;
}


#endif
