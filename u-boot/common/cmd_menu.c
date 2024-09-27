#include <common.h>
#include <command.h>
#include <console.h>

static char awaitkey(unsigned long delay, int* error_p)
{
    int i,get_number;
    char c;
    char data_buf[100];

	strcpy(data_buf, "mmc read 8200000 1800 1");
	run_command(data_buf, 0);
	volatile unsigned int *mem = (volatile unsigned int *)0x08200000;
	//printf("default: %d \r", *mem);

    if (delay == -1) {
        while (1) {
            if (tstc()) /* we got a key press */
                return getc();
        }
    }
    else {
        for (i = 0; i < delay; i++) {
		if (tstc()){ /* we got a key press */
			get_number=getc();
			if((get_number==0x03))
				break;
			return get_number;
			}
            mdelay (1*1000);
			printf(" %d 等待时间 %d s \r", *mem,(int)delay-1-i);
			if(i==delay-1){
				switch(*mem){
					case 0:
						c='0';
						break;
					case 1:
						c='1';
						break;
					case 2:
						c='2';
						break;
					case 3:
						c='3';
						break;
					case 4:
						c='4';
						break;
					case 5:
						c='5';
						break;
					case 6:
						c='6';
						break;
					case 7:
						c='7';
						break;
					case 8:
						c='8';
						break;
					case 9:
						c='9';
						break;
					case 10:
						c='a';
						break;
					case 11:
						c='b';
						break;
					case 12:
						c='c';
						break;
					case 13:
						c='d';
						break;
					case 14:
						c='e';
						break;
					case 15:
						c='f';
						break;
					default:
						c='q';
						break;
				}
				return c;
			}
        }
    }
    if (error_p)
        *error_p = -1;
    return 0;
}

void main_menu_usage(void)
{

	printf("\r\n***************** neardi *****************\r\n");
    printf("\r---------------- update dtb --------------\r\n");
    printf("\r\n");
    printf("0 lkd3588-f0 \r\n");
	printf("1 lkd3588-f1\r\n");
    printf("2 lkd3588-f2 \r\n");
	printf("3 lkd3588-f3 \r\n");
    printf("4 lkd3588-f4 \r\n");
    printf("5 lkd3588-t0\r\n");
	printf("6 lkd3588-t1\r\n");
	printf("7 lkd3588-p0\r\n");
	printf("8 lpa3588-f0 \r\n");
	printf("9 lpa3588-f1 \r\n");
	printf("a lpa3588-f2 \r\n");
	printf("b lpa3588-f3 \r\n");
	printf("c lpa3588-f4 \r\n");
	printf("d lpa3588-t0 \r\n");
	printf("e lpb3588-f0  \r\n");
    printf("f lpb3588-t0  \r\n");
	printf("i 进入内核\r\n");
    printf("r 重启设备\r\n");
    printf("q 退出菜单\r\n");
    printf("\r\n");
    printf("输入选择: \r\n");

}

void menu_shell(void)
{
    char c;
    char cmd_buf[200];
	char data_buf[200];
	main_menu_usage();

    while (1)
    {
     //printf(" %d s\n",i++);
      c = awaitkey(21, NULL);
      printf("%c\n", c);
      switch (c)
      {
		case '0':
		{
			  strcpy(data_buf, "mw 0x08200000 0 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
			  return;
		}
        case '1':
        {
			  strcpy(data_buf, "mw 0x08200000 1 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
			 return;
        }
        case '2':
        {
			strcpy(data_buf, "mw 0x08200000 2 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
	          return;
        }
	  case '3':
	        {
	          strcpy(data_buf, "mw 0x08200000 3 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
	          return;
	        }
	  case '4':
	        {
	          strcpy(data_buf, "mw 0x08200000 4 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
	          return;
	        }
	  case '5':
	        {
	          strcpy(data_buf, "mw 0x08200000 5 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
	          return;
	        }
	  case '6':
	        {
	          strcpy(data_buf, "mw 0x08200000 6 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
	          return;
	        }
	   case '7':
	        {
	          strcpy(data_buf, "mw 0x08200000 7 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
	          return;
	        }
	    case '8':
	        {
	          strcpy(data_buf, "mw 0x08200000 8 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
	          return;
	        }
		 case '9':
	        {
	          strcpy(data_buf, "mw 0x08200000 9 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
	          return;
	        }
		  case 'a':
	        {
	          strcpy(data_buf, "mw 0x08200000 a 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
	          return;
	        }
		   case 'b':
	        {
	          strcpy(data_buf, "mw 0x08200000 b 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
	          return;
	        }
		    case 'c':
	        {
	          strcpy(data_buf, "mw 0x08200000 c 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
	          return;
	        }
			case 'd':
	        {
	          strcpy(data_buf, "mw 0x08200000 d 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
	          return;
	        }
		   case 'e':
	        {
	          strcpy(data_buf, "mw 0x08200000 e 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
	          return;
	        }
		    case 'f':
	        {
	          strcpy(data_buf, "mw 0x08200000 f 1;mmc write 0x08200000 1800 1");
			  run_command(data_buf, 0);
			  strcpy(data_buf, "mw 0x08200010 1 1;mmc write 0x08200010 1810 1");
			  run_command(data_buf, 0);
	          //strcpy(cmd_buf, "usb start;fatload usb 0:1 0x08300000 rk3588-neardi-linux-lz160-t2.dtb;setenv fdt_addr_r 0x08200000;boot");
	          //run_command(cmd_buf, 0);
	          return;
	        }
			case 'i':
			{
			  strcpy(cmd_buf, "boot");
			  run_command(cmd_buf, 0);
			  return;
			}
			case 'r':
			 {
			  strcpy(cmd_buf, "reset");
			  run_command(cmd_buf, 0);
			  return;
			  }
			 case 'q':
			  {
				strcpy(data_buf, "mw 0x08200010 0 1;mmc write 0x08200010 1810 1");
				run_command(data_buf, 0);
			    return;
			   }
			  default: ;
      }

    }
}

int do_menu (cmd_tbl_t *cmdtp, int flag, int argc, char *const argv[])
{
    menu_shell();
    return 0;
}

U_BOOT_CMD(
 menu, 1, 0, do_menu,
 "Menu List",
 "U-boot NEARDI-DTB Menu List\n"
);
