/********************************** (C) COPYRIGHT *******************************
 * File Name          : SecureKey_CH58x.ld
 * Description        : SecureKey_WCH 专用链接脚本（基于官方 Link_CH58x.ld）
 *
 * CH583 片内 Flash 共计 480KB：
 *   0x00000 - 0x6FFFF   Code Flash   448KB   ← 本脚本负责（FLASH 区域）
 *   0x70000 - 0x77FFF   DataFlash     32KB   ← 不归链接器管，由 EEPROM API 访问
 *
 * DataFlash 分区见 include/flash_layout.h：
 *   0x0000 - 0x7DFF   安全存储区（凭证、计数器等）
 *   0x7E00 - 0x7FFF   BLE 协议栈 SNV（已被 BLE 库占用，禁止越界写入）
 *
 * 说明：当前**未启用 Bootloader**，固件仍从 0x00000000 启动。
 *       若将来引入 Bootloader（开发计划 1.1 的可选项，预留 8KB），
 *       需把下面的 FLASH ORIGIN 改成 0x00002000 并同步修改 flash_layout.h。
 *******************************************************************************/

ENTRY( _start )
/*
 * 栈大小：官方例程为 512 字节。
 * 本项目叠加了 BLE 协议栈 + CTAPHID 多帧处理，再加上 micro-ecc 的 P-256
 * 大数运算——后者在栈上开大量临时数组（uECC_verify / uECC_vli_modInv /
 * uECC_vli_modMult 的调用链合计约 1~1.5KB），是最大的栈消耗者，
 * 故提高到 3072 字节。
 * 栈位于 RAM 顶端；实测 .bss 结束于 0x20004F8C，与栈底之间有约 11KB 空隙，
 * 因此增大栈并不会挤压 .bss（真越界时链接器会直接报错）。
 */
__stack_size = 3072;

PROVIDE( _stack_size = __stack_size );

MEMORY
{
	FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 448K
	RAM (xrw) : ORIGIN = 0x20000000, LENGTH = 32K
}


SECTIONS
{
	.init :
	{
		_sinit = .;
		. = ALIGN(4);
		KEEP(*(SORT_NONE(.init)))
		. = ALIGN(4);
		_einit = .;
	} >FLASH AT>FLASH
	
 /*   .vector :
    {
        *(.vector);
    } >FLASH AT>FLASH */
    
    .highcodelalign : 
    {       
        . = ALIGN(4);
        PROVIDE(_highcode_lma = .); 
    } >FLASH AT>FLASH 
    
    .highcode : 
    {
        . = ALIGN(4);
        PROVIDE(_highcode_vma_start = .);
        *(.vector);
		KEEP(*(SORT_NONE(.vector_handler)))
		. = ALIGN(4);
		KEEP(*(wch_user_vectors))
		. = ALIGN(4);
        *(.highcode);
        *(.highcode.*);
		. = ALIGN(4); 
        PROVIDE(_highcode_vma_end = .);
    } >RAM AT>FLASH
     
	.text :
	{
		. = ALIGN(4);
		KEEP(*(SORT_NONE(.handle_reset)))
		*(.text)
		*(.text.*)
		*(.rodata)
		*(.rodata*)
		*(.sdata2.*)
		*(.glue_7)
		*(.glue_7t)
		*(.gnu.linkonce.t.*)
		
		/* section information for finsh shell */
		. = ALIGN(4);
    	__fsymtab_start = .;
    	KEEP(*(FSymTab))
    	__fsymtab_end = .;
    	. = ALIGN(4);
    	__vsymtab_start = .;
    	KEEP(*(VSymTab))
    	__vsymtab_end = .;
    	. = ALIGN(4);
    
    	/* section information for initial. */
    	. = ALIGN(4);
    	__rt_init_start = .;
    	KEEP(*(SORT(.rti_fn*)))
    	__rt_init_end = .;
    	. = ALIGN(4);
    	/* section information for modules */
    	. = ALIGN(4);
    	__rtmsymtab_start = .;
    	KEEP(*(RTMSymTab))
    	__rtmsymtab_end = .;
		. = ALIGN(4);
		. = ALIGN(4);
	} >FLASH AT>FLASH 

	.fini :
	{
		KEEP(*(SORT_NONE(.fini)))
		. = ALIGN(4);
	} >FLASH AT>FLASH

	PROVIDE( _etext = . );
	PROVIDE( _eitcm = . );	

	.preinit_array  :
	{
	  PROVIDE_HIDDEN (__preinit_array_start = .);
	  KEEP (*(.preinit_array))
	  PROVIDE_HIDDEN (__preinit_array_end = .);
	} >FLASH AT>FLASH 
	
	.init_array     :
	{
	  PROVIDE_HIDDEN (__init_array_start = .);
	  KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
	  KEEP (*(.init_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .ctors))
	  PROVIDE_HIDDEN (__init_array_end = .);
	} >FLASH AT>FLASH 
	
	.fini_array     :
	{
	  PROVIDE_HIDDEN (__fini_array_start = .);
	  KEEP (*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
	  KEEP (*(.fini_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .dtors))
	  PROVIDE_HIDDEN (__fini_array_end = .);
	} >FLASH AT>FLASH 
	
	.ctors          :
	{
	  /* gcc uses crtbegin.o to find the start of
	     the constructors, so we make sure it is
	     first.  Because this is a wildcard, it
	     doesn't matter if the user does not
	     actually link against crtbegin.o; the
	     linker won't look for a file to match a
	     wildcard.  The wildcard also means that it
	     doesn't matter which directory crtbegin.o
	     is in.  */
	  KEEP (*crtbegin.o(.ctors))
	  KEEP (*crtbegin?.o(.ctors))
	  /* We don't want to include the .ctor section from
	     the crtend.o file until after the sorted ctors.
	     The .ctor section from the crtend file contains the
	     end of ctors marker and it must be last */
	  KEEP (*(EXCLUDE_FILE (*crtend.o *crtend?.o ) .ctors))
	  KEEP (*(SORT(.ctors.*)))
	  KEEP (*(.ctors))
	} >FLASH AT>FLASH 
	
	.dtors          :
	{
	  KEEP (*crtbegin.o(.dtors))
	  KEEP (*crtbegin?.o(.dtors))
	  KEEP (*(EXCLUDE_FILE (*crtend.o *crtend?.o ) .dtors))
	  KEEP (*(SORT(.dtors.*)))
	  KEEP (*(.dtors))
	} >FLASH AT>FLASH 

	.dalign    : 
	{
		. = ORIGIN(RAM) + MAX(0x800 , SIZEOF(.highcode));
	} >RAM AT>FLASH	

	.dlalign :
	{
		. = ALIGN(4); 
		PROVIDE(_data_lma = .);
	} >FLASH AT>FLASH

	.data :
	{
		. = ALIGN(4); 
		PROVIDE(_data_vma = .);
    	*(.gnu.linkonce.r.*)
    	*(.data .data.*)
    	*(.gnu.linkonce.d.*)
		. = ALIGN(8);
    	PROVIDE( __global_pointer$ = . + 0x800 );
    	*(.sdata .sdata.*)
    	*(.gnu.linkonce.s.*)
    	. = ALIGN(8);
    	*(.srodata.cst16)
    	*(.srodata.cst8)
    	*(.srodata.cst4)
    	*(.srodata.cst2)
    	*(.srodata .srodata.*)
    	. = ALIGN(4);
		PROVIDE( _edata = .);
	} >RAM AT>FLASH

	.bss :
	{
		. = ALIGN(4);
		PROVIDE( _sbss = .);
  	    *(.sbss*)
        *(.gnu.linkonce.sb.*)
		*(.bss*)
     	*(.gnu.linkonce.b.*)		
		*(COMMON*)
		. = ALIGN(4);
		PROVIDE( _ebss = .);
	} >RAM AT>FLASH

	PROVIDE( _end = _ebss);
	PROVIDE( end = . );
	
	.stack ORIGIN(RAM)+LENGTH(RAM)  - __stack_size :
	{
        PROVIDE( _heap_end = . );
        . = ALIGN(4);
        PROVIDE(_susrstack = . );
        . = . + __stack_size;
        PROVIDE( _eusrstack = .);
        PROVIDE(__freertos_irq_stack_top = .);
	} >RAM  
}
