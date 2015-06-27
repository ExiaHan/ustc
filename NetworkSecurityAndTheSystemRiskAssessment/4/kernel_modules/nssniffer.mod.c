#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xf3600c71, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x283b8bd5, __VMLINUX_SYMBOL_STR(nf_unregister_hook) },
	{ 0xd57e7e61, __VMLINUX_SYMBOL_STR(filp_close) },
	{ 0x615d07b4, __VMLINUX_SYMBOL_STR(nf_register_hook) },
	{ 0xe882cda4, __VMLINUX_SYMBOL_STR(filp_open) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xf2bc7d4a, __VMLINUX_SYMBOL_STR(vfs_write) },
	{ 0x4c4fef19, __VMLINUX_SYMBOL_STR(kernel_stack) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";
