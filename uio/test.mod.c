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
	{ 0x3df5362e, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xb448adc9, __VMLINUX_SYMBOL_STR(platform_bus_type) },
	{ 0xa45efc0c, __VMLINUX_SYMBOL_STR(driver_unregister) },
	{ 0x28e194c2, __VMLINUX_SYMBOL_STR(platform_device_unregister) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x72f241fa, __VMLINUX_SYMBOL_STR(driver_register) },
	{ 0x3f27e850, __VMLINUX_SYMBOL_STR(platform_device_register_full) },
	{ 0xd999b770, __VMLINUX_SYMBOL_STR(__uio_register_device) },
	{ 0xd6aa1fed, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xf8a96516, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x973710a, __VMLINUX_SYMBOL_STR(uio_unregister_device) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=uio";


MODULE_INFO(srcversion, "228CCC11756457FE2E9F02A");
