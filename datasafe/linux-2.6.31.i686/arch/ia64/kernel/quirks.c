/*
 * This file contains work-arounds for ia64 platform bugs.
 */
#include <linux/pci.h>

/*
 * quirk_intel_ide_controller: If an ide/ata controller is
 * at legacy mode, BIOS might initiates BAR(bar 0~3 and 5)
 * with incorrect value. This quirk will reset the incorrect
 * value to 0.
 */
static void __devinit quirk_intel_ide_controller(struct pci_dev *dev)
{
	unsigned int pos;
	struct resource *res;
	int fixed = 0;
	u8 tmp8;

	if ((dev->class >> 8) != PCI_CLASS_STORAGE_IDE)
		return;

	/* TODO: What if one channel is in native mode ... */
	pci_read_config_byte(dev, PCI_CLASS_PROG, &tmp8);
	if ((tmp8 & 5) == 5)
		return;

	for( pos = 0; pos < 6; pos ++ ) {
		res = &dev->resource[pos];
		if (!(res->flags & (IORESOURCE_IO | IORESOURCE_MEM)))
			continue;

		if (!res->start && res->end) {
			res->start = res->end = 0;
			res->flags = 0;
			fixed = 1;
		}
	}
	if (fixed)
		printk(KERN_WARNING
			"PCI device %s: BIOS resource configuration fixed.\n",
			pci_name(dev));
}

DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82801DB_11, quirk_intel_ide_controller);

