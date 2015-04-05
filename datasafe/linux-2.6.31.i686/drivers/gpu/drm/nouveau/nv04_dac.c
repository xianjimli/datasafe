/*
 * Copyright 2003 NVIDIA, Corporation
 * Copyright 2006 Dave Airlie
 * Copyright 2007 Maarten Maathuis
 * Copyright 2007-2009 Stuart Bennett
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "drmP.h"
#include "drm_crtc_helper.h"

#include "nouveau_drv.h"
#include "nouveau_encoder.h"
#include "nouveau_connector.h"
#include "nouveau_crtc.h"
#include "nouveau_hw.h"
#include "nvreg.h"

int nv04_dac_output_offset(struct drm_encoder *encoder)
{
	struct dcb_entry *dcb = nouveau_encoder(encoder)->dcb;
	int offset = 0;

	if (dcb->or & (8 | OUTPUT_C))
		offset += 0x68;
	if (dcb->or & (8 | OUTPUT_B))
		offset += 0x2000;

	return offset;
}

/*
 * arbitrary limit to number of sense oscillations tolerated in one sample
 * period (observed to be at least 13 in "nvidia")
 */
#define MAX_HBLANK_OSC 20

/*
 * arbitrary limit to number of conflicting sample pairs to tolerate at a
 * voltage step (observed to be at least 5 in "nvidia")
 */
#define MAX_SAMPLE_PAIRS 10

static int sample_load_twice(struct drm_device *dev, bool sense[2])
{
	int i;

	for (i = 0; i < 2; i++) {
		bool sense_a, sense_b, sense_b_prime;
		int j = 0;

		/*
		 * wait for bit 0 clear -- out of hblank -- (say reg value 0x4),
		 * then wait for transition 0x4->0x5->0x4: enter hblank, leave
		 * hblank again
		 * use a 10ms timeout (guards against crtc being inactive, in
		 * which case blank state would never change)
		 */
		if (!nouveau_wait_until(dev, 10000000, NV_PRMCIO_INP0__COLOR,
					0x00000001, 0x00000000))
			return -EBUSY;
		if (!nouveau_wait_until(dev, 10000000, NV_PRMCIO_INP0__COLOR,
					0x00000001, 0x00000001))
			return -EBUSY;
		if (!nouveau_wait_until(dev, 10000000, NV_PRMCIO_INP0__COLOR,
					0x00000001, 0x00000000))
			return -EBUSY;

		udelay(100);
		/* when level triggers, sense is _LO_ */
		sense_a = nv_rd08(dev, NV_PRMCIO_INP0) & 0x10;

		/* take another reading until it agrees with sense_a... */
		do {
			udelay(100);
			sense_b = nv_rd08(dev, NV_PRMCIO_INP0) & 0x10;
			if (sense_a != sense_b) {
				sense_b_prime =
					nv_rd08(dev, NV_PRMCIO_INP0) & 0x10;
				if (sense_b == sense_b_prime) {
					/* ... unless two consecutive subsequent
					 * samples agree; sense_a is replaced */
					sense_a = sense_b;
					/* force mis-match so we loop */
					sense_b = !sense_a;
				}
			}
		} while ((sense_a != sense_b) && ++j < MAX_HBLANK_OSC);

		if (j == MAX_HBLANK_OSC)
			/* with so much oscillation, default to sense:LO */
			sense[i] = false;
		else
			sense[i] = sense_a;
	}

	return 0;
}

static enum drm_connector_status nv04_dac_detect(struct drm_encoder *encoder,
						 struct drm_connector *connector)
{
	struct drm_device *dev = encoder->dev;
	uint8_t saved_seq1, saved_pi, saved_rpc1;
	uint8_t saved_palette0[3], saved_palette_mask;
	uint32_t saved_rtest_ctrl, saved_rgen_ctrl;
	int i;
	uint8_t blue;
	bool sense = true;

	/*
	 * for this detection to work, there needs to be a mode set up on the
	 * CRTC.  this is presumed to be the case
	 */

	if (nv_two_heads(dev))
		/* only implemented for head A for now */
		NVSetOwner(dev, 0);

	saved_seq1 = NVReadVgaSeq(dev, 0, NV_VIO_SR_CLOCK_INDEX);
	NVWriteVgaSeq(dev, 0, NV_VIO_SR_CLOCK_INDEX, saved_seq1 & ~0x20);

	saved_rtest_ctrl = NVReadRAMDAC(dev, 0, NV_PRAMDAC_TEST_CONTROL);
	NVWriteRAMDAC(dev, 0, NV_PRAMDAC_TEST_CONTROL,
		      saved_rtest_ctrl & ~NV_PRAMDAC_TEST_CONTROL_PWRDWN_DAC_OFF);

	msleep(10);

	saved_pi = NVReadVgaCrtc(dev, 0, NV_CIO_CRE_PIXEL_INDEX);
	NVWriteVgaCrtc(dev, 0, NV_CIO_CRE_PIXEL_INDEX,
		       saved_pi & ~(0x80 | MASK(NV_CIO_CRE_PIXEL_FORMAT)));
	saved_rpc1 = NVReadVgaCrtc(dev, 0, NV_CIO_CRE_RPC1_INDEX);
	NVWriteVgaCrtc(dev, 0, NV_CIO_CRE_RPC1_INDEX, saved_rpc1 & ~0xc0);

	nv_wr08(dev, NV_PRMDIO_READ_MODE_ADDRESS, 0x0);
	for (i = 0; i < 3; i++)
		saved_palette0[i] = nv_rd08(dev, NV_PRMDIO_PALETTE_DATA);
	saved_palette_mask = nv_rd08(dev, NV_PRMDIO_PIXEL_MASK);
	nv_wr08(dev, NV_PRMDIO_PIXEL_MASK, 0);

	saved_rgen_ctrl = NVReadRAMDAC(dev, 0, NV_PRAMDAC_GENERAL_CONTROL);
	NVWriteRAMDAC(dev, 0, NV_PRAMDAC_GENERAL_CONTROL,
		      (saved_rgen_ctrl & ~(NV_PRAMDAC_GENERAL_CONTROL_BPC_8BITS |
					   NV_PRAMDAC_GENERAL_CONTROL_TERMINATION_75OHM)) |
		      NV_PRAMDAC_GENERAL_CONTROL_PIXMIX_ON);

	blue = 8;	/* start of test range */

	do {
		bool sense_pair[2];

		nv_wr08(dev, NV_PRMDIO_WRITE_MODE_ADDRESS, 0);
		nv_wr08(dev, NV_PRMDIO_PALETTE_DATA, 0);
		nv_wr08(dev, NV_PRMDIO_PALETTE_DATA, 0);
		/* testing blue won't find monochrome monitors.  I don't care */
		nv_wr08(dev, NV_PRMDIO_PALETTE_DATA, blue);

		i = 0;
		/* take sample pairs until both samples in the pair agree */
		do {
			if (sample_load_twice(dev, sense_pair))
				goto out;
		} while ((sense_pair[0] != sense_pair[1]) &&
							++i < MAX_SAMPLE_PAIRS);

		if (i == MAX_SAMPLE_PAIRS)
			/* too much oscillation defaults to LO */
			sense = false;
		else
			sense = sense_pair[0];

	/*
	 * if sense goes LO before blue ramps to 0x18, monitor is not connected.
	 * ergo, if blue gets to 0x18, monitor must be connected
	 */
	} while (++blue < 0x18 && sense);

out:
	nv_wr08(dev, NV_PRMDIO_PIXEL_MASK, saved_palette_mask);
	NVWriteRAMDAC(dev, 0, NV_PRAMDAC_GENERAL_CONTROL, saved_rgen_ctrl);
	nv_wr08(dev, NV_PRMDIO_WRITE_MODE_ADDRESS, 0);
	for (i = 0; i < 3; i++)
		nv_wr08(dev, NV_PRMDIO_PALETTE_DATA, saved_palette0[i]);
	NVWriteRAMDAC(dev, 0, NV_PRAMDAC_TEST_CONTROL, saved_rtest_ctrl);
	NVWriteVgaCrtc(dev, 0, NV_CIO_CRE_PIXEL_INDEX, saved_pi);
	NVWriteVgaCrtc(dev, 0, NV_CIO_CRE_RPC1_INDEX, saved_rpc1);
	NVWriteVgaSeq(dev, 0, NV_VIO_SR_CLOCK_INDEX, saved_seq1);

	if (blue == 0x18) {
		NV_TRACE(dev, "Load detected on head A\n");
		return connector_status_connected;
	}

	return connector_status_disconnected;
}

enum drm_connector_status nv17_dac_detect(struct drm_encoder *encoder,
					  struct drm_connector *connector)
{
	struct drm_device *dev = encoder->dev;
	struct drm_nouveau_private *dev_priv = dev->dev_private;
	struct dcb_entry *dcb = nouveau_encoder(encoder)->dcb;
	uint32_t testval, regoffset = nv04_dac_output_offset(encoder);
	uint32_t saved_powerctrl_2 = 0, saved_powerctrl_4 = 0, saved_routput,
		saved_rtest_ctrl, temp, saved_gpio_ext = 0, routput;
	int head, present = 0;

#define RGB_TEST_DATA(r, g, b) (r << 0 | g << 10 | b << 20)
	if (dcb->type == OUTPUT_TV) {
		testval = RGB_TEST_DATA(0xa0, 0xa0, 0xa0);

		if (dev_priv->vbios->tvdactestval)
			testval = dev_priv->vbios->tvdactestval;
	} else {
		testval = RGB_TEST_DATA(0x140, 0x140, 0x140); /* 0x94050140 */

		if (dev_priv->vbios->dactestval)
			testval = dev_priv->vbios->dactestval;
	}

	saved_rtest_ctrl = NVReadRAMDAC(dev, 0, NV_PRAMDAC_TEST_CONTROL + regoffset);
	NVWriteRAMDAC(dev, 0, NV_PRAMDAC_TEST_CONTROL + regoffset,
		      saved_rtest_ctrl & ~NV_PRAMDAC_TEST_CONTROL_PWRDWN_DAC_OFF);

	saved_powerctrl_2 = nvReadMC(dev, NV_PBUS_POWERCTRL_2);

	nvWriteMC(dev, NV_PBUS_POWERCTRL_2, saved_powerctrl_2 & 0xd7ffffff);
	if (regoffset == 0x68) {
		saved_powerctrl_4 = nvReadMC(dev, NV_PBUS_POWERCTRL_4);
		nvWriteMC(dev, NV_PBUS_POWERCTRL_4, saved_powerctrl_4 & 0xffffffcf);
	}

	if (dev_priv->chipset >= 0x34) {
		saved_gpio_ext = NVReadCRTC(dev, 0, NV_PCRTC_GPIO_EXT);

		NVWriteCRTC(dev, 0, NV_PCRTC_GPIO_EXT, (saved_gpio_ext & ~(3 << 20)) |
			    (dcb->type == OUTPUT_TV ? (1 << 20) : 0));
	}

	msleep(4);

	saved_routput = NVReadRAMDAC(dev, 0, NV_PRAMDAC_DACCLK + regoffset);
	head = (saved_routput & 0x100) >> 8;
#if 0
	/* if there's a spare crtc, using it will minimise flicker for the case
	 * where the in-use crtc is in use by an off-chip tmds encoder */
	if (xf86_config->crtc[head]->enabled && !xf86_config->crtc[head ^ 1]->enabled)
		head ^= 1;
#endif
	/* nv driver and nv31 use 0xfffffeee, nv34 and 6600 use 0xfffffece */
	routput = (saved_routput & 0xfffffece) | head << 8;

	if (nv_arch(dev) >= NV_40) {
		if (dcb->type == OUTPUT_TV)
			routput |= 1 << 20;
		else
			routput &= ~(1 << 20);
	}

	NVWriteRAMDAC(dev, 0, NV_PRAMDAC_DACCLK + regoffset, routput);
	msleep(1);

	temp = NVReadRAMDAC(dev, 0, NV_PRAMDAC_DACCLK + regoffset);
	NVWriteRAMDAC(dev, 0, NV_PRAMDAC_DACCLK + regoffset, temp | 1);

	NVWriteRAMDAC(dev, head, NV_PRAMDAC_TESTPOINT_DATA,
		      NV_PRAMDAC_TESTPOINT_DATA_NOTBLANK | testval);
	temp = NVReadRAMDAC(dev, head, NV_PRAMDAC_TEST_CONTROL);
	NVWriteRAMDAC(dev, head, NV_PRAMDAC_TEST_CONTROL,
		      temp | NV_PRAMDAC_TEST_CONTROL_TP_INS_EN_ASSERTED);
	msleep(5);

	temp = NVReadRAMDAC(dev, 0, NV_PRAMDAC_TEST_CONTROL + regoffset);

	if (dcb->type == OUTPUT_TV)
		present = (nv17_tv_detect(encoder, connector, (temp >> 28) & 0xe)
			   == connector_status_connected);
	else
		present = temp & NV_PRAMDAC_TEST_CONTROL_SENSEB_ALLHI;

	temp = NVReadRAMDAC(dev, head, NV_PRAMDAC_TEST_CONTROL);
	NVWriteRAMDAC(dev, head, NV_PRAMDAC_TEST_CONTROL,
		      temp & ~NV_PRAMDAC_TEST_CONTROL_TP_INS_EN_ASSERTED);
	NVWriteRAMDAC(dev, head, NV_PRAMDAC_TESTPOINT_DATA, 0);

	/* bios does something more complex for restoring, but I think this is good enough */
	NVWriteRAMDAC(dev, 0, NV_PRAMDAC_DACCLK + regoffset, saved_routput);
	NVWriteRAMDAC(dev, 0, NV_PRAMDAC_TEST_CONTROL + regoffset, saved_rtest_ctrl);
	if (regoffset == 0x68)
		nvWriteMC(dev, NV_PBUS_POWERCTRL_4, saved_powerctrl_4);
	nvWriteMC(dev, NV_PBUS_POWERCTRL_2, saved_powerctrl_2);

	if (dev_priv->chipset >= 0x34)
		NVWriteRAMDAC(dev, 0, NV_PCRTC_GPIO_EXT, saved_gpio_ext);

	if (present) {
		NV_INFO(dev, "Load detected on output %c\n", '@' + ffs(dcb->or));
		return connector_status_connected;
	}

	return connector_status_disconnected;
}


static bool nv04_dac_mode_fixup(struct drm_encoder *encoder,
				struct drm_display_mode *mode,
				struct drm_display_mode *adjusted_mode)
{
	return true;
}

static void nv04_dac_prepare(struct drm_encoder *encoder)
{
	struct drm_encoder_helper_funcs *helper = encoder->helper_private;
	struct drm_device *dev = encoder->dev;
	struct drm_nouveau_private *dev_priv = dev->dev_private;
	int head = nouveau_crtc(encoder->crtc)->index;
	struct nv04_crtc_reg *crtcstate = dev_priv->mode_reg.crtc_reg;

	helper->dpms(encoder, DRM_MODE_DPMS_OFF);

	nv04_dfp_disable(dev, head);

	/* Some NV4x have unknown values (0x3f, 0x50, 0x54, 0x6b, 0x79, 0x7f)
	 * at LCD__INDEX which we don't alter
	 */
	if (!(crtcstate[head].CRTC[NV_CIO_CRE_LCD__INDEX] & 0x44))
		crtcstate[head].CRTC[NV_CIO_CRE_LCD__INDEX] = 0;
}


static void nv04_dac_mode_set(struct drm_encoder *encoder,
			      struct drm_display_mode *mode,
			      struct drm_display_mode *adjusted_mode)
{
	struct nouveau_encoder *nv_encoder = nouveau_encoder(encoder);
	struct drm_device *dev = encoder->dev;
	struct drm_nouveau_private *dev_priv = dev->dev_private;
	int head = nouveau_crtc(encoder->crtc)->index;

	NV_TRACE(dev, "%s called for encoder %d\n", __func__,
		      nv_encoder->dcb->index);

	if (nv_gf4_disp_arch(dev)) {
		struct drm_encoder *rebind;
		uint32_t dac_offset = nv04_dac_output_offset(encoder);
		uint32_t otherdac;

		/* bit 16-19 are bits that are set on some G70 cards,
		 * but don't seem to have much effect */
		NVWriteRAMDAC(dev, 0, NV_PRAMDAC_DACCLK + dac_offset,
			      head << 8 | NV_PRAMDAC_DACCLK_SEL_DACCLK);
		/* force any other vga encoders to bind to the other crtc */
		list_for_each_entry(rebind, &dev->mode_config.encoder_list, head) {
			if (rebind == encoder
			    || nouveau_encoder(rebind)->dcb->type != OUTPUT_ANALOG)
				continue;

			dac_offset = nv04_dac_output_offset(rebind);
			otherdac = NVReadRAMDAC(dev, 0, NV_PRAMDAC_DACCLK + dac_offset);
			NVWriteRAMDAC(dev, 0, NV_PRAMDAC_DACCLK + dac_offset,
				      (otherdac & ~0x0100) | (head ^ 1) << 8);
		}
	}

	/* This could use refinement for flatpanels, but it should work this way */
	if (dev_priv->chipset < 0x44)
		NVWriteRAMDAC(dev, 0, NV_PRAMDAC_TEST_CONTROL + nv04_dac_output_offset(encoder), 0xf0000000);
	else
		NVWriteRAMDAC(dev, 0, NV_PRAMDAC_TEST_CONTROL + nv04_dac_output_offset(encoder), 0x00100000);
}

static void nv04_dac_commit(struct drm_encoder *encoder)
{
	struct nouveau_encoder *nv_encoder = nouveau_encoder(encoder);
	struct drm_device *dev = encoder->dev;
	struct nouveau_crtc *nv_crtc = nouveau_crtc(encoder->crtc);
	struct drm_encoder_helper_funcs *helper = encoder->helper_private;

	helper->dpms(encoder, DRM_MODE_DPMS_ON);

	NV_INFO(dev, "Output %s is running on CRTC %d using output %c\n",
		drm_get_connector_name(&nouveau_encoder_connector_get(nv_encoder)->base),
		nv_crtc->index, '@' + ffs(nv_encoder->dcb->or));
}

void nv04_dac_update_dacclk(struct drm_encoder *encoder, bool enable)
{
	struct drm_device *dev = encoder->dev;
	struct drm_nouveau_private *dev_priv = dev->dev_private;
	struct dcb_entry *dcb = nouveau_encoder(encoder)->dcb;

	if (nv_gf4_disp_arch(dev)) {
		uint32_t *dac_users = &dev_priv->dac_users[ffs(dcb->or) - 1];
		int dacclk_off = NV_PRAMDAC_DACCLK + nv04_dac_output_offset(encoder);
		uint32_t dacclk = NVReadRAMDAC(dev, 0, dacclk_off);

		if (enable) {
			*dac_users |= 1 << dcb->index;
			NVWriteRAMDAC(dev, 0, dacclk_off, dacclk | NV_PRAMDAC_DACCLK_SEL_DACCLK);

		} else {
			*dac_users &= ~(1 << dcb->index);
			if (!*dac_users)
				NVWriteRAMDAC(dev, 0, dacclk_off,
					dacclk & ~NV_PRAMDAC_DACCLK_SEL_DACCLK);
		}
	}
}

static void nv04_dac_dpms(struct drm_encoder *encoder, int mode)
{
	struct drm_device *dev = encoder->dev;
	struct nouveau_encoder *nv_encoder = nouveau_encoder(encoder);

	if (nv_encoder->last_dpms == mode)
		return;
	nv_encoder->last_dpms = mode;

	NV_INFO(dev, "Setting dpms mode %d on vga encoder (output %d)\n",
		     mode, nv_encoder->dcb->index);

	nv04_dac_update_dacclk(encoder, mode == DRM_MODE_DPMS_ON);
}

static void nv04_dac_save(struct drm_encoder *encoder)
{
	struct nouveau_encoder *nv_encoder = nouveau_encoder(encoder);
	struct drm_device *dev = encoder->dev;

	if (nv_gf4_disp_arch(dev))
		nv_encoder->restore.output = NVReadRAMDAC(dev, 0, NV_PRAMDAC_DACCLK +
							  nv04_dac_output_offset(encoder));
}

static void nv04_dac_restore(struct drm_encoder *encoder)
{
	struct nouveau_encoder *nv_encoder = nouveau_encoder(encoder);
	struct drm_device *dev = encoder->dev;

	if (nv_gf4_disp_arch(dev))
		NVWriteRAMDAC(dev, 0, NV_PRAMDAC_DACCLK + nv04_dac_output_offset(encoder),
			      nv_encoder->restore.output);

	nv_encoder->last_dpms = NV_DPMS_CLEARED;
}

static void nv04_dac_destroy(struct drm_encoder *encoder)
{
	struct nouveau_encoder *nv_encoder = nouveau_encoder(encoder);

	NV_DEBUG(encoder->dev, "\n");

	drm_encoder_cleanup(encoder);
	kfree(nv_encoder);
}

static const struct drm_encoder_helper_funcs nv04_dac_helper_funcs = {
	.dpms = nv04_dac_dpms,
	.save = nv04_dac_save,
	.restore = nv04_dac_restore,
	.mode_fixup = nv04_dac_mode_fixup,
	.prepare = nv04_dac_prepare,
	.commit = nv04_dac_commit,
	.mode_set = nv04_dac_mode_set,
	.detect = nv04_dac_detect
};

static const struct drm_encoder_helper_funcs nv17_dac_helper_funcs = {
	.dpms = nv04_dac_dpms,
	.save = nv04_dac_save,
	.restore = nv04_dac_restore,
	.mode_fixup = nv04_dac_mode_fixup,
	.prepare = nv04_dac_prepare,
	.commit = nv04_dac_commit,
	.mode_set = nv04_dac_mode_set,
	.detect = nv17_dac_detect
};

static const struct drm_encoder_funcs nv04_dac_funcs = {
	.destroy = nv04_dac_destroy,
};

int nv04_dac_create(struct drm_device *dev, struct dcb_entry *entry)
{
	const struct drm_encoder_helper_funcs *helper;
	struct drm_encoder *encoder;
	struct nouveau_encoder *nv_encoder = NULL;

	nv_encoder = kzalloc(sizeof(*nv_encoder), GFP_KERNEL);
	if (!nv_encoder)
		return -ENOMEM;

	encoder = to_drm_encoder(nv_encoder);

	nv_encoder->dcb = entry;
	nv_encoder->or = ffs(entry->or) - 1;

	if (nv_gf4_disp_arch(dev))
		helper = &nv17_dac_helper_funcs;
	else
		helper = &nv04_dac_helper_funcs;

	drm_encoder_init(dev, encoder, &nv04_dac_funcs, DRM_MODE_ENCODER_DAC);
	drm_encoder_helper_add(encoder, helper);

	encoder->possible_crtcs = entry->heads;
	encoder->possible_clones = 0;

	return 0;
}