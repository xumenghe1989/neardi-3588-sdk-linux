/******************************************************************************
 *
 * Copyright(c) 2007 - 2022 Realtek Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 *****************************************************************************/
#define _RTW_DFS_C_

#include <drv_types.h>

enum rtw_dfs_regd rtw_rfctl_get_dfs_domain(struct rf_ctl_t *rfctl)
{
#ifdef CONFIG_DFS_MASTER
	return rfctl->dfs_region_domain;
#else
	return RTW_DFS_REGD_NONE;
#endif
}

bool rtw_rfctl_dfs_domain_unknown(struct rf_ctl_t *rfctl)
{
#ifdef CONFIG_DFS_MASTER
	return rtw_rfctl_get_dfs_domain(rfctl) == RTW_DFS_REGD_NONE;
#else
	return true;
#endif
}

#ifdef CONFIG_DFS_MASTER
bool rtw_rfctl_overlap_radar_detect_ch(struct rf_ctl_t *rfctl, enum band_type band, u8 ch, u8 bw, u8 offset)
{
	bool ret = false;
	u32 hi = 0, lo = 0;
	u32 r_hi = 0, r_lo = 0;
	int i;

	if (band != BAND_ON_5G || !rfctl->radar_detect_enabled)
		goto exit;

	if (rtw_bchbw_to_freq_range(band, ch, bw, offset, &hi, &lo) == _FALSE) {
		rtw_warn_on(1);
		goto exit;
	}

	if (rtw_bchbw_to_freq_range(band, rfctl->radar_detect_ch
			, rfctl->radar_detect_bw, rfctl->radar_detect_offset
			, &r_hi, &r_lo) == _FALSE) {
		rtw_warn_on(1);
		goto exit;
	}

	if (rtw_is_range_overlap(hi, lo, r_hi, r_lo))
		ret = true;

exit:
	return ret;
}

bool rtw_rfctl_hwband_is_tx_blocked_by_ch_waiting(struct rf_ctl_t *rfctl, enum phl_band_idx hwband)
{
	if (hwband >= HW_BAND_MAX)
		return false;

	if (IS_CH_WAITING(rfctl)) {
		enum band_type band;
		u8 ch, bw, offset;

		if (rtw_get_oper_bchbw_by_hwband(rfctl_to_dvobj(rfctl), hwband
				, &band, &ch, &bw, &offset) != _SUCCESS)
			return false;

		return rtw_rfctl_overlap_radar_detect_ch(rfctl
			, band, ch, bw, offset);
	}
	return false;
}

bool adapter_is_tx_blocked_by_ch_waiting(_adapter *adapter)
{
	struct rf_ctl_t *rfctl = adapter_to_rfctl(adapter);
	struct _ADAPTER_LINK *alink = GET_PRIMARY_LINK(adapter);

	if (!alink)
		return false;

	return rtw_rfctl_hwband_is_tx_blocked_by_ch_waiting(rfctl, ALINK_GET_HWBAND(alink));
}

bool alink_is_tx_blocked_by_ch_waiting(struct _ADAPTER_LINK *alink)
{
	_adapter *adapter = alink->adapter;
	struct rf_ctl_t *rfctl = adapter_to_rfctl(adapter);

	return rtw_rfctl_hwband_is_tx_blocked_by_ch_waiting(rfctl, ALINK_GET_HWBAND(alink));
}

bool rtw_chset_is_bchbw_non_ocp(RT_CHANNEL_INFO *ch_set, enum band_type band, u8 ch, u8 bw, u8 offset)
{
	bool ret = _FALSE;
	u32 hi = 0, lo = 0;
	int i;

	if (rtw_bchbw_to_freq_range(band, ch, bw, offset, &hi, &lo) == _FALSE)
		goto exit;

	for (i = 0; i < MAX_CHANNEL_NUM && ch_set[i].ChannelNum != 0; i++) {
		if (ch_set[i].band != band)
			continue;
		if (!rtw_bch2freq(band, ch_set[i].ChannelNum)) {
			rtw_warn_on(1);
			continue;
		}

		if (!CH_IS_NON_OCP(&ch_set[i]))
			continue;

		if (lo <= rtw_bch2freq(band, ch_set[i].ChannelNum)
			&& rtw_bch2freq(band, ch_set[i].ChannelNum) <= hi
		) {
			ret = _TRUE;
			break;
		}
	}

exit:
	return ret;
}

bool rtw_chset_is_chbw_non_ocp(RT_CHANNEL_INFO *ch_set, u8 ch, u8 bw, u8 offset) RTW_FUNC_2G_5G_ONLY
{
	return rtw_chset_is_bchbw_non_ocp(ch_set, rtw_is_2g_ch(ch) ? BAND_ON_24G : BAND_ON_5G, ch, bw, offset);
}

bool rtw_chset_is_ch_non_ocp(RT_CHANNEL_INFO *ch_set, u8 ch) RTW_FUNC_2G_5G_ONLY
{
	return rtw_chset_is_chbw_non_ocp(ch_set, ch, CHANNEL_WIDTH_20, CHAN_OFFSET_NO_EXT);
}

bool rtw_chset_is_bch_non_ocp(RT_CHANNEL_INFO *ch_set, enum band_type band, u8 ch)
{
	return rtw_chset_is_bchbw_non_ocp(ch_set, band, ch, CHANNEL_WIDTH_20, CHAN_OFFSET_NO_EXT);
}

static u32 rtw_chset_get_bch_non_ocp_ms(RT_CHANNEL_INFO *ch_set, enum band_type band, u8 ch, u8 bw, u8 offset)
{
	int ms = 0;
	systime current_time;
	u32 hi = 0, lo = 0;
	int i;

	if (rtw_bchbw_to_freq_range(band, ch, bw, offset, &hi, &lo) == _FALSE)
		goto exit;

	current_time = rtw_get_current_time();

	for (i = 0; i < MAX_CHANNEL_NUM && ch_set[i].ChannelNum != 0; i++) {
		if (ch_set[i].band != band)
			continue;
		if (!rtw_bch2freq(band, ch_set[i].ChannelNum)) {
			rtw_warn_on(1);
			continue;
		}

		if (!CH_IS_NON_OCP(&ch_set[i]))
			continue;

		if (lo <= rtw_bch2freq(band, ch_set[i].ChannelNum)
			&& rtw_bch2freq(band, ch_set[i].ChannelNum) <= hi
		) {
			if (rtw_systime_to_ms(ch_set[i].non_ocp_end_time - current_time) > ms)
				ms = rtw_systime_to_ms(ch_set[i].non_ocp_end_time - current_time);
		}
	}

exit:
	return ms;
}

/**
 * rtw_chset_update_non_ocp_ms_by_freq - update non_ocp_end_time according to the given @hi, @lo frequency into @ch_set
 * @ch_set: the given channel set
 * @hi: high frequency on which radar is detected
 * @lo: low frequency on which radar is detected
 * @ms: ms to add from now to update non_ocp_end_time, ms < 0 means use NON_OCP_TIME_MS
 */
static bool rtw_chset_update_non_ocp_ms_by_freq(RT_CHANNEL_INFO *ch_set, u32 hi, u32 lo, int ms)
{
	enum band_type band;
	int i;
	bool updated = 0;

	band = rtw_freq2band(hi);

	for (i = 0; i < MAX_CHANNEL_NUM && ch_set[i].ChannelNum != 0; i++) {
		if (ch_set[i].band != band)
			continue;
		if (!rtw_bch2freq(band, ch_set[i].ChannelNum)) {
			rtw_warn_on(1);
			continue;
		}

		if (lo <= rtw_bch2freq(band, ch_set[i].ChannelNum)
			&& rtw_bch2freq(band, ch_set[i].ChannelNum) <= hi
		) {
			if (ms >= 0)
				ch_set[i].non_ocp_end_time = rtw_get_current_time() + rtw_ms_to_systime(ms);
			else
				ch_set[i].non_ocp_end_time = rtw_get_current_time() + rtw_ms_to_systime(NON_OCP_TIME_MS);
			ch_set[i].flags |= RTW_CHF_NON_OCP;
			updated = 1;
		}
	}

	return updated;
}

static bool rtw_chset_update_non_ocp_ms_by_band_cch(RT_CHANNEL_INFO *ch_set, enum band_type band, u8 cch, u8 bw, int ms)
{
	u32 hi, lo;

	if (rtw_bcchbw_to_freq_range(band, cch, bw, &hi, &lo) == _FALSE)
		return _FALSE;

	return rtw_chset_update_non_ocp_ms_by_freq(ch_set, hi, lo, ms);
}

bool rtw_chset_update_non_ocp_ms_by_band(RT_CHANNEL_INFO *ch_set, enum band_type band, u8 ch, u8 bw, u8 offset, int ms)
{
	u32 hi, lo;

	if (rtw_bchbw_to_freq_range(band, ch, bw, offset, &hi, &lo) == _FALSE)
		return _FALSE;

	return rtw_chset_update_non_ocp_ms_by_freq(ch_set, hi, lo, ms);
}

static bool rtw_chset_chk_non_ocp_finish_for_bchbw(struct rf_ctl_t *rfctl, enum band_type band, u8 ch, u8 bw, u8 offset)
{
	RT_CHANNEL_INFO *ch_set = rfctl->channel_set;
	u8 cch;
	u8 *op_chs;
	u8 op_ch_num;
	int i;
	int ch_idx;
	bool ret = 0;

	cch = rtw_get_center_ch_by_band(band, ch, bw, offset);

	if (!rtw_get_op_chs_by_bcch_bw(band, cch, bw, &op_chs, &op_ch_num))
		goto exit;

	for (i = 0; i < op_ch_num; i++) {
		if (0)
			RTW_INFO("%u,%u,%u,%u - cch:%u, bw:%u, op_ch:%u\n", band, ch, bw, offset, cch, bw, *(op_chs + i));
		ch_idx = rtw_chset_search_bch(ch_set, band, *(op_chs + i));
		if (ch_idx == -1)
			break;
		if (!(ch_set[ch_idx].flags & RTW_CHF_NON_OCP) || CH_IS_NON_OCP(&ch_set[ch_idx]))
			break;
	}

	if (op_ch_num != 0 && i == op_ch_num) {
		ret = 1;
		/* clear RTTW_CHF_NON_OCP flag */
		for (i = 0; i < op_ch_num; i++) {
			ch_idx = rtw_chset_search_bch(ch_set, band, *(op_chs + i));
			ch_set[ch_idx].flags &= ~RTW_CHF_NON_OCP;
		}
		for (i = HW_BAND_0; i < HW_BAND_MAX; i++) /* single chset shared by all hwband */
			rtw_nlrtw_nop_finish_event(rfctl, i, band, cch, bw);
	}

exit:
	return ret;
}

/* called by watchdog to clear RTW_CHF_NON_OCP and generate NON_OCP finish event */
void rtw_chset_chk_non_ocp_finish(struct rf_ctl_t *rfctl)
{
	enum band_type band;
	u8 ch, bw, offset;
	int i;

	bw = CHANNEL_WIDTH_160;
	while (1) {
		for (i = 0; i < rfctl->max_chan_nums; i++) {
			band = rfctl->channel_set[i].band;
			ch = rfctl->channel_set[i].ChannelNum;
			if (!(rfctl->channel_set[i].flags & RTW_CHF_NON_OCP))
				continue;
			if (!rtw_get_offset_by_bchbw(band, ch, bw, &offset))
				continue;

			rtw_chset_chk_non_ocp_finish_for_bchbw(rfctl, band, ch, bw, offset);
		}
		if (bw-- == CHANNEL_WIDTH_20)
			break;
	}
}

u32 rtw_get_ch_waiting_ms(struct rf_ctl_t *rfctl, enum band_type band, u8 ch, u8 bw, u8 offset, u32 *r_non_ocp_ms, u32 *r_cac_ms)
{
	u32 non_ocp_ms;
	u32 cac_ms;
	u8 in_rd_range = 0; /* if in current radar detection range*/

	if (rtw_chset_is_bchbw_non_ocp(rfctl->channel_set, band, ch, bw, offset))
		non_ocp_ms = rtw_chset_get_bch_non_ocp_ms(rfctl->channel_set, band, ch, bw, offset);
	else
		non_ocp_ms = 0;

	if (rfctl->radar_detect_enabled) {
		u32 cur_hi, cur_lo, hi, lo;

		if (rtw_bchbw_to_freq_range(band, ch, bw, offset, &hi, &lo) == _FALSE) {
			RTW_ERR("input range band:%u, ch:%u, bw:%u, offset:%u\n", band, ch, bw, offset);
			rtw_warn_on(1);
		}

		if (rtw_bchbw_to_freq_range(BAND_ON_5G, rfctl->radar_detect_ch, rfctl->radar_detect_bw, rfctl->radar_detect_offset, &cur_hi, &cur_lo) == _FALSE) {
			RTW_ERR("cur detection range band:%u, ch:%u, bw:%u, offset:%u\n", BAND_ON_5G, rfctl->radar_detect_ch, rfctl->radar_detect_bw, rfctl->radar_detect_offset);
			rtw_warn_on(1);
		}

		if (rtw_is_range_a_in_b(hi, lo, cur_hi, cur_lo))
			in_rd_range = 1;
	}

	if (!rtw_chset_is_dfs_bchbw(rfctl->channel_set, band, ch, bw, offset))
		cac_ms = 0;
	else if (in_rd_range && !non_ocp_ms) {
		if (IS_CH_WAITING(rfctl))
			cac_ms = rtw_systime_to_ms(rfctl->cac_end_time - rtw_get_current_time());
		else
			cac_ms = 0;
	} else if (rtw_is_long_cac_bch(band, ch, bw, offset, rtw_rfctl_get_dfs_domain(rfctl)))
		cac_ms = CAC_TIME_CE_MS;
	else
		cac_ms = CAC_TIME_MS;

	if (r_non_ocp_ms)
		*r_non_ocp_ms = non_ocp_ms;
	if (r_cac_ms)
		*r_cac_ms = cac_ms;

	return non_ocp_ms + cac_ms;
}

/*
* called in rtw_dfs_rd_enable()
* assume the request channel coverage is DFS range
* base on the current status and the request channel coverage to check if need to reset complete CAC time
*/
static bool rtw_is_cac_reset_needed(struct rf_ctl_t *rfctl, u8 ch, u8 bw, u8 offset)
{
	bool needed = _FALSE;
	u32 cur_hi, cur_lo, hi, lo;

	if (rfctl->radar_detected == 1) {
		needed = _TRUE;
		goto exit;
	}

	if (rfctl->radar_detect_ch == 0) {
		needed = _TRUE;
		goto exit;
	}

	if (rtw_chbw_to_freq_range(ch, bw, offset, &hi, &lo) == _FALSE) {
		RTW_ERR("request detection range ch:%u, bw:%u, offset:%u\n", ch, bw, offset);
		rtw_warn_on(1);
	}

	if (rtw_chbw_to_freq_range(rfctl->radar_detect_ch, rfctl->radar_detect_bw, rfctl->radar_detect_offset, &cur_hi, &cur_lo) == _FALSE) {
		RTW_ERR("cur detection range ch:%u, bw:%u, offset:%u\n", rfctl->radar_detect_ch, rfctl->radar_detect_bw, rfctl->radar_detect_offset);
		rtw_warn_on(1);
	}

	if (hi <= lo || cur_hi <= cur_lo) {
		RTW_ERR("hi:%u, lo:%u, cur_hi:%u, cur_lo:%u\n", hi, lo, cur_hi, cur_lo);
		rtw_warn_on(1);
	}

	if (rtw_is_range_a_in_b(hi, lo, cur_hi, cur_lo)) {
		/* request is in current detect range */
		goto exit;
	}

	/* check if request channel coverage has new range and the new range is in DFS range */
	if (!rtw_is_range_overlap(hi, lo, cur_hi, cur_lo)) {
		/* request has no overlap with current */
		needed = _TRUE;
	} else if (rtw_is_range_a_in_b(cur_hi, cur_lo, hi, lo)) {
		/* request is supper set of current */
		if ((hi != cur_hi && rtw_chset_is_dfs_range(rfctl->channel_set, hi, cur_hi))
			|| (lo != cur_lo && rtw_chset_is_dfs_range(rfctl->channel_set, cur_lo, lo)))
			needed = _TRUE;
	} else {
		/* request is not supper set of current, but has overlap */
		if ((lo < cur_lo && rtw_chset_is_dfs_range(rfctl->channel_set, cur_lo, lo))
			|| (hi > cur_hi && rtw_chset_is_dfs_range(rfctl->channel_set, hi, cur_hi)))
			needed = _TRUE;
	}

exit:
	return needed;
}

static void rtw_reset_cac(struct rf_ctl_t *rfctl, u8 ch, u8 bw, u8 offset)
{
#define RD_CONFIG_INT_MS 2000
	u32 non_ocp_ms;
	u32 cac_ms;
	u32 rd_ready_ms = 0;

	rtw_get_ch_waiting_ms(rfctl, BAND_ON_5G
		, ch
		, bw
		, offset
		, &non_ocp_ms
		, &cac_ms
	);
	if (non_ocp_ms < RD_CONFIG_INT_MS)
		rd_ready_ms = RD_CONFIG_INT_MS - non_ocp_ms;

	rfctl->cac_start_time = rtw_get_current_time() + rtw_ms_to_systime(non_ocp_ms);
	rfctl->cac_end_time = rfctl->cac_start_time + rtw_ms_to_systime(rd_ready_ms + cac_ms);

	/* skip special value */
	if (rfctl->cac_start_time == RTW_CAC_STOPPED) {
		rfctl->cac_start_time++;
		rfctl->cac_end_time++;
	}
	if (rfctl->cac_end_time == RTW_CAC_STOPPED)
		rfctl->cac_end_time++;
}

u32 rtw_force_stop_cac(struct rf_ctl_t *rfctl, u32 timeout_ms)
{
	struct dvobj_priv *dvobj = rfctl_to_dvobj(rfctl);
	systime start;
	u32 pass_ms;

	start = rtw_get_current_time();

	rfctl->cac_force_stop = 1;

	while (rtw_get_passing_time_ms(start) <= timeout_ms
		&& IS_UNDER_CAC(rfctl)
	) {
		if (dev_is_surprise_removed(dvobj) || dev_is_drv_stopped(dvobj))
			break;
		rtw_msleep_os(20);
	}

	if (IS_UNDER_CAC(rfctl)) {
		if (!dev_is_surprise_removed(dvobj) && !dev_is_drv_stopped(dvobj))
			RTW_INFO("%s waiting for cac stop timeout!\n", __func__);
	}

	rfctl->cac_force_stop = 0;

	pass_ms = rtw_get_passing_time_ms(start);

	return pass_ms;
}

static void rtw_dfs_ch_switch_hdl(struct dvobj_priv *dvobj, u8 band_idx)
{
	_adapter *m_iface = rtw_mi_get_ap_mesh_iface_by_hwband(dvobj, band_idx);
	u8 ifbmp_m;
	u8 ifbmp_s;
	u8 i;

	if (!m_iface) {
		RTW_WARN(FUNC_HWBAND_FMT" can't get ap/mesh iface\n", FUNC_HWBAND_ARG(band_idx));
		rtw_warn_on(1);
		return;
	}

	ifbmp_m = rtw_mi_get_ap_mesh_ifbmp_by_hwband(dvobj, band_idx);
	ifbmp_s = rtw_mi_get_ld_sta_ifbmp_by_hwband(dvobj, band_idx);

	rtw_dfs_hal_csa_mg_tx_pause(dvobj, band_idx, true);

#ifdef CONFIG_AP_MODE
	if (ifbmp_m) {
		RTW_INFO(FUNC_HWBAND_FMT" ch sel by AP/MESH ifaces\n", FUNC_HWBAND_ARG(band_idx));
		/* trigger channel selection with consideraton of asoc STA ifaces */
		rtw_change_bss_chbw_cmd(m_iface, RTW_CMDF_DIRECTLY
			, ifbmp_m, ifbmp_s, REQ_CH_NONE, REQ_BW_ORI, REQ_OFFSET_NONE);
	}
#endif

	rtw_dfs_hal_csa_mg_tx_pause(dvobj, band_idx, false);

	rtw_mi_os_xmit_schedule(m_iface);
}

u8 rtw_dfs_rd_hdl(struct dvobj_priv *dvobj, enum phl_band_idx hwband, u8 radar_cch, enum channel_width radar_bw)
{
	struct rf_ctl_t *rfctl = dvobj_to_rfctl(dvobj);
	bool detected;

	if (!rfctl->radar_detect_enabled || rfctl->radar_detect_hwband != hwband)
		goto exit;

	if (IS_CH_WAITING(rfctl) && !IS_UNDER_CAC(rfctl)) {
		/* non_ocp, ignore radar detect */
		goto cac_status_chk;
	}

	detected = (radar_cch > 0 && radar_bw != CHANNEL_WIDTH_MAX) ? true : false;
	if (!rfctl->dbg_dfs_fake_radar_detect_cnt && !detected)
		goto cac_status_chk;

	if (!rfctl->dbg_dfs_fake_radar_detect_cnt
		&& rfctl->dbg_dfs_radar_detect_trigger_non
	) {
		/* radar detect debug mode, trigger no mlme flow */
		RTW_INFO(FUNC_HWBAND_FMT" radar detected on test mode, trigger no mlme flow\n", FUNC_HWBAND_ARG(hwband));
		goto cac_status_chk;
	}

	if (rfctl->dbg_dfs_fake_radar_detect_cnt != 0) {
		RTW_INFO(FUNC_HWBAND_FMT" fake radar detected, cnt:%d\n", FUNC_HWBAND_ARG(hwband)
			, rfctl->dbg_dfs_fake_radar_detect_cnt);
		rfctl->dbg_dfs_fake_radar_detect_cnt--;

		/* TODO: fack radar detected with specific range */
		radar_cch = rfctl->radar_detect_cch;
		radar_bw = rfctl->radar_detect_bw;

	} else
		RTW_INFO(FUNC_HWBAND_FMT" radar detected\n", FUNC_HWBAND_ARG(hwband));

	rfctl->radar_detected = 1;

	rtw_chset_update_non_ocp_ms_by_band_cch(rfctl->channel_set, BAND_ON_5G
		, radar_cch, radar_bw, -1);

	if (IS_UNDER_CAC(rfctl))
		rtw_nlrtw_cac_abort_event(rfctl, hwband, rfctl->radar_detect_cch, rfctl->radar_detect_bw);
	rtw_nlrtw_radar_detect_event(rfctl, hwband, radar_cch, radar_bw);

	rtw_dfs_ch_switch_hdl(dvobj, hwband);

	if (rfctl->radar_detect_enabled)
		goto set_timer;
	goto exit;

cac_status_chk:

	if (!IS_CAC_STOPPED(rfctl)
		&& ((IS_UNDER_CAC(rfctl) && rfctl->cac_force_stop)
			|| !IS_CH_WAITING(rfctl)
			)
	) {
		_adapter *m_iface;

		rfctl->cac_start_time = rfctl->cac_end_time = RTW_CAC_STOPPED;
		rtw_dfs_hal_set_cac_status(dvobj, hwband, false);

		m_iface = rtw_mi_get_ap_mesh_iface_by_hwband(dvobj, hwband);
		if (m_iface) {
			if (!rtw_mi_check_fwstate_by_hwband(dvobj, hwband, WIFI_UNDER_LINKING|WIFI_UNDER_SURVEY)) {
				struct _ADAPTER_LINK *alink = rtw_get_adapter_link_by_hwband(m_iface, hwband);
				u8 do_rfk = _TRUE;
				enum band_type u_band;
				u8 u_ch, u_bw, u_offset;

				if (rtw_mi_get_bch_setting_union_by_hwband(dvobj, hwband, &u_band, &u_ch, &u_bw, &u_offset))
					set_bch_bwmode(m_iface, alink, u_band, u_ch, u_offset, u_bw, do_rfk);
				else
					rtw_warn_on(1);
			}
		} else
			RTW_ERR(FUNC_HWBAND_FMT" can't get ap/mesh iface\n", FUNC_HWBAND_ARG(hwband));

		rtw_nlrtw_cac_finish_event(rfctl, hwband, rfctl->radar_detect_cch, rfctl->radar_detect_bw);
	}

set_timer:
	_set_timer(&rfctl->radar_detect_timer
		, rtw_dfs_hal_radar_detect_polling_int_ms(dvobj));

exit:
	return H2C_SUCCESS;
}

static u8 rtw_dfs_rd_cmd(struct dvobj_priv *dvobj, enum phl_band_idx hwband)
{
	struct cmd_obj *cmdobj;
	struct drvextra_cmd_parm *parm;
	struct cmd_priv *cmdpriv = &dvobj->cmdpriv;
	_adapter *adapter = dvobj_get_primary_adapter(dvobj);
	u8 res = _FAIL;

	cmdobj = rtw_zmalloc(sizeof(struct cmd_obj));
	if (cmdobj == NULL)
		goto exit;
	cmdobj->padapter = adapter;

	parm = rtw_zmalloc(sizeof(struct drvextra_cmd_parm));
	if (parm == NULL) {
		rtw_mfree(cmdobj, sizeof(struct cmd_obj));
		goto exit;
	}

	parm->ec_id = DFS_RADAR_DETECT_WK_CID;
	parm->type = hwband;
	parm->size = 0;
	parm->pbuf = NULL;

	init_h2fwcmd_w_parm_no_rsp(cmdobj, parm, CMD_SET_DRV_EXTRA);
	CMD_OBJ_SET_HWBAND(cmdobj, hwband);
	res = rtw_enqueue_cmd(cmdpriv, cmdobj);

exit:
	return res;
}

static void rtw_dfs_rd_timer_hdl(void *ctx)
{
	struct rf_ctl_t *rfctl = (struct rf_ctl_t *)ctx;
	struct dvobj_priv *dvobj = rfctl_to_dvobj(rfctl);

	rtw_dfs_rd_cmd(dvobj, rfctl->radar_detect_hwband);
}

static void rtw_dfs_rd_enable(struct rf_ctl_t *rfctl, u8 band_idx, u8 ch, u8 bw, u8 offset, bool bypass_cac)
{
	struct dvobj_priv *dvobj = rfctl_to_dvobj(rfctl);

	RTW_INFO(FUNC_HWBAND_FMT" on %u,%u,%u\n", FUNC_HWBAND_ARG(band_idx), ch, bw, offset);

	if (rfctl->radar_detect_enabled && rfctl->radar_detect_hwband != band_idx) {
		RTW_WARN(FUNC_HWBAND_FMT" radar_detect has been enabled for "HWBAND_FMT"\n"
			, FUNC_HWBAND_ARG(band_idx), HWBAND_ARG(rfctl->radar_detect_hwband));
		rtw_warn_on(1);
		return;
	}

	if (bypass_cac)
		rfctl->cac_start_time = rfctl->cac_end_time = RTW_CAC_STOPPED;
	else if (rtw_is_cac_reset_needed(rfctl, ch, bw, offset) == _TRUE)
		rtw_reset_cac(rfctl, ch, bw, offset);

	rfctl->radar_detect_by_others[band_idx] = false;

	rfctl->radar_detect_hwband = band_idx;
	rfctl->radar_detect_ch = ch;
	rfctl->radar_detect_bw = bw;
	rfctl->radar_detect_offset = offset;
	rfctl->radar_detect_cch = rtw_get_center_ch_by_band(BAND_ON_5G, ch, bw, offset);

	rfctl->radar_detected = 0;

	if (!rfctl->radar_detect_enabled) {
		RTW_INFO(FUNC_HWBAND_FMT" set radar_detect_enabled\n", FUNC_HWBAND_ARG(band_idx));
		rfctl->radar_detect_enabled = 1;
		//#ifdef CONFIG_LPS
		//LPS_Leave(adapter, "RADAR_DETECT_EN");
		//#endif
		_set_timer(&rfctl->radar_detect_timer
			, rtw_dfs_hal_radar_detect_polling_int_ms(dvobj));
	}

	rtw_dfs_hal_update_region(dvobj, band_idx);
	rtw_dfs_hal_radar_detect_enable(dvobj, band_idx, IS_CH_WAITING(rfctl), ch, bw, offset);
}

static void rtw_dfs_rd_disable(struct rf_ctl_t *rfctl, u8 band_idx, u8 ch, u8 bw, u8 offset, bool by_others)
{
	struct dvobj_priv *dvobj = rfctl_to_dvobj(rfctl);

	rfctl->radar_detect_by_others[band_idx] = by_others;

	if (rfctl->radar_detect_hwband == band_idx) {
		if (rfctl->radar_detect_enabled) {
			RTW_INFO(FUNC_HWBAND_FMT" clear radar_detect_enabled\n", FUNC_HWBAND_ARG(band_idx));

			rfctl->radar_detect_enabled = 0;
			rfctl->radar_detected = 0;
			rfctl->radar_detect_hwband = HW_BAND_MAX;
			rfctl->radar_detect_ch = 0;
			rfctl->radar_detect_bw = 0;
			rfctl->radar_detect_offset = 0;
			rfctl->radar_detect_cch = 0;
			rfctl->cac_start_time = rfctl->cac_end_time = RTW_CAC_STOPPED;
			_cancel_timer_ex(&rfctl->radar_detect_timer);
		}

		rtw_dfs_hal_radar_detect_disable(dvobj, band_idx);
	}

	if (by_others) {
		rfctl->radar_detect_ch = ch;
		rfctl->radar_detect_bw = bw;
		rfctl->radar_detect_offset = offset;
		rfctl->radar_detect_cch = rtw_get_center_ch_by_band(BAND_ON_5G, ch, bw, offset);
	} else {
		rfctl->radar_detect_ch = 0;
		rfctl->radar_detect_bw = 0;
		rfctl->radar_detect_offset = 0;
	}
}

static bool _rtw_dfs_rd_en_decision(struct rf_ctl_t *rfctl, struct mi_state *mstate
	, enum band_type u_band, u8 u_ch, enum channel_width u_bw, enum chan_offset u_offset, bool *ld_sta_in_dfs)
{
	bool needed = false;

	if (MSTATE_STA_LG_NUM(mstate) > 0) {
		/* STA mode is linking */
		goto exit;
	}

	if (MSTATE_STA_LD_NUM(mstate) > 0) {
		if (rtw_chset_is_dfs_bchbw(rfctl->channel_set, u_band, u_ch, u_bw, u_offset)) {
			/*
			* if operate as slave w/o radar detect,
			* rely on AP on which STA mode connects
			*/
			if (IS_DFS_SLAVE_WITH_RD(rfctl) && !rtw_rfctl_dfs_domain_unknown(rfctl))
				needed = true;
			*ld_sta_in_dfs = true;
		}
		goto exit;
	}

	if (!MSTATE_AP_NUM(mstate) && !MSTATE_MESH_NUM(mstate)) {
		/* No working AP/Mesh mode */
		goto exit;
	}

	if (!rtw_chset_is_dfs_bchbw(rfctl->channel_set, u_band, u_ch, u_bw, u_offset))
		goto exit;

	needed = true;

exit:
	return needed;
}

static void rtw_dfs_rd_en_decision(struct dvobj_priv *dvobj, enum phl_band_idx hwband
	, _adapter *adapter, struct _ADAPTER_LINK *alink, u8 mlme_act, u8 excl_ifbmp)
{
	struct rf_ctl_t *rfctl = dvobj_to_rfctl(dvobj);
	u8 band_idx;

	for (band_idx = HW_BAND_0; band_idx < HW_BAND_MAX; band_idx++) {
		struct mi_state mstate;
		u8 ifbmp;
		enum band_type u_band;
		u8 u_ch, u_bw, u_offset;
		bool ld_sta_in_dfs;
		bool needed;

		/* hwband < HW_BAND_MAX means specific hwband */
		if (hwband < HW_BAND_MAX && hwband != band_idx)
			continue;

		/* alink != NULL means specific hwband */
		if (alink && band_idx != ALINK_GET_HWBAND(alink))
			continue;

		ld_sta_in_dfs = false;
		needed = false;

		if (mlme_act == MLME_ACTION_NONE
			|| mlme_act == MLME_OPCH_SWITCH
		) {
			ifbmp = ~excl_ifbmp;
			rtw_mi_status_by_hwband_ifbmp(dvobj, band_idx, ifbmp, &mstate);
			rtw_mi_get_bch_setting_union_by_hwband_ifbmp(dvobj, band_idx, ifbmp, &u_band, &u_ch, &u_bw, &u_offset);

		} else {
			struct _ADAPTER_LINK *alink_by_hwband;

			if (alink)
				alink_by_hwband = alink;
			else
				alink_by_hwband = rtw_get_adapter_link_by_hwband(adapter, band_idx);

			ifbmp = ~excl_ifbmp & ~BIT(adapter->iface_id);
			rtw_mi_status_by_hwband_ifbmp(dvobj, band_idx, ifbmp, &mstate);
			rtw_mi_get_bch_setting_union_by_hwband_ifbmp(dvobj, band_idx, ifbmp, &u_band, &u_ch, &u_bw, &u_offset);

			switch (mlme_act) {
			case MLME_STA_CONNECTING:
				MSTATE_STA_LG_NUM(&mstate)++;
				break;
			case MLME_STA_CONNECTED:
				MSTATE_STA_LD_NUM(&mstate)++;
				break;
			case MLME_STA_DISCONNECTED:
				break;
			#ifdef CONFIG_AP_MODE
			case MLME_AP_STARTED:
				MSTATE_AP_NUM(&mstate)++;
				break;
			case MLME_AP_STOPPED:
				break;
			#endif
			#ifdef CONFIG_RTW_MESH
			case MLME_MESH_STARTED:
				MSTATE_MESH_NUM(&mstate)++;
				break;
			case MLME_MESH_STOPPED:
				break;
			#endif
			default:
				rtw_warn_on(1);
				break;
			}

			if (alink_by_hwband) {
				enum band_type band = ALINK_GET_BAND(alink_by_hwband);
				u8 ch = ALINK_GET_CH(alink_by_hwband);
				u8 bw = ALINK_GET_BW(alink_by_hwband);
				u8 offset = ALINK_GET_OFFSET(alink_by_hwband);

				if (u_ch) {
					if (!MLME_IS_OPCH_SW(adapter) && CHK_MLME_STATE(adapter, WIFI_UNDER_LINKING | WIFI_ASOC_STATE)) {
						if (!rtw_is_bchbw_grouped(band, ch, bw, offset, u_band, u_ch, u_bw, u_offset)) {
							RTW_WARN(FUNC_HWBAND_FMT" "ADPT_FMT" can't sync %u,%u,%u,%u with %u,%u,%u,%u\n"
								, FUNC_HWBAND_ARG(band_idx), ADPT_ARG(adapter)
								, band, ch, bw, offset, u_band, u_ch, u_bw, u_offset);
							goto apply;
						}

						rtw_sync_bchbw(&band, &ch, &bw, &offset, &u_band, &u_ch, &u_bw, &u_offset);
					}
				} else {
					u_band = band;
					u_ch = ch;
					u_bw = bw;
					u_offset = offset;
				}
			}
		}

		needed = _rtw_dfs_rd_en_decision(rfctl, &mstate, u_band, u_ch, u_bw, u_offset, &ld_sta_in_dfs);

apply:
		if (adapter)
			RTW_INFO(FUNC_HWBAND_FMT" needed:%d, "ADPT_FMT" mlme_act:%u, excl_ifbmp:0x%02x\n"
				, FUNC_HWBAND_ARG(band_idx), needed, ADPT_ARG(adapter), mlme_act, excl_ifbmp);
		else
			RTW_INFO(FUNC_HWBAND_FMT" needed:%d, excl_ifbmp:0x%02x\n"
				, FUNC_HWBAND_ARG(band_idx), needed, excl_ifbmp);

		RTW_INFO(FUNC_HWBAND_FMT" ld_sta_num:%u, lg_sta_num:%u, ap_num:%u, mesh_num:%u, %u,%u,%u,%u\n"
			, FUNC_HWBAND_ARG(band_idx), MSTATE_STA_LD_NUM(&mstate), MSTATE_STA_LG_NUM(&mstate)
			, MSTATE_AP_NUM(&mstate), MSTATE_MESH_NUM(&mstate)
			, u_band, u_ch, u_bw, u_offset);

		if (needed == _TRUE)
			rtw_dfs_rd_enable(rfctl, band_idx, u_ch, u_bw, u_offset, ld_sta_in_dfs);
		else
			rtw_dfs_rd_disable(rfctl, band_idx, u_ch, u_bw, u_offset, ld_sta_in_dfs);
	}
}

void rtw_dfs_rd_en_dec_on_mlme_act(_adapter *adapter, struct _ADAPTER_LINK *alink, u8 mlme_act, u8 excl_ifbmp)
{
	if (adapter && mlme_act != MLME_ACTION_NONE)
		rtw_dfs_rd_en_decision(adapter_to_dvobj(adapter), HW_BAND_MAX, adapter, alink, mlme_act, excl_ifbmp);

	rtw_warn_on(!adapter);
	rtw_warn_on(mlme_act == MLME_ACTION_NONE);
}

void rtw_dfs_rd_en_dec_update(struct dvobj_priv *dvobj, enum phl_band_idx hwband)
{
	rtw_dfs_rd_en_decision(dvobj, hwband, NULL, NULL, MLME_ACTION_NONE, 0);
}

u8 rtw_dfs_rd_en_decision_cmd(struct dvobj_priv *dvobj, enum phl_band_idx hwband)
{
	struct cmd_obj *cmdobj;
	struct drvextra_cmd_parm *parm;
	struct cmd_priv *cmdpriv = &dvobj->cmdpriv;
	_adapter *adapter = dvobj_get_primary_adapter(dvobj);
	u8 res = _FAIL;

	cmdobj = rtw_zmalloc(sizeof(struct cmd_obj));
	if (cmdobj == NULL)
		goto exit;

	cmdobj->padapter = adapter;

	parm = rtw_zmalloc(sizeof(struct drvextra_cmd_parm));
	if (parm == NULL) {
		rtw_mfree(cmdobj, sizeof(struct cmd_obj));
		goto exit;
	}

	parm->ec_id = DFS_RADAR_DETECT_EN_DEC_WK_CID;
	parm->type = hwband;
	parm->size = 0;
	parm->pbuf = NULL;

	init_h2fwcmd_w_parm_no_rsp(cmdobj, parm, CMD_SET_DRV_EXTRA);
	CMD_OBJ_SET_HWBAND(cmdobj, hwband);
	res = rtw_enqueue_cmd(cmdpriv, cmdobj);

exit:
	return res;
}
#endif /* CONFIG_DFS_MASTER */

/* choose channel with shortest waiting (non ocp + cac) time */
static bool rtw_choose_shortest_waiting_ch(struct rf_ctl_t *rfctl
	, enum band_type sel_band, u8 sel_ch, u8 max_bw
	, enum band_type *dec_band, u8 *dec_ch, u8 *dec_bw, u8 *dec_offset
	, u8 e_flags, u8 d_flags, enum band_type cur_band, u8 cur_ch, bool by_int_info, u8 mesh_only)
{
#ifndef DBG_CHOOSE_SHORTEST_WAITING_CH
#define DBG_CHOOSE_SHORTEST_WAITING_CH 0
#endif
	struct dvobj_priv *dvobj = rfctl_to_dvobj(rfctl);
	struct registry_priv *regsty = dvobj_to_regsty(dvobj);
	enum band_type band;
	u8 ch, bw, offset;
	enum band_type band_c = BAND_MAX;
	u8 ch_c = 0, bw_c = 0, offset_c = 0;
	int i;
	u32 min_waiting_ms = 0;
	u16 int_factor_c = 0;

	if (!dec_ch || !dec_bw || !dec_offset) {
		rtw_warn_on(1);
		return _FALSE;
	}

	RTW_INFO("%s: sel_ch:%s-%u max_bw:%u e_flags:0x%02x d_flags:0x%02x cur_ch:%s-%u within_sb:%d%s%s\n"
		, __func__, band_str(sel_band), sel_ch, max_bw, e_flags, d_flags
		, band_str(cur_band), cur_ch, rfctl->ch_sel_within_same_band
		, by_int_info ? " int" : "", mesh_only ? " mesh_only" : "");

	/* full search and narrow bw judegement first to avoid potetial judegement timing issue */
	for (bw = CHANNEL_WIDTH_20; bw <= max_bw; bw++) {
		if (!rtw_hw_is_bw_support(dvobj, bw))
			continue;

		for (i = 0; i < rfctl->max_chan_nums; i++) {
			u32 non_ocp_ms = 0;
			u32 cac_ms = 0;
			u32 waiting_ms = 0;
			u16 int_factor = 0;
			bool dfs_ch;
			bool non_ocp;
			bool long_cac;

			band = rfctl->channel_set[i].band;
			ch = rfctl->channel_set[i].ChannelNum;
			if (sel_band != BAND_MAX) {
				if (band != sel_band)
					continue;
			} else if (rfctl->ch_sel_within_same_band && cur_band != band)
				continue;
			if (sel_ch) {
				if (ch != sel_ch)
					continue;
			}

			if (band == BAND_ON_24G) {
				if (bw > REGSTY_BW_2G(regsty))
					continue;
			#if CONFIG_IEEE80211_BAND_5GHZ
			} else if (band == BAND_ON_5G) {
				if (bw > REGSTY_BW_5G(regsty))
					continue;
			#endif
			#if CONFIG_IEEE80211_BAND_6GHZ
			} else if (band == BAND_ON_6G) {
				if (bw > REGSTY_BW_6G(regsty))
					continue;
			#endif
			}

			if (mesh_only && band == BAND_ON_24G && ch >= 5 && ch <= 9 && bw > CHANNEL_WIDTH_20)
				continue;

			if (!rtw_get_offset_by_bchbw(band, ch, bw, &offset))
				continue;

			if (!rtw_chset_is_bchbw_valid(rfctl->channel_set, band, ch, bw, offset, 0, 0))
				continue;

			if ((e_flags & RTW_CHF_DFS) || (d_flags & RTW_CHF_DFS)) {
				dfs_ch = rtw_chset_is_dfs_bchbw(rfctl->channel_set, band, ch, bw, offset);
				if (((e_flags & RTW_CHF_DFS) && !dfs_ch)
					|| ((d_flags & RTW_CHF_DFS) && dfs_ch))
					continue;
			}

			if ((e_flags & RTW_CHF_LONG_CAC) || (d_flags & RTW_CHF_LONG_CAC)) {
				long_cac = rtw_is_long_cac_bch(band, ch, bw, offset, rtw_rfctl_get_dfs_domain(rfctl));
				if (((e_flags & RTW_CHF_LONG_CAC) && !long_cac)
					|| ((d_flags & RTW_CHF_LONG_CAC) && long_cac))
					continue;
			}

			if ((e_flags & RTW_CHF_NON_OCP) || (d_flags & RTW_CHF_NON_OCP)) {
				non_ocp = rtw_chset_is_bchbw_non_ocp(rfctl->channel_set, band, ch, bw, offset);
				if (((e_flags & RTW_CHF_NON_OCP) && !non_ocp)
					|| ((d_flags & RTW_CHF_NON_OCP) && non_ocp))
					continue;
			}

			#ifdef CONFIG_DFS_MASTER
			waiting_ms = rtw_get_ch_waiting_ms(rfctl, band, ch, bw, offset, &non_ocp_ms, &cac_ms);
			#endif

			#if 0 /* def CONFIG_RTW_ACS */
			if (by_int_info) {
				/* for now, consider only primary channel */
				int_factor = hal_data->acs.interference_time[i];
			}
			#endif

			if (DBG_CHOOSE_SHORTEST_WAITING_CH)
				RTW_INFO("%s:%s,%u,%u,%u %u(non_ocp:%u, cac:%u), int:%u\n"
					, __func__, band_str(band), ch, bw, offset, waiting_ms, non_ocp_ms, cac_ms, int_factor);

			if (ch_c == 0
				/* first: smaller wating time */
				|| min_waiting_ms > waiting_ms
				/* then: less interference */
				|| (min_waiting_ms == waiting_ms && int_factor_c > int_factor)
				/* then: wider bw */
				|| (min_waiting_ms == waiting_ms && int_factor_c == int_factor && bw > bw_c)
				/* if all condition equal, same channel -> same band prefer */
				|| (min_waiting_ms == waiting_ms && int_factor_c == int_factor && bw == bw_c
					&& (((cur_band != band_c || cur_ch != ch_c) && (cur_band == band && cur_ch == ch))
						|| (cur_band != band_c && cur_band == band))
					)
			) {
				band_c = band;
				ch_c = ch;
				bw_c = bw;
				offset_c = offset;
				min_waiting_ms = waiting_ms;
				int_factor_c = int_factor;
			}
		}
	}

	if (ch_c != 0) {
		RTW_INFO("%s: select %s,%u,%u,%u waiting_ms:%u\n"
			, __func__, band_str(band_c), ch_c, bw_c, offset_c, min_waiting_ms);
		if (dec_band)
			*dec_band = band_c;
		*dec_ch = ch_c;
		*dec_bw = bw_c;
		*dec_offset = offset_c;
		return _TRUE;
	} else {
		RTW_INFO("%s: not found\n", __func__);
		if (d_flags == 0)
			rtw_warn_on(1);
	}

	return _FALSE;
}

bool rtw_rfctl_choose_bchbw(struct rf_ctl_t *rfctl
	, enum band_type sel_band, u8 sel_ch, u8 max_bw
	, enum band_type cur_band, u8 cur_ch
	, enum band_type *band, u8 *ch, u8 *bw, u8 *offset
	, bool by_int_info, u8 mesh_only, const char *caller)
{
	bool ch_avail = _FALSE;

#if defined(CONFIG_DFS_MASTER)
	if (!rtw_rfctl_dfs_domain_unknown(rfctl)) {
		if (rfctl->radar_detected
			&& rfctl->dbg_dfs_choose_dfs_ch_first
		) {
			ch_avail = rtw_choose_shortest_waiting_ch(rfctl, sel_band, sel_ch, max_bw
						, band, ch, bw, offset
						, RTW_CHF_DFS, 0
						, cur_band, cur_ch, by_int_info, mesh_only);
			if (ch_avail == _TRUE) {
				RTW_INFO("%s choose 5G DFS channel for debug\n", caller);
				goto exit;
			}
		}

		if (rfctl->radar_detected
			&& (rfctl->dfs_ch_sel_e_flags || rfctl->dfs_ch_sel_d_flags)
		) {
			ch_avail = rtw_choose_shortest_waiting_ch(rfctl, sel_band, sel_ch, max_bw
						, band, ch, bw, offset
						, rfctl->dfs_ch_sel_e_flags, rfctl->dfs_ch_sel_d_flags
						, cur_band, cur_ch, by_int_info, mesh_only);
			if (ch_avail == _TRUE) {
				RTW_INFO("%s choose with dfs_ch_sel_ e_flags:0x%02x d_flags:0x%02x for debug\n"
					, caller, rfctl->dfs_ch_sel_e_flags, rfctl->dfs_ch_sel_d_flags);
				goto exit;
			}
		}

		ch_avail = rtw_choose_shortest_waiting_ch(rfctl, sel_band, sel_ch, max_bw
					, band, ch, bw, offset
					, 0, 0
					, cur_band, cur_ch, by_int_info, mesh_only);
	} else
#endif /* defined(CONFIG_DFS_MASTER) */
	{
		ch_avail = rtw_choose_shortest_waiting_ch(rfctl, sel_band, sel_ch, max_bw
					, band, ch, bw, offset
					, 0, RTW_CHF_DFS
					, cur_band, cur_ch, by_int_info, mesh_only);
	}
#if defined(CONFIG_DFS_MASTER)
exit:
#endif
	if (ch_avail == _FALSE)
		RTW_WARN("%s no available channel\n", caller);

	return ch_avail;
}

bool rtw_rfctl_choose_chbw(struct rf_ctl_t *rfctl, u8 sel_ch, u8 max_bw, u8 cur_ch, RTW_FUNC_2G_5G_ONLY
	u8 *ch, u8 *bw, u8 *offset, bool by_int_info, u8 mesh_only, const char *caller)
{
	enum band_type sel_band = sel_ch ? (rtw_is_2g_ch(sel_ch) ? BAND_ON_24G : BAND_ON_5G) : BAND_MAX;
	enum band_type cur_band = rtw_is_2g_ch(cur_ch) ? BAND_ON_24G : BAND_ON_5G;
	enum band_type *band = NULL;

	return rtw_rfctl_choose_bchbw(rfctl
		, sel_band, sel_ch, max_bw
		, cur_band, cur_ch
		, band, ch, bw, offset
		, by_int_info, mesh_only, caller);
}

void rtw_rfctl_dfs_init(struct rf_ctl_t *rfctl, struct registry_priv *regsty)
{
	rfctl->ch_sel_within_same_band = 1;

#ifdef CONFIG_DFS_MASTER
	rfctl->dfs_region_domain = regsty->dfs_region_domain;
	rfctl->cac_start_time = rfctl->cac_end_time = RTW_CAC_STOPPED;
	rtw_init_timer(&(rfctl->radar_detect_timer), rtw_dfs_rd_timer_hdl, rfctl);
#endif

#if CONFIG_DFS_SLAVE_WITH_RADAR_DETECT
	rfctl->dfs_slave_with_rd = 1;
#endif
}

