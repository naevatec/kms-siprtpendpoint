/*
 * (C) Copyright 2015 Kurento (http://kurento.org/)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */


#include "kmsrtpfilterutils.h"
#include <commons/constants.h>
#include <gst/rtp/gstrtpbuffer.h>
#include <gst/rtp/gstrtcpbuffer.h>




static gboolean
check_ssrc (guint32 ssrc, SipFilterSsrcInfo* filter_info)
{
	if (filter_info->expected == 0) {
		GList* it = filter_info->old;

		while (it != NULL) {
			if (ssrc == GPOINTER_TO_UINT(it->data))
				return TRUE;
			it = it->next;
		}
		filter_info->expected = ssrc;
		return FALSE;
	}
	if (ssrc == filter_info->expected)
		return FALSE;
	return TRUE;
}

static GstPadProbeReturn
filter_ssrc_rtp_buffer (GstBuffer *buffer, SipFilterSsrcInfo* filter_info)
{
	GstRTPBuffer rtp_buffer =  GST_RTP_BUFFER_INIT;

	if (gst_rtp_buffer_map (buffer, GST_MAP_READ, &rtp_buffer)) {
		GST_DEBUG ("filter old ssrc RTP buffer");
		guint32 checked_ssrc = gst_rtp_buffer_get_ssrc (&rtp_buffer);

		gst_rtp_buffer_unmap (&rtp_buffer);
		if (check_ssrc (checked_ssrc, filter_info)) {
			GST_INFO ("RTP packet dropped from a previous RTP flow with SSRC %u", checked_ssrc);
			return GST_PAD_PROBE_DROP;
		} else {
			// We are pushing an EXPECTED SSRC, so after its processing this probe is no longer needed
			GST_DEBUG ("filter old ssrc forwarded buffer %u", checked_ssrc);
			return GST_PAD_PROBE_OK;
		}
	}

	GST_WARNING ("Buffer not mapped to RTP");
	return GST_PAD_PROBE_OK;
}


static gboolean
filter_buffer (GstBuffer ** buffer, guint idx, gpointer user_data)
{
	SipFilterSsrcInfo* filter_info = (SipFilterSsrcInfo*)user_data;

	if (filter_ssrc_rtp_buffer(*buffer, filter_info) == GST_PAD_PROBE_DROP)
		*buffer = NULL;

	return TRUE;
}

static GstPadProbeReturn
filter_ssrc_rtp (GstPad *pad, GstPadProbeInfo *info, gpointer user_data)
{
	SipFilterSsrcInfo* filter_info = (SipFilterSsrcInfo*) user_data;
	GstBuffer *buffer;

	GST_DEBUG ("Filtering RTP packets from previous flows to this receiver");
	buffer = GST_PAD_PROBE_INFO_BUFFER (info);
	if (buffer != NULL) {
		GST_DEBUG ("RTP buffer received from Filtering RTP packets from previous flows to this receiver");

		return filter_ssrc_rtp_buffer (buffer, filter_info);
	} else  {
		GstBufferList *buffer_list;

		buffer_list = gst_pad_probe_info_get_buffer_list (info);

		if (buffer_list != NULL) {
			GST_DEBUG ("filter old ssrc buffer list RTP");
			if (!gst_buffer_list_foreach(buffer_list, filter_buffer, user_data))
				GST_WARNING("Filtering buffer list for old ssrc failed");
		}
	}
	return GST_PAD_PROBE_OK;
}

static GstPadProbeReturn
filter_ssrc_rtcp (GstPad *pad, GstPadProbeInfo *info, gpointer user_data)
{
	SipFilterSsrcInfo* filter_info = (SipFilterSsrcInfo*)user_data;
	GstBuffer *buffer;

	buffer = GST_PAD_PROBE_INFO_BUFFER (info);

	GstRTCPBuffer rtcp_buffer = GST_RTCP_BUFFER_INIT;

	GST_DEBUG ("Filtering RTCP buffer from previous flows to this receiver");
    if (gst_rtcp_buffer_map (buffer, GST_MAP_READ, &rtcp_buffer)) {
    	GstRTCPPacket packet;
		gboolean has_packet;

		has_packet = gst_rtcp_buffer_get_first_packet (&rtcp_buffer, &packet);

		GST_DEBUG ("Filtering RTCP packets from previous flows to this receiver");
    	gst_rtcp_buffer_unmap (&rtcp_buffer);
		return  GST_PAD_PROBE_DROP;

    	while (has_packet) {
    		GstRTCPType  packet_type = gst_rtcp_packet_get_type (&packet);

    		if (packet_type == GST_RTCP_TYPE_SR) {
        		guint32 ssrc, rtptime, packet_count, octet_count;
        		guint64 ntptime;

    			gst_rtcp_packet_sr_get_sender_info    (&packet, &ssrc, &ntptime, &rtptime, &packet_count, &octet_count);
    			if (check_ssrc (ssrc, filter_info)) {
    				GST_DEBUG("Unexpected SSRC RTCP packet received: %u, expected: %u", ssrc, filter_info->expected);
    				gst_rtcp_packet_remove (&packet);
    			}
    		}
    		has_packet = gst_rtcp_packet_move_to_next (&packet);
    	}
    	gst_rtcp_buffer_unmap (&rtcp_buffer);
	}

    return GST_PAD_PROBE_OK;
}


gulong
kms_sip_rtp_filter_setup_probe_rtp (GstPad *pad, SipFilterSsrcInfo* filter_info)
{
	if (filter_info != NULL) {
		GST_DEBUG("Installing RTP probe for %s", GST_ELEMENT_NAME(gst_pad_get_parent_element (pad)));
		return gst_pad_add_probe (pad, GST_PAD_PROBE_TYPE_BUFFER | GST_PAD_PROBE_TYPE_BUFFER_LIST | GST_PAD_PROBE_TYPE_PUSH | GST_PAD_PROBE_TYPE_PULL,
				(GstPadProbeCallback) filter_ssrc_rtp, GUINT_TO_POINTER(filter_info), NULL);
	} else {
	    GST_DEBUG("No RTP probe installed for %s", GST_ELEMENT_NAME(gst_pad_get_parent_element (pad)));
	    return 0;
	}
}

gulong
kms_sip_rtp_filter_setup_probe_rtcp (GstPad *pad, SipFilterSsrcInfo* filter_info)
{
	if (filter_info != NULL) {
	    GST_DEBUG("Installing RTCP probe for %s", GST_ELEMENT_NAME(gst_pad_get_parent_element (pad)));
	    return gst_pad_add_probe (pad, GST_PAD_PROBE_TYPE_BUFFER,
	        (GstPadProbeCallback) filter_ssrc_rtcp, filter_info, NULL);
	} else {
	    GST_DEBUG("No RTCP probe installed for %s", GST_ELEMENT_NAME(gst_pad_get_parent_element (pad)));
	    return 0;
	}
}


void
kms_sip_rtp_filter_release_probe_rtp (GstPad *pad, gulong probe_id)
{
	if (probe_id == 0)
		return;

    GST_DEBUG("Removing RTP probe for %s", GST_ELEMENT_NAME(gst_pad_get_parent_element (pad)));
    gst_pad_remove_probe (pad, probe_id);

}

void
kms_sip_rtp_filter_release_probe_rtcp (GstPad *pad, gulong probe_id)
{
	if (probe_id == 0)
		return;

    GST_DEBUG("Removing RTCP probe for %s", GST_ELEMENT_NAME(gst_pad_get_parent_element (pad)));
    gst_pad_remove_probe (pad, probe_id);

}

SipFilterSsrcInfo*
kms_sip_rtp_filter_create_filtering_info (guint32 expected, SipFilterSsrcInfo* previous)
{
	SipFilterSsrcInfo* info = g_new (SipFilterSsrcInfo, 1);

	info->expected = expected;
	info->old = NULL;
	if (previous != NULL) {
		GList* it = previous->old;

		if (previous->expected != 0)
			info->old = g_list_append (info->old, GUINT_TO_POINTER(previous->expected));
		while (it != NULL) {
			info->old = g_list_append (info->old, it->data);
			it = it->next;
		}
	}

	return info;
}

void kms_sip_rtp_filter_release_filtering_info (SipFilterSsrcInfo* info)
{
	if (info->old != NULL) {
		g_list_free (info->old);
	}
	g_free (info);
}


