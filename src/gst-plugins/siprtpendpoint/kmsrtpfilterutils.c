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
check_ssrc (guint32 ssrc, GList *old_ssrc)
{
	GList *it = old_ssrc;

	while (it != NULL) {
		if (ssrc == GPOINTER_TO_UINT(it->data))
			return TRUE;
		it = it->next;
	}
	return FALSE;
}

static GstPadProbeReturn
filter_old_ssrc_rtp_buffer (GstBuffer *buffer, GList *old_ssrc)
{
	GstRTPBuffer rtp_buffer =  GST_RTP_BUFFER_INIT;

	if (gst_rtp_buffer_map (buffer, GST_MAP_READ, &rtp_buffer)) {
		GST_DEBUG ("filter old ssrc RTP buffer");
		guint32 checked_ssrc = gst_rtp_buffer_get_ssrc (&rtp_buffer);

		gst_rtp_buffer_unmap (&rtp_buffer);
		if (check_ssrc (checked_ssrc, old_ssrc)) {
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
	GList *old_ssrc = user_data;

	if (filter_old_ssrc_rtp_buffer(*buffer, old_ssrc) == GST_PAD_PROBE_DROP)
		*buffer = NULL;

	return TRUE;
}

static GstPadProbeReturn
filter_old_ssrc_rtp (GstPad *pad, GstPadProbeInfo *info, gpointer user_data)
{
	GList *old_ssrc = user_data;
	GstBuffer *buffer;

	GST_DEBUG ("Filtering RTP packets from previous flows to this receiver");
	buffer = GST_PAD_PROBE_INFO_BUFFER (info);
	if (buffer != NULL) {
		GST_DEBUG ("RTP buffer received from Filtering RTP packets from previous flows to this receiver");

		return filter_old_ssrc_rtp_buffer (buffer, old_ssrc);
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
filter_old_ssrc_rtcp (GstPad *pad, GstPadProbeInfo *info, gpointer user_data)
{
	GList *old_ssrc = user_data;
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
    			if (check_ssrc (ssrc, old_ssrc)) {
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
kms_sip_rtp_filter_setup_probe_rtp (GstPad *pad, GList *old_ssrc)
{
    GST_DEBUG("Installing RTP probe for %s", GST_ELEMENT_NAME(gst_pad_get_parent_element (pad)));
    return gst_pad_add_probe (pad, GST_PAD_PROBE_TYPE_BUFFER | GST_PAD_PROBE_TYPE_BUFFER_LIST | GST_PAD_PROBE_TYPE_PUSH | GST_PAD_PROBE_TYPE_PULL,
        (GstPadProbeCallback) filter_old_ssrc_rtp, g_list_copy(old_ssrc), (GDestroyNotify) g_list_free);
}

gulong
kms_sip_rtp_filter_setup_probe_rtcp (GstPad *pad, GList *old_ssrc)
{
    GST_DEBUG("Installing RTCP probe for %s", GST_ELEMENT_NAME(gst_pad_get_parent_element (pad)));
    return gst_pad_add_probe (pad, GST_PAD_PROBE_TYPE_BUFFER,
        (GstPadProbeCallback) filter_old_ssrc_rtcp, g_list_copy(old_ssrc), (GDestroyNotify) g_list_free);
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



