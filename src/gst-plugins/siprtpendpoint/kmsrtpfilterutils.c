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
#include <gst/net/gstnet.h>
#include <sys/time.h>

#define GST_CAT_DEFAULT kms_sip_rtp_endpoint_debug
GST_DEBUG_CATEGORY_EXTERN(GST_CAT_DEFAULT);

static gboolean
check_source_address (GstBuffer *buffer, GInetSocketAddress *peer_address)
{
	GstNetAddressMeta *address_meta;
	GInetSocketAddress *source_address;
	GInetAddress *inet_address_peer;
	GInetAddress *inet_address_source;

	// If no filter, we don't let RTP buffer get through
	if (peer_address == NULL) {
		return FALSE;
	}
	// If no RTP source information we don't let it go through
	address_meta = gst_buffer_get_net_address_meta(buffer);
	if (address_meta == NULL) {
		GST_DEBUG("check_source_address: no source address in buffer");
		return FALSE;
	}
	source_address = G_INET_SOCKET_ADDRESS(address_meta->addr);
	if (source_address == NULL) {
		GST_DEBUG("check_source_address: empty source address in buffer");
		return FALSE;
	}

	// If port different, just filter out
	if (g_inet_socket_address_get_port(source_address) != g_inet_socket_address_get_port(peer_address)) {
		GST_DEBUG("check_source_address: source port does not match");
		return FALSE;
	}

	inet_address_source = g_inet_socket_address_get_address (source_address);
	inet_address_peer = g_inet_socket_address_get_address (peer_address);
	if (!g_inet_address_get_is_any(inet_address_peer) && !g_inet_address_equal(inet_address_peer, inet_address_source)) {
		GST_DEBUG("check_source_address: source ip address does not match");
		return FALSE;
	}
	return TRUE;
}

static GstPadProbeReturn
filter_ssrc_rtp_buffer (GstBuffer *buffer, SipFilterSsrcInfo* filter_info)
{
	// First we decide if filter out or not RTP buffer depending on source address
	if (!check_source_address (buffer, filter_info->peer_address)) {
		GST_DEBUG("filter_ssrc_rtp_buffer: dropping RTP packet");
		return GST_PAD_PROBE_DROP;
	}

	// We now leave ssrc and timestamp management to downstream gstreamer elements, so no further filtering nor manipulation needed here.
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

	buffer = GST_PAD_PROBE_INFO_BUFFER (info);
	if (buffer != NULL) {
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

	// First we decide if filter out or not RTP buffer depending on source address
	if (!check_source_address (buffer, filter_info->peer_rtcp_address)) {
		GST_DEBUG("filter_ssrc_rtp_buffer: dropping RTCP packet");
		return GST_PAD_PROBE_DROP;
	}

	// We now leave ssrc and timestamp management to downstream gstreamer elements, so no further filtering nor manipulation needed here.
	return GST_PAD_PROBE_OK;
}


gulong
kms_sip_rtp_filter_setup_probe_rtp (GstPad *pad, SipFilterSsrcInfo* filter_info)
{
	if (filter_info != NULL) {
		GstElement *parent_element;

		parent_element = gst_pad_get_parent_element (pad);
		GST_DEBUG("Installing RTP probe for %s", GST_ELEMENT_NAME(parent_element));
		gst_object_unref (parent_element);
		return gst_pad_add_probe (pad, GST_PAD_PROBE_TYPE_BUFFER | GST_PAD_PROBE_TYPE_BUFFER_LIST | GST_PAD_PROBE_TYPE_PUSH | GST_PAD_PROBE_TYPE_PULL,
				(GstPadProbeCallback) filter_ssrc_rtp, GUINT_TO_POINTER(filter_info), NULL);
	} else {
		GstElement *parent_element;

		parent_element = gst_pad_get_parent_element (pad);
	    GST_DEBUG("No RTP probe installed for %s", GST_ELEMENT_NAME(parent_element));
		gst_object_unref (parent_element);
	    return 0;
	}
}

gulong
kms_sip_rtp_filter_setup_probe_rtcp (GstPad *pad, SipFilterSsrcInfo* filter_info)
{
	if (filter_info != NULL) {
		GstElement *parent_element;

		parent_element = gst_pad_get_parent_element (pad);
	    GST_DEBUG("Installing RTCP probe for %s", GST_ELEMENT_NAME(parent_element));
		gst_object_unref (parent_element);
	    return gst_pad_add_probe (pad, GST_PAD_PROBE_TYPE_BUFFER,
	        (GstPadProbeCallback) filter_ssrc_rtcp, filter_info, NULL);
	} else {
		GstElement *parent_element;

		parent_element = gst_pad_get_parent_element (pad);
	    GST_DEBUG("No RTCP probe installed for %s", GST_ELEMENT_NAME(parent_element));
		gst_object_unref (parent_element);
	    return 0;
	}
}


void
kms_sip_rtp_filter_release_probe_rtp (GstPad *pad, gulong probe_id)
{
	GstElement *parent_element;

	if (probe_id == 0)
		return;

	parent_element = gst_pad_get_parent_element (pad);
    GST_DEBUG("Removing RTP probe for %s", GST_ELEMENT_NAME(parent_element));
	gst_object_unref (parent_element);
    gst_pad_remove_probe (pad, probe_id);

}

void
kms_sip_rtp_filter_release_probe_rtcp (GstPad *pad, gulong probe_id)
{
	GstElement *parent_element;

	if (probe_id == 0)
		return;

	parent_element = gst_pad_get_parent_element (pad);
	GST_DEBUG("Removing RTCP probe for %s", GST_ELEMENT_NAME(parent_element));
	gst_object_unref (parent_element);
    gst_pad_remove_probe (pad, probe_id);

}

SipFilterSsrcInfo*
kms_sip_rtp_filter_create_filtering_info (SipFilterSsrcInfo* previous, guint media_type)
{
	SipFilterSsrcInfo* info = g_new (SipFilterSsrcInfo, 1);
	GInetAddress *addr;
	gchar *addr_str;
	guint port;

	// Initialize filter_info
	info->peer_address = NULL;
	info->peer_rtcp_address = NULL;
	info->media_type = media_type;

	g_rec_mutex_init (&info->mutex);

	if (previous != NULL) {
		port = g_inet_socket_address_get_port (previous->peer_address);
		addr = g_inet_socket_address_get_address (previous->peer_address);
		addr_str = g_inet_address_to_string (addr);
		GST_DEBUG("create_filtering_info, setting expected remote address : %s:%d", addr_str, port);
		g_free(addr_str);
		port = g_inet_socket_address_get_port (previous->peer_rtcp_address);
		addr = g_inet_socket_address_get_address (previous->peer_rtcp_address);
		addr_str = g_inet_address_to_string (addr);
		GST_DEBUG("create_filtering_info, setting expected remote RTCP address : %s:%d", addr_str, port);
		g_free(addr_str);
	}

	return info;
}

void kms_sip_rtp_filter_set_addresses (SipFilterSsrcInfo *filter_info, GInetSocketAddress *rtp_address, GInetSocketAddress *rtcp_address)
{
	if (rtp_address != NULL) {
		filter_info->peer_address = rtp_address;
	}
	if (rtcp_address != NULL) {
		filter_info->peer_rtcp_address = rtcp_address;
	}
}


void kms_sip_rtp_filter_release_filtering_info (SipFilterSsrcInfo* info)
{
	g_rec_mutex_clear (&info->mutex);
	if (info->peer_address != NULL) {
		g_object_unref(info->peer_address);
	}
	if (info->peer_rtcp_address != NULL) {
		g_object_unref(info->peer_rtcp_address);
	}
	g_free (info);
}


void kms_sip_rtp_filter_set_added_client_rtp (GstElement * gstmultiudpsink, gchararray host, gint port, gpointer udata)
{
	SipFilterSsrcInfo *info = (SipFilterSsrcInfo*) udata;
	GInetSocketAddress *addr = (GInetSocketAddress*) g_inet_socket_address_new_from_string (host, port);
	GST_DEBUG("Filtering source RTP %s: %d", host, port);
	if (info->peer_address != NULL)  {
		g_object_unref(info->peer_address);
	}
	info->peer_address = addr;
}

void kms_sip_rtp_filter_set_added_client_rtcp (GstElement * gstmultiudpsink, gchararray host, gint port, gpointer udata)
{
	SipFilterSsrcInfo *info = (SipFilterSsrcInfo*) udata;
	GInetSocketAddress *addr = (GInetSocketAddress*) g_inet_socket_address_new_from_string (host, port);
	GST_DEBUG("Filtering source RTCP %s:%d", host, port);

	if (info->peer_rtcp_address != NULL)  {
		g_object_unref(info->peer_rtcp_address);
	}
	info->peer_rtcp_address = addr;
}


