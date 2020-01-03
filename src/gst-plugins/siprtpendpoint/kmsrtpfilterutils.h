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


#ifndef KMSRTPFILTERUTILS_H_
#define KMSRTPFILTERUTILS_H_

#include <gst/gst.h>

typedef struct _SipFilterSsrcInfo SipFilterSsrcInfo;

struct _SipFilterSsrcInfo {
	guint32 expected;
	GList*  old;
};

gulong
kms_sip_rtp_filter_setup_probe_rtp (GstPad *pad, SipFilterSsrcInfo* filter_info);

gulong
kms_sip_rtp_filter_setup_probe_rtcp (GstPad *pad, SipFilterSsrcInfo* filter_info);

void
kms_sip_rtp_filter_release_probe_rtp (GstPad *pad, gulong probe_id);

void
kms_sip_rtp_filter_release_probe_rtcp (GstPad *pad, gulong probe_id);

SipFilterSsrcInfo*
kms_sip_rtp_filter_create_filtering_info (guint32 expected, SipFilterSsrcInfo* previous);

void kms_sip_rtp_filter_release_filtering_info (SipFilterSsrcInfo* info);

#endif /* KMSRTPFILTERUTILS_H_ */
