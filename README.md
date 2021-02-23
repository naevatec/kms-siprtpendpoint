[![License badge](https://img.shields.io/badge/license-Apache2-orange.svg)](http://www.apache.org/licenses/LICENSE-2.0)
[![Documentation badge](https://readthedocs.org/projects/fiware-orion/badge/?version=latest)](https://doc-kurento.readthedocs.io)
[![Docker badge](https://img.shields.io/docker/pulls/fiware/orion.svg)](https://hub.docker.com/r/fiware/stream-oriented-kurento/)
[![Support badge]( https://img.shields.io/badge/support-sof-yellowgreen.svg)](https://stackoverflow.com/questions/tagged/kurento)

[![][KurentoImage]][Kurento]

Copyright 2019 [Kurento]. Licensed under [Apache 2.0 License].

[Kurento]: https://kurento.org
[KurentoImage]: https://secure.gravatar.com/avatar/21a2a12c56b2a91c8918d5779f1778bf?s=120
[Apache 2.0 License]: http://www.apache.org/licenses/LICENSE-2.0



kms-siprtpendpoint
=======================

SipRtpEndpoint is a replacement for RtpEndpoint that allows renegotiation of media. Currently RtpEndpoint once SDP have been negotiated 
does not allow to renegotiate media. That is further invocations of `generateOffer`, `processOffer` and `processAnswer` result in an error about the RtpEndpoint already negotiated.

This is a drawback when integrating. among other cases, with SIP VoIP networks that use [SIP 183 provisional media establishment](https://tools.ietf.org/html/draft-ietf-sip-183-00) because in that cases for a single generated offer, remote network can answer back with several SDP answers. Each SDP answer means some media (temporary) between remote endpoint and local RtpEndpoint. Each time a temporary SDP answer is received, old media should be discarded and new media according to the temporary answer should be established.

To this aim, SipRtpEndpoint behaves exactly as an RtpEndpoint but allows to call any of the SDP negotitation APIs (`generateOffer`, `processOffer` or `processAnswer`) any time and as much times as needed. Each time one of this APIs are called, old media is discarded and the correspoding new media is established.

Another element that many VoIP providers present is that they can change SSRC on the fly  of a live RTP flow. This may be due to internal switching of media in VoIP provider, but it makes the RtpEndpoint useless as any change on the fly to the SSRC takes the RtpEndpoint to an open ended pipeline that causes a "not linked" error and pauses the RtpEndpoint. SipRtpEndpoint supports SSRC switching on the fly by examining incoming SSRC in RTP/RTCP packets and if not used in previous media connections it let them pass, but changing in the RTP/RTCP packet the SSRC to the one of the first packet received in current RTP flow. We also need to adapt timestamping on switched media so that Kurento pipeline does not get disrupted.

SipRtpEndpoint is implemented as a derived class from BaseRtpEndpoint to provide the same features that RtrEndpoint. And internally is implemented as a RtpEndpoint connected through a pair of PassThrough elements (one for input media and the other for output media). First time SDP is negotiated, that negotiation is delegated on internal RtpEndpoint. Whenever a renegotiation is done, old internal RtpEndpoint is closed and discarded and a new one is instantiated and reconnected to Passthrough elements and negotiation is delegated on that new RtpEndpoint.

The main involved APIs are:
* `generateOffer` when renegotiation is done using a new `generateOffer` call, old RtpEndpoint is discarded and just the `generateOffer` is delegated on the new internal RtpEndpoint.
* `processOffer` when renegotiation is done using a new `processOffer` call, old RtpEndpoint is discarded and just the `processOffer` is delegated on the new internal RtpEndpoint.
* `processAnswer` when renegotiation is done using a new `processAnswer` call, is a little bit more complicated, because the answeer corresponds to an original offer generated using `generateOffer`on this same SipRtpEndpoint. Thus local media description should be preserved, mainly with regard to socket ports and SSRC's. So, old RtpEndpoint is discarded, but before being discarded, allocated Sockets and SSRCs are preserved and feed to the new instantiated RtpEndpoint so that local media preserves socket ports and SSRCs as expected. This behaviour also introduces a problem that is, if remote old media is not stopped before renegotiation, as we are preserving sockets, thos sockets may be receiving old and new media flows simultaneously. Due to the architecture of RtpEndpoint in KMS this forces to filter out old media in new RtpEndpoint.
  
  



About Kurento
=============

Kurento is an open source software project providing a platform suitable for creating modular applications with advanced real-time communication capabilities. For knowing more about Kurento, please visit the Kurento project website: https://www.kurento.org.

Kurento is part of [FIWARE]. For further information on the relationship of FIWARE and Kurento check the [Kurento FIWARE Catalog Entry]. Kurento is also part of the [NUBOMEDIA] research initiative.

[FIWARE]: http://www.fiware.org
[Kurento FIWARE Catalog Entry]: http://catalogue.fiware.org/enablers/stream-oriented-kurento
[NUBOMEDIA]: http://www.nubomedia.eu



Documentation
-------------

The Kurento project provides detailed [documentation] including tutorials, installation and development guides. The [Open API specification], also known as *Kurento Protocol*, is available on [apiary.io].

[documentation]: https://www.kurento.org/documentation
[Open API specification]: http://kurento.github.io/doc-kurento/
[apiary.io]: http://docs.streamoriented.apiary.io/



Useful Links
------------

Usage:

* [Installation Guide](http://doc-kurento.readthedocs.io/en/stable/user/installation.html)
* [Compilation Guide](http://doc-kurento.readthedocs.io/en/stable/dev/dev_guide.html#developing-kms)
* [Contribution Guide](http://doc-kurento.readthedocs.io/en/stable/project/contribute.html)

Issues:

* [Bug Tracker](https://github.com/Kurento/bugtracker/issues)
* [Support](http://doc-kurento.readthedocs.io/en/stable/user/support.html)

News:

* [Kurento Blog](https://www.kurento.org/blog)
* [Google Groups](https://groups.google.com/forum/#!forum/kurento)



Source
------

All source code belonging to the Kurento project can be found in the [Kurento GitHub organization page].

[Kurento GitHub organization page]: https://github.com/Kurento



Licensing and distribution
--------------------------

Copyright 2018 Kurento

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
