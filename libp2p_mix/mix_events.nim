# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Events that the Mix library emits for its host. A host listens on the broker
## context that it gives to MixProtocol. Production uses the default context.

{.push raises: [].}

import libp2p/peerid
import brokers/[event_broker, broker_context]

export event_broker, broker_context

EventBroker:
  ## Mix could not dial `peerId`, the next hop of a packet that this node sends
  ## or forwards. The packet is lost. A host can back the peer off.
  type MixHopDialFailed* = object
    peerId*: PeerId
