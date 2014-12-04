---
layout: page
title: fi_getinfo(3)
tagline: Libfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

fi_getinfo / fi_freeinfo \- Obtain / free fabric interface information

# SYNOPSIS

{% highlight c %}
#include <rdma/fabric.h>

int fi_getinfo(int version, const char *node, const char *service,
        uint64_t flags, struct fi_info *hints, struct fi_info **info);

int fi_freeinfo(struct fi_info *info);

struct fi_info *fi_dupinfo(const struct fi_info *info);
{% endhighlight %}

# ARGUMENTS

*version*
: Interface version requested by application.

*node*
: Optional, name or fabric address to resolve.

*service*
: Optional, service name or port number of address.

*flags*
: Operation flags for the fi_getinfo call.

*hints*
: Reference to an fi_info structure that specifies criteria for
  selecting the returned fabric information.

*info*
: A pointer to a linked list of fi_info structures containing response
  information.

# DESCRIPTION

Returns information about available fabric services for reaching the
specified node or service, subject to any provided hints.  Callers
must provide at least one of the node, service, or hints parameters.
If no matching fabric information is available, info will be set to
NULL.

Based on the input hints, node, and service parameters, a list of
fabric domains and endpoints will be returned.  Each fi_info structure
will describe an endpoint that meets the application's specified
communication criteria.  Each endpoint will be associated with a
domain.  Applications can restrict the number of returned endpoints by
including additional criteria in their search hints.  Relaxing or
eliminating input hints will increase the number and type of endpoints
that are available.  Providers that return multiple endpoints to a
single fi_getinfo call should return the endpoints that are highest
performing.  Providers may indicate that an endpoint and domain can
support additional capabilities than those requested by the user only
if such support will not adversely affect performance.

The version parameter is used by the application to request the
desired version of the interfaces.  The version determines the format
of all data structures used by any of the fabric interfaces.
Applications should use the FI_VERSION(major, minor) macro to indicate
the version, with hard-coded integer values for the major and minor
values.  The FI_MAJOR_VERSION and FI_MINOR_VERSION enum values defined
in fabric.h specify the latest version of the installed library.
However, it is recommended that the integer values for
FI_MAJOR_VERSION and FI_MINOR_VERSION be used, rather than referencing
the enum types in order to ensure compatibility with future versions
of the library.  This protects against the application being built
from source against a newer version of the library that introduces new
fields to data structures, which would not be initialized by the
application.

Either node, service, or hints must be provided, with any combination
being supported.  If node is provided, fi_getinfo will attempt to
resolve the fabric address to the given node.  The hints parameter, if
provided, may be used to control the resulting output as indicated
below.  If node is not given, fi_getinfo will attempt to resolve the
fabric addressing information based on the provided hints.

The caller must call fi_freeinfo to release fi_info structures returned
by this call.

# FI_INFO

{% highlight c %}
struct fi_info {
	struct fi_info        *next;
	uint64_t              caps;
	uint64_t              mode;
	enum fi_ep_type       ep_type;
	uint32_t              addr_format;
	size_t                src_addrlen;
	size_t                dest_addrlen;
	void                  *src_addr;
	void                  *dest_addr;
	fi_connreq_t          connreq;
	struct fi_tx_attr *tx_attr;
	struct fi_rx_attr *rx_attr;
	struct fi_ep_attr     *ep_attr;
	struct fi_domain_attr *domain_attr;
	struct fi_fabric_attr *fabric_attr;
};
{% endhighlight %}

*next*
: Pointer to the next fi_info structure in the list.  Will be NULL
  if no more structures exist.

*caps - fabric interface capabilities*
: If specified, indicates the desired capabilities of the fabric
  interfaces.  Supported capabilities are listed in the _Capabilities_
  section below.

*mode*
: Operational modes supported by the application.  See the _Mode_
  section below.

*ep_type - endpoint type*
: If specified, indicates the type of fabric interface communication
  desired.  Supported types are listed in the _Endpoint types_
  section below.

*addr_format - address format*
: If specified, indicates the format of addresses referenced by the
  fabric interfaces and data structures.  Supported formats are listed
  in the _Addressing formats_ section below.

*src_addrlen - source address length*
: Indicates the length of the source address (must be specified if
  *src_addr* is specified).  This field will be ignored in hints if
  FI_SOURCE is specified.

*dest_addrlen - destination address length*
: Indicates the length of the destination address (must be specified
  if *dst_addr* is specified).  This field will be ignored in hints
  unless FI_SOURCE is specified.

*src_addr - source address*
: If specified, indicates the source address.  This field will be
  ignored in hints if FI_SOURCE is specified.

*dest_addr - destination address*
: If specified, indicates the destination address.  This field will be
  ignored in hints unless FI_SOURCE is specified.

*connreq - connection request*
: References a specific connection request, otherwise the field must
  be NULL.  This field is used when processing connection requests and
  responses.  See fi_eq(3), fi_reject(3), and fi_endpoint(3).

*tx_attr - transmit context attributes*
: Optionally supplied transmit context attributes.  Transmit context
  attributes may be specified and returned as part of fi_getinfo.
  When provided as hints, requested values of struct fi_tx_ctx_attr
  should be set.  On output, the actual transmit context attributes
  that can be provided will be returned.  Output values will be
  greater than or or equal to the requested input values.

*rx_attr - receive context attributes*
: Optionally supplied receive context attributes.  Receive context
  attributes may be specified and returned as part of fi_getinfo.
  When provided as hints, requested values of struct fi_rx_ctx_attr
  should be set.  On output, the actual receive context attributes
  that can be provided will be returned.  Output values will be
  greater than or or equal to the requested input values.

*ep_attr - endpoint attributes*
: Optionally supplied endpoint attributes.  Endpoint attributes may be
  specified and returned as part of fi_getinfo.  When provided as
  hints, requested values of struct fi_ep_attr should be set.  On
  output, the actual endpoint attributes that can be provided will be
  returned.  Output values will be greater than or equal to requested
  input values.  See fi_endpoint(3) for details.

*domain_attr - domain attributes*
: Optionally supplied domain attributes.  Domain attributes may be
  specified and returned as part of fi_getinfo.  When provided as
  hints, requested values of struct fi_domain_attr should be set.  On
  output, the actual domain attributes that can be provided will be
  returned.  Output values will be greater than or equal to requested
  input values.  See fi_domain(3) for details.

*fabric_attr - fabric attributes*
: Optionally supplied fabric attributes.  Fabric attributes may be
  specified and returned as part of fi_getinfo.  When provided as
  hints, requested values of struct fi_fabric_attr should be set.  On
  output, the actual fabric attributes that can be provided will be
  returned.  See fi_fabric(3) for details.

# CAPABILITIES

Interface capabilities are obtained by OR-ing the following flags
together.  If capabilities in the hint parameter are set to 0, the
underlying provider will return the set of capabilities which are
supported.  Otherwise, providers will only return data matching the
specified set of capabilities.  Providers may indicate support for
additional capabilities beyond those requested when the use of
expanded capabilities will not adversely affect performance or expose
the application to communication beyond that which was requested.
Applications may use this feature to request a minimal set of
requirements, then check the returned capabilities to enable
additional optimizations.

*FI_MSG*
: Specifies that an endpoint should support sending and receiving
  messages or datagrams.  Message capabilities imply support for send
  and/or receive queues.  Endpoints supporting this capability support
  operations defined by struct fi_ops_msg.

  The ep_cap may be used to specify or restrict the type of messaging
  operations that are supported.  In the absence of any relevant
  flags, FI_MSG implies the ability to send and receive messages.
  Applications can use the FI_SEND and FI_RECV flags to optimize an
  endpoint as send-only or receive-only.

*FI_RMA*
: Specifies that the endpoint should support RMA read and write
  operations.  Endpoints supporting this capability support operations
  defined by struct fi_rma_ops.  In the absence of any relevant flags,
  FI_RMA implies the ability to initiate and be the target of remote
  memory reads and writes.  Applications can use the FI_READ,
  FI_WRITE, FI_REMOTE_READ, and FI_REMOTE_WRITE flags to restrict the
  types of RMA operations supported by an endpoint.

*FI_TAGGED*
: Specifies that the endpoint should handle tagged message transfers.
  tagged message transfers associate a user-specified key or tag with
  each message that is used for matching purposes at the remote side.
  Endpoints supporting this capability support operations defined by
  struct fi_tagged_ops.  In the absence of any relevant flags,
  FI_TAGGED implies the ability to send and receive tagged messages.
  Applications can use the FI_SEND and FI_RECV flags to optimize an
  endpoint as send-only or receive-only.

*FI_ATOMICS*
: Specifies that the endpoint supports some set of atomic operations.
  Endpoints supporting this capability support operations defined by
  struct fi_atomic_ops.  In the absence of any relevant flags,
  FI_ATOMICS implies the ability to initiate and be the target of
  remote atomic reads and writes.  Applications can use the FI_READ,
  FI_WRITE, FI_REMOTE_READ, and FI_REMOTE_WRITE flags to restrict the
  types of atomic operations supported by an endpoint.

*FI_MULTICAST*
: Indicates that the endpoint should support multicast data transfers.
  Endpoints supporting this capability support multicast operations
  defined by struct fi_msg_ops, when a multicast address is specified
  as the destination address.  In the absence of any relevant flags,
  FI_MULTICAST implies the ability to send and receive messages.
  Applications can use the FI_SEND and FI_RECV flags to optimize an
  endpoint as send-only or receive-only.

*FI_DYNAMIC_MR*
: The provider supports applications registering any range of
  addresses in their virtual address space, whether or not those
  addresses are back by physical pages or have been allocated to the
  app.  Providers that lack this capability require that registered
  memory regions be backed by allocated memory pages.

*FI_NAMED_RX_CTX*
: Requests that endpoints which support multiple receive contexts
  allow an initiator to target (or name) a specific receive context as
  part of a data transfer operation.

*FI_BUFFERED_RECV*
: Requests that the communication endpoint should attempt to queue
  inbound data that arrives before a receive buffer has been posted.
  In the absence of this flag, any messages that arrive before a
  receive is posted are lost.  Applications may access endpoint
  options (getopt/setopt) to determine the size of available buffered
  receive space.

*FI_INJECT*
: Indicates that the endpoint be able to support the FI_INJECT flag on
  data transfer operations and the 'inject' data transfer calls.  The
  minimum supported size of an inject operation that an endpoint with
  this capability must support is 8-bytes.  Applications may access
  endpoint options (getopt/setopt) to determine injected transfer
  limits.

*FI_MULTI_RECV*
: Specifies that the endpoint must support the FI_MULTI_RECV flag when
  posting receive buffers.

*FI_SOURCE*
: Requests that the endpoint return source addressing data as part of
  its completion data.  This capability only applies to connectionless
  endpoints.  Note that returning source address information may
  require that the provider perform address translation and/or look-up
  based on data available in the underlying protocol in order to
  provide the requested data, which may adversely affect performance.

*FI_READ*
: Indicates that the user requires an endpoint capable of initiating
  reads against remote memory regions.  Remote reads include some RMA
  and atomic operations.

*FI_WRITE*
: Indicates that the user requires an endpoint capable of initiating
  writes against remote memory regions.  Remote writes include some
  RMA and most atomic operations.

*FI_SEND*
: Indicates that the user requires an endpoint capable of sending
  message data transfers.  Message transfers include base message
  operations as well as tagged message functionality.

*FI_RECV*
: Indicates that the user requires an endpoint capable of receiving
  message data transfers.  Message transfers include base message
  operations as well as tagged message functionality.

*FI_REMOTE_READ*
: Indicates that the user requires an endpoint capable of receiving
  read memory operations from remote endpoints.  Remote read
  operations include some RMA and atomic operations.

*FI_REMOTE_WRITE*
: Indicates that the user requires an endpoint capable of receiving
  write memory operations from remote endpoints.  Remote write
  operations include some RMA operations and most atomic operations.

*FI_REMOTE_CQ_DATA*
: Applications may include a small message with a data transfer that
  is placed directly into a remote event queue as part of a completion
  event.  This is referred to as remote CQ data (sometimes referred to
  as immediate data).  The FI_REMOTE_CQ_DATA indicates that an
  endpoint must support the FI_REMOTE_CQ_DATA flag on data transfer
  operations.  The minimum supported size of remote CQ data that an
  endpoint with this capability must support is 4-bytes.  Applications
  may access endpoint options (getopt/setopt) to determine remote CQ
  data limits.

*FI_REMOTE_SIGNAL*
: Indicates that the endpoint support the FI_REMOTE_SIGNAL flag on
  data transfer operations.  Support requires marking outbound data
  transfers as signaled and handling incoming transfers appropriately.

*FI_REMOTE_COMPLETE*
: Indicates that the endpoint support the FI_REMOTE_COMPLETE flag on
  data transfer operations.  Support requires marking outbound data
  transfers as using remote completions and responding to incoming
  transfers appropriately.

*FI_CANCEL*
: Indicates that the user desires the ability to cancel outstanding
  data transfer operations.  If FI_CANCEL is not set, a provider may
  optimize code paths with the assumption that fi_cancel will not be
  used by the application.

*FI_TRIGGER*
: Indicates that the endpoint should support triggered operations.
  Endpoints support this capability must meet the usage model as
  described by fi_trigger.3.

# MODE

The operational mode bits are used to convey requirements that an
application must adhere to when using the fabric interfaces.  Modes
specify optimal ways of accessing the reported endpoint or domain.
Applications that are designed to support a specific mode of operation
may see improved performance when that mode is desired by the
provider.  It is recommended that providers support applications that
disable any provider preferred modes.

On input to fi_getinfo, applications set the mode bits that they
support.  On output, providers will clear mode bits that are not
necessary to achieve high-performance.  Mode bits that remain set
indicate application requirements for using the fabric interfaces
created using the returned fi_info.  The set of modes are listed
below.

*FI_CONTEXT*
: Specifies that the provider requires that applications use struct
  fi_context as their per operation context parameter.  This structure
  should be treated as opaque to the application.  For performance
  reasons, this structure must be allocated by the user, but may be
  used by the fabric provider to track the operation.  Typically,
  users embed struct fi_context within their own context structure.
  The struct fi_context must remain valid until the corresponding
  operation completes or is successfully canceled.  As such,
  fi_context should NOT be allocated on the stack.  Doing so is likely
  to result in stack corruption that will be difficult to debug.
  Users should not update or interpret the fields in this structure,
  or reuse it until the original operation has completed.  The
  structure is specified in rdma/fabric.h.

*FI_LOCAL_MR*
: The provider is optimized around having applications register memory
  for locally accessed data buffers.  Data buffers used in send and
  receive operations and as the source buffer for RMA and atomic
  operations must be registered by the application for access domains
  opened with this capability.

*FI_MSG_PREFIX*
: Message prefix mode indicates that an application will provide
  buffer space in front of all message send and receive buffers for
  use by the provider.  Typically, the provider uses this space to
  implement a protocol, with the protocol headers being written into
  the prefix area.  The contents of the prefix space should be treated
  as opaque.  The use of FI_MSG_PREFIX may improve application
  performance over certain providers by reducing the number of IO
  vectors referenced by underlying hardware and eliminating provider
  buffer allocation.

  FI_MSG_PREFIX only applies to send and receive operations, including
  tagged sends and receives.  RMA and atomics do not require the
  application to provide prefix buffers.  Prefix buffer space must be
  provided with all sends and receives, regardless of the size of the
  transfer or other transfer options.  The ownership of prefix buffers
  is treated the same as the corresponding message buffers, but the
  size of the prefix buffer is not counted toward any message limits,
  including inject.

  Applications that support prefix mode must supply buffer space
  before their own message data.  The size of space that must be
  provided is specified by the msg_prefix_size endpoint attribute.
  Providers are required to define a msg_prefix_size that is a
  multiple of 8 bytes.  Additionally, applications may receive
  provider generated packets that do not contain application data.
  Such received messages will indicate a transfer size of 0 bytes.

*FI_PROV_MR_ATTR*
: The provider assigns one or more attributes associated with a memory
  registration request.  The provider will set this mode if it returns
  the the memory registration keys that applications must use, or if
  it requires that the MR offset associated with a memory region be
  the same as the virtual address of the memory.

  Applications that support provider MR attributes will need to
  exchange MR parameters with remote peers for RMA and atomic
  operations.  The exchanged data should include both the address of
  the memory region as well as the MR key.  If this mode is disabled,
  then applications may select the MR key associated with a
  registration request, and the resulting memory region will start at
  a base address of 0.  Applications can request that providers select
  MR attributes by forcing this bit set after fi_getinfo returns.

# ENDPOINT TYPES

*FI_EP_UNSPEC*
: The type of endpoint is not specified.  This is usually provided as
  input, with other attributes of the endpoint or the provider
  selecting the type.

*FI_EP_MSG*
: Provides a reliable, connection-oriented data transfer service with
  flow control that maintains message boundaries.

*FI_EP_DGRAM*
: Supports a connectionless, unreliable datagram communication.
  Message boundaries are maintained, but the maximum message size may
  be limited to the fabric MTU.  Flow control is not guaranteed.

*FI_EP_RDM*
: Reliable datagram message.  Provides a reliable, unconnected data
  transfer service with flow control that maintains message
  boundaries.

# ADDRESSING FORMATS

Multiple fabric interfaces take as input either a source or
destination address parameter.  This includes struct fi_info (src_addr
and dest_addr), CM calls (getname, getpeer, connect, join, and leave),
and AV calls (insert, lookup, and straddr).  The fi_info addr_format
field indicates the expected address format for these operations.

A provider may support one or more of the following addressing
formats.  In some cases, a selected addressing format may need to be
translated or mapped into into an address which is native to the
fabric.  See `fi_av`(3).

*FI_ADDR_UNSPEC*
: FI_ADDR_UNSPEC indicates that a provider specific address format
  should be selected.  Provider specific addresses may be protocol
  specific or a vendor proprietary format.  Applications that select
  FI_ADDR_UNSPEC should be prepared to be treat returned addressing
  data as opaque.  FI_ADDR_UNSPEC targets apps which make use of an
  out of band address exchange.  Applications which use FI_ADDR_UNSPEC
  may use fi_getname() to obtain a provider specific address assigned
  to an allocated endpoint.

*FI_SOCKADDR*
: Address is of type sockaddr.  The specific socket address format
  will be determined at run time by interfaces examining the sa_family
  field.

*FI_SOCKADDR_IN*
: Address is of type sockaddr_in (IPv4).

*FI_SOCKADDR_IN6*
: Address is of type sockaddr_in6 (IPv6).

*FI_SOCKADDR_IB*
: Address is of type sockaddr_ib (defined in Linux kernel source

*FI_ADDR_PSMX*
: Address is an Intel proprietary format that is used with their PSMX
  (extended performance scaled messaging) protocol.

# FLAGS

The operation of the fi_getinfo call may be controlled through the use of
input flags.  Valid flags include the following.

*FI_NUMERICHOST*
: Indicates that the node parameter is a numeric string representation
  of a fabric address, such as a dotted decimal IP address.  Use of
  this flag will suppress any lengthy name resolution protocol.

*FI_SOURCE*
: Indicates that the node and service parameters specify the local
  source address to associate with an endpoint.  This flag is often
  used with passive endpoints.

# RETURN VALUE

fi_getinfo() returns 0 on success. On error, fi_getinfo() returns a
negative value corresponding to fabric errno. Fabric errno values are
defined in `rdma/fi_errno.h`.

fi_dupinfo() duplicates a single fi_info structure and all the
substructures within it and returns a pointer to the new fi_info
structure.  This new fi_info structure must be freed via
fi_freeinfo().  fi_dupinfo() returns NULL on error.

# ERRORS

*FI_EBADFLAGS*
: The specified endpoint or domain capability or operation flags are
  invalid.

*FI_ENOMEM*
: Indicates that there was insufficient memory to complete the operation.

*FI_ENODATA*
: Indicates that no providers could be found which support the requested
  fabric information.

*FI_ENOSYS*
: No fabric providers were found.

# NOTES

If hints are provided, the operation will be controlled by the values
that are supplied in the various fields (see section on _fi_info_).
Applications that require specific communication interfaces, domains,
capabilities or other requirements, can specify them using fields in
_hints_.  Libfabric returns a linked list in *info* that points to a
list of matching interfaces.  *info* is set to NULL if there are no
communication interfaces or none match the input hints.

If node is provided, fi_getinfo will attempt to resolve the fabric
address to the given node.  If node is not provided, fi_getinfo will
attempt to resolve the fabric addressing information based on the
provided hints.  The caller must call fi_freeinfo to release fi_info
structures returned by fi_getinfo.

If neither node, service or hints are provided, then fi_getinfo simply
returns the list all available communication interfaces.

Multiple threads may call
`fi_getinfo` "simultaneously, without any requirement for serialization."

# SEE ALSO

[`fi_open`(3)](fi_open.3.html),
[`fi_endpoint`(3)](fi_endpoint.3.html),
[`fi_domain`(3)](fi_domain.3.html)
