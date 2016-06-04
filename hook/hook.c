#include <ntddk.h>
#include <tdikrnl.h>

/*
 * Protocols
 */
#define IPPROTO_IP              0               /* dummy for IP */
#define IPPROTO_ICMP            1               /* control message protocol */
#define IPPROTO_TCP             6               /* tcp */
#define IPPROTO_UDP             17              /* user datagram protocol */

typedef unsigned short  u_short;
typedef unsigned char   u_char;


static NTSTATUS	DeviceDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp);
static VOID		OnUnload(IN PDRIVER_OBJECT DriverObject);

static NTSTATUS	c_n_a_device(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT *fltobj,
							 PDEVICE_OBJECT *oldobj, wchar_t *devname);
void del_listen_obj(struct listen_entry *le, BOOLEAN no_guard);
int tdifw_filter(struct flt_request *request);

/* device objects for: */
PDEVICE_OBJECT
	g_tcpfltobj = NULL,		// \Device\Tcp
	g_udpfltobj = NULL,		// \Device\Udp
	g_ipfltobj = NULL,		// \Device\RawIp
	g_tcpoldobj = NULL, 
	g_udpoldobj = NULL, 
	g_ipoldobj = NULL;

/* process list entry */
struct plist_entry {
	struct	plist_entry *next;
	
	// id & name
	ULONG	pid;
	char	*pname;
	KEVENT	*pname_event;

	int		context;
};

struct prefix {
	ULONG		magic;
	struct		prefix *next;
	struct		prefix *prev;
	ULONG		size;
	const char	*file;
	ULONG		line;
	char		data[];
};

struct postfix {
	ULONG	size;
	ULONG	magic;
};

/*
 * Structure used by kernel to store most
 * addresses.
 */
struct sockaddr {
        u_short sa_family;              /* address family */
        char    sa_data[14];            /* up to 14 bytes of direct address */
};

/*
 * Internet address (old style... should be updated)
 */
struct in_addr {
        union {
                struct { u_char s_b1,s_b2,s_b3,s_b4; } S_un_b;
                struct { u_short s_w1,s_w2; } S_un_w;
                ULONG S_addr;
        } S_un;
#define s_addr  S_un.S_addr
                                /* can be used for most tcp & ip code */
#define s_host  S_un.S_un_b.s_b2
                                /* host on imp */
#define s_net   S_un.S_un_b.s_b1
                                /* network */
#define s_imp   S_un.S_un_w.s_w2
                                /* imp */
#define s_impno S_un.S_un_b.s_b4
                                /* imp # */
#define s_lh    S_un.S_un_b.s_b3
                                /* logical host */
};
/*
 * Socket address, internet style.
 */
struct sockaddr_in {
        short   sin_family;
        u_short sin_port;
        struct  in_addr sin_addr;
        char    sin_zero[8];
};

#define RULE_ID_SIZE		32
#define malloc_np(size)	mt_malloc((size), __FILE__, __LINE__)	
#define MAGIC	'TMEM'

static KSPIN_LOCK guard;
static struct prefix *first, *last;
static ULONG count;

static struct postfix	*check(struct prefix *p);

PDEVICE_OBJECT get_original_devobj(PDEVICE_OBJECT flt_devobj, int *proto);
NTSTATUS DeviceDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp);
u_short tdifw_ntohs(u_short netshort);
void del_tcp_conn_obj(struct conn_entry *ce, BOOLEAN no_guard);

/*
 * request for filter ipc.h
 */
struct flt_request {
	int		struct_size;	/* should be sizeof(flt_request) */

	int		type;			/* see TYPE_xxx */
	ULONG	status;			/* for TYPE_CONNECT_xxx */

	int		result;			/* see FILTER_xxx */
	int		direction;		/* see DIRECTION_xxx */
	int		proto;			/* see IPPROTO_xxx */

	ULONG	pid;
	ULONG	sid_a_size;

	/* addr */

	struct {
		struct	sockaddr from;
		struct	sockaddr to;
		int		len;
	} addr;

	/* info from packet filter (valid for FILTER_PACKET_LOG) */
	struct {
		int		is_broadcast;	// 0 or 1 (for now unused)
		UCHAR	tcp_flags;
		UCHAR	icmp_type;
		UCHAR	icmp_code;
		int		tcp_state;		// see TCP_STATE_xxx
	} packet;
	
	/* info for logging */

	ULONG	log_skipped;
	ULONG	log_bytes_in;
	ULONG	log_bytes_out;
	char	log_rule_id[RULE_ID_SIZE];

	/* for internal use (like private:) */

	char	*pname;
	struct	_SID_AND_ATTRIBUTES *sid_a;
};

/* process list */
static struct {
	struct		plist_entry *head;
	struct		plist_entry *tail;
	KSPIN_LOCK	guard;
} g_plist;

static struct plist_entry *find_ple(ULONG pid, KIRQL *irql, struct plist_entry **prev);


void *
mt_malloc(ULONG size, const char *file, ULONG line)
{
	KIRQL irql;
	struct prefix *data;
	struct postfix *pd;

#if 1
	// check pool integrity
	KeAcquireSpinLock(&guard, &irql);
	
	for (data = first; data; data = data->next)
		check(data);
	
	for (data = last; data; data = data->prev)
		check(data);
	
	KeReleaseSpinLock(&guard, irql);
#endif

	if (size == 0) {
		KdPrint(("memtrack: mt_malloc: size == 0!\n"));
		// INT_3;
		return NULL;
	}

	data = (struct prefix *)ExAllocatePool(NonPagedPool,
		sizeof(struct prefix) + size + sizeof(struct postfix));
	if (data == NULL)
		return NULL;

	data->magic = MAGIC;
	data->next = NULL;
	data->prev = NULL;
	data->size = size;
	data->file = file;
	data->line = line;

	memset(data->data, 0xcc, size);		// fill by 0xcc: new

	pd = (struct postfix *)(data->data + data->size);

	pd->size = size;
	pd->magic = MAGIC;

	KeAcquireSpinLock(&guard, &irql);
	
	if (last) {
		last->next = data;
		data->prev = last;
		last = data;
	}
	else {
		data->prev = NULL;
		first = last = data;
	}
	count++;

	KeReleaseSpinLock(&guard, irql);
	return data->data;
}

struct plist_entry *
add_ple(ULONG pid, KIRQL *irql)
{
	struct plist_entry *ple;

	if (irql != NULL)
		KeAcquireSpinLock(&g_plist.guard, irql);

	// add new entry to g_plist
	ple = (struct plist_entry *)malloc_np(sizeof(*ple));
	if (ple != NULL) {
		memset(ple, 0, sizeof(*ple));
		ple->pid = pid;

		// append
		if (g_plist.tail != NULL) {
			g_plist.tail->next = ple;
			g_plist.tail = ple;
		} else
			g_plist.head = g_plist.tail = ple;

	} else {
		KdPrint(("[tdi_fw] add_ple: malloc_np!\n"));
	
		if (irql != NULL)
			KeReleaseSpinLock(&g_plist.guard, *irql);
	}

	return ple;
}

struct plist_entry *
find_ple(ULONG pid, KIRQL *irql, struct plist_entry **prev)
{
	struct plist_entry *ple, *prev_ple;

	if (irql != NULL)
		KeAcquireSpinLock(&g_plist.guard, irql);

	prev_ple = NULL;
	for (ple = g_plist.head; ple != NULL; ple = ple->next) {
		if (ple->pid == pid) {
			if (prev != NULL)
				*prev = prev_ple;
			return ple;
		}
		prev_ple = ple;
	}

	if (irql != NULL)
		KeReleaseSpinLock(&g_plist.guard, *irql);
	
	return NULL;
}

// try to get pname by pid  pid_pname.c
BOOLEAN
pid_pname_resolve(ULONG pid, char *buf, int buf_size)
{
	BOOLEAN result;
	KIRQL irql;
	struct plist_entry *ple = find_ple(pid, &irql, NULL);

	if (ple == NULL)
		return FALSE;

	if (ple->pname != NULL) {
		if (buf_size > 0) {
			strncpy(buf, ple->pname, buf_size);
			buf[buf_size - 1] = '\0';
		}
		result = TRUE;
	} else
		result = FALSE;
	
	KeReleaseSpinLock(&g_plist.guard, irql);
	return result;
}

// set pname_event by pid
NTSTATUS
pid_pname_set_event(ULONG pid, KEVENT *event)
{
	KIRQL irql;
	struct plist_entry *ple = find_ple(pid, &irql, NULL);

	if (ple == NULL) {
		// try to add
		ple = add_ple(pid, &irql);
		if (ple == NULL)
			return STATUS_INSUFFICIENT_RESOURCES;
	}

	ple->pname_event = event;

	KeReleaseSpinLock(&g_plist.guard, irql);
	return STATUS_SUCCESS;
}


/* types of request */
enum {
	TYPE_CONNECT = 1,
	TYPE_DATAGRAM,
	TYPE_RESOLVE_PID,
	TYPE_CONNECT_ERROR,
	TYPE_LISTEN,
	TYPE_NOT_LISTEN,
	TYPE_CONNECT_CANCELED,
	TYPE_CONNECT_RESET,
	TYPE_CONNECT_TIMEOUT,
	TYPE_CONNECT_UNREACH,
	TYPE_PROCESS_CREATE,		// add by tan wen
	TYPE_PROCESS_TERMINATE		// add by tan wen
};

typedef	struct _SID_AND_ATTRIBUTES {
	PSID	Sid;
	ULONG	Attributes;
} SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;

#define CURRENT_THREAD	(HANDLE)-2
#define CURRENT_PROCESS	(HANDLE)-1

#define TOKEN_QUERY		0x0008

typedef	enum _TOKEN_INFORMATION_CLASS {
	TokenUser =	1,
	TokenGroups,
	TokenPrivileges,
	TokenOwner,
	TokenPrimaryGroup,
	TokenDefaultDacl,
	TokenSource,
	TokenType,
	TokenImpersonationLevel,
	TokenStatistics,
	TokenRestrictedSids
} TOKEN_INFORMATION_CLASS;


NTSTATUS
NTAPI
ZwOpenThreadToken (
	IN HANDLE		ThreadHandle,
	IN ACCESS_MASK	DesiredAccess,
	IN BOOLEAN		OpenAsSelf,
	OUT	PHANDLE		TokenHandle
);

NTSTATUS
NTAPI
ZwOpenProcessToken (
	IN HANDLE       ProcessHandle,
	IN ACCESS_MASK  DesiredAccess,
	OUT PHANDLE     TokenHandle
);

NTSTATUS
NTAPI
ZwQueryInformationToken	(
	IN HANDLE					TokenHandle,
	IN TOKEN_INFORMATION_CLASS	TokenInformationClass,
	OUT	PVOID					TokenInformation,
	IN ULONG					Length,
	OUT	PULONG					ResultLength
);


struct postfix *
check(struct prefix *p)
{
	struct postfix *pd;

	if (p->magic != MAGIC) {
		KdPrint(("memtrack: check: invalid pre-magic! 0x%x\n", p));
		// INT_3;
		return NULL;
	}

	pd = (struct postfix *)(p->data + p->size);

	if (pd->magic != MAGIC) {
		KdPrint(("memtrack: memtrack_free: invalid post-magic! 0x%x\n", pd));
		// INT_3;
		return NULL;
	}

	if (p->size != pd->size) {
		KdPrint(("memtrack: memtracl_free: invalid post-size! 0x%x 0x%x\n", p, pd));
		// INT_3;
		return NULL;
	}

	return pd;
}


void
free(void *ptr)
{
	KIRQL irql;
	struct prefix *data = (struct prefix *)((char *)ptr - sizeof(struct prefix));
	struct postfix *pd = check(data);

	if (pd == NULL)
		return;

	KeAcquireSpinLock(&guard, &irql);

	if (data->next != NULL)
		data->next->prev = data->prev;
	else
		last = data->prev;
	if (data->prev != NULL)
		data->prev->next = data->next;
	else
		first = data->next;

	memset(data->data, 0xc9, data->size);	// fill by 0xc9: free

	data->size = (ULONG)-1;
	pd->size = (ULONG)-1;

	count--;
	KeReleaseSpinLock(&guard, irql);

	ExFreePool(data);
}


struct _SID_AND_ATTRIBUTES *
get_current_sid_a(ULONG *sid_a_size)		// must be called at PASSIVE_LEVEL!
{
	NTSTATUS status;
	HANDLE token;
	ULONG size;
	SID_AND_ATTRIBUTES *sid_a;

	*sid_a_size = 0;

	// open thread token
	status = ZwOpenThreadToken(CURRENT_THREAD, TOKEN_QUERY, FALSE, &token);
	if (status == STATUS_NO_TOKEN) {
		// open process token
		status = ZwOpenProcessToken(CURRENT_PROCESS, TOKEN_QUERY, &token);
	}
	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] get_current_sid_a: ZwOpen{Thread|Process}Token: 0x%x!\n"));
		return NULL;
	}

	size = sizeof(*sid_a) + 100;		// default size
	
	sid_a = (SID_AND_ATTRIBUTES *)malloc_np(size);
	if (sid_a == NULL) {
		KdPrint(("[tdi_fw] get_current_sid_a: malloc_np!\n"));
		goto done;
	}

	status = ZwQueryInformationToken(token, TokenUser, sid_a, size, &size);
	if (status == STATUS_BUFFER_TOO_SMALL) {
		free(sid_a);
		
		sid_a = (SID_AND_ATTRIBUTES *)malloc_np(size);
		if (sid_a == NULL) {
			KdPrint(("[tdi_fw] get_current_sid_a: malloc_np!\n"));
			goto done;
		}

		status = ZwQueryInformationToken(token, TokenUser, sid_a, size, &size);
	}
	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] get_current_sid_a: ZwQueryInformationToken: 0x%x!\n"));

		free(sid_a);
		sid_a = NULL;
		goto done;
	}

	// got sid & attributes!

	*sid_a_size = size;

done:
	ZwClose(token);
	return sid_a;
}


// size of cyclic queue for logging
#define REQUEST_QUEUE_SIZE	1024

// I think 128 is a good number :-) (better than 256 :))
#define MAX_CHAINS_COUNT	128

// how many users can be assigned per rule? (MUST: MAX_SIDS_COUNT % 8 == 0 !!!)
#define MAX_SIDS_COUNT		128

/*
 * IP rule for quick filter (addr & port are in network order)
 */
struct flt_rule {
	union {
		struct	flt_rule *next;		// for internal use
		int		chain;				// useful for IOCTL_CMD_APPENDRULE
	};
	int		result;
	int		proto;
	int		direction;
	ULONG	addr_from;
	ULONG	mask_from;
	USHORT	port_from;
	USHORT	port2_from;		/* if nonzero use port range from port_from */
	ULONG	addr_to;
	ULONG	mask_to;
	USHORT	port_to;
	USHORT	port2_to;		/* if nonzero use port range from port_to */
	int		log;			/* see RULE_LOG_xxx */

	UCHAR	sid_mask[MAX_SIDS_COUNT / 8];	/* SIDs bitmask */

	char	rule_id[RULE_ID_SIZE];
};

/* rules chains (main (first entry) and process-related) */
static struct {
	struct {
		struct		flt_rule *head;
		struct		flt_rule *tail;
		char		*pname;				// name of process
		BOOLEAN		active;				// filter chain is active
	} chain[MAX_CHAINS_COUNT];
	KSPIN_LOCK	guard;
} g_rules;

/* filter result */
enum {
	FILTER_ALLOW = 1,
	FILTER_DENY,
	FILTER_PACKET_LOG,
	FILTER_PACKET_BAD,
	FILTER_DISCONNECT
};

#define IPPROTO_ANY		-1
/*
 * direction type for filter
 * for quick filter:
 *  if proto == IPPROTO_TCP (DIRECTION_IN - accept connections; DIRECTION_OUT - connect)
 *  if proto == IPPROTO_UDP (DIRECTION_IN - receive datagram; DIRECTION_OUT - send datagram)
 */
#define DIRECTION_IN	0
#define DIRECTION_OUT	1
#define DIRECTION_ANY	-1

#define RULE_LOG_NOLOG			0
#define RULE_LOG_LOG			1
#define RULE_LOG_COUNT			2

#define IPPROTO_ANY		-1

/* "ALLOW * * FROM ANY TO ANY" rule */
static struct flt_rule g_allow_all = {
	{0},
	FILTER_ALLOW,
	IPPROTO_ANY,
	DIRECTION_ANY,
	0,	// from
	0,
	0,
	0,
	0,	// to
	0,
	0,
	0,
	RULE_LOG_LOG,
	"",	// setup mask before using it!
	"startup"		// rule for startup only
};

/* logging request queue */
static struct {
	struct		flt_request *data;
	KSPIN_LOCK	guard;
	ULONG		head;	/* write to head */
	ULONG		tail;	/* read from tail */
	HANDLE		event_handle;
	PKEVENT		event;
} g_queue;

BOOLEAN g_got_log = FALSE;	// got log app

// write request to request queue
BOOLEAN
log_request(struct flt_request *request)
{
	KIRQL irql, irql2;
	ULONG next_head;
	char pname_buf[256], *pname;
	struct plist_entry *ple;

	if (!g_got_log && request->type == TYPE_RESOLVE_PID)	// don't log - no log app
		return FALSE;

	KeAcquireSpinLock(&g_queue.guard, &irql);

	next_head = (g_queue.head + 1) % REQUEST_QUEUE_SIZE;
	
	if (next_head == g_queue.tail) {
		// queue overflow: reject one entry from tail
		KdPrint(("[tdi_fw] log_request: queue overflow!\n"));
		
		request->log_skipped = g_queue.data[g_queue.tail].log_skipped + 1;
		
		// free process name & sid!
		if (g_queue.data[g_queue.tail].pname != NULL)
			free(g_queue.data[g_queue.tail].pname);
		if (g_queue.data[g_queue.tail].sid_a != NULL)
			free(g_queue.data[g_queue.tail].sid_a);
		
		g_queue.tail = (g_queue.tail + 1) % REQUEST_QUEUE_SIZE;

	} else
		request->log_skipped = 0;

	memcpy(&g_queue.data[g_queue.head], request, sizeof(struct flt_request));

	// try to get process name
	pname = NULL;
	if (request->pid != (ULONG)-1 &&
		pid_pname_resolve(request->pid, pname_buf, sizeof(pname_buf))) {
		
		KdPrint(("[tdi_fw] log_request: pid:%u; pname:%s\n",
			request->pid, pname_buf));

		// ala strdup()
		pname = (char *)malloc_np(strlen(pname_buf) + 1);
		if (pname != NULL)
			strcpy(pname, pname_buf);
		else
			KdPrint(("[tdi_fw] log_request: malloc_np!\n"));
	}

	g_queue.data[g_queue.head].pname = pname;
	g_queue.head = next_head;

	// don't free sid & attributes
	if (request->sid_a != NULL)
		request->sid_a = NULL;

	KeReleaseSpinLock(&g_queue.guard, irql);

	// signal to user app
	if (g_queue.event != NULL)
		KeSetEvent(g_queue.event, IO_NO_INCREMENT, FALSE);
	
	return TRUE;
}


BOOLEAN
default_chain_only(void)
{
	int i;

	if (!g_rules.chain[0].active)
		return FALSE;

	for (i = 1; i < MAX_CHAINS_COUNT; i++)
		if (g_rules.chain[i].active)
			return FALSE;

	return TRUE;

}

//---------------------------------------------------------------------------- obj tbl.c
// for searching objects information by file object

NTSTATUS	ot_init(void);
void		ot_free(void);

#define FILEOBJ_CONTROLOBJ	0
#define FILEOBJ_ADDROBJ		1
#define FILEOBJ_CONNOBJ		2

NTSTATUS	ot_add_fileobj(
	PDEVICE_OBJECT devobj, PFILE_OBJECT fileobj, int fileobj_type, int ipproto,
	CONNECTION_CONTEXT conn_ctx);

NTSTATUS	ot_del_fileobj(
	PFILE_OBJECT fileobj, int *fileobj_type);

// maximum length of TDI_ADDRESS_TYPE_*
#define TDI_ADDRESS_MAX_LENGTH	TDI_ADDRESS_LENGTH_OSI_TSAP
#define TA_ADDRESS_MAX			(sizeof(TA_ADDRESS) - 1 + TDI_ADDRESS_MAX_LENGTH)
#define TDI_ADDRESS_INFO_MAX	(sizeof(TDI_ADDRESS_INFO) - 1 + TDI_ADDRESS_MAX_LENGTH)

// max event index
#ifdef TDI_EVENT_ERROR_EX
// 2k
#	define MAX_EVENT	(TDI_EVENT_ERROR_EX + 1)
#else
// NT4
#	define MAX_EVENT	(TDI_EVENT_CHAINED_RECEIVE_EXPEDITED + 1)
#endif

/* replaced context */
typedef struct {
	PFILE_OBJECT	fileobj;		/* address object */
    PVOID			old_handler;	/* old event handler */
    PVOID			old_context;	/* old event handler context */
} TDI_EVENT_CONTEXT;

struct ot_entry {
	ULONG signature;
	struct ot_entry		*next;
	
	ULONG				pid;
	
	struct				_SID_AND_ATTRIBUTES *sid_a;
	ULONG				sid_a_size;
	
	PDEVICE_OBJECT		devobj;
	PFILE_OBJECT		fileobj;
	PFILE_OBJECT		associated_fileobj;
	
	int					type;
	int					ipproto;
	
	TDI_EVENT_CONTEXT	ctx[MAX_EVENT];
	UCHAR				local_addr[TA_ADDRESS_MAX];
	UCHAR				remote_addr[TA_ADDRESS_MAX];

	CONNECTION_CONTEXT	conn_ctx;
	
	struct listen_entry	*listen_entry;	// for address object
	struct conn_entry	*conn_entry;	// for connection object

	// traffic count for connection object
	ULONG				bytes_out;
	ULONG				bytes_in;
	
	BOOLEAN				log_disconnect;
};


#define HASH_SIZE	0x1000
#define CALC_HASH(fileobj)  (((ULONG)(fileobj) >> 5) % HASH_SIZE)

static struct ot_entry **g_ot_hash;
KSPIN_LOCK g_ot_hash_guard;

// for searching connection objects by address object & connection context

struct ctx_entry {
	struct ctx_entry *next;
	PFILE_OBJECT addrobj;
	CONNECTION_CONTEXT conn_ctx;
	PFILE_OBJECT connobj;
};

static struct ctx_entry **g_cte_hash;
KSPIN_LOCK g_cte_hash_guard;


NTSTATUS
ot_del_fileobj(PFILE_OBJECT fileobj, int *fileobj_type)
{
	ULONG hash = CALC_HASH(fileobj);
	KIRQL irql;
	struct ot_entry *ote, *prev_ote;
	NTSTATUS status;

	if (fileobj == NULL)
		return STATUS_INVALID_PARAMETER_1;

	KeAcquireSpinLock(&g_ot_hash_guard, &irql);

	prev_ote = NULL;
	for (ote = g_ot_hash[hash]; ote; ote = ote->next) {
		if (ote->fileobj == fileobj)
			break;
		prev_ote = ote;
	}

	if (ote == NULL) {
		KdPrint(("[tdi_fw] ot_del_fileobj: fileobj 0x%x not found!\n", fileobj));
		status = STATUS_OBJECT_NAME_NOT_FOUND;
		goto done;
	}

	if (ote->type == FILEOBJ_ADDROBJ && ote->listen_entry != NULL)
		del_listen_obj(ote->listen_entry, FALSE);
	else if (ote->type == FILEOBJ_CONNOBJ && ote->conn_entry != NULL) {
		if (ote->ipproto == IPPROTO_TCP && ote->log_disconnect)
			// log_disconnect(ote);
		
		del_tcp_conn_obj(ote->conn_entry, FALSE);
	}

	if (fileobj_type != NULL)
		*fileobj_type = ote->type;

	if (prev_ote != NULL)
		prev_ote->next = ote->next;
	else
		g_ot_hash[hash] = ote->next;

	if (ote->sid_a != NULL)
		free(ote->sid_a);

	free(ote);

	status = STATUS_SUCCESS;

done:
	KeReleaseSpinLock(&g_ot_hash_guard, irql);

	return status;
}

struct ot_entry *
ot_find_fileobj(PFILE_OBJECT fileobj, KIRQL *irql)
{
	ULONG hash = CALC_HASH(fileobj);
	struct ot_entry *ote;

	if (fileobj == NULL)
		return NULL;

	if (irql != NULL)
		KeAcquireSpinLock(&g_ot_hash_guard, irql);

	for (ote = g_ot_hash[hash]; ote != NULL; ote = ote->next)
		if (ote->fileobj == fileobj)
			break;

	if (ote == NULL) {
		KdPrint(("[tdi_fw] ot_find_fileobj: fileobj 0x%x not found!\n", fileobj));
		if (irql != NULL)
			KeReleaseSpinLock(&g_ot_hash_guard, *irql);
	}

	return ote;
}

// -------------------------------conn state.c


// how much entry in connection will live in "CLOSED" state? (sec)
#define MAX_CLOSED_TIME		20

struct listen_entry {
	struct			listen_entry *next;
	struct			listen_entry *prev;		/* using double-linked list */
	int				ipproto;
	ULONG			addr;		// IPv4 only (yet)
	USHORT			port;
	PFILE_OBJECT	addrobj;
};

static struct listen_entry **g_listen = NULL;

static KSPIN_LOCK g_listen_guard;
// !!! to avoid deadlocks with g_ot_hash_guard this spinlock MUST be acquired _after_ g_conn_guard !!!

#define LISTEN_HASH_SIZE	0x1000
#define CALC_LISTEN_HASH(ipproto, port)	((ULONG)((ipproto) + (port)) % LISTEN_HASH_SIZE)

struct conn_entry {
	struct			conn_entry *next;
	struct			conn_entry *prev;		/* using double-linked list */
	int				state;
	ULONG			laddr;		// IPv4 only (yet)
	USHORT			lport;
	ULONG			raddr;
	USHORT			rport;
	PFILE_OBJECT	connobj;

	struct			conn_entry *next_to_del;
	LARGE_INTEGER	ticks;
};

static struct conn_entry **g_conn = NULL;
static struct conn_entry *g_conn_to_del = NULL;
static KSPIN_LOCK g_conn_guard;
static KEVENT g_conn_new_to_del;
static HANDLE g_conn_thread;

#define CONN_HASH_SIZE	0x1000
#define CALC_CONN_HASH(laddr, lport, raddr, rport)	((ULONG)((laddr) + (lport) + (raddr) + (rport)) % CONN_HASH_SIZE)

static void		conn_thread(PVOID param);


void
del_listen_obj(struct listen_entry *le, BOOLEAN no_guard)
{
	KIRQL irql;

	KdPrint(("[tdi_fw] del_listen_obj: NOT_LISTEN %x:%u (ipproto=%d)\n", le->addr, tdifw_ntohs(le->port), le->ipproto));

	if (!no_guard)
		KeAcquireSpinLock(&g_listen_guard, &irql);	// lock our hash

	// delete le from our hash
	
	if (le->prev != NULL)
		le->prev->next = le->next;
	else {
		ULONG hash = CALC_LISTEN_HASH(le->ipproto, le->port);
		g_listen[hash] = le->next;
	}
	
	if (le->next != NULL)
		le->next->prev = le->prev;

	free(le);

	if (!no_guard)
		KeReleaseSpinLock(&g_listen_guard, irql);	// unlock our hash
}

/*
 * TCP states
 */
enum {
	TCP_STATE_NONE,
	TCP_STATE_SYN_SENT,
	TCP_STATE_SYN_RCVD,
	TCP_STATE_ESTABLISHED_IN,
	TCP_STATE_ESTABLISHED_OUT,
	TCP_STATE_FIN_WAIT1,
	TCP_STATE_FIN_WAIT2,
	TCP_STATE_TIME_WAIT,
	TCP_STATE_CLOSE_WAIT,
	TCP_STATE_LAST_ACK,
	TCP_STATE_CLOSED,
	
	TCP_STATE_MAX
};

void
del_tcp_conn_obj(struct conn_entry *ce, BOOLEAN no_guard)
{
	KIRQL irql;

	KdPrint(("[tdi_fw] del_tcp_conn_obj: CLOSED %x:%u <-> %x:%u (state=%d)\n",
		ce->laddr, tdifw_ntohs(ce->lport), ce->raddr, tdifw_ntohs(ce->rport), ce->state));

	if (!no_guard)
		KeAcquireSpinLock(&g_conn_guard, &irql);	// lock our hash

	// set state to TCP_STATE_CLOSED and add to special list to queue it for deleting
	ce->state = TCP_STATE_CLOSED;
	ce->next_to_del = g_conn_to_del;
	g_conn_to_del = ce;

	KeQueryTickCount(&ce->ticks);

	KeSetEvent(&g_conn_new_to_del, IO_NO_INCREMENT, FALSE);

	ce->connobj = NULL;		// no connection object related for now!!!

	KdPrint(("[tdi_fw] del_tcp_conn_obj: state table entry scheduled for deletion!\n"));

	if (!no_guard)
		KeReleaseSpinLock(&g_conn_guard, irql);	// unlock our hash
}

struct _SID_AND_ATTRIBUTES *
copy_sid_a(SID_AND_ATTRIBUTES *sid_a, ULONG sid_a_size)
{
	SID_AND_ATTRIBUTES *result;
	
	if (sid_a == NULL)
		return NULL;

	result = (SID_AND_ATTRIBUTES *)malloc_np(sid_a_size);
	if (result == NULL)
		return NULL;

	memcpy(result, sid_a, sid_a_size);

	result->Sid = (char *)result + ((char *)(sid_a->Sid) - (char *)sid_a);

	return result;
}


void
log_disconnect(struct ot_entry *ote_conn)
{
	TA_ADDRESS *local_addr, *remote_addr;
	struct flt_request request;

	local_addr = (TA_ADDRESS *)(ote_conn->local_addr);
	remote_addr = (TA_ADDRESS *)(ote_conn->remote_addr);

	// KdPrint(("[tdi_flt] del_tcp_conn: %x:%u -> %x:%u\n",
	// 	ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
	// 	ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port),
	// 	ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
	// 	ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port)));

	memset(&request, 0, sizeof(request));

	request.struct_size = sizeof(request);

	request.result = FILTER_DISCONNECT;
	request.proto = ote_conn->ipproto;
	request.direction = DIRECTION_ANY;

	request.pid = (ULONG)-1;		// don't use pid because on close there's no info in database

	// get user SID & attributes!
	if ((request.sid_a = copy_sid_a(ote_conn->sid_a, ote_conn->sid_a_size)) != NULL)
		request.sid_a_size = ote_conn->sid_a_size;

	memcpy(&request.addr.from, &local_addr->AddressType, sizeof(struct sockaddr));
	memcpy(&request.addr.to, &remote_addr->AddressType, sizeof(struct sockaddr));
	request.addr.len = sizeof(struct sockaddr_in);

	request.log_bytes_in = ote_conn->bytes_in;
	request.log_bytes_out = ote_conn->bytes_out;
	
	log_request(&request);
}


void
ot_cleanup_ote(struct ot_entry *ote)
{
	struct ot_entry *saved_next;
    PFILE_OBJECT saved_fileobj;
    unsigned int i;

    // set all fields to zero except "next" and "fileobj" (cleanup listen/conn_entry if any)

    saved_next = ote->next;
    saved_fileobj = ote->fileobj;

    if (ote->type == FILEOBJ_ADDROBJ && ote->listen_entry != NULL) {

		del_listen_obj(ote->listen_entry, FALSE);
    
    } else if (ote->type == FILEOBJ_CONNOBJ && ote->conn_entry != NULL) {
		if (ote->ipproto == IPPROTO_TCP && ote->log_disconnect)
			// log_disconnect(ote);
    	
		del_tcp_conn_obj(ote->conn_entry, FALSE);
	}

	memset(ote, 0, sizeof(*ote));

    ote->next = saved_next;
    ote->fileobj = saved_fileobj;

    // restore fileobjs
	for (i = 0; i < MAX_EVENT; i++)
		ote->ctx[i].fileobj = saved_fileobj;

}


NTSTATUS
ot_add_fileobj(PDEVICE_OBJECT devobj, PFILE_OBJECT fileobj, int fileobj_type, int ipproto,
			   CONNECTION_CONTEXT conn_ctx)		// must be called at PASSIVE_LEVEL!
{
	ULONG hash = CALC_HASH(fileobj);
	KIRQL irql;
	struct ot_entry *ote;
	NTSTATUS status;
	int i;
	SID_AND_ATTRIBUTES *sid_a;
	ULONG sid_a_size;

	if (fileobj == NULL)
		return STATUS_INVALID_PARAMETER_2;

	// while we're at PASSIVE_LEVEL get SID & attributes
	sid_a = get_current_sid_a(&sid_a_size);

	KeAcquireSpinLock(&g_ot_hash_guard, &irql);
	
	for (ote = g_ot_hash[hash]; ote != NULL; ote = ote->next)
		if (ote->fileobj == fileobj)
			break;

	if (ote == NULL) {
		ote = (struct ot_entry *)malloc_np(sizeof(*ote));
		if (ote == NULL) {
			KdPrint(("[tdi_fw] ot_add_fileobj: malloc_np\n"));
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto done;
		}
		memset(ote, 0, sizeof(*ote));

		ote->next = g_ot_hash[hash];
		g_ot_hash[hash] = ote;

		ote->fileobj = fileobj;
		for (i = 0; i < MAX_EVENT; i++)
			ote->ctx[i].fileobj = fileobj;

	} else {
		KdPrint(("[tdi_fw] ot_add_fileobj: reuse fileobj 0x%x\n", fileobj));

        ot_cleanup_ote(ote);
	}

	ote->signature = 'OTE ';
	ote->pid = (ULONG)PsGetCurrentProcessId();

	// save SID & attributes
	ote->sid_a = sid_a;
	ote->sid_a_size = sid_a_size;
	sid_a = NULL;

	ote->devobj = devobj;

	ote->type = fileobj_type;
	ote->ipproto = ipproto;
	ote->conn_ctx = conn_ctx;

	status = STATUS_SUCCESS;

done:
	// cleanup
	KeReleaseSpinLock(&g_ot_hash_guard, irql);
	if (sid_a != NULL)
		free(sid_a);

	return status;
}


 // IRP completion routines and their contexts              disp obj.c    

static NTSTATUS	tdi_create_addrobj_complete(
	IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

// context for tdi_create_addrobj_complete2
typedef struct {
	TDI_ADDRESS_INFO	*tai;		/* address info -- result of TDI_QUERY_ADDRESS_INFO */
	PFILE_OBJECT		fileobj;	/* FileObject from IO_STACK_LOCATION */
} TDI_CREATE_ADDROBJ2_CTX;

static NTSTATUS tdi_create_addrobj_complete2(
	IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

//----------------------------------------------------------------------------

/* this completion routine queries address and port from address object */
struct ot_entry	*ot_find_fileobj(PFILE_OBJECT fileobj, KIRQL *irql);
// Note: don't forget KeReleaseSpinLock(&g_ot_hash_guard, irql);

//----------------------------------------------------------------------------

NTSTATUS
add_listen(struct ot_entry *ote_addr)
{
	TA_ADDRESS *address = (TA_ADDRESS *)(ote_addr->local_addr);
	struct listen_entry *le;
	KIRQL irql;
	ULONG hash;

	if (address->AddressType != TDI_ADDRESS_TYPE_IP)
		return STATUS_INVALID_PARAMETER;

	le = (struct listen_entry *)malloc_np(sizeof(*le));
	if (le == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	memset(le, 0, sizeof(*le));

	le->addrobj = ote_addr->fileobj;
	le->addr = ((TDI_ADDRESS_IP *)(address->Address))->in_addr;
	le->port = ((TDI_ADDRESS_IP *)(address->Address))->sin_port;
	le->ipproto = ote_addr->ipproto;

	KdPrint(("[tdi_fw] add_list: got LISTEN %x:%u (ipproto=%d)\n", le->addr, tdifw_ntohs(le->port), le->ipproto));

	// save le in ote

	if (ote_addr->listen_entry != NULL) {
		KdPrint(("[tdi_fw] add_listen: duplicate listen for addrobj!\n"));

		free(le);
		return STATUS_OBJECT_NAME_EXISTS;
	}

	ote_addr->listen_entry = le;

	// add to our hash

	hash = CALC_LISTEN_HASH(le->ipproto, le->port);

	KeAcquireSpinLock(&g_listen_guard, &irql);
	
	le->next = g_listen[hash];
	if (g_listen[hash] != NULL)
		g_listen[hash]->prev = le;
	g_listen[hash] = le;

	KeReleaseSpinLock(&g_listen_guard, irql);

	return STATUS_SUCCESS;
}

//                  obj tbl



//                   tdi_fw.c
/*
 * Completion routines must call this function at the end of their execution
 */
NTSTATUS
tdi_generic_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	KdPrint(("[tdi_fw] tdi_generic_complete: STATUS = 0x%x\n", Irp->IoStatus.Status));

	if (Irp->PendingReturned) {
		KdPrint(("[tdi_fw] tdi_generic_complete: PENDING\n"));
		IoMarkIrpPending(Irp);
	}

	return STATUS_SUCCESS;
}

/* this completion routine queries address and port from address object */
NTSTATUS
tdi_create_addrobj_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(Irp);
	PIRP query_irp = (PIRP)Context;
	PDEVICE_OBJECT devobj;
	TDI_CREATE_ADDROBJ2_CTX *ctx = NULL;
	PMDL mdl = NULL;

	KdPrint(("[tdi_fw] tdi_create_addrobj_complete: devobj 0x%x; addrobj 0x%x\n",
		DeviceObject, irps->FileObject));

	if (Irp->IoStatus.Status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: status 0x%x\n", Irp->IoStatus.Status));

		status = Irp->IoStatus.Status;
		goto done;
	}

	// query addrobj address:port

	ctx = (TDI_CREATE_ADDROBJ2_CTX *)malloc_np(sizeof(TDI_CREATE_ADDROBJ2_CTX));
	if (ctx == NULL) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: malloc_np\n"));
		
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	ctx->fileobj = irps->FileObject;

	ctx->tai = (TDI_ADDRESS_INFO *)malloc_np(TDI_ADDRESS_INFO_MAX);
	if (ctx->tai == NULL) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: malloc_np!\n"));

		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	mdl = IoAllocateMdl(ctx->tai, TDI_ADDRESS_INFO_MAX, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: IoAllocateMdl!\n"));
		
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	MmBuildMdlForNonPagedPool(mdl);

	devobj = get_original_devobj(DeviceObject, NULL);	// use original devobj!
	if (devobj == NULL) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: get_original_devobj!\n"));

		status = STATUS_INVALID_PARAMETER;
		goto done;
	}

	TdiBuildQueryInformation(query_irp, devobj, irps->FileObject,
		tdi_create_addrobj_complete2, ctx,
		TDI_QUERY_ADDRESS_INFO, mdl);

	status = IoCallDriver(devobj, query_irp);
	query_irp = NULL;
	mdl = NULL;
	ctx = NULL;

	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: IoCallDriver: 0x%x\n", status));
		goto done;
	}

	status = STATUS_SUCCESS;

done:
	// cleanup
	if (mdl != NULL)
		IoFreeMdl(mdl);
	
	if (ctx != NULL) {
		if (ctx->tai != NULL)
			free(ctx->tai);
		free(ctx);
	}
	
	if (query_irp != NULL)
		IoCompleteRequest(query_irp, IO_NO_INCREMENT);

	Irp->IoStatus.Status = status;
	
	if (status != STATUS_SUCCESS) {
		// tdi_create failed - remove fileobj from hash
		ot_del_fileobj(irps->FileObject, NULL);
	}

	return tdi_generic_complete(DeviceObject, Irp, Context);
}

/* this completion routine gets address and port from reply to TDI_QUERY_ADDRESS_INFO */
NTSTATUS
tdi_create_addrobj_complete2(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	NTSTATUS status;
	TDI_CREATE_ADDROBJ2_CTX *ctx = (TDI_CREATE_ADDROBJ2_CTX *)Context;
	TA_ADDRESS *addr = ctx->tai->Address.Address;
	struct ot_entry *ote_addr;
	KIRQL irql;
	int ipproto;

	// KdPrint(("[tdi_fw] tdi_create_addrobj_complete2: address: %x:%u\n", 
	// 	 ntohl(((TDI_ADDRESS_IP *)(addr->Address))->in_addr),
	// 	 ntohs(((TDI_ADDRESS_IP *)(addr->Address))->sin_port)));

	// save address

	ote_addr = ot_find_fileobj(ctx->fileobj, &irql);
	if (ote_addr == NULL) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete2: ot_find_fileobj(0x%x)\n",
			ctx->fileobj));
		status = STATUS_OBJECT_NAME_NOT_FOUND;
		goto done;
	}

	if (addr->AddressLength > sizeof(ote_addr->local_addr)) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete2: address too long! (%u)\n",
			addr->AddressLength));
		status = STATUS_BUFFER_OVERFLOW;
		goto done;
	}
	memcpy(ote_addr->local_addr, addr, addr->AddressLength);

	if (ote_addr->ipproto != IPPROTO_TCP) {
		// set "LISTEN" state for this addrobj
		status = add_listen(ote_addr);
		if (status != STATUS_SUCCESS) {
			KdPrint(("[tdi_fw] tdi_create_addrobj_complete2: add_listen: 0x%x!\n", status));
			goto done;
		}
	}

	status = STATUS_SUCCESS;
done:
	if (ote_addr != NULL)
		KeReleaseSpinLock(&g_ot_hash_guard, irql);

	// cleanup MDL to avoid unlocking pages from NonPaged pool
	if (Irp->MdlAddress != NULL) {
		IoFreeMdl(Irp->MdlAddress);
		Irp->MdlAddress = NULL;
	}

	free(ctx->tai);
	free(ctx);

	// success anyway
	return STATUS_SUCCESS;
}

//---------------------------------------------------

// information about completion routine
struct completion {
	PIO_COMPLETION_ROUTINE	routine;
	PVOID					context;
};

/*
 * TDI_CREATE handler
 */

int
tdi_create(PIRP irp, PIO_STACK_LOCATION irps, struct completion *completion)
{
	NTSTATUS status;
	FILE_FULL_EA_INFORMATION *ea = (FILE_FULL_EA_INFORMATION *)irp->AssociatedIrp.SystemBuffer;

	/* pid resolving stuff: a good place for it (PASSIVE level, begin of working with TDI-objects) */
	ULONG pid = (ULONG)PsGetCurrentProcessId();

	// if process name is unknown try to resolve it
	if (!pid_pname_resolve(pid, NULL, 0)) {
		KEVENT event;
		struct flt_request request;
	
		KeInitializeEvent(&event, NotificationEvent, FALSE);
		pid_pname_set_event(pid, &event);

		memset(&request, 0, sizeof(request));
		request.struct_size = sizeof(request);

		request.type = TYPE_RESOLVE_PID;
		request.pid = pid;

		// get user SID & attributes!
		request.sid_a = get_current_sid_a(&request.sid_a_size);
		
		if (log_request(&request)) {
			// wait a little for reply from user-mode application
			LARGE_INTEGER li;
			li.QuadPart = 5000 * -10000;	// 5 sec

			status = KeWaitForSingleObject(&event, UserRequest, KernelMode, FALSE, &li);

		} else {
			// check all rulesets: we've got the only _default_ ruleset active
			status = default_chain_only() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		}

		if (request.sid_a != NULL)
			free(request.sid_a);

		// reset wait event
		pid_pname_set_event(pid, NULL);

		if (status != STATUS_SUCCESS)
			return FILTER_DENY;			// deny it!
	}

	/* TDI_CREATE related stuff */

	if (ea != NULL) {
		/*
		 * We have FILE_FULL_EA_INFORMATION
		 */

		PDEVICE_OBJECT devobj;
		int ipproto;
		
		devobj = get_original_devobj(irps->DeviceObject, &ipproto);
		if (devobj == NULL) {
			KdPrint(("[tdi_fw] tdi_create: unknown device object 0x%x!\n", irps->DeviceObject));
			return FILTER_DENY;
		}
		// NOTE: for RawIp you can extract protocol number from irps->FileObject->FileName

		if (ea->EaNameLength == TDI_TRANSPORT_ADDRESS_LENGTH &&
			memcmp(ea->EaName, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH) == 0) {

			PIRP query_irp;

			/*
			 * This is creation of address object
			 */

			KdPrint(("[tdi_fw] tdi_create: devobj 0x%x; addrobj 0x%x\n",
				irps->DeviceObject,
				irps->FileObject));

			status = ot_add_fileobj(irps->DeviceObject, irps->FileObject, FILEOBJ_ADDROBJ, ipproto, NULL);
			if (status != STATUS_SUCCESS) {
				KdPrint(("[tdi_fw] tdi_create: ot_add_fileobj: 0x%x\n", status));
				return FILTER_DENY;
			}

			// while we're on PASSIVE_LEVEL build control IRP for completion
			query_irp = TdiBuildInternalDeviceControlIrp(TDI_QUERY_INFORMATION,
				devobj, irps->FileObject, NULL, NULL);
			if (query_irp == NULL) {
				KdPrint(("[tdi_fw] tdi_create: TdiBuildInternalDeviceControlIrp\n"));
				return FILTER_DENY;
			}

			/* set IRP completion & context for completion */

			completion->routine = tdi_create_addrobj_complete;
			completion->context = query_irp;

		} else if (ea->EaNameLength == TDI_CONNECTION_CONTEXT_LENGTH &&
			memcmp(ea->EaName, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH) == 0) {
			
			/*
			 * This is creation of connection object
			 */

			CONNECTION_CONTEXT conn_ctx = *(CONNECTION_CONTEXT *)
				(ea->EaName + ea->EaNameLength + 1);

			KdPrint(("[tdi_fw] tdi_create: devobj 0x%x; connobj 0x%x; conn_ctx 0x%x\n",
				irps->DeviceObject,
				irps->FileObject,
				conn_ctx));

			status = ot_add_fileobj(irps->DeviceObject, irps->FileObject,
				FILEOBJ_CONNOBJ, ipproto, conn_ctx);

			if (status != STATUS_SUCCESS) {
				KdPrint(("[tdi_fw] tdi_create: ot_add_fileobj: 0x%x\n", status));
				return FILTER_DENY;
			}
		}
	
	} else {
		/*
		 * This is creation of control object
		 */
		
		KdPrint(("[tdi_fw] tdi_create(pid:%u): devobj 0x%x; Control Object: 0x%x\n",
			pid, irps->DeviceObject, irps->FileObject));
	}

	return FILTER_ALLOW;
}

int i;
/* create & attach device */
NTSTATUS
c_n_a_device(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT *fltobj, PDEVICE_OBJECT *oldobj,
			 wchar_t *devname)
{
	NTSTATUS status;
	UNICODE_STRING str;

	/* create filter device */

	status = IoCreateDevice(DriverObject,
							0,
							NULL,
							FILE_DEVICE_UNKNOWN,
							0,
							TRUE,
							fltobj);
	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] c_n_a_device: IoCreateDevice(%S): 0x%x\n", devname, status));
		return status;
	}

	(*fltobj)->Flags |= DO_DIRECT_IO;

	RtlInitUnicodeString(&str, devname);
	
	status = IoAttachDevice(*fltobj, &str, oldobj);
	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] DriverEntry: IoAttachDevice(%S): 0x%x\n", devname, status));
		return status;
	}

	KdPrint(("[tdi_fw] DriverEntry: %S fileobj: 0x%x\n", devname, *fltobj));

	return STATUS_SUCCESS;
}

//  block end tdi

	/* get original device object by filtered */
PDEVICE_OBJECT
get_original_devobj(PDEVICE_OBJECT flt_devobj, int *proto)
{
// #ifndef USE_TDI_HOOKING
	PDEVICE_OBJECT result;
	int ipproto;

	if (flt_devobj == g_tcpfltobj) {
		result = g_tcpoldobj;
		ipproto = IPPROTO_TCP;
	} else if (flt_devobj == g_udpfltobj) {
		result = g_udpoldobj;
		ipproto = IPPROTO_UDP;
	} else if (flt_devobj == g_ipfltobj) {
		result = g_ipoldobj;
		ipproto = IPPROTO_IP;
	} else {
		KdPrint(("[tdi_fw] get_original_devobj: Unknown DeviceObject 0x%x!\n",
			flt_devobj));
		ipproto = IPPROTO_IP;		// what else?
		result = NULL;
	}

	if (result != NULL && proto != NULL)
		*proto = ipproto;

	return result;
}

/* dispatch */
// NTSTATUS
// DeviceDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
// {
//     PDEVICE_OBJECT old_devobj = get_original_devobj(DeviceObject, NULL);
//     NTSTATUS status;
    
// 	if (old_devobj != NULL) {
// 		IoSkipCurrentIrpStackLocation(irp);
// 		status = IoCallDriver(old_devobj, irp);
// 	}else{
// 		KdPrint(("[tdi_fw] tdi_send_irp_to_old_driver: Unknown DeviceObject 0x%x!\n", DeviceObject));

// 		status = irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
// 		IoCompleteRequest (irp, IO_NO_INCREMENT);
		
// 		return status;
// 	}
// }
/* dispatch */
#define TDI_USER_DEV_MAX 5
PDEVICE_OBJECT g_user_devices[TDI_USER_DEV_MAX] = { NULL };

#if DBG
#	define ENTRY(code, fn)	{code, fn, #code}
#	define LAST_ENTRY		{0, NULL, NULL}
#else
#	define ENTRY(code, fn)	{code, fn}
#	define LAST_ENTRY		{0, NULL}
#endif

// // IRP_MJ_INTERNAL_DEVICE_CONTROL ioctl dispatch routines
// extern tdi_ioctl_fn_t
// 	tdi_associate_address,
// 	tdi_connect,
// 	tdi_disassociate_address,
// 	tdi_set_event_handler,
// 	tdi_send_datagram,
// 	tdi_receive_datagram,
// 	tdi_disconnect,
// 	tdi_send,
// 	tdi_receive,
// 	tdi_deny_stub;

typedef int tdi_ioctl_fn_t(PIRP irp, PIO_STACK_LOCATION irps, struct completion *completion);

// helper struct for calling of TDI ioctls
struct tdi_ioctl {
	UCHAR			MinorFunction;
	tdi_ioctl_fn_t	*fn;

#if DBG
	// for debugging
	const char		*desc;
#endif
};
//----------------------------------------------------------------------------

/*
 * TDI_RECEIVE_DATAGRAM handler
 */

int quick_filter(struct flt_request *request, struct flt_rule *rule)
{
	// In fact, I care nothing about rules. I simply call user's function
	// to deciede the result.
	struct flt_rule *myrule = rule;
	return tdifw_filter(request);
}

NTSTATUS
tdi_receive_datagram_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(Irp);
	TDI_REQUEST_KERNEL_RECEIVEDG *param = (TDI_REQUEST_KERNEL_RECEIVEDG *)(&irps->Parameters);
	PFILE_OBJECT addrobj = irps->FileObject;
	struct ot_entry *ote_addr = NULL;
	KIRQL irql;
	int result = FILTER_DENY, ipproto;
	NTSTATUS status = STATUS_SUCCESS;
	struct flt_request request;
	struct flt_rule rule;
	TA_ADDRESS *local_addr, *remote_addr;

	memset(&request, 0, sizeof(request));

	// check device object: UDP or RawIP
	if (get_original_devobj(DeviceObject, &ipproto) == NULL ||
		(ipproto != IPPROTO_UDP && ipproto != IPPROTO_IP)) {
		// unknown device object!
		KdPrint(("[tdi_fw] tdi_receive_datagram_complete: unknown DeviceObject 0x%x!\n",
			DeviceObject));
		status = STATUS_UNSUCCESSFUL;
		goto done;
	}

	KdPrint(("[tdi_fw] tdi_receive_datagram_complete: addrobj 0x%x; status 0x%x; information %u\n",
		addrobj, Irp->IoStatus.Status, Irp->IoStatus.Information));

	if (Irp->IoStatus.Status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] tdi_receive_datagram_complete: status 0x%x\n",
			Irp->IoStatus.Status));
		status = Irp->IoStatus.Status;
		goto done;
	}

	ote_addr = ot_find_fileobj(addrobj, &irql);
	if (ote_addr == NULL) {
		KdPrint(("[tdi_fw] tdi_receive_datagram_complete: ot_find_fileobj(0x%x)!\n",
			addrobj));
		status = STATUS_UNSUCCESSFUL;
		goto done;
	}

	request.struct_size = sizeof(request);

	request.type = TYPE_DATAGRAM;
	request.direction = DIRECTION_IN;
	request.proto = ipproto;
	request.pid = ote_addr->pid;
	
	// get user SID & attributes!
	if ((request.sid_a = copy_sid_a(ote_addr->sid_a, ote_addr->sid_a_size)) != NULL)
		request.sid_a_size = ote_addr->sid_a_size;

	local_addr = (TA_ADDRESS *)(ote_addr->local_addr);
	remote_addr = ((TRANSPORT_ADDRESS *)(param->ReceiveDatagramInformation->RemoteAddress))->Address;

	// KdPrint(("[tdi_fw] tdi_receive_datagram_complete(pid:%u): %x:%u -> %x:%u\n",
	// 	ote_addr->pid,
	// 	ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
	// 	ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port),
	// 	ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
	// 	ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port)));

	memcpy(&request.addr.from, &remote_addr->AddressType, sizeof(struct sockaddr));
	memcpy(&request.addr.to, &local_addr->AddressType, sizeof(struct sockaddr));
	request.addr.len = sizeof(struct sockaddr_in);

	memset(&rule, 0, sizeof(rule));

	result = quick_filter(&request, &rule);

	memcpy(request.log_rule_id, rule.rule_id, RULE_ID_SIZE);

	// if (rule.log >= RULE_LOG_LOG) {
	// 	ULONG bytes = Irp->IoStatus.Information;

	// 	// traffic stats
	// 	KeAcquireSpinLockAtDpcLevel(&g_traffic_guard);
		
	// 	g_traffic[TRAFFIC_TOTAL_IN] += bytes;
		
	// 	if (rule.log >= RULE_LOG_COUNT) {
	// 		request.log_bytes_in = bytes;

	// 		g_traffic[TRAFFIC_COUNTED_IN] += bytes;

	// 	} else
	// 		request.log_bytes_in = (ULONG)-1;

	// 	KeReleaseSpinLockFromDpcLevel(&g_traffic_guard);

	// 	log_request(&request);
	// }

done:
	// convert result to NTSTATUS
	if (result == FILTER_ALLOW)
		status = STATUS_SUCCESS;
	else {		/* FILTER_DENY */

		if (status == STATUS_SUCCESS)
			status = Irp->IoStatus.Status = STATUS_ACCESS_DENIED;	// good status?

	}

	// cleanup
	if (ote_addr != NULL)
		KeReleaseSpinLock(&g_ot_hash_guard, irql);
	if (request.sid_a != NULL)
		free(request.sid_a);
	
	return tdi_generic_complete(DeviceObject, Irp, Context);
}


int
tdi_receive_datagram(PIRP irp, PIO_STACK_LOCATION irps, struct completion *completion)
{
	KdPrint(("[tdi_fw] tdi_receive_datagram: addrobj 0x%x\n", irps->FileObject));

	completion->routine = tdi_receive_datagram_complete;

	return FILTER_ALLOW;
}

struct tdi_ioctl g_tdi_ioctls = ENTRY(TDI_RECEIVE_DATAGRAM,	tdi_receive_datagram);

// struct tdi_ioctl g_tdi_ioctls[] = {
// 	ENTRY(TDI_ASSOCIATE_ADDRESS,	tdi_associate_address),
// 	ENTRY(TDI_CONNECT,				tdi_connect),
// 	ENTRY(TDI_DISASSOCIATE_ADDRESS,	tdi_disassociate_address),
// 	ENTRY(TDI_SET_EVENT_HANDLER,	tdi_set_event_handler),
// 	ENTRY(TDI_SEND_DATAGRAM,		tdi_send_datagram),
// 	ENTRY(TDI_RECEIVE_DATAGRAM,		tdi_receive_datagram),
// 	ENTRY(TDI_DISCONNECT,			tdi_disconnect),
// 	ENTRY(TDI_SEND,					tdi_send),
// 	ENTRY(TDI_RECEIVE,				tdi_receive),
// // #if 1		// for now only deny stubs for security reasons
// 	ENTRY(TDI_ACCEPT,				tdi_deny_stub),
// 	ENTRY(TDI_LISTEN,				tdi_deny_stub),
// // #endif
// 	LAST_ENTRY
// };

/* context for tdi_skip_complete */
typedef struct {
    PIO_COMPLETION_ROUTINE	old_cr;			/* old (original) completion routine */
    PVOID					old_context;	/* old (original) parameter for old_cr */
    PIO_COMPLETION_ROUTINE	new_cr;			/* new (replaced) completion routine */
	PVOID					new_context;	/* new (replaced) parameter for new_cr */
	PFILE_OBJECT			fileobj;		/* FileObject from IO_STACK_LOCATION */
	PDEVICE_OBJECT			new_devobj;		/* filter device object */
	UCHAR					old_control;	/* old (original) irps->Control */
} TDI_SKIP_CTX;


/*
 * completion routine for case if we use IoSkipCurrentIrpStackLocation way
 * or we USE_TDI_HOOKING
 */
NTSTATUS
tdi_skip_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	TDI_SKIP_CTX *ctx = (TDI_SKIP_CTX *)Context;
	NTSTATUS status;
	PIO_STACK_LOCATION irps;

	if (Irp->IoStatus.Status != STATUS_SUCCESS)
		KdPrint(("[tdi_fw] tdi_skip_complete: status 0x%x\n", Irp->IoStatus.Status));

	// restore IRP for using in our completion

	Irp->CurrentLocation--;
	Irp->Tail.Overlay.CurrentStackLocation--;

	irps = IoGetCurrentIrpStackLocation(Irp);

	KdPrint(("[tdi_fw] tdi_skip_complete: DeviceObject = 0x%x; FileObject = 0x%x\n",
		DeviceObject, irps->FileObject));

	DeviceObject = irps->DeviceObject;

	if (ctx->new_cr != NULL) {
		// restore fileobject (it's NULL)
		irps->FileObject = ctx->fileobj;
		// set new device object in irps
		irps->DeviceObject = ctx->new_devobj;
		
		// call new completion 
		status = ctx->new_cr(ctx->new_devobj, Irp, ctx->new_context);

	} else
		status = STATUS_SUCCESS;

	/* patch IRP back */

	// restore routine and context (and even control!)
	irps->CompletionRoutine = ctx->old_cr;
	irps->Context = ctx->old_context;
	irps->Control = ctx->old_control;

	// restore device object
	irps->DeviceObject = DeviceObject;

	Irp->CurrentLocation++;
	Irp->Tail.Overlay.CurrentStackLocation++;

	if (ctx->old_cr != NULL) {

		if (status != STATUS_MORE_PROCESSING_REQUIRED) {
			// call old completion (see the old control)
			BOOLEAN b_call = FALSE;

			if (Irp->Cancel) {
				// cancel
				if (ctx->old_control & SL_INVOKE_ON_CANCEL)
					b_call = TRUE;
			} else {
				if (Irp->IoStatus.Status >= STATUS_SUCCESS) {
					// success
					if (ctx->old_control & SL_INVOKE_ON_SUCCESS)
						b_call = TRUE;
				} else {
					// error
					if (ctx->old_control & SL_INVOKE_ON_ERROR)
						b_call = TRUE;
				}
			}

			if (b_call)
				status = ctx->old_cr(DeviceObject, Irp, ctx->old_context);
		
		} else {

			/*
			 * patch IRP to set IoManager to call completion next time
			 */

			// restore Control
			irps->Control = ctx->old_control;

		}
	}

	free(ctx);

	return status;
}



/*
 * Dispatch routines call this function to complete their processing.
 * They _MUST_ call this function anyway.
 */
NTSTATUS
tdi_dispatch_complete(PDEVICE_OBJECT devobj, PIRP irp, int filter,
					  PIO_COMPLETION_ROUTINE cr, PVOID context)
{
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status;

	if (filter == FILTER_DENY) {
		
		/*
		 * DENY: complete request with status "Access violation"
		 */

		KdPrint(("[tdi_fw] tdi_dispatch_complete: [DROP!]"
			" major 0x%x, minor 0x%x for devobj 0x%x; fileobj 0x%x\n",
			irps->MajorFunction,
			irps->MinorFunction,
			devobj,
			irps->FileObject));

		if (irp->IoStatus.Status == STATUS_SUCCESS) {
			// change status
			status = irp->IoStatus.Status = STATUS_ACCESS_DENIED;
		} else {
			// set IRP status unchanged
			status = irp->IoStatus.Status;
		}

		IoCompleteRequest (irp, IO_NO_INCREMENT);
		
	} else if (filter == FILTER_ALLOW) {

		/*
		 * ALLOW: pass IRP to the next driver
		 */

#ifndef USE_TDI_HOOKING

		PDEVICE_OBJECT old_devobj = get_original_devobj(devobj, NULL);

		if (old_devobj == NULL) {
			KdPrint(("[tdi_fw] tdi_send_irp_to_old_driver: Unknown DeviceObject 0x%x!\n", devobj));
	
			status = irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
			IoCompleteRequest (irp, IO_NO_INCREMENT);
			
			return status;
		}

#endif

		KdPrint(("[tdi_fw] tdi_dispatch_complete: [ALLOW.]"
			" major 0x%x, minor 0x%x for devobj 0x%x; fileobj 0x%x\n",
			irps->MajorFunction,
			irps->MinorFunction,
			devobj,
			irps->FileObject));

#ifndef USE_TDI_HOOKING

		if (cr == NULL || irp->CurrentLocation <= 1) {
			/*
			 * we use _THIS_ way of sending IRP to old driver
			 * a) to avoid NO_MORE_STACK_LOCATIONS
			 * b) and if we haven't our completions - no need to copy stack locations!
			 */

			// stay on this location after IoCallDriver
			IoSkipCurrentIrpStackLocation(irp);

#endif

			if (cr != NULL) {
				/*
				 * set completion routine (this way is slow)
				 */

				// save old completion routine and context
				TDI_SKIP_CTX *ctx = (TDI_SKIP_CTX *)malloc_np(sizeof(*ctx));
				if (ctx == NULL) {
					KdPrint(("[tdi_fw] tdi_send_irp_to_old_driver: malloc_np\n"));
					
					status = irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					IoCompleteRequest(irp, IO_NO_INCREMENT);
					
					return status;
				}

				ctx->old_cr = irps->CompletionRoutine;
				ctx->old_context = irps->Context;
				ctx->new_cr = cr;
				ctx->new_context = context;
				ctx->fileobj = irps->FileObject;
				ctx->new_devobj = devobj;

				ctx->old_control = irps->Control;

				IoSetCompletionRoutine(irp, tdi_skip_complete, ctx, TRUE, TRUE, TRUE);
			}

#ifndef USE_TDI_HOOKING			
		} else {
			PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(irp),
				next_irps = IoGetNextIrpStackLocation(irp);
			
			memcpy(next_irps, irps, sizeof(*irps));

			if (cr != NULL) {
				/*
				 * this way for completion is more quicker than used above
				 */

				IoSetCompletionRoutine(irp, cr, context, TRUE, TRUE, TRUE);
			} else
				IoSetCompletionRoutine(irp, tdi_generic_complete, NULL, TRUE, TRUE, TRUE);
		}
#endif

		/* call original driver */

#ifndef USE_TDI_HOOKING
		status = IoCallDriver(old_devobj, irp);
#else
		status = g_old_DriverObject.MajorFunction[irps->MajorFunction](devobj, irp);
#endif

	} else {	/* FILTER_UNKNOWN */

		/*
		 * UNKNOWN: just complete the request
		 */

		status = irp->IoStatus.Status = STATUS_SUCCESS;	// ???
		IoCompleteRequest (irp, IO_NO_INCREMENT);
	}

	return status;
}


NTSTATUS
DeviceDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
	PIO_STACK_LOCATION irps;
	NTSTATUS status;
	int i;				// add by tanwen

	// sanity check
	if (irp == NULL) {
		KdPrint(("[tdi_fw] DeviceDispatch: !irp\n"));
		return STATUS_SUCCESS;
	}
	
	// add by tanwen
	// for(i=0;i<TDI_USER_DEV_MAX;++i)
	// {
	// 	if(g_user_devices[i] == DeviceObject)
	// 		return tdifw_user_device_dispatch(DeviceObject,irp);
	// }

	irps = IoGetCurrentIrpStackLocation(irp);

	if (DeviceObject == g_tcpfltobj || DeviceObject == g_udpfltobj ||
		DeviceObject == g_ipfltobj) {

		/*
		 * This IRP is for filtered device
		 */

		int result;
		struct completion completion;

		memset(&completion, 0, sizeof(completion));

		// Analyze MajorFunction
		switch (irps->MajorFunction) {

			case IRP_MJ_CREATE:	{/* create fileobject */
				
				result = tdi_create(irp, irps, &completion);

				status = tdi_dispatch_complete(DeviceObject, irp, result,
					completion.routine, completion.context);
				
				break;
			}
			// case IRP_MJ_DEVICE_CONTROL:
				
			// 	KdPrint(("[tdi_fw] DeviceDispatch: IRP_MJ_DEVICE_CONTROL, control 0x%x for 0x%08X\n",
			// 		irps->Parameters.DeviceIoControl.IoControlCode, irps->FileObject));

			// 	if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
			// 		/*
			// 		 * try to convert it to IRP_MJ_INTERNAL_DEVICE_CONTROL
			// 		 * (works on PASSIVE_LEVEL only!)
			// 		 */
			// 		status = TdiMapUserRequest(DeviceObject, irp, irps);
			// 	} else
			// 		status = STATUS_NOT_IMPLEMENTED; // set fake status

			// 	if (status != STATUS_SUCCESS) {
			// 		void *buf = (irps->Parameters.DeviceIoControl.IoControlCode == IOCTL_TDI_QUERY_DIRECT_SEND_HANDLER) ?
			// 			irps->Parameters.DeviceIoControl.Type3InputBuffer : NULL;

			// 		// send IRP to original driver
			// 		status = tdi_dispatch_complete(DeviceObject, irp, FILTER_ALLOW, NULL, NULL);

			// 		if (buf != NULL && status == STATUS_SUCCESS) {

			// 			g_TCPSendData = *(TCPSendData_t **)buf;

			// 			KdPrint(("[tdi_fw] DeviceDispatch: IOCTL_TDI_QUERY_DIRECT_SEND_HANDLER: TCPSendData = 0x%x\n",
			// 				g_TCPSendData));

			// 			*(TCPSendData_t **)buf = new_TCPSendData;
			// 		}

			// 		break;
			// 	}

				// don't break! go to internal device control!
			
			case IRP_MJ_INTERNAL_DEVICE_CONTROL: {
				/*
				 * Analyze ioctl for TDI driver
				 */
				int i;

				if (irps->MinorFunction == TDI_RECEIVE_DATAGRAM){
					
	// #if DBG
					// print description
					// KdPrint(("[tdi_fw] DeviceDispatch: %s (0x%x) for 0x%x\n",
					// 	ENTRY(TDI_RECEIVE_DATAGRAM,	tdi_receive_datagram).desc,
					// 	irps->MinorFunction,
					// 	irps->FileObject));
	// #endif

					if (g_tdi_ioctls.fn == NULL){
						// send IRP to original driver
						status = tdi_dispatch_complete(DeviceObject, irp, FILTER_ALLOW,
							NULL, NULL);
						break;
					}

					// call dispatch function

					result = g_tdi_ioctls.fn(irp, irps, &completion);

					// complete request
					status = tdi_dispatch_complete(DeviceObject, irp, result,
						completion.routine, completion.context);

					break;
				}
		
				// if dispatch function hasn't been found
				if (g_tdi_ioctls.MinorFunction == 0){
					// send IRP to original driver
					status = tdi_dispatch_complete(DeviceObject, irp, FILTER_ALLOW, NULL, NULL);
				}

				break;
			}

			// case IRP_MJ_CLEANUP:		/* cleanup fileobject */

			// 	result = tdi_cleanup(irp, irps, &completion);

			// 	status = tdi_dispatch_complete(DeviceObject, irp, result,
			// 		completion.routine, completion.context);
			// 	break;

			// case IRP_MJ_CLOSE:
			// 	KdPrint(("[tdi_fw] DeviceDispatch: IRP_MJ_CLOSE fileobj 0x%x\n", irps->FileObject));

			// 	// passthrough IRP
			// 	status = tdi_dispatch_complete(DeviceObject, irp, FILTER_ALLOW,
			// 		completion.routine, completion.context);

			// 	break;

			default:{
				KdPrint(("[tdi_fw] DeviceDispatch: major 0x%x, minor 0x%x for 0x%x\n",
					irps->MajorFunction, irps->MinorFunction, irps->FileObject));

				// passthrough IRP
				status = tdi_dispatch_complete(DeviceObject, irp, FILTER_ALLOW,
					completion.routine, completion.context);
				break;
			}
		}

	} 
// else if (DeviceObject == g_devcontrol) {

// 		/*
// 		 * this IRP is for control device
// 		 */

// 		// set default status
// 		status = STATUS_SUCCESS;

// 		if (irps->MajorFunction == IRP_MJ_CREATE) {

// 			// initialize for user-mode part (exclusive access - 1 user-mode logging part)
// 			filter_init_2();

// 			g_got_log = TRUE;

// 		} else if (irps->MajorFunction == IRP_MJ_CLOSE) {

// 			// cleanup for user-mode logging part
// 			filter_free_2();

// 			g_got_log = FALSE;

// 		} if (irps->MajorFunction == IRP_MJ_DEVICE_CONTROL) {

// 			/*
// 			 * control request
// 			 */

// 			ULONG ioctl = irps->Parameters.DeviceIoControl.IoControlCode,
// 				len = irps->Parameters.DeviceIoControl.InputBufferLength,
// 				size = irps->Parameters.DeviceIoControl.OutputBufferLength;
// 			char *out_buf;

// 			if (IOCTL_TRANSFER_TYPE(ioctl) == METHOD_NEITHER) {
// 				// this type of transfer unsupported
// 				out_buf = NULL;
// 			} else
// 				out_buf = (char *)irp->AssociatedIrp.SystemBuffer;

// 			// process control request
// 			status = process_request(ioctl, out_buf, &len, size);

// 			irp->IoStatus.Information = len;

// 		}

// 		irp->IoStatus.Status = status;

// 		IoCompleteRequest(irp, IO_NO_INCREMENT);

// 	} else if (DeviceObject == g_devnfo) {

// 		/*
// 		 * this IRP is for information device
// 		 */

// 		// set default status
// 		status = STATUS_SUCCESS;

// 		if (irps->MajorFunction == IRP_MJ_DEVICE_CONTROL) {

// 			/*
// 			 * control request
// 			 */

// 			ULONG ioctl = irps->Parameters.DeviceIoControl.IoControlCode,
// 				len = irps->Parameters.DeviceIoControl.InputBufferLength,
// 				size = irps->Parameters.DeviceIoControl.OutputBufferLength;
// 			char *out_buf;

// 			if (IOCTL_TRANSFER_TYPE(ioctl) == METHOD_NEITHER) {
// 				// this type of transfer unsupported
// 				out_buf = NULL;
// 			} else
// 				out_buf = (char *)irp->AssociatedIrp.SystemBuffer;

// 			// process control request
// 			status = process_nfo_request(ioctl, out_buf, &len, size);

// 			irp->IoStatus.Information = len;

// 		}

// 		irp->IoStatus.Status = status;

// 		IoCompleteRequest(irp, IO_NO_INCREMENT);

// 	} else {

// 		KdPrint(("[tdi_fw] DeviceDispatch: ioctl for unknown DeviceObject 0x%x\n", DeviceObject));

// #ifndef USE_TDI_HOOKING
// 		// ??? just complete IRP
// 		status = irp->IoStatus.Status = STATUS_SUCCESS;
// 		IoCompleteRequest(irp, IO_NO_INCREMENT);
// #else
// 		// call original handler
// 		status = g_old_DriverObject.MajorFunction[irps->MajorFunction](
// 			DeviceObject, irp);
// #endif
// 	}

	return status;
}


u_short tdifw_ntohs(u_short netshort)
{
	u_short result = 0;
	((char *)&result)[0] = ((char *)&netshort)[1];
	((char *)&result)[1] = ((char *)&netshort)[0];
	return result;
}


int tdifw_filter(struct flt_request *request)
{
    if(request->proto == IPPROTO_TCP)
    {
        struct sockaddr_in* from = (struct sockaddr_in*)&request->addr.from;
        struct sockaddr_in* to = (struct sockaddr_in*)&request->addr.to;

        // È»ºó´òÓ¡Ð­ÒéÀàÐÍ
        DbgPrint("tdifw_smpl: protocol type = TCP\r\n");
        // ´òÓ¡µ±Ç°½ø³ÌµÄPID¡£
        DbgPrint("tdifw_smpl: currect process = %d\r\n",request->pid);

        // ´òÓ¡ÊÂ¼þÀàÐÍ
        switch(request->type)
        {
        case TYPE_CONNECT:
            DbgPrint("tdifw_smpl: event: CONNECT\r\n");
            break;
        case TYPE_DATAGRAM:
            DbgPrint("tdifw_smpl: event: DATAGRAM\r\n");
            break;
        case TYPE_CONNECT_ERROR:
            DbgPrint("tdifw_smpl: event: CONNECT ERROR\r\n");
            break;
        case TYPE_LISTEN:
            DbgPrint("tdifw_smpl: event: LISTEN\r\n");
            break;
        case TYPE_NOT_LISTEN:
            DbgPrint("tdifw_smpl: event: NOT LISTEN\r\n");
            break;
        case TYPE_CONNECT_CANCELED:
            DbgPrint("tdifw_smpl: event: CONNECT CANCELED\r\n");
            break;
        case TYPE_CONNECT_RESET:
            DbgPrint("tdifw_smpl: event: CONNECT RESET\r\n");
            break;
        case TYPE_CONNECT_TIMEOUT:
            DbgPrint("tdifw_smpl: event: CONNECT TIMEOUT\r\n");
            break;
        case TYPE_CONNECT_UNREACH:
            DbgPrint("tdifw_smpl: event: CONNECT UNREACH\r\n");
            break;
        default:
            break;
        }
  

        // Èç¹ûÊÇTCP£¬ÎÒÃÇ´òÓ¡¸ü¶àµÄÄÚÈÝ¡£°üÀ¨·½Ïò£¬À´Ô´IPµØÖ·
        // Ä¿µÄIPµØÖ·£¬µÈµÈ¡£µ«ÊÇ¶ÔÓÚÆäËûÐ­Òé¾Í²»´òÓ¡ÁË¡£
        DbgPrint("tdifw_smpl: direction = %d\r\n",request->direction);
        //DbgPrint("tdifw_smpl: src port = %d\r\n",tdifw_ntohs(from->sin_port));
        // DbgPrint("tdifw_smpl: src ip = %d.%d.%d.%d\r\n",
        //     from->sin_addr.S_un.S_un_b.s_b1,
        //     from->sin_addr.S_un.S_un_b.s_b2,
        //     from->sin_addr.S_un.S_un_b.s_b3,
        //     from->sin_addr.S_un.S_un_b.s_b4);
        // //DbgPrint("tdifw_smpl: dst port = %d\r\n",tdifw_ntohs(to->sin_port));
        // DbgPrint("tdifw_smpl: dst ip = %d.%d.%d.%d\r\n",
        //     to->sin_addr.S_un.S_un_b.s_b1,
        //     to->sin_addr.S_un.S_un_b.s_b2,
        //     to->sin_addr.S_un.S_un_b.s_b3,
        //     to->sin_addr.S_un.S_un_b.s_b4);
    }

    return FILTER_ALLOW;
}


VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{

	IoDeleteDevice(DriverObject->DeviceObject);
	return;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DbgPrint("Jason running\n");

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) 
		theDriverObject->MajorFunction[i] = DeviceDispatch;
	theDriverObject->DriverUnload = OnUnload;


	// Add by tanwen.
	// Call this function before hooking! So that when tdifw_filter() happened, 
	// Our driver has been initialized.
	// status = tdifw_driver_entry(theDriverObject,theRegistryPath);

	status = c_n_a_device(theDriverObject, &g_tcpfltobj, &g_tcpoldobj, L"\\Device\\Tcp");
	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] DriverEntry: c_n_a_device: 0x%x\n", status));
		goto done;
	}

	status = c_n_a_device(theDriverObject, &g_udpfltobj, &g_udpoldobj, L"\\Device\\Udp");
	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] DriverEntry: c_n_a_device: 0x%x\n", status));
		goto done;
	}

	status = c_n_a_device(theDriverObject, &g_ipfltobj, &g_ipoldobj, L"\\Device\\RawIp");
	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] DriverEntry: c_n_a_device: 0x%x\n", status));
		goto done;
	}

	done:
	if (status != STATUS_SUCCESS) {
		// cleanup
		OnUnload(theDriverObject);
	}

	return status;
}



