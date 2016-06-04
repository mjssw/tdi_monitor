
#include "..\tdifw-1.4.4\src\drv\tdi_fw.h"

NTSTATUS
tdifw_driver_entry(
			IN PDRIVER_OBJECT theDriverObject,
            IN PUNICODE_STRING theRegistryPath)
{        
    return STATUS_SUCCESS;
}

VOID
tdifw_driver_unload(
			IN PDRIVER_OBJECT DriverObject)
{
    return;
}

NTSTATUS tdifw_user_device_dispatch(
	IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
    // do nothing just rewrite
    return STATUS_UNSUCCESSFUL;
}

u_short
tdifw_ntohs (u_short netshort)
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

        DbgPrint("$$$protocol type = TCP\r\n");

        DbgPrint("$$$currect process = %d\r\n",request->pid);

        switch(request->type)
        {
        case TYPE_CONNECT:
            DbgPrint("$$$event: CONNECT\r\n");
            break;
        case TYPE_DATAGRAM:
            DbgPrint("$$$event: DATAGRAM\r\n");
            break;
        case TYPE_CONNECT_ERROR:
            DbgPrint("$$$event: CONNECT ERROR\r\n");
            break;
        case TYPE_LISTEN:
            DbgPrint("$$$event: LISTEN\r\n");
            break;
        case TYPE_NOT_LISTEN:
            DbgPrint("$$$event: NOT LISTEN\r\n");
            break;
        case TYPE_CONNECT_CANCELED:
            DbgPrint("$$$event: CONNECT CANCELED\r\n");
            break;
        case TYPE_CONNECT_RESET:
            DbgPrint("$$$event: CONNECT RESET\r\n");
            break;
        case TYPE_CONNECT_TIMEOUT:
            DbgPrint("$$$event: CONNECT TIMEOUT\r\n");
            break;
        case TYPE_CONNECT_UNREACH:
            DbgPrint("$$$event: CONNECT UNREACH\r\n");
            break;
        default:
            break;
        }
  
        DbgPrint("$$$direction = %d\r\n",request->direction);
        DbgPrint("$$$src port = %d\r\n",tdifw_ntohs(from->sin_port)); //高低位转换
        DbgPrint("$$$src ip = %d.%d.%d.%d\r\n",
            from->sin_addr.S_un.S_un_b.s_b1,
            from->sin_addr.S_un.S_un_b.s_b2,
            from->sin_addr.S_un.S_un_b.s_b3,
            from->sin_addr.S_un.S_un_b.s_b4);
        DbgPrint("$$$dst port = %d\r\n",tdifw_ntohs(to->sin_port));
        DbgPrint("$$$dst ip = %d.%d.%d.%d\r\n",
            to->sin_addr.S_un.S_un_b.s_b1,
            to->sin_addr.S_un.S_un_b.s_b2,
            to->sin_addr.S_un.S_un_b.s_b3,
            to->sin_addr.S_un.S_un_b.s_b4);
    }

    return FILTER_ALLOW;
}
