/*******************************************************************************
*                Copyright 2007, MARVELL SEMICONDUCTOR, LTD.                   *
* THIS CODE CONTAINS CONFIDENTIAL INFORMATION OF MARVELL.                      *
* NO RIGHTS ARE GRANTED HEREIN UNDER ANY PATENT, MASK WORK RIGHT OR COPYRIGHT  *
* OF MARVELL OR ANY THIRD PARTY. MARVELL RESERVES THE RIGHT AT ITS SOLE        *
* DISCRETION TO REQUEST THAT THIS CODE BE IMMEDIATELY RETURNED TO MARVELL.     *
* THIS CODE IS PROVIDED "AS IS". MARVELL MAKES NO WARRANTIES, EXPRESSED,       *
* IMPLIED OR OTHERWISE, REGARDING ITS ACCURACY, COMPLETENESS OR PERFORMANCE.   *
*                                                                              *
* MARVELL COMPRISES MARVELL TECHNOLOGY GROUP LTD. (MTGL) AND ITS SUBSIDIARIES, *
* MARVELL INTERNATIONAL LTD. (MIL), MARVELL TECHNOLOGY, INC. (MTI), MARVELL    *
* SEMICONDUCTOR, INC. (MSI), MARVELL ASIA PTE LTD. (MAPL), MARVELL JAPAN K.K.  *
* (MJKK), MARVELL ISRAEL LTD. (MSIL).                                          *
*******************************************************************************/


#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "com_type.h"
#include "ErrorCode.h"
#include "shm_type.h"
#include "shm_api.h"


#define CHECK_RESULT(name, res, res_ok)	if ((res) != (res_ok))  \
    {   \
        MV_SHM_Print("%s:%u:%s: [%08x] [%s] Failed\n", \
        __FILE__, __LINE__, __FUNCTION__, (res), (name));  \
        assert(0);   \
    }

#define CHECK_NOTERROR(name, res, error) if ((res) == (error))  \
    {   \
        MV_SHM_Print("%s:%u:%s: [%08x] [%s] Failed, error(%d) = %s\n", \
        __FILE__, __LINE__, __FUNCTION__, (res), (name), \
        errno, strerror(errno));  \
        assert(0);   \
    }

/*******************************************************************************
    Module Variable
*/

static shm_dev_t shm_cache;
static shm_dev_t shm_noncache;
static shm_dev_t shm_secure_cache;
static shm_dev_t shm_secure_noncache;


int SHM_DEVICE_LOAD_COUNT = 0; //should be a sington in a process

/*******************************************************************************
    Module API
*/
/*******************************************************************************
  *open shm_cache and shm_noncache device, map the address space separately
  *each process should only Init once.
  */

#ifdef ANDROID
#include <cutils/log.h>

VOID MV_SHM_Print( CHAR* fmt, ... )
{
	va_list ap;
	char buffer[512];

	va_start( ap, fmt );
	vsprintf(buffer, fmt, ap);
	va_end( ap );

	ALOGD( buffer );
	return;
}

#else
int MV_SHM_Print(const char *format, ...)
{

}

#endif


#ifdef __GLIBC__

#include <execinfo.h>
#include <sys/types.h>
#include <sys/syscall.h>

void MV_SHM_Dump_Stack()
{
	void *array[16];
	size_t size;
	char **strings;
	size_t i;
	char name[16];

	size = backtrace (array, 16);
	strings = backtrace_symbols (array, size);

	prctl(PR_GET_NAME, name, 0, 0, 0);

	MV_SHM_Print("shm %s(%5d %5d): Backtrace Stack %d level\n",
		name, syscall(SYS_gettid), getpid(), size);

	for (i = 0; i < size; i++)
		MV_SHM_Print("  %s\n", strings[i]);

	free (strings);
}
#else
void MV_SHM_Dump_Stack()
{

}
#endif

HRESULT MV_SHM_DumpProcessMemoryMap(void)
{
	int pid = getpid();
	char line[256];
	char *p, path[64];
	FILE *fp;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	fp = fopen(path, "r");
	if (!fp)
                return E_FILEOPEN;
	MV_SHM_Print("================shm process pid[%d]============"
		"=========================================\n",pid);
	while (fgets(line, sizeof(line), fp) != NULL) {
		p = strrchr(line, '\n');
		if (p) *p = 0;
		MV_SHM_Print(line);
	}

	fclose(fp);

	return S_OK;
}

void MV_SHM_Dump_Node(ldns_rbtree_t *shm_root)
{
	ldns_rbnode_t *node;
	shm_address_t *tmp;
    dump_stack_android();
	node = ldns_rbtree_first(shm_root);
	while (node != LDNS_RBTREE_NULL) {
		tmp = (shm_address_t *)(node->key);
		node = ldns_rbtree_next(node);
        MV_SHM_Print("SHM:DUMP:N:0x%x,PA:0x%x,VA=0x%x,SZ=0x%x", \
            tmp, tmp->m_phyaddress, tmp->m_virtaddress, tmp->m_size);
    }
}

static ldns_rbnode_t *MV_SHM_insert_phyaddress_node(ldns_rbtree_t *shm_root,
						shm_address_t *shm_node)
{
	shm_node->m_flag = SHM_PHYS_INSERT;
	return ldns_rbtree_insert(shm_root, &shm_node->phys_node);
}

static shm_address_t *MV_SHM_lookup_phyaddress_node(
	struct ldns_rbtree_t *shm_root, const uint address)
{
	ldns_rbnode_t *search_node;
	shm_address_t shm_node;

	shm_node.m_flag = SHM_PHYS_SEARCH;
	shm_node.m_phyaddress = address;

	search_node = ldns_rbtree_search(shm_root, &shm_node);
	if (search_node != NULL)
		return (shm_address_t *)(search_node->key);
	else
		return NULL;
}

static ldns_rbnode_t *MV_SHM_delete_phyaddress_node(ldns_rbtree_t *shm_root,
						shm_address_t *shm_node)
{
	shm_node->m_flag = SHM_PHYS_DELETE;
	return ldns_rbtree_delete(shm_root, shm_node->phys_node.key);
}

static ldns_rbnode_t *MV_SHM_insert_virtaddress_node(ldns_rbtree_t *shm_root,
						shm_address_t *shm_node)
{
	shm_node->m_flag = SHM_VIRT_INSERT;
	return ldns_rbtree_insert(shm_root, &shm_node->virt_node);
}

static shm_address_t *MV_SHM_lookup_virtaddress_node(
	ldns_rbtree_t *shm_root, const uint address)
{
	ldns_rbnode_t *search_node;
	shm_address_t shm_node;

	shm_node.m_flag = SHM_VIRT_SEARCH;
	shm_node.m_virtaddress = address;

	search_node = ldns_rbtree_search(shm_root, &shm_node);
	if (search_node != NULL)
		return (shm_address_t *)(search_node->key);
	else
		return NULL;
}

static ldns_rbnode_t *MV_SHM_delete_virtaddress_node(ldns_rbtree_t *shm_root,
						shm_address_t *shm_node)
{
	shm_node->m_flag = SHM_VIRT_DELETE;
	return ldns_rbtree_delete(shm_root, shm_node->virt_node.key);
}

inline static int shm_compare(shm_address_t *a, shm_address_t *b)
{
	int res = 0;

	switch (a->m_flag) {
	case SHM_PHYS_INSERT:
		if (a->m_phyaddress < b->m_phyaddress)
			res = -1;
		else if (a->m_phyaddress > b->m_phyaddress)
			res = 1;
		else
			res = 0;
		break;

	case SHM_PHYS_SEARCH:
	case SHM_PHYS_DELETE:
		if (a->m_phyaddress < b->m_phyaddress) {
			res = -1;
		} else if (a->m_phyaddress > b->m_phyaddress) {
			if (a->m_phyaddress < (b->m_phyaddress + b->m_size)) {
				res = 0;
			} else {
				res = 1;
			}
		} else {
			res = 0;
		}
		break;

	case SHM_VIRT_INSERT:
		if (a->m_virtaddress< b->m_virtaddress)
			res = -1;
		else if (a->m_virtaddress > b->m_virtaddress)
			res = 1;
		else
			res = 0;
		break;

	case SHM_VIRT_SEARCH:
	case SHM_VIRT_DELETE:
		if (a->m_virtaddress < b->m_virtaddress) {
			res = -1;
		} else if (a->m_virtaddress > b->m_virtaddress) {
			if (a->m_virtaddress < (b->m_virtaddress + b->m_size)) {
				res = 0;
			} else {
				res = 1;
			}
		} else {
			res = 0;
		}
		break;

	default:
		printf("%s parameter error\n", __FUNCTION__);
		break;
	}
	return res;
}

static int shm_compare_v(const void *a, const void *b)
{
	return shm_compare((shm_address_t *)a, (shm_address_t *)b);
}

shm_address_t *malloc_shm_node(void)
{
	shm_address_t *node;
	node = malloc(sizeof(shm_address_t));
	if (node == NULL)
		return NULL;
	node->phys_node.key = node;
	node->virt_node.key = node;
	return node;
}

static int MV_SHM_Munmap_Base(size_t virtaddress,
				size_t size, int mem_type);

static int MV_SHM_free_all_node(shm_free_t *shm)
{
	int i = 0;
	int frist = 0;
	ldns_rbnode_t *node;
	shm_address_t *tmp;
	uint middle1, middle2, middle_size;

	shm->flag = 0;
	shm->node = NULL;

    MV_SHM_Print("SHM:FREE:START:%d\n", __LINE__);
    MV_SHM_Dump_Node(&shm->shm_root->m_phyaddr_root);
    MV_SHM_Dump_Node(&shm->shm_root->m_virtaddr_root);
	node = ldns_rbtree_first(&shm->shm_root->m_phyaddr_root);
	while (node != LDNS_RBTREE_NULL) {
		tmp = (shm_address_t *)(node->key);
		node = ldns_rbtree_next(node);

		middle1 = tmp->m_phyaddress + tmp->m_size/2;
		middle2 = shm->address + shm->size/2;
		middle_size = (tmp->m_size + shm->size)/2;
		if (middle1 > middle2)
			middle1 = middle1 - middle2;
		else
			middle1 = middle2 - middle1;

		if (middle1 < middle_size) {
			MV_SHM_Print("MV_SHM_free_all_node No.[%d], root[%p]"
				" Node_phys[%08x] Node_virt[%08x] Node_size[%08x]"
				" address[%08x] size[%08x]\n",
				i, tmp, tmp->m_phyaddress, tmp->m_virtaddress,
				tmp->m_size, shm->address, shm->size);
			i++;
			if ((tmp->m_phyaddress == shm->address)
				&& (tmp->m_size == shm->size)
				&& (shm->flag == 0)) {
				shm->flag = 1;
				if ((shm->node != NULL) && (frist == 1))
					free(shm->node);
				shm->node = tmp;
			} else {
				if (MV_SHM_Munmap_Base(tmp->m_virtaddress,
					tmp->m_size, shm->mem_type) == 0) {
					MV_SHM_delete_phyaddress_node(
                                            &shm->shm_root->m_phyaddr_root, tmp);
					MV_SHM_delete_virtaddress_node(
                                            &shm->shm_root->m_virtaddr_root, tmp);

					if ((frist == 0) && (shm->flag == 0)) {
						frist = 1;
						shm->node = tmp;
					} else {
						free(tmp);
					}
				}
			}
		}
	}
    MV_SHM_Print("SHM:FREE:END:%d\n", __LINE__);
    MV_SHM_Dump_Node(&shm->shm_root->m_phyaddr_root);
    MV_SHM_Dump_Node(&shm->shm_root->m_virtaddr_root);
	return 0;
}

static int MV_SHM_mmap_preparation(int fd, shm_driver_operation_t *op)
{
	int res;
	res = ioctl(fd, SHM_DEVICE_CMD_MMAP_PREPARATION, op);
	if ((res != 0) || ((size_t)(op->m_param2) == 0)){
		MV_SHM_Print("MV_SHM_mmap_preparation fail\n");
		return -1;
	}

	return 0;
}

static size_t MV_SHM_Mmap_Base(shm_dev_t *shm_dev,
			size_t physaddress, size_t size)
{
	if (shm_dev->mem_type == SHM_CACHE
		|| shm_dev->mem_type == SHM_NONCACHE) {
		return (size_t)mmap(0, size, PROT_READ | PROT_WRITE,
			MAP_SHARED, shm_dev->base.m_fd, 0);
	} else if (shm_dev->mem_type == SHM_SECURE_CACHE
		|| shm_dev->mem_type == SHM_SECURE_NONCACHE) {
		/*wait yongsen's api*/
		return physaddress;
	}
}

static int MV_SHM_Munmap_Base(size_t virtaddress,
				size_t size, int mem_type)
{
	if (mem_type == SHM_CACHE
		|| mem_type == SHM_NONCACHE) {
		return munmap( (void *)virtaddress, size);
	} else if (mem_type == SHM_SECURE_CACHE
		|| mem_type == SHM_SECURE_NONCACHE) {
		/*wait yongsen's api*/
	}
}

static HRESULT MV_SHM_GetMemInfo_Base(shm_dev_t *shm_dev,
					pMV_SHM_MemInfo_t pInfo)
{
	HRESULT res;

	if (pInfo == NULL) {
		MV_SHM_Print("MV_SHM_GetBaseInfo_Base parameter"
			" pInfo[%p] error\n", pInfo);
		return E_INVALIDARG;
	}

	if (SHM_DEVICE_LOAD_COUNT <= 0) {
		MV_SHM_Print("MV_SHM_GetBaseInfo_Base shm device"
			" not be open\n");
		return E_NOTREADY;
	}

	res = ioctl( shm_dev->base.m_fd,
		SHM_DEVICE_CMD_GET_MEMINFO, pInfo);
	CHECK_NOTERROR("ioctl", res, -1);

	return S_OK;
}

static HRESULT MV_SHM_GetBaseInfo_Base(shm_dev_t *shm_dev,
					pMV_SHM_BaseInfo_t pInfo)
{
	if (pInfo == NULL) {
		MV_SHM_Print("MV_SHM_GetBaseInfo_Base parameter"
			" pInfo[%p] error\n", pInfo);
		return E_INVALIDARG;
	}

	if (SHM_DEVICE_LOAD_COUNT <= 0) {
		MV_SHM_Print("MV_SHM_GetBaseInfo_Base shm device"
			" not be open\n");
		return E_NOTREADY;
	}

	GaloisMemcpy(pInfo, &shm_dev->base,
			sizeof(shm_dev->base));

	return S_OK;
}

static size_t MV_SHM_Malloc_Base(shm_dev_t *shm_dev,
			size_t Size, size_t Alignment)
{
	HRESULT res;
	shm_driver_operation_t op;
	int i = 50;

	if ((SHM_DEVICE_LOAD_COUNT <= 0) || (Size == 0) ||
		(Alignment % 2)) {
		MV_SHM_Print("user space MV_SHM_Malloc_Base shm device not open"
			" or parameter error. open[%d] size[%08x] align[%x] "
			"mem_type[%d]\n", SHM_DEVICE_LOAD_COUNT, Size, Alignment,
			shm_dev->mem_type);
		return ERROR_SHM_MALLOC_FAILED;
	}

	if (shm_check_alignment(Alignment) != S_OK) {
		MV_SHM_Print("user space MV_SHM_Malloc_Base parameter error. "
			"size[%08x] align[%x] mem_type[%d]\n", Size,
			Alignment, shm_dev->mem_type);
		return ERROR_SHM_MALLOC_FAILED;

	}

	shm_round_size(Size);
	shm_round_alignment(Alignment);

	while (i) {
		op.m_param1 = Size;
		op.m_param2 = Alignment;
		op.m_param3 = 0;
		res = ioctl( shm_dev->base.m_fd,
			SHM_DEVICE_CMD_ALLOCATE, &op);

		if (-1 == res || ERROR_SHM_MALLOC_FAILED == op.m_param1) {
			if (op.m_param3 == 1) {
				MV_SHM_Print("user space %s no task to be kill for"
					" alloc shm, so fail\n", __FUNCTION__);
				break;
			}
			if (0 == i) {
				MV_SHM_Print("user space %s line %d:trying 10 times"
					" to alloc shm but fail\n", __FUNCTION__,
					__LINE__);
				break;
			} else {
				usleep(100000);
				MV_SHM_Print("user space %s line %d:fail to allocte"
					" shm, re-try again:%d\n", __FUNCTION__,
					__LINE__, i);
				i--;
				continue;
			}
		} else
		    break;
	}

	if (op.m_param1 == ERROR_SHM_MALLOC_FAILED) {
		MV_SHM_Print("user space MV_SHM_Malloc_Base malloc shm fail\n");
		return ERROR_SHM_MALLOC_FAILED;
	}

	return op.m_param1;
}

static HRESULT MV_SHM_Free_Base(shm_dev_t *shm_dev, size_t Offset)
{
	HRESULT res;
	shm_driver_operation_t op;

	if (SHM_DEVICE_LOAD_COUNT <= 0) {
		MV_SHM_Print("MV_SHM_Free_Base shm device"
			" not be open\n");
		return E_NOTREADY;
	}

	op.m_param1 = Offset;
	res = ioctl(shm_dev->base.m_fd, SHM_DEVICE_CMD_FREE, &op);
	CHECK_NOTERROR("ioctl", res, -1);

	return S_OK;
}

static HRESULT MV_SHM_Unmap_Base(shm_dev_t *shm_dev, size_t Offset)
{
	shm_address_t *address_node;
	int res = 0;

	if (SHM_DEVICE_LOAD_COUNT <= 0) {
		MV_SHM_Print("MV_SHM_Unmap_Base shm device"
			" not be open\n");
		return E_NOTREADY;
	}

	pthread_rwlock_wrlock(&shm_dev->addr.m_rb_rwlock);
	address_node =
		MV_SHM_lookup_phyaddress_node(&shm_dev->addr.m_phyaddr_root,
			(shm_dev->base.m_base_physaddr + Offset));
	if (address_node == NULL) {
		pthread_rwlock_unlock(&shm_dev->addr.m_rb_rwlock);
		return S_OK;
	}
	res = MV_SHM_Munmap_Base(address_node->m_virtaddress,
			address_node->m_size, shm_dev->mem_type);
	if (res == 0) {
		MV_SHM_delete_phyaddress_node(
			&shm_dev->addr.m_phyaddr_root,address_node);
		MV_SHM_delete_virtaddress_node(
			&shm_dev->addr.m_virtaddr_root,address_node);
		free(address_node);
	}
	pthread_rwlock_unlock(&shm_dev->addr.m_rb_rwlock);
	return S_OK;
}

static HRESULT MV_SHM_UnmapVirt_Base(shm_dev_t *shm_dev, void* virtaddress)
{
	shm_address_t *address_node;
	shm_driver_operation_t op;
	int res = 0;

	if (SHM_DEVICE_LOAD_COUNT <= 0) {
		MV_SHM_Print("MV_SHM_UnmapVirt_Base shm device"
			" not be open\n");
		return E_NOTREADY;
	}

	pthread_rwlock_wrlock(&shm_dev->addr.m_rb_rwlock);
	address_node = MV_SHM_lookup_virtaddress_node(
		&shm_dev->addr.m_virtaddr_root,(size_t)virtaddress);
	if (address_node == NULL) {
		pthread_rwlock_unlock(&shm_dev->addr.m_rb_rwlock);
		MV_SHM_Print("MV_SHM_UnmapVirt_Base shm device"
			" not found virtaddress[%08x]\n",virtaddress);
		return S_OK;
	}
	op.m_param1 = address_node->m_phyaddress
			- shm_dev->base.m_base_physaddr;
	res = MV_SHM_Munmap_Base(address_node->m_virtaddress,
			address_node->m_size, shm_dev->mem_type);
	if (res == 0) {
		MV_SHM_delete_phyaddress_node(
			&shm_dev->addr.m_phyaddr_root,address_node);
		MV_SHM_delete_virtaddress_node(
			&shm_dev->addr.m_virtaddr_root,address_node);
		free(address_node);
	}
	pthread_rwlock_unlock(&shm_dev->addr.m_rb_rwlock);
	MV_SHM_Print("MV_SHM_UnmapVirt_Base shm device"
			" free offset[%08x]\n", op.m_param1);
	res = ioctl(shm_dev->base.m_fd, SHM_DEVICE_CMD_FREE, &op);
	CHECK_NOTERROR("ioctl", res, -1);

	return S_OK;
}


static HRESULT MV_SHM_InvalidateCache_Base(shm_dev_t *shm_dev,
			size_t virtaddr, size_t physaddr, size_t Size)
{
	HRESULT res;
	shm_driver_operation_t op;

	if (SHM_DEVICE_LOAD_COUNT <= 0) {
		MV_SHM_Print("MV_SHM_InvalidateCache_Base shm device"
			" not be open\n");
		return E_NOTREADY;
	}

	op.m_param1 = virtaddr;
	op.m_param2 = Size;
	op.m_param3 = physaddr;

	if (0 == op.m_param1 || 0 == op.m_param3 || 0 == op.m_param2
		|| physaddr - shm_dev->base.m_base_physaddr >=
		shm_dev->base.m_size) {
		MV_SHM_Print("%s, cache operation outofrange "
			"size[%08x], virt[%08x] phys[%08x] "
			"shmsize[%08x] shmphys[%08x] shmtype[%d]\n",
			__FUNCTION__, Size, op.m_param1, op.m_param3,
			shm_dev->base.m_size, shm_dev->base.m_base_physaddr,
			shm_dev->mem_type);
        MV_SHM_Print("SHM:MV_SHM_InvalidateCache_Base\n");
        dump_stack_android();
		return E_OUTOFRANGE;
	}

	res = ioctl(shm_dev->base.m_fd, SHM_DEVICE_CMD_INVALIDATE, &op);
	CHECK_NOTERROR("ioctl", res, -1);

	return S_OK;
}

static HRESULT MV_SHM_CleanCache_Base(shm_dev_t *shm_dev,
			size_t virtaddr, size_t physaddr, size_t Size)
{
	HRESULT res;
	shm_driver_operation_t op;

	if (SHM_DEVICE_LOAD_COUNT <= 0) {
		MV_SHM_Print("MV_SHM_CleanCache_Base shm device"
			" not be open\n");
		return E_NOTREADY;
	}

	op.m_param1 = virtaddr;
	op.m_param2 = Size;
	op.m_param3 = physaddr;

	if (0 == op.m_param1 || 0 == op.m_param3 || 0 == op.m_param2
		|| physaddr - shm_dev->base.m_base_physaddr >=
		shm_dev->base.m_size) {
		MV_SHM_Print("%s, cache operation outofrange "
			"size[%08x], virt[%08x] phys[%08x] "
			"shmsize[%08x] shmphys[%08x] shmtype[%d]\n",
			__FUNCTION__, Size, op.m_param1, op.m_param3,
			shm_dev->base.m_size, shm_dev->base.m_base_physaddr,
			shm_dev->mem_type);
        MV_SHM_Print("SHM:MV_SHM_CleanCache_Base\n");
        dump_stack_android();
		return E_OUTOFRANGE;
	}

	res = ioctl(shm_dev->base.m_fd, SHM_DEVICE_CMD_CLEAN, &op);
	CHECK_NOTERROR("ioctl", res, -1);

	return S_OK;
}

static HRESULT MV_SHM_CleanAndInvalidateCache_Base(shm_dev_t *shm_dev,
				size_t virtaddr, size_t physaddr, size_t Size)
{
	HRESULT res;
	shm_driver_operation_t op;

	if (SHM_DEVICE_LOAD_COUNT <= 0) {
		MV_SHM_Print("MV_SHM_CleanAndInvalidateCache_Base shm device"
			" not be open\n");
		return E_NOTREADY;
	}

	op.m_param1 = virtaddr;
	op.m_param2 = Size;
	op.m_param3 = physaddr;

	if (0 == op.m_param1 || 0 == op.m_param3 || 0 == op.m_param2
	|| physaddr - shm_dev->base.m_base_physaddr >=
		shm_dev->base.m_size) {
		MV_SHM_Print("%s, cache operation outofrange "
			"size[%08x], virt[%08x] phys[%08x] "
			"shmsize[%08x] shmphys[%08x] shmtype[%d]\n",
			__FUNCTION__, Size, op.m_param1, op.m_param3,
			shm_dev->base.m_size, shm_dev->base.m_base_physaddr,
			shm_dev->mem_type);
        MV_SHM_Print("SHM:MV_SHM_CleanAndInvalidateCache_Base\n");
        dump_stack_android();
		return E_OUTOFRANGE;
	}

	res = ioctl(shm_dev->base.m_fd,
		SHM_DEVICE_CMD_CLEANANDINVALIDATE, &op);
	CHECK_NOTERROR("ioctl", res, -1);

	return S_OK;
}

static PVOID MV_SHM_GetVirtAddr_Base(shm_dev_t *shm_dev, size_t Offset)
{
	shm_address_t *address_node;
	shm_driver_operation_t op;
	shm_free_t shm_free;
    ldns_rbnode_t *node;

	if ((SHM_DEVICE_LOAD_COUNT <= 0) ||
		((Offset >= shm_dev->base.m_size) &&((shm_dev->mem_type == SHM_CACHE)
			|| (shm_dev->mem_type == SHM_NONCACHE)))) {
		MV_SHM_Print("user space MV_SHM_GetVirtAddr_Base shm device not"
			" open or parameter fail. open[%d] offset[%08x] >= "
			"shm_size[%08x] mem_type[%d]\n", SHM_DEVICE_LOAD_COUNT,
			Offset, shm_dev->base.m_size, shm_dev->mem_type);
		return NULL;
	}

	pthread_rwlock_wrlock(&shm_dev->addr.m_rb_rwlock);
	address_node = MV_SHM_lookup_phyaddress_node(
			&(shm_dev->addr.m_phyaddr_root),
			(shm_dev->base.m_base_physaddr + Offset));

	if (address_node == NULL) {
		address_node = malloc_shm_node();
		if(address_node == NULL) {
			MV_SHM_Print("user space MV_SHM_GetVirtAddr_Base"
				" malloc fail\n");
			pthread_rwlock_unlock(&shm_dev->addr.m_rb_rwlock);
			return NULL;
		}

		op.m_param1 = shm_dev->base.m_base_physaddr + Offset;
		if (MV_SHM_mmap_preparation(shm_dev->base.m_fd, &op) != 0) {
			MV_SHM_Print("user space MV_SHM_GetVirtAddr_Base "
				"MV_SHM_mmap_preparation fail\n");
			free(address_node);
			pthread_rwlock_unlock(&shm_dev->addr.m_rb_rwlock);
			return NULL;
		}

		address_node->m_phyaddress = op.m_param1;
		address_node->m_size = op.m_param2;
		address_node->m_virtaddress = MV_SHM_Mmap_Base(shm_dev,
			address_node->m_phyaddress, address_node->m_size);

		if (address_node->m_virtaddress == (size_t)MAP_FAILED) {
			MV_SHM_Print("user space MV_SHM_GetVirtAddr_Base "
				"MV_SHM_Mmap_Base fail\n");
			free(address_node);
			pthread_rwlock_unlock(&shm_dev->addr.m_rb_rwlock);
			MV_SHM_DumpProcessMemoryMap();
			return NULL;
		}

		if (MV_SHM_insert_phyaddress_node(
			&(shm_dev->addr.m_phyaddr_root), address_node) == NULL) {
            MV_SHM_Print("SHM:GETV:PHY:0x%x,%d\n", Offset, __LINE__);
			MV_SHM_Dump_Node(&(shm_dev->addr.m_phyaddr_root));
            node = MV_SHM_delete_phyaddress_node(&(shm_dev->addr.m_phyaddr_root), \
                address_node);
            MV_SHM_delete_virtaddress_node(&(shm_dev->addr.m_virtaddr_root), \
                node->key);
            MV_SHM_insert_phyaddress_node(
			&(shm_dev->addr.m_phyaddr_root), address_node);
        }
	    if (MV_SHM_insert_virtaddress_node(
			&(shm_dev->addr.m_virtaddr_root), address_node) == NULL) {
			MV_SHM_Print("SHM:GETV:VIRT:0x%x,%d\n", Offset, __LINE__);
			MV_SHM_Dump_Node(&(shm_dev->addr.m_virtaddr_root));
            node = MV_SHM_delete_virtaddress_node(&(shm_dev->addr.m_virtaddr_root), \
                address_node);
            MV_SHM_delete_phyaddress_node(&(shm_dev->addr.m_phyaddr_root), \
                node->key);
            MV_SHM_insert_virtaddress_node(&(shm_dev->addr.m_virtaddr_root),
                address_node);
        }
		pthread_rwlock_unlock(&shm_dev->addr.m_rb_rwlock);
		return (PVOID)(address_node->m_virtaddress+
				((Offset + shm_dev->base.m_base_physaddr)
				- address_node->m_phyaddress));;
	} else {
		op.m_param1 = shm_dev->base.m_base_physaddr + Offset;
		if (MV_SHM_mmap_preparation(shm_dev->base.m_fd, &op) != 0) {
			MV_SHM_Print("user space MV_SHM_GetVirtAddr_Base 2 "
				"MV_SHM_mmap_preparation fail\n");
			pthread_rwlock_unlock(&shm_dev->addr.m_rb_rwlock);
			return NULL;
		}

		if ((address_node->m_size == op.m_param2) &&
			(address_node->m_phyaddress == op.m_param1)) {
			pthread_rwlock_unlock(&shm_dev->addr.m_rb_rwlock);
			return (PVOID)(address_node->m_virtaddress+
				((Offset + shm_dev->base.m_base_physaddr)
				- address_node->m_phyaddress));
		} else {
			shm_free.address = op.m_param1;
			shm_free.size = op.m_param2;
			shm_free.shm_root = &shm_dev->addr;
			shm_free.mem_type = shm_dev->mem_type;
			MV_SHM_free_all_node(&shm_free);

			address_node = shm_free.node;
			if (shm_free.flag == 0) {
				address_node->m_phyaddress = op.m_param1;
				address_node->m_size = op.m_param2;
				address_node->m_virtaddress = MV_SHM_Mmap_Base(shm_dev,
					address_node->m_phyaddress, address_node->m_size);

				if (address_node->m_virtaddress == (size_t)MAP_FAILED) {
					MV_SHM_Print("user space MV_SHM_GetVirtAddr_Base 4 "
						"MV_SHM_Mmap_Base fail\n");
					free(address_node);
					pthread_rwlock_unlock(&shm_dev->addr.m_rb_rwlock);
					MV_SHM_DumpProcessMemoryMap();
					return NULL;
				}

                if (MV_SHM_insert_phyaddress_node(
                    &(shm_dev->addr.m_phyaddr_root), address_node) == NULL) {
                    MV_SHM_Print("SHM:GETV:PHY:0x%x,%d\n", Offset, __LINE__);
                    MV_SHM_Dump_Node(&(shm_dev->addr.m_phyaddr_root));
                    node = MV_SHM_delete_phyaddress_node(&(shm_dev->addr.m_phyaddr_root), \
                        address_node);
                    MV_SHM_delete_virtaddress_node(&(shm_dev->addr.m_virtaddr_root), \
                        node->key);
                    MV_SHM_insert_phyaddress_node(
                    &(shm_dev->addr.m_phyaddr_root), address_node);
                }
                if (MV_SHM_insert_virtaddress_node(
                    &(shm_dev->addr.m_virtaddr_root), address_node) == NULL) {
                    MV_SHM_Print("SHM:GETV:VIRT:0x%x,%d\n", Offset, __LINE__);
                    MV_SHM_Dump_Node(&(shm_dev->addr.m_virtaddr_root));
                    node = MV_SHM_delete_virtaddress_node(&(shm_dev->addr.m_virtaddr_root), \
                        address_node);
                    MV_SHM_delete_phyaddress_node(&(shm_dev->addr.m_phyaddr_root), \
                        node->key);
                    MV_SHM_insert_virtaddress_node(&(shm_dev->addr.m_virtaddr_root),
                        address_node);
                }
			}
			pthread_rwlock_unlock(&shm_dev->addr.m_rb_rwlock);
			return (PVOID)(address_node->m_virtaddress+
				((Offset + shm_dev->base.m_base_physaddr)
					- address_node->m_phyaddress));;
		}
	}
}

static PVOID MV_SHM_GetPhysAddr_Base(shm_dev_t *shm_dev, size_t Offset)
{
	if ((SHM_DEVICE_LOAD_COUNT <= 0) || (Offset >= shm_dev->base.m_size)) {
		MV_SHM_Print("user space MV_SHM_GetPhysAddr_Base shm"
			" device not be open or offset[%08x] > shm_size[%08x]\n",
			Offset, shm_dev->base.m_size);
		return NULL;
	}

	return (PVOID)(Offset + shm_dev->base.m_base_physaddr);
}

static size_t MV_SHM_RevertVirtAddr_Base(shm_dev_t *shm_dev, void * ptr)
{
	shm_address_t *address_node;

	if (SHM_DEVICE_LOAD_COUNT <= 0) {
		MV_SHM_Print("user space MV_SHM_RevertVirtAddr_Base shm"
			" device not be open virtaddr[%08x]\n",(size_t)ptr);
		return ERROR_SHM_MALLOC_FAILED;
	}

	pthread_rwlock_rdlock(&shm_dev->addr.m_rb_rwlock);
	address_node =
		MV_SHM_lookup_virtaddress_node(
		&shm_dev->addr.m_virtaddr_root,(size_t)ptr);
	pthread_rwlock_unlock(&shm_dev->addr.m_rb_rwlock);

	if (address_node == NULL) {
		MV_SHM_Print("user space MV_SHM_RevertVirtAddr_Base can't found"
			" this virtaddr[%08x]\n",(size_t)ptr);
		return ERROR_SHM_MALLOC_FAILED;
	} else {
		return (size_t)((address_node->m_phyaddress +
			((size_t)ptr - address_node->m_virtaddress))
			- shm_dev->base.m_base_physaddr);
	}
}

static size_t MV_SHM_RevertPhysAddr_Base(shm_dev_t *shm_dev, void * ptr)
{
	if (SHM_DEVICE_LOAD_COUNT <= 0){
		MV_SHM_Print("user space MV_SHM_RevertPhysAddr_Base shm"
			" device not be open virtaddr[%08x]\n",(size_t)ptr);
		return ERROR_SHM_MALLOC_FAILED;
	}

	if (((size_t)ptr < shm_dev->base.m_base_physaddr) ||
		((size_t)ptr >= shm_dev->base.m_base_physaddr
		+ shm_dev->base.m_size)) {
		MV_SHM_Print("user space MV_SHM_RevertPhysAddr_Base parameter error"
			" physaddr[%08x] shm_base[%08x] shm_end[%08x]\n",(size_t)ptr,
			shm_dev->base.m_base_physaddr, shm_dev->base.m_base_physaddr
			+ shm_dev->base.m_size);
		return ERROR_SHM_MALLOC_FAILED;
	}

	return ((size_t)ptr - shm_dev->base.m_base_physaddr);
}

static int MV_SHM_Add_Refcount(shm_dev_t *shm_dev, size_t offset)
{
	int res;
	shm_driver_operation_t op;

	if (SHM_DEVICE_LOAD_COUNT <= 0) {
		MV_SHM_Print("user space MV_SHM_Add_Refcount shm"
			" device not be open offset[%08x]\n", offset);
		return E_NOTREADY;
	}

	op.m_param1 = offset;
	res = ioctl(shm_dev->base.m_fd,
		SHM_DEVICE_CMD_ADD_REFERENCE_COUNT, &op);
	if ((res != 0) && (op.m_param1 != 0)) {
		MV_SHM_Print("MV_SHM_reference fail\n");
		return -1;
	}

	return 0;
}

static int MV_SHM_GetMemory_Base(shm_dev_t *shm_dev, size_t offset)
{
	if (SHM_DEVICE_LOAD_COUNT <= 0) {
		MV_SHM_Print("user space MV_SHM_GetMemory_Base shm"
			" device not be open offset[%08x]\n", offset);
		return E_NOTREADY;
	}

	if (MV_SHM_Add_Refcount(shm_dev, offset) != 0) {
		MV_SHM_Print("MV_SHM_reference fail\n");
		return -1;
	}

	if (MV_SHM_GetVirtAddr_Base(shm_dev, offset) == NULL) {
		MV_SHM_Print("MV_SHM_GetMemory_Base map fail\n");
		return -1;
	}
	return 0;
}

static int MV_SHM_PutMemory_Base(shm_dev_t *shm_dev, size_t offset)
{
	MV_SHM_Unmap_Base(shm_dev, offset);
	return MV_SHM_Free_Base(shm_dev, offset);
}

static HRESULT MV_SHM_Init_Base(shm_dev_t *shm_dev, int mem_type)
{
	HRESULT res = 0;
	int fd_cache;

	ldns_rbtree_init(&shm_dev->addr.m_phyaddr_root, shm_compare_v);
	ldns_rbtree_init(&shm_dev->addr.m_virtaddr_root, shm_compare_v);
	shm_dev->mem_type = mem_type;

	res = pthread_rwlock_init(&shm_dev->addr.m_rb_rwlock, NULL);
	if (res != 0) {
		MV_SHM_Print("MV_SHM_Init_Base pthread_rwlock_init"
			" shm_type[%d] fail:\n", mem_type);
		goto rwlock_err;
	}

	if (mem_type == SHM_CACHE) {
		fd_cache = open( SHM_DEVICE_PATH_CACHE, O_RDWR);
		if (fd_cache == -1) {
			MV_SHM_Print("MV_SHM_Init_Base open shm_type[%d]"
				" fail: errno:%d %s\n",mem_type,errno,
				strerror(errno));
			goto open_err;
		}

		res = ioctl(fd_cache, SHM_DEVICE_CMD_GET_DEVINFO,
					&shm_dev->base);
		if (res == -1) {
			MV_SHM_Print("MV_SHM_Init_Base ioctl shm_type[%d]"
				" fail: errno:%d %s\n",mem_type,errno,
				strerror(errno));
			goto ioctl_err;
		}
	} else if (mem_type == SHM_NONCACHE) {
		fd_cache = open( SHM_DEVICE_PATH_NONCACHE, O_RDWR);
		if (fd_cache == -1) {
			MV_SHM_Print("MV_SHM_Init_Base open shm_type[%d]"
				" fail: errno:%d %s\n",mem_type,errno,
				strerror(errno));
			goto open_err;
		}
		res = ioctl(fd_cache, SHM_DEVICE_CMD_GET_DEVINFO,
				&shm_dev->base);
		if (res == -1) {
			MV_SHM_Print("MV_SHM_Init_Base ioctl shm_type[%d]"
				" fail: errno:%d %s\n",mem_type,errno,
				strerror(errno));
			goto ioctl_err;
		}
	} else if (mem_type == SHM_SECURE_CACHE) {
		fd_cache = open( SHM_DEVICE_PATH_SECURE_CACHE, O_RDWR);
		if (fd_cache == -1) {
			MV_SHM_Print("MV_SHM_Init_Base open shm_type[%d]"
				" fail: errno:%d %s\n",mem_type,errno,
				strerror(errno));
			goto open_err;
		}

		res = ioctl(fd_cache, SHM_DEVICE_CMD_GET_DEVINFO,
					&shm_dev->base);
		if (res == -1) {
			MV_SHM_Print("MV_SHM_Init_Base ioctl shm_type[%d]"
				" fail: errno:%d %s\n",mem_type,errno,
				strerror(errno));
			goto ioctl_err;
		}
	} else if (mem_type == SHM_SECURE_NONCACHE) {
		fd_cache = open( SHM_DEVICE_PATH_SECURE_NONCACHE, O_RDWR);
		if (fd_cache == -1) {
			MV_SHM_Print("MV_SHM_Init_Base open shm_type[%d]"
				" fail: errno:%d %s\n",mem_type,errno,
				strerror(errno));
			goto open_err;
		}
		res = ioctl(fd_cache, SHM_DEVICE_CMD_GET_DEVINFO,
				&shm_dev->base);
		if (res == -1) {
			MV_SHM_Print("MV_SHM_Init_Base ioctl shm_type[%d]"
				" fail: errno:%d %s\n",mem_type,errno,
				strerror(errno));
			goto ioctl_err;
		}
	} else {
		return -1;
	}

	shm_dev->base.m_fd = fd_cache;

	return S_OK;

ioctl_err:
	close(shm_dev->base.m_fd);
	shm_dev->base.m_fd = -1;
open_err:
	pthread_rwlock_destroy(&shm_dev->addr.m_rb_rwlock);
rwlock_err:
	return -1;
}

static HRESULT MV_SHM_Exit_Base(shm_dev_t *shm_dev)
{
	pthread_rwlock_destroy(&shm_dev->addr.m_rb_rwlock);

	close(shm_dev->base.m_fd);
	shm_dev->base.m_fd = -1;

	return S_OK;
}


HRESULT MV_SHM_Init(void)
{
	HRESULT res = S_OK;

	SHM_DEVICE_LOAD_COUNT++;
	if (SHM_DEVICE_LOAD_COUNT > 1)
	    return S_OK;
	res = MV_SHM_Init_Base(&shm_cache, SHM_CACHE);
	if (res == -1) {
		MV_SHM_Print("MV_SHM_Init shm cache fail\n");
		goto cache_fail;
	}

	res = MV_SHM_Init_Base(&shm_noncache, SHM_NONCACHE);
	if (res == -1) {
		MV_SHM_Print("MV_SHM_Init shm noncache fail\n");
		goto noncache_fail;
	}

	res = MV_SHM_Init_Base(&shm_secure_cache, SHM_SECURE_CACHE);
	if (res == -1) {
		MV_SHM_Print("MV_SHM_Init shm secure cache fail\n");
		goto secure_cache_fail;
	}

	res = MV_SHM_Init_Base(&shm_secure_noncache, SHM_SECURE_NONCACHE);
	if (res == -1) {
		MV_SHM_Print("MV_SHM_Init shm secure noncache fail\n");
		goto secure_noncache_fail;
	}

	return S_OK;

secure_noncache_fail:
	MV_SHM_Exit_Base(&shm_secure_cache);
secure_cache_fail:
	MV_SHM_Exit_Base(&shm_noncache);
noncache_fail:
	MV_SHM_Exit_Base(&shm_cache);
cache_fail:
	return -1;

}

HRESULT MV_SHM_Exit(void)
{
	SHM_DEVICE_LOAD_COUNT--;
	if (SHM_DEVICE_LOAD_COUNT != 0)
		return S_OK;

	MV_SHM_Exit_Base(&shm_cache);
	MV_SHM_Exit_Base(&shm_noncache);
	MV_SHM_Exit_Base(&shm_secure_cache);
	MV_SHM_Exit_Base(&shm_secure_noncache);

	return S_OK;
}

HRESULT MV_SHM_GetCacheMemInfo( pMV_SHM_MemInfo_t pInfo )
{
	return MV_SHM_GetMemInfo_Base(&shm_cache, pInfo);
}

HRESULT MV_SHM_GetNonCacheMemInfo( pMV_SHM_MemInfo_t pInfo)
{
	return MV_SHM_GetMemInfo_Base(&shm_noncache, pInfo);
}

HRESULT MV_SHM_GetCacheBaseInfo( pMV_SHM_BaseInfo_t pInfo)
{
	return MV_SHM_GetBaseInfo_Base(&shm_cache,pInfo);
}

HRESULT MV_SHM_GetNonCacheBaseInfo( pMV_SHM_BaseInfo_t pInfo)
{
	return MV_SHM_GetBaseInfo_Base(&shm_noncache,pInfo);
}

size_t MV_SHM_Malloc( size_t Size, size_t Alignment)
{
	return MV_SHM_Malloc_Base(&shm_cache, Size, Alignment);
}

HRESULT MV_SHM_Unmap( size_t Offset)
{
	return MV_SHM_Unmap_Base(&shm_cache, Offset);
}

HRESULT MV_SHM_Free( size_t Offset)
{
	MV_SHM_Unmap_Base(&shm_cache, Offset);
	return MV_SHM_Free_Base(&shm_cache, Offset);
}

HRESULT MV_SHM_InvalidateCache(size_t Offset, size_t Size)
{
	return MV_SHM_InvalidateCache_Base(&shm_cache,
		(size_t)MV_SHM_GetCacheVirtAddr(Offset),
		(size_t)MV_SHM_GetCachePhysAddr(Offset), Size);
}

HRESULT MV_SHM_CleanCache(size_t Offset, size_t Size)
{
	return MV_SHM_CleanCache_Base(&shm_cache,
		(size_t)MV_SHM_GetCacheVirtAddr(Offset),
		(size_t)MV_SHM_GetCachePhysAddr(Offset), Size);
}

HRESULT MV_SHM_CleanAndInvalidateCache(size_t Offset, size_t Size)
{
	return MV_SHM_CleanAndInvalidateCache_Base(&shm_cache,
		(size_t)MV_SHM_GetCacheVirtAddr(Offset),
		(size_t)MV_SHM_GetCachePhysAddr(Offset), Size);
}

HRESULT MV_SHM_InvalidateCache_Fast(size_t virtaddress,
				size_t Offset, size_t Size)
{
	return MV_SHM_InvalidateCache_Base(&shm_cache, virtaddress,
		(size_t)MV_SHM_GetCachePhysAddr(Offset), Size);
}

HRESULT MV_SHM_CleanCache_Fast(size_t virtaddress,
				size_t Offset, size_t Size)
{
	return MV_SHM_CleanCache_Base(&shm_cache, virtaddress,
		(size_t)MV_SHM_GetCachePhysAddr(Offset), Size);
}

HRESULT MV_SHM_CleanAndInvalidateCache_Fast(size_t virtaddress,
					size_t Offset, size_t Size)
{
	return MV_SHM_CleanAndInvalidateCache_Base(&shm_cache, virtaddress,
		(size_t)MV_SHM_GetCachePhysAddr(Offset), Size);
}

PVOID MV_SHM_GetNonCacheVirtAddr(size_t Offset)
{
	return MV_SHM_GetVirtAddr_Base(&shm_noncache, Offset);
}

PVOID MV_SHM_GetCacheVirtAddr(size_t Offset)
{
	return MV_SHM_GetVirtAddr_Base(&shm_cache, Offset);
}

PVOID MV_SHM_GetNonCachePhysAddr(size_t Offset)
{
	return MV_SHM_GetPhysAddr_Base(&shm_noncache, Offset);
}

PVOID MV_SHM_GetCachePhysAddr(size_t Offset)
{
	return MV_SHM_GetPhysAddr_Base(&shm_cache, Offset);
}

size_t MV_SHM_RevertNonCacheVirtAddr(void * ptr)
{
	return MV_SHM_RevertVirtAddr_Base(&shm_noncache, ptr);
}

size_t MV_SHM_RevertCacheVirtAddr(void * ptr)
{
	return MV_SHM_RevertVirtAddr_Base(&shm_cache, ptr);
}

size_t MV_SHM_RevertNonCachePhysAddr(void * ptr)
{
	return MV_SHM_RevertPhysAddr_Base(&shm_noncache, ptr);
}

size_t MV_SHM_RevertCachePhysAddr(void * ptr)
{
	return MV_SHM_RevertPhysAddr_Base(&shm_cache, ptr);
}

size_t MV_SHM_NONCACHE_Malloc( size_t Size, size_t Alignment)
{
	return MV_SHM_Malloc_Base(&shm_noncache, Size, Alignment);
}

HRESULT MV_SHM_NONCACHE_Free( size_t Offset)
{
	MV_SHM_Unmap_Base(&shm_noncache, Offset);
	return MV_SHM_Free_Base(&shm_noncache, Offset);
}

int MV_SHM_GetMemory(size_t offset)
{
	return MV_SHM_GetMemory_Base(&shm_cache, offset);
}

int MV_SHM_PutMemory(size_t offset)
{
	return MV_SHM_PutMemory_Base(&shm_cache, offset);
}

int MV_SHM_NONCACHE_GetMemory(size_t offset)
{
	return MV_SHM_GetMemory_Base(&shm_noncache, offset);
}

int MV_SHM_NONCACHE_PutMemory(size_t offset)
{
	return MV_SHM_PutMemory_Base(&shm_noncache, offset);
}

void *MV_SHM_Secure_Malloc( size_t Size, size_t Alignment)
{
	size_t offset = MV_SHM_Malloc_Base(&shm_secure_cache, Size, Alignment);
	if (offset != ERROR_SHM_MALLOC_FAILED) {
		return (void *)(offset + shm_secure_cache.base.m_base_physaddr);
	} else {
		return NULL;
	}
}

int MV_SHM_Secure_Free( void* physaddress)
{
	return MV_SHM_Free_Base(&shm_secure_cache, physaddress -
			shm_secure_cache.base.m_base_physaddr);
}

void *MV_SHM_Secure_Map(void* physaddress,  size_t size)
{
	size_t offset = (size_t)physaddress - shm_secure_cache.base.m_base_physaddr;
	if (MV_SHM_Add_Refcount(&shm_secure_cache, offset) != 0) {
		MV_SHM_Print("MV_SHM_Secure_Map add reference fail\n");
		return NULL;
	}
	return (void *)MV_SHM_GetVirtAddr_Base(&shm_secure_cache, offset);
}

int MV_SHM_Secure_Unmap(void* virtaddress)
{
	return MV_SHM_UnmapVirt_Base(&shm_secure_cache, virtaddress);
}

int MV_SHM_Secure_InvalidateCache(void* virtaddress,
				void* physaddress, size_t Size)
{
	MV_SHM_Print("MV_SHM_Secure_InvalidateCache wait yongsen's api\n");
	return 0;
}

int MV_SHM_Secure_CleanCache(void* virtaddress,
				void* physaddress, size_t Size)
{
	MV_SHM_Print("MV_SHM_Secure_CleanCache wait yongsen's api\n");
	return 0;
}

int MV_SHM_Secure_CleanAndInvalidateCache(void* virtaddress,
					void* physaddress, size_t Size)
{
	MV_SHM_Print("MV_SHM_Secure_CleanAndInvalidateCache wait yongsen's api\n");
	return 0;
}

void *MV_SHM_Secure_Noncache_Malloc( size_t Size, size_t Alignment)
{
	size_t offset = MV_SHM_Malloc_Base(&shm_secure_noncache, Size, Alignment);
	if (offset != ERROR_SHM_MALLOC_FAILED) {
		return (void *)(offset + shm_secure_noncache.base.m_base_physaddr);
	} else {
		return NULL;
	}
}

int MV_SHM_Secure_Noncache_Free( void* physaddress)
{
	return MV_SHM_Free_Base(&shm_secure_noncache, physaddress -
			shm_secure_noncache.base.m_base_physaddr);
}

void *MV_SHM_Secure_Noncache_Map(void* physaddress,  size_t size)
{
	size_t offset = physaddress - shm_secure_noncache.base.m_base_physaddr;
	if (MV_SHM_Add_Refcount(&shm_secure_noncache, offset) != 0) {
		MV_SHM_Print("MV_SHM_Secure_Noncache_Map add reference fail\n");
		return NULL;
	}
	return (void *)MV_SHM_GetVirtAddr_Base(&shm_secure_noncache, offset);
}

int MV_SHM_Secure_Noncache_Unmap(void* virtaddress)
{
	return MV_SHM_UnmapVirt_Base(&shm_secure_noncache, virtaddress);
}



int MV_SHM_CheckTest(int device, shm_check_test_t *op)
{
	HRESULT res = 0;

	if (SHM_DEVICE_LOAD_COUNT <= 0)
		return E_NOTREADY;

	if (device == 0) {
		res = ioctl( shm_cache.base.m_fd,
			SHM_DEVICE_CMD_CHECK_TEST, op);
	} else if (device == 1) {
		res = ioctl( shm_noncache.base.m_fd,
			SHM_DEVICE_CMD_CHECK_TEST, op);
	} else {
		res = -1;
	}

	if ((res != 0) && (op->res != 0)) {
		MV_SHM_Print("MV_SHM_CheckTest fail\n");
		return -1;
	}

	return 0;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
