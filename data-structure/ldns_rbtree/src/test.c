#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rbtree.h"


enum shm_flags {
	SHM_PHYS_INSERT,
	SHM_PHYS_SEARCH,
	SHM_PHYS_DELETE,
	SHM_VIRT_INSERT,
	SHM_VIRT_SEARCH,
	SHM_VIRT_DELETE,
};


typedef struct {
	size_t m_phyaddress;
	size_t m_virtaddress;
	size_t m_size;
	int m_flag;
} shm_key;

typedef struct {
	ldns_rbnode_t phys;
	ldns_rbnode_t virt;
	shm_key key;
} shm_node;




ldns_rbtree_t *shm_root;
ldns_rbtree_t *shm_virt_root;


int shm_compare(shm_key *a, shm_key *b)
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

int shm_compare_v(const void *a, const void *b)
{
	return shm_compare((shm_key *)a, (shm_key *)b);
}

shm_node *malloc_shm_node(void)
{
	shm_node * tmp;
	tmp = malloc(sizeof(shm_node));
	if (tmp == NULL)
		return NULL;
	tmp->phys.key = &tmp->key;
	tmp->virt.key = &tmp->key;

	tmp->phys.data = tmp;
	tmp->virt.data = tmp;
	return tmp;
}


int shm_add(int phys, int virt, int size)
{
	shm_node * tmp;
	shm_node * p;

	tmp = malloc_shm_node();
	if (tmp == NULL) {
		printf("malloc shm node fail\n");
		return -1;
	}

	tmp->key.m_phyaddress = phys;
	tmp->key.m_virtaddress = virt;
	tmp->key.m_size = size;

	tmp->key.m_flag = SHM_PHYS_INSERT;
	p = ldns_rbtree_insert(shm_root, &tmp->phys);
	if (p == NULL) {
		printf("phys insert fail phy[%d] virt[%d] size[%d]\n",
			phys, virt, size);
	}
	tmp->key.m_flag = SHM_VIRT_INSERT;
	p = ldns_rbtree_insert(shm_virt_root, &tmp->virt);
	if (p == NULL) {
		printf("virt insert fail phy[%d] virt[%d] size[%d]\n",
			phys, virt, size);
	}
//	printf("ldns_rbtree_insertphys %d virt %d size %d\n",
//			phys, virt, size);
	return 0;
}

int shm_search(int phys, int virt, int flag)
{
	shm_key *pkey, tmp_key;
	ldns_rbnode_t *search_node;

	tmp_key.m_flag = flag;
	tmp_key.m_phyaddress = phys;
	tmp_key.m_virtaddress = virt;

	if (flag == SHM_PHYS_SEARCH) {
		search_node = ldns_rbtree_search(shm_root, &tmp_key);
	} else if (flag == SHM_VIRT_SEARCH) {
		search_node = ldns_rbtree_search(shm_virt_root, &tmp_key);
	}

	if (search_node == NULL) {
		printf("search fail phys %d virt %d flag %d\n", phys, virt, flag);
		return -1;
	}
	pkey = (shm_key *)(search_node->key);
//	printf("ldns_rbtree_search went to find[%d] in flag[%d] phys %ld virt %ld size %ld\n",
//		phys, flag, pkey->m_phyaddress, pkey->m_virtaddress, pkey->m_size);
	return 0;
}

ldns_rbnode_t *shm_delete(int phys, int virt, int flag)
{
	shm_key *pkey, tmp_key;
	ldns_rbnode_t *delete_node;

	tmp_key.m_flag = flag;
	tmp_key.m_phyaddress = phys;
	tmp_key.m_virtaddress = virt;
	if (flag == SHM_PHYS_DELETE) {
		delete_node = ldns_rbtree_delete(shm_root, &tmp_key);
	} else if (flag == SHM_VIRT_DELETE) {
		delete_node = ldns_rbtree_delete(shm_virt_root, &tmp_key);
	}

	if (delete_node == NULL) {
		printf("delete fail phys %d virt %d flag %d\n", phys, virt, flag);
		return NULL;
	}
	pkey = (shm_key *)(delete_node->key);
//	printf("ldns_rbtree_delete went delete[%d] in flag[%d] phys %ld virt %ld size %ld\n",
//		phys, flag, pkey->m_phyaddress, pkey->m_virtaddress, pkey->m_size);

	return delete_node;
}

int shm_traverse(void)
{
	ldns_rbnode_t *cur_node;
	shm_key *pkey;
	int i = 0;

	cur_node = ldns_rbtree_first(shm_root);
	while (cur_node != LDNS_RBTREE_NULL) {
		pkey = (shm_key *)(cur_node->key);
		printf("shm_traverse PHYSICAL No %d phys %ld virt %ld size %ld\n",
			i, pkey->m_phyaddress, pkey->m_virtaddress, pkey->m_size);
		i++;
		cur_node = ldns_rbtree_next(cur_node);
	}

	i = 0;
	cur_node = ldns_rbtree_first(shm_virt_root);
	while (cur_node != LDNS_RBTREE_NULL) {
		pkey = (shm_key *)(cur_node->key);
		printf("shm_traverse VRITUAL No %d phys %ld virt %ld size %ld\n",
			i, pkey->m_phyaddress, pkey->m_virtaddress, pkey->m_size);
		i++;
		cur_node = ldns_rbtree_next(cur_node);
	}
}


int main(void)
{
	ldns_rbnode_t *tmp;
	int i = 0;

	shm_root = ldns_rbtree_create(shm_compare_v);
	if (!shm_root)
		return -1;

	shm_virt_root = ldns_rbtree_create(shm_compare_v);
	if (!shm_virt_root)
		return -1;


/*	shm_add(34,340,20);
	shm_add(54,540,20);
	shm_add(74,740,20);
	shm_add(94,940,20);
	shm_add(114,1140,20);


	shm_search(34,0,SHM_PHYS_SEARCH);
	shm_search(53,0,SHM_PHYS_SEARCH);
	shm_search(54,0,SHM_PHYS_SEARCH);
	shm_search(114,0,SHM_PHYS_SEARCH);
	shm_search(90,0,SHM_PHYS_SEARCH);

	shm_traverse();

	shm_delete(34,340,SHM_PHYS_DELETE);
	tmp = shm_delete(34,340,SHM_VIRT_DELETE);
	free((void *)tmp->data);

	shm_delete(54,540,SHM_PHYS_DELETE);
	tmp = shm_delete(54,540,SHM_VIRT_DELETE);
	free((void *)tmp->data);

	shm_delete(74,740,SHM_PHYS_DELETE);
	tmp = shm_delete(74,740,SHM_VIRT_DELETE);
	free((void *)tmp->data);

	shm_delete(94,940,SHM_PHYS_DELETE);
	tmp = shm_delete(94,940,SHM_VIRT_DELETE);
	free((void *)tmp->data);
*/
	for (i=0; i<30000; i++) {
		shm_add(i,i*10,10);
	}

	for (i=0; i<30000; i++) {
		shm_delete(i,i*10,SHM_PHYS_DELETE);
		tmp = shm_delete(i,i*10,SHM_VIRT_DELETE);
		free((void *)tmp->data);
	}
	shm_traverse();

	return 0;
}

