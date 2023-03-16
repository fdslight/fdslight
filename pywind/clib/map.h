#ifndef __MAP_H
#define __MAP_H

typedef void (*map_del_func_t)(void *);
typedef void (*map_each_func_t)(void *);

struct map_node{
	// 临时用
	struct map_node *tmp;
	// 对应列表的上一个map_node
	struct map_node *list_prev;
	// 对应列表的下一个map_node
	struct map_node *list_next;
	// 节点树对应的前一个
	struct map_node *tree_prev;
	struct map_node *next_nodes[256];
	void *data;
	unsigned long long refcnt;
	unsigned char key_v;
	// 是否是数据节点
	char is_data_node;
};

struct map{
	struct map_node *tree_root;
	struct map_node *list_head;
	struct map_node *empty_head;
	unsigned int cur_alloc_num;
	unsigned int pre_alloc_num;
	unsigned char length;
};

int map_new(struct map **m,unsigned char length);
void map_release(struct map *m,map_del_func_t fn);

/// 预先分配资源
int map_pre_alloc(struct map *m,unsigned int size);

int map_add(struct map *m,const char *key,void *data);
void map_del(struct map *m,const char *key,map_del_func_t fn);

void *map_find(struct map *m,const char *key,char *is_found);
/// 数据遍历,注意遍历过程中不可删除数据
void map_each(struct map *m,map_each_func_t fn);


#endif


