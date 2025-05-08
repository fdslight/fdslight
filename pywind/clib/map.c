#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include "map.h"
#include "debug.h"

/// 获取空的map node
static struct map_node *__map_node_get(struct map *m)
{
	struct map_node *node;

	if(NULL!=m->empty_head){
		node=m->empty_head;
		m->empty_head=node->tmp;
		node->tmp=NULL;
	}else{
		//DBG("call malloc for struct map_node\r\n");

		node=malloc(sizeof(struct map_node));

		if(NULL==node) return NULL;

		bzero(node,sizeof(struct map_node));
		m->cur_alloc_num+=1;
	}
	return node;
}

/// 回收map node
static void __map_node_put(struct map *m,struct map_node *node)
{

	//DBG_FLAGS;

	if(m->cur_alloc_num>m->pre_alloc_num){
		free(node);
		m->cur_alloc_num-=1;
		return;
	}

	bzero(node,sizeof(struct map_node));
	node->tmp=m->empty_head;
	m->empty_head=node;
}


int map_new(struct map **m,unsigned char length)
{
	struct map *t=malloc(sizeof(struct map));
	struct map_node *root=NULL;

	if(NULL==t){
		STDERR("cannot malloc struct map\r\n");
		return -1;
	}

	root=malloc(sizeof(struct map_node));
	if(NULL==root){
		STDERR("cannot malloc struct map_node\r\n");
		free(t);
		return -1;
	}

	bzero(t,sizeof(struct map));
	bzero(root,sizeof(struct map_node));

	t->tree_root=root;
	t->length=length;

	*m=t;

	return 0;
}

void map_release(struct map *m,map_del_func_t fn)
{
	struct map_node *node,*t;

	node=m->list_head;

	while(NULL!=node){
		t=node->list_next;
		if(NULL!=fn && node->is_data_node) fn(node->data);
		free(node);
		node=t;
	}

	node=m->empty_head;
	while(NULL!=node){
		t=node->tmp;
		free(node);
		node=t;
	}
}

int map_pre_alloc(struct map *m,unsigned int size)
{
	struct map_node *t;
	int rs=0;
	
	for(int n=0;n<size;n++){
		t=malloc(sizeof(struct map_node));
		if(NULL==t){
			rs=-1;
			STDERR("cannot malloc struct map_node\r\n");
			break;
		}
		bzero(t,sizeof(struct map_node));
		t->tmp=m->empty_head;
		m->empty_head=t;
	}

	m->pre_alloc_num=size;
	m->cur_alloc_num=size;

	return rs;
}

int map_add(struct map *m,const char *key,void *data)
{
	unsigned char v;
	char x,is_found;
	struct map_node *node,*t,*tt,*tmp_list_head=NULL;
	int rs=0;

	// 如果找到数据那么直接返回
	map_find(m,key,&is_found);
	if(is_found) return -1;
	
	node=m->tree_root;
	for(int n=0;n<m->length;n++){
		x=*key++;
		v=(unsigned char)x;
		t=node->next_nodes[v];

		if(NULL==t){
			t=__map_node_get(m);
			if(NULL==t){
				rs=-1;
				STDERR("cannot get struct map_node\r\n");
				break;
			}
			t->key_v=v;
			// 添加到list
			if(NULL!=m->list_head){
				m->list_head->list_prev=t;
			//DBG_FLAGS;
			}
			t->list_next=m->list_head;
			m->list_head=t;
		}

		node->next_nodes[v]=t;
		t->tree_prev=node;

		t->tmp=tmp_list_head;
		tmp_list_head=t;

		node=t;
	}

	if(0!=rs) return rs;
	
	// 所有引用计数加1
	t=tmp_list_head;

	while(NULL!=t){
		t->refcnt+=1;
		t=t->tmp;
	}

	// 所有引用计数加1
	t=tmp_list_head;

	// tmp置为NULL,避免其他函数使用此变量出现错误的内存访问
	while(NULL!=t){
		//DBG("%d\r\n",t->refcnt);
		tt=t->tmp;
		t->tmp=NULL;
		t=tt;
	}

	m->tree_root->refcnt+=1;
	m->tree_root->tmp=NULL;
	m->key_tot_num+=1;

	node->is_data_node=1;
	node->data=data;

	//DBG("%d\r\n",m->tree_root);

	return 0;
}


void map_del(struct map *m,const char *key,map_del_func_t fn)
{
	unsigned char v;
	char x,is_found;

	struct map_node *node=m->tree_root,*t,*tmp_list=NULL;

	//DBG("%d\r\n",m->tree_root);
	
	//如没找到记录那么直接返回
	t=map_find(m,key,&is_found);
	if(!is_found) return;

	if(NULL!=fn) fn(t);

	// 首先进行反转,由下到上删除
	for(int n=0;n<m->length;n++){
		x=*key++;
		v=(unsigned char)x;
		
		node=node->next_nodes[v];
		node->tmp=tmp_list;
		tmp_list=node;

		//DBG("%d\r\n",m->tree_root);
	}

	//DBG("%d %d\r\n",m->tree_root,t);
	// 所有引用计数减少1
	node=tmp_list;

	while(NULL!=node){
		node->refcnt-=1;
		if(node->refcnt!=0){
			node=node->tmp;
			continue;
		}

		// 引用计数为0那么删除该节点
		// 首先把指向该节点的索引值置为NULL
		node->tree_prev->next_nodes[node->key_v]=NULL;

		// 解除关联
		if(NULL!=node->list_next){
			node->list_next->list_prev=node->list_prev;
		}

		if(NULL!=node->list_prev){
			node->list_prev->list_next=node->list_next;
		}else{
			m->list_head=node->list_next;
		}
		
		t=node->tmp;
		__map_node_put(m,node);
		node=t;
	}
	//DBG("%d\r\n",m->tree_root);
	m->tree_root->refcnt-=1;
	m->key_tot_num-=1;
}

void *map_find(struct map *m,const char *key,char *is_found)
{
	struct map_node *node=m->tree_root;
	unsigned char v;
	char x;

	*is_found=0;
	
	for(int n=0;n<m->length;n++){
		x=*key++;
		v=(unsigned char)x;

		node=node->next_nodes[v];
		if(NULL==node) break;
	}

	if(NULL==node) return NULL;

	*is_found=1;

	return node->data;
}

void map_each(struct map *m,map_each_func_t fn)
{
	struct map_node *node=m->list_head;

	while(NULL!=node){
		//DBG("%d\r\n",node->is_data_node);
		if(node->is_data_node && NULL!=fn) fn(node->data);
		node=node->list_next;
	}
}



