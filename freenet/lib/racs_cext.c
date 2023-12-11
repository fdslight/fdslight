#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include<sys/socket.h>
#include<string.h>
#include<structmember.h>

#include "../../pywind/clib/netutils.h"

static PyObject *
__is_same_subnet(PyObject *self,PyObject *args)
{
    unsigned char *address,*subnet;
    unsigned char prefix;
    int is_ipv6;
    Py_ssize_t sa,sb;

    if(!PyArg_ParseTuple(args,"y#y#Bp",&address,&sa,&subnet,&sb,&prefix,&is_ipv6)) return NULL;

    return PyBool_FromLong(is_same_subnet(address,subnet,prefix,is_ipv6));
}

static PyObject *
__is_same_subnet_with_msk(PyObject *self,PyObject *args)
{
    unsigned char *address,*subnet,*mask;
    int is_ipv6;
    Py_ssize_t sa,sb,sc;

    if(!PyArg_ParseTuple(args,"y#y#y#p",&address,&sa,&subnet,&sb,&mask,&sc,&is_ipv6)) return NULL;

    return PyBool_FromLong(is_same_subnet_with_msk(address,subnet,mask,is_ipv6));
}

static PyObject *
modify_ip_address_from_ippkt(PyObject *self,PyObject *args)
{
	int is_src,is_ipv6;
	Py_ssize_t size,addr_size;
	unsigned char *netpkt;
	unsigned char *rewrite_addr;
	struct netutil_iphdr *iphdr;
	struct netutil_ip6hdr *ip6hdr;

	if(!PyArg_ParseTuple(args,"y#y#pp",&netpkt,&size,&rewrite_addr,&addr_size,&is_src,&is_ipv6)) return NULL;

	if(is_ipv6 && size < 49) {
		Py_RETURN_NONE;
	}

	if(is_ipv6 && 16!=addr_size){
		Py_RETURN_NONE;
	}

	if(!is_ipv6 && size<29){
		Py_RETURN_NONE;
	}

	if(!is_ipv6 && 4!=addr_size){
		Py_RETURN_NONE;
	}

	if(is_ipv6){
		ip6hdr=(struct netutil_ip6hdr *)netpkt;
		rewrite_ip6_addr(ip6hdr,rewrite_addr,is_src);
		Py_RETURN_NONE;
	}

	iphdr=(struct netutil_iphdr *)netpkt;
	rewrite_ip_addr(iphdr,rewrite_addr,is_src);

	Py_RETURN_NONE;
}

static PyMethodDef racs_methods[] = {
	{"is_same_subnet",__is_same_subnet,METH_VARARGS,"is same subnet"},
    {"is_same_subnet_with_msk",__is_same_subnet_with_msk,METH_VARARGS,"is same subnet with mask"},
    {"modify_ip_address_from_netpkt",(PyCFunction)modify_ip_address_from_ippkt,METH_VARARGS,"modify ip address from ip packet"},

	{NULL,NULL,0,NULL}
};

static struct PyModuleDef racs_module = {
	PyModuleDef_HEAD_INIT,
	"racs_cext",
	NULL,
	-1,
	racs_methods
};


PyMODINIT_FUNC
PyInit_racs_cext(void)
{
	PyObject *m;

	m = PyModule_Create(&racs_module);

	if (NULL == m) return NULL;

	return m;

}