#!/usr/bin/env python3

class host_match(object):
    __rule_tree = None
    __rules = None
    # 内部关键字,查找以及增加规则时要转换
    __internal_keywords = None

    def __init__(self):
        self.clear()
        self.__internal_keywords = [
            "refcnt", "action", "rule_info",
        ]

    def match(self, host: str):
        """匹配主机
        """
        host = host.lower()
        _list = host.split(".")
        _list.reverse()

        o = self.__rule_tree
        is_found = True
        for x in _list:
            if x in self.__internal_keywords: x = "__%s" % x
            if x not in o:
                is_found = False
                break
            o = o[x]

        if is_found:
            # 这里可能存在xxx.xx格式的域名情况,需要额外考虑
            # o["rule_info"]可能为空
            if o["rule_info"]:
                return True, o["rule_info"]["action"]
            # 补全一个空元素,以便join方法形成".xxx.xx"域名
            _list.append("")
            _list.reverse()
            return self.match(".".join(_list))

        # 未匹配那么查找子项所有匹配是否存在
        if "*" in o:
            return True, o["*"]["rule_info"]["action"]

        return False, None

    def add_rule(self, rule_object: tuple):
        """加入规则
        :param rule,规则
        :param action
        :return Boolean,添加成功那么返回True,不存在则返回False
        """
        rule, flags = rule_object
        rule = rule.lower()
        if rule in self.__rules: return False
        _list = rule.split(".")
        _list.reverse()
        o = self.__rule_tree

        for x in _list:
            if x in self.__internal_keywords: x = "__%s" % x
            # 新建的引用计数为0
            if x not in o: o[x] = {"refcnt": 0, "action": None, "rule_info": None}
            o = o[x]
            o["refcnt"] += 1
        o["rule_info"] = {"action": flags}
        self.__rules[rule] = None
        return True

    def del_rule(self, rule: str):
        """删除规则
        :return Boolean,删除成功那么返回True,不存在则返回False
        """
        rule = rule.lower()
        if rule not in self.__rules: return False

        _list = rule.split(".")
        _list.reverse()

        o = self.__rule_tree
        is_found = True

        for x in _list:
            if x in self.__internal_keywords: x = "__%s" % x
            if x not in o:
                is_found = False
                break
            o = o[x]
        if not is_found: return

        o = self.__rule_tree

        for x in _list:
            t = o
            o = o[x]
            o["refcnt"] -= 1
            if o["refcnt"] == 0:
                del t[x]
                break
            ''''''
        del self.__rules[rule]
        return True

    @property
    def rule_tree(self):
        return self.__rule_tree

    @property
    def rules(self):
        rules = []
        for x in self.__rules: rules.append(x)
        return rules

    def exists(self, rule: str):
        """检查规则是否存在
        """
        return rule in self.__rules

    def clear(self):
        self.__rule_tree = {}
        self.__rules = {}

#cls = host_match()
#cls.add_rule(("*.google.com",1))
# cls.add_rule("*.google.com", "this is action")
# cls.add_rule("*", "this is action")
# print(cls.rules)
# print(cls.rule_tree)
# print(cls.match("www.google.com"))
