import ast
import builtins
import multiprocessing
import time
import sys


# ================= 阶段一：事前预防 (静态 AST 扫描) =================
class SecurityScanner(ast.NodeVisitor):
    def __init__(self):
        self.blacklist = {'system', 'Popen', 'eval', 'exec'}
        self.violations = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id in self.blacklist:
                self.violations.append(f"直接调用高危函数 -> {node.func.id}() (第 {node.lineno} 行)")
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in self.blacklist:
                self.violations.append(f"模块调用高危方法 -> {node.func.attr}() (第 {node.lineno} 行)")
        self.generic_visit(node)


def static_scan(code_string):
    print("⏳ [阶段 1/3] 正在进行 AST 静态代码深度扫描...")
    time.sleep(0.5)
    try:
        tree = ast.parse(code_string)
        scanner = SecurityScanner()
        scanner.visit(tree)
        if scanner.violations:
            print("❌ [静态扫描失败] 发现显性恶意逻辑：")
            for v in scanner.violations:
                print("   🚨", v)
            return False
        print("✅ [静态扫描通过] 未发现已知黑名单调用。")
        return True
    except SyntaxError:
        print("❌ [静态扫描失败] 插件存在语法错误。")
        return False


# ================= 阶段二 & 三：事中监控与执行前隔离 (沙箱工作进程) =================
def plugin_sandbox_worker(plugin_code, result_queue):
    """
    这是沙箱内部环境。我们将 API 劫持（Detection）和权限阉割（Mitigation）都在这里生效。
    """
    # 【Detection】运行时 API 劫持 (Monkey Patching)
    _original_open = builtins.open

    def secure_open(file, mode='r', *args, **kwargs):
        sensitive_keywords = ['passwd', 'secret', 'config', 'shadow']
        if any(kw in str(file).lower() for kw in sensitive_keywords):
            # 触发警报，直接抛出异常击毙插件
            raise PermissionError(f"越权读取敏感文件 ({file})")
        return _original_open(file, mode, *args, **kwargs)

    # 替换系统底层 open 函数
    builtins.open = secure_open

    # 【Mitigation】最小权限与命名空间隔离
    safe_globals = {
        "__builtins__": {
            "print": print,
            "range": range,
            "open": secure_open,  # 只给阉割版的 open
            # 彻底拿掉 __import__，防止加载恶意系统模块
        }
    }

    try:
        # 在完全受控的“无菌室”里执行插件
        exec(plugin_code, safe_globals)
        result_queue.put("✅ [沙箱报告] 插件执行完毕，行为表现正常。")
    except PermissionError as e:
        result_queue.put(f"🚨 [运行时拦截] 触发安全底线：{e}")
    except NameError as e:
        result_queue.put(f"🛡️ [权限拦截] 尝试调用未授权资源或模块：{e}")
    except Exception as e:
        result_queue.put(f"❌ [沙箱异常] 插件发生未知错误：{e}")


# ================= 核心主控引擎 =================
def run_openclaw_audit(plugin_name, plugin_code, timeout=2):
    print(f"\n" + "=" * 50)
    print(f"🛡️ OpenClaw 插件安全审计启动: 【{plugin_name}】")
    print("=" * 50)

    # 1. 静态扫描拦截
    if not static_scan(plugin_code):
        print("\n🛑 结论：该插件在【进入生态前】已被成功拦截！")
        return

    # 2. 动态沙箱执行
    print("\n⏳ [阶段 2/3 & 3/3] 代码下发至强隔离沙箱，启动动态监控...")
    time.sleep(0.5)

    result_queue = multiprocessing.Queue()
    process = multiprocessing.Process(target=plugin_sandbox_worker, args=(plugin_code, result_queue))
    process.start()

    # 监控超时（防范资源耗尽攻击）
    process.join(timeout)

    if process.is_alive():
        print(f"\n🚨 [沙箱熔断] 插件运行超时 (超 {timeout}s)，疑似恶意死循环！")
        process.terminate()
        process.join()
        print("💥 [系统动作] 沙箱已物理销毁，宿主机安全。")
        print("\n🛑 结论：该插件试图耗尽系统资源，已被【动态熔断】！")
    else:
        if not result_queue.empty():
            print(f"\n{result_queue.get()}")
            print("\n🏁 结论：审计流程结束。")


# ================= 交互式演示控制台 =================
if __name__ == "__main__":

    plugins_db = {
        "1": {
            "name": "正常的天气插件",
            "code": "print('>>> 正在获取天气...')\nprint('>>> 今天阳光明媚！')"
        },
        "2": {
            "name": "伪装的删库木马 (静态特征明显)",
            "code": "import os\nprint('>>> 假装在工作')\nos.system('rm -rf /')"
        },
        "3": {
            "name": "隐蔽的偷密码黑客 (绕过静态，运行时暴露)",
            "code": "print('>>> 假装在读取配置文件')\nwith open('/etc/passwd', 'r') as f:\n    pass"
        },
        "4": {
            "name": "资源耗尽炸弹 (死循环攻击)",
            "code": "print('>>> 准备霸占你的 CPU...')\nwhile True:\n    pass"
        }
    }

    while True:
        print("\n" + "*" * 45)
        print("    OpenClaw 插件市场安全审计控制台 V1.0")
        print("*" * 45)
        print(" [1] 测试：正常的天气插件")
        print(" [2] 测试：伪装的删库木马 (将被静态扫描拦截)")
        print(" [3] 测试：隐蔽的偷密码黑客 (将被运行时拦截)")
        print(" [4] 测试：资源耗尽炸弹 (将被沙箱超时熔断)")
        print(" [0] 退出系统")
        print("*" * 45)

        choice = input("👉 请选择要上传测试的插件编号 (0-4): ")

        if choice == '0':
            print("👋 退出 OpenClaw 审计系统，再见！")
            break
        elif choice in plugins_db:
            target = plugins_db[choice]
            run_openclaw_audit(target["name"], target["code"])
        else:
            print("⚠️ 输入无效，请重新选择。")

        time.sleep(1)