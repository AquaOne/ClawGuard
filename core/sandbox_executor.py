import multiprocessing
import time
import sys


# ================= 核心防御系统（零信任沙箱） =================

def plugin_wrapper(plugin_code, result_queue):
    """
    这是沙箱的内部环境。插件会被关在这个受限的盒子里运行。
    """
    # 1. 剥夺危险的内置函数 (限制执行命名空间)
    # 让插件连 import 模块的资格都没有，直接从底层拔掉网线和系统调用能力
    safe_globals = {
        "__builtins__": {
            "print": print,
            "range": range,
            # 故意不给 __import__，插件就无法引入 os, sys, requests 等高危模块
        }
    }

    try:
        # 2. 在受控环境中执行代码
        exec(plugin_code, safe_globals)
        result_queue.put("✅ 插件执行完毕，安全退出。")
    except Exception as e:
        result_queue.put(f"❌ 插件内部发生错误: {e}")


def run_in_sandbox(plugin_name, plugin_code, timeout_seconds=2):
    """
    沙箱控制器：负责启动、监控和销毁沙箱容器
    """
    print("\n" + "=" * 50)
    print(f"📦 [沙箱引擎] 正在为插件 '{plugin_name}' 分配独立隔离环境...")
    print(f"🔒 [权限策略] 应用最小权限：禁止引入外部模块，最大执行时间 {timeout_seconds} 秒")
    print("=" * 50)

    # 使用队列来接收沙箱内部的反馈
    result_queue = multiprocessing.Queue()

    # 启动一个完全独立的进程来运行插件（物理隔离）
    process = multiprocessing.Process(target=plugin_wrapper, args=(plugin_code, result_queue))
    process.start()

    # 倒计时监控（如果在规定时间内没跑完，直接当做恶意攻击处理）
    process.join(timeout_seconds)

    if process.is_alive():
        print(f"\n🚨 [沙箱熔断警报] 插件运行超时！检测到疑似资源耗尽攻击 (死循环/挖矿)。")
        print("💥 [防御动作] 正在物理销毁沙箱容器...")
        process.terminate()  # 强行拔电源
        process.join()  # 收尸
        print("🛡️ [系统状态] 恶意进程已清除，OpenClaw 主系统安然无恙！\n")
    else:
        # 如果正常结束，获取结果
        if not result_queue.empty():
            print(f"\n{result_queue.get()}\n")


# ================= 模拟场景（展示效果演示） =================

if __name__ == "__main__":
    # 测试案例 1：安分守己的正常插件
    good_plugin = """
print(">>> [受控输出] 插件正在计算：1 + 1 = 2")
print(">>> [受控输出] 业务逻辑处理完成。")
"""

    # 测试案例 2：试图搞死系统的恶意插件（无限死循环，吃光 CPU）
    evil_plugin = """
print(">>> [受控输出] 嘿嘿，我要开始霸占你的 CPU 了！")
while True:
    pass # 无限死循环，如果是普通系统，现在已经卡死了
"""

    # 测试案例 3：试图绕过沙箱加载危险模块的插件
    sneaky_plugin = """
print(">>> [受控输出] 让我偷偷加载一下 os 模块...")
import os
os.system('echo 哈哈')
"""

    print("▶️ OpenClaw 沙箱安全测试启动\n")
    time.sleep(1)

    print("【第一场：测试合规插件】")
    run_in_sandbox("绿色计算插件", good_plugin)
    time.sleep(1.5)

    print("【第二场：测试越权加载插件】")
    run_in_sandbox("偷摸越权插件", sneaky_plugin)
    time.sleep(1.5)

    print("【第三场：测试恶意死循环插件】")
    run_in_sandbox("霸占资源插件", evil_plugin)