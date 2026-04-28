# 
# 
# 1. 先导入需要的模块
# 
# 

# ========== 顶部新增：数据库相关导入 ==========
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import declarative_base,sessionmaker
from datetime import datetime
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
import uvicorn




# 导入Python自带的AST模块，核心中的核心
import ast
# 导入日志模块，后面记录审计日志用
import logging
from typing import List, Dict

import json
import time
# import signal
import builtins
from typing import Tuple, Dict

from concurrent.futures import ThreadPoolExecutor, TimeoutError

from datetime import datetime, timedelta


# 配置日志，让我们能看到审计过程
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ClawGuard-AST")



# ========== 数据库初始化 ==========
# SQLite数据库文件，不用额外装数据库服务，新手零配置
SQLALCHEMY_DATABASE_URL = "sqlite:///./clawguard.db"
# 创建数据库引擎，解决SQLite线程问题
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
# 数据库会话工厂
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
# 数据库模型基类
Base = declarative_base()

# ========== 密码加密&JWT鉴权配置 ==========
# 密码加密上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# JWT密钥（你可以改成自己的随机字符串，生产环境一定要保密！）
SECRET_KEY = "clawguard123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120  # 令牌2小时过期
# OAuth2鉴权方案
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")


# ========== 数据库表模型 ==========
# 1. 用户表：存平台登录用户，实现鉴权
class DBUser(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, index=True, nullable=False, comment="用户名")
    hashed_password = Column(String(200), nullable=False, comment="加密后的密码")
    role = Column(String(20), default="user", comment="角色：admin/admin/user/guest")
    create_time = Column(DateTime, default=datetime.now, comment="创建时间")
    is_active = Column(Integer, default=1, comment="是否启用：1启用/0禁用")

# 2. 审计日志表：存所有安全检测记录，全链路可追溯
class DBAuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    task_id = Column(String(64), unique=True, index=True, comment="检测任务唯一ID")
    agent_id = Column(String(64), default="default-agent", comment="AI Agent/插件ID")
    final_status = Column(String(20), nullable=False, comment="最终结果：passed/blocked/error")
    final_message = Column(String(500), nullable=False, comment="检测结果描述")
    code_content = Column(Text, comment="检测的代码内容")
    static_audit_result = Column(Text, comment="静态审计结果JSON")
    sandbox_check_result = Column(Text, comment="沙箱检测结果JSON")
    runtime_monitor_result = Column(Text, comment="运行时监控结果JSON")
    create_time = Column(DateTime, default=datetime.now, comment="检测时间")
    operator = Column(String(50), default="anonymous", comment="操作人")
    cost_time = Column(Float, comment="检测耗时，单位秒")



# ========== 数据库工具函数 ==========
# 获取数据库会话，API接口用
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 密码加密
def get_password_hash(password: str):
    # 新增：bcrypt标准截断，彻底解决超长报错
    password = password.encode('utf-8')[:72].decode('utf-8', 'ignore')
    return pwd_context.hash(password)

# 密码校验
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# 创建JWT访问令牌
def create_access_token(data: dict):
    to_encode = data.copy()
    # 新增：JWT标准过期时间，彻底修复令牌无效
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 校验令牌，获取当前用户
async def get_current_user(token: str = Depends(oauth2_scheme), db = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="令牌无效或已过期",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(DBUser).filter(DBUser.username == username).first()
    if user is None or user.is_active == 0:
        raise credentials_exception
    return user

# 初始化管理员账号（第一次运行自动创建）
def init_admin_user():
    db = SessionLocal()
    # 检查管理员是否存在
    admin = db.query(DBUser).filter(DBUser.username == "admin").first()
    if not admin:
        # 创建默认管理员，账号admin，密码clawguard123
        admin_user = DBUser(
            username="admin",
            hashed_password=get_password_hash("clawguard123"),
            role="admin"
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
        logger.info("初始化管理员账号成功：账号admin，密码clawguard123")
    db.close()



# ========== 升级后的审计日志管理器 ==========
class AuditManager:
    def __init__(self):
        logger.info("初始化ClawGuard审计日志管理器...")

    # 写入审计日志（检测完成后调用，全量存库）
    def save_audit_log(self, db, task_id: str, agent_id: str, final_status: str, 
                      final_message: str, code_content: str, static_result: dict, 
                      sandbox_result: dict, runtime_result: dict, operator: str, cost_time: float):
        try:
            audit_log = DBAuditLog(
                task_id=task_id,
                agent_id=agent_id,
                final_status=final_status,
                final_message=final_message,
                code_content=code_content,
                static_audit_result=json.dumps(static_result, ensure_ascii=False),
                sandbox_check_result=json.dumps(sandbox_result, ensure_ascii=False),
                runtime_monitor_result=json.dumps(runtime_result, ensure_ascii=False),
                operator=operator,
                cost_time=cost_time
            )
            db.add(audit_log)
            db.commit()
            db.refresh(audit_log)
            logger.info(f"审计日志写入成功，任务ID：{task_id}")
            return audit_log
        except Exception as e:
            logger.error(f"审计日志写入失败：{str(e)}", exc_info=True)
            return None

    # 分页查询审计日志（给API用）
    def get_audit_logs(self, db, page_num: int = 1, page_size: int = 20, status: str = None):
        query = db.query(DBAuditLog)
        # 按状态筛选
        if status:
            query = query.filter(DBAuditLog.final_status == status)
        # 按时间倒序，最新的在前
        query = query.order_by(DBAuditLog.create_time.desc())
        # 分页
        total = query.count()
        logs = query.offset((page_num - 1) * page_size).limit(page_size).all()
        return {
            "total": total,
            "page_num": page_num,
            "page_size": page_size,
            "list": logs
        }

# 全局初始化审计管理器
audit_manager = AuditManager()






# 
# 
#  2.定义我们的安全策略
# 
# 


## 安全策略：统一管理所有黑名单、规则，适配静态审计+沙箱
# 安全策略：统一管理静态审计+沙箱+运行时监控的所有规则
class SecurityPolicy:
    # ========== 第一阶段：静态审计用的黑名单 ==========
    blocked_modules: list[str] = ["os", "subprocess", "pty", "sys", "socket", "requests"]
    blocked_calls: list[str] = ["exec", "eval", "__import__", "getattr", "setattr", "system", "popen"]
    
    # ========== 第二阶段：沙箱用的配置 ==========
    sensitive_paths: list[str] = ["/etc/passwd", "/etc/shadow", ".env", "config.json", "/root", "C:\\Windows"]
    sandbox_timeout: int = 5
    allowed_builtins: list[str] = ["print", "len", "range", "list", "dict", "str", "int", "float", "bool", "Exception"]

    # ========== 第三阶段：运行时监控新增的规则 ==========
    # 1. 循环次数限制：防止死循环/资源耗尽，单函数最大循环次数
    max_loop_count: int = 500
    # 2. 函数调用频率限制：1秒内最多调用多少次函数，防止高频恶意调用
    max_call_frequency: int = 100
    # 3. 敏感操作最大次数：比如open文件、调用print，最多多少次
    max_sensitive_operation_count: int = 10
    # 4. 单函数最大执行行数：防止函数里无限执行代码
    max_exec_lines_per_function: int = 1000
    # 5. 要监控的敏感函数列表（和钩子函数对应）
    monitored_sensitive_funcs: list[str] = ["open", "print", "exec", "eval"]
    # 6. 异常熔断阈值：最多抛出多少次异常，防止异常爆破
    max_exception_count: int = 5

# 全局初始化策略，全项目通用
policy = SecurityPolicy()



# 
# 
# 3.写 AST 遍历器，检查每个节点
# 
# 


# AST审计器：遍历AST树，检查危险行为
class ASTInspector(ast.NodeVisitor):
    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        self.violations = []  # 存违规记录
        self.log_stack = []   # 存审计过程日志

    # 打印审计日志的辅助方法
    def _trace(self, msg: str):
        self.log_stack.append(f"[*] {msg}")
        logger.info(msg)

    # 重写visit_Import方法：检查import xxx 语句
    def visit_Import(self, node: ast.Import):
        # node.names 就是import后面的模块名，比如import os, sys 就是[os, sys]
        for alias in node.names:
            module_name = alias.name
            # 如果模块在黑名单里，就记录违规
            if module_name in self.policy.blocked_modules:
                violation_msg = f"禁止导入高危模块：{module_name}，行号：{node.lineno}"
                self.violations.append(violation_msg)
                self._trace(f"[!] 发现违规：{violation_msg}")
        # 必须加这个，继续遍历子节点
        self.generic_visit(node)

    # 重写visit_ImportFrom方法：检查from xxx import xxx 语句
    def visit_ImportFrom(self, node: ast.ImportFrom):
        # node.module 就是from后面的模块名，比如from os import system 就是os
        if node.module in self.policy.blocked_modules:
            violation_msg = f"禁止从高危模块导入内容：{node.module}，行号：{node.lineno}"
            self.violations.append(violation_msg)
            self._trace(f"[!] 发现违规：{violation_msg}")
        self.generic_visit(node)
    
    # 重写visit_Call方法：检查函数调用，比如eval()、exec()
    def visit_Call(self, node: ast.Call):
        # node.func 就是被调用的函数，分两种情况：直接调用eval()，或者xxx.eval()
        # 情况1：直接调用函数，比如eval("xxx")
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.policy.blocked_calls:
                violation_msg = f"禁止调用高危函数：{func_name}()，行号：{node.lineno}"
                self.violations.append(violation_msg)
                self._trace(f"[!] 发现违规：{violation_msg}")
        # 情况2：调用属性函数，比如os.system()
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if func_name in self.policy.blocked_calls:
                violation_msg = f"禁止调用高危属性函数：{func_name}()，行号：{node.lineno}"
                self.violations.append(violation_msg)
                self._trace(f"[!] 发现违规：{violation_msg}")
        self.generic_visit(node)


# 
# 
# 4.写审计入口方法，把整个流程串起来
# 
# 

# 审计主函数：传入代码，返回审计结果
def audit_code(code: str, policy: SecurityPolicy) -> Dict:
    logger.info("开始执行ClawGuard静态代码审计...")
    # 1. 初始化审计器
    inspector = ASTInspector(policy)
    
    try:
        # 2. 把代码解析成AST树（这一步会自动检查语法错误）
        inspector._trace("正在解析代码，生成AST抽象语法树...")
        tree = ast.parse(code)
        
        # 3. 遍历AST树，执行检查
        inspector._trace("开始遍历AST树，执行安全检查...")
        inspector.visit(tree)
        
        # 4. 处理审计结果
        if len(inspector.violations) > 0:
            # 有违规，拦截
            inspector._trace(f"审计完成，发现{len(inspector.violations)}条违规，拦截代码执行！")
            return {
                "status": "blocked",
                "message": "ClawGuard静态审计拦截",
                "violations": inspector.violations,
                "logs": inspector.log_stack
            }
        else:
            # 无违规，通过
            inspector._trace("审计完成，未发现违规行为，代码通过检测！")
            return {
                "status": "passed",
                "message": "ClawGuard静态审计通过",
                "violations": [],
                "logs": inspector.log_stack
            }
    
    except SyntaxError as e:
        # 代码本身有语法错误，直接拦截
        error_msg = f"代码语法错误：{str(e)}，行号：{e.lineno}"
        logger.error(error_msg)
        return {
            "status": "error",
            "message": "代码语法校验失败",
            "details": error_msg
        }


#===========================================================================
# ===========================================================================
# 5.实现最简沙箱核心 
# ===========================================================================
# ===========================================================================




# ========== 安全沙箱运行时核心类 ==========
class SandboxRuntime:

    def __init__(self, code: str, policy: SecurityPolicy):
        self.code = code  # 要执行的代码
        self.policy = policy  # 安全策略
        self.telemetry = []  # 沙箱执行日志，全程留痕
        self.is_running = False  # 沙箱运行状态
         # 【新增】初始化运行时监控器
        self.runtime_monitor = RuntimeBehaviorMonitor(policy)

    # 辅助方法：记录沙箱日志，和第一阶段的审计日志统一格式
    def _emit(self, msg: str):
        log_msg = f"[SANDBOX] {msg}"
        self.telemetry.append(log_msg)
        logger.info(log_msg)

    # ========== 钩子函数：劫持open函数，拦截敏感文件访问 ==========
    def _hooked_open(self, file, mode='r', *args, **kwargs):
        """
        替换原生open函数，代码里调用open()的时候，实际执行的是这个函数
        核心逻辑：先检查文件路径是不是敏感的，是就拒绝，不是就给虚拟内容
        """
         # 【新增】给监控器标记敏感操作
        self.runtime_monitor.behavior_metrics["sensitive_operation_count"] += 1

        # 把文件路径转成字符串，统一处理
        file_path = str(file)
        self._emit(f"拦截到文件打开操作：路径={file_path}，模式={mode}")

        # 1. 检查是不是敏感路径
        for sensitive_path in self.policy.sensitive_paths:
            if sensitive_path in file_path:
                self._emit(f"[!] 敏感路径访问被拒绝：{file_path} 匹配黑名单 {sensitive_path}")
                # 主动抛出异常，终止代码执行
                raise PermissionError(f"ClawGuard 访问拒绝：禁止操作敏感路径 {file_path}")

        # 2. 非敏感路径，返回一个虚拟的文件对象，不给真实的系统文件权限
        self._emit(f"路径{file_path}通过安全检查，返回虚拟文件对象")
        # 写一个假的文件类，完全模拟文件操作，但不碰真实磁盘
        class VirtualFile:
            def read(self):
                return "### ClawGuard 沙箱虚拟文件内容 ###"
            def readline(self):
                return "### 虚拟文件行内容 ###"
            def write(self, content):
                # 禁止写操作，防止篡改文件
                raise PermissionError("ClawGuard 访问拒绝：沙箱禁止写文件操作")
            def close(self):
                pass
            # 实现上下文管理器，支持 with open(...) as f: 写法
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.close()
        
        return VirtualFile()




    # ========== 核心：构建阉割版的全局命名空间 ==========
    def _build_restricted_globals(self) -> Dict:
        self._emit("正在构建受限全局执行环境...")
        
        restricted_builtins = {}
        # 遍历白名单，只允许我们指定的内置函数
        for func_name in self.policy.allowed_builtins:
            # 这里用 builtins.__dict__ 代替 __builtins__
            if func_name in builtins.__dict__:
                restricted_builtins[func_name] = builtins.__dict__[func_name]
        
        # 【重点】把我们的钩子open函数加到内置函数里
        restricted_builtins["open"] = self._hooked_open
        self._emit(f"已加载白名单内置函数：{list(restricted_builtins.keys())}")

        restricted_globals = {
            "__builtins__": restricted_builtins,
            "__name__": "__sandbox__",
            "__file__": "sandbox_exec.py",
        }

        self._emit("受限全局环境构建完成，已屏蔽所有高危内置能力")
        return restricted_globals

    

    # ========== 沙箱执行入口 ==========
    def run(self) -> Tuple[bool, str, Dict]:
        """
        执行沙箱代码，返回结果
        :return: (是否执行成功, 错误信息, 执行详情)
        """
        self._emit("="*30 + "沙箱启动" + "="*30)
        self.is_running = True
        restricted_globals = self._build_restricted_globals()




        try:
            clean_code = self.code.replace('\xa0', ' ').replace('\r', '')
            self._emit(f"开始在受限环境中执行代码，超时时间：{self.policy.sandbox_timeout}秒")
            
            # ========== 【新增】启动运行时监控 ==========
            self.runtime_monitor.start()
            
            # 核心：执行代码，全程被监控
            exec(clean_code, restricted_globals, {})

            # ========== 【新增】代码正常执行完，停止监控 ==========
            self.runtime_monitor.stop()

            self._emit("代码执行完成，控制流正常，未触发敏感操作")
            return True, None, {
                "status": "passed",
                "telemetry": self.telemetry,
                "runtime_monitor_report": self.runtime_monitor.get_report(), # 新增：返回监控报告
                "globals_leftover": list(restricted_globals.keys())
            }

        except TimeoutError as e:
            # 超时也要停止监控
            self.runtime_monitor.stop()
            error_msg = str(e)
            self._emit(f"[!] {error_msg}")
            return False, error_msg, {
                "status": "timeout",
                "telemetry": self.telemetry,
                "runtime_monitor_report": self.runtime_monitor.get_report(),
                "error": error_msg
            }

        except Exception as e:
            # 熔断/异常也要停止监控
            self.runtime_monitor.stop()
            error_msg = f"沙箱执行终止：{str(e)}"
            self._emit(f"[!] {error_msg}")
            return False, error_msg, {
                "status": "blocked",
                "telemetry": self.telemetry,
                "runtime_monitor_report": self.runtime_monitor.get_report(),
                "error": error_msg
            }

        finally:
            # 一定要关闭闹钟！不然主程序会被意外终止
            self.is_running = False
            self._emit("="*30 + "沙箱关闭" + "="*30)


# 
# 
import sys
import time
from typing import Dict, List
# ============================================================================
# ============================================================================
# ====================== 运行时行为监控核心类 ==================================
# ============================================================================
# ============================================================================

class RuntimeBehaviorMonitor:
    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        # ========== 实时采集的行为数据 ==========
        self.behavior_metrics = {
            "total_exec_lines": 0,  # 总共执行了多少行代码
            "loop_count": 0,        # 循环执行次数
            "function_call_count": 0, # 总函数调用次数
            "function_call_history": [], # 函数调用时间记录，算频率用
            "sensitive_operation_count": 0, # 敏感操作次数
            "exception_count": 0,   # 异常抛出次数
            "current_function_exec_lines": 0, # 当前函数执行的行数
            "current_function_name": "", # 当前正在执行的函数名
        }
        # ========== 监控状态 ==========
        self.is_running = False
        self.fuse_triggered = False # 熔断是否触发
        self.fuse_reason = "" # 熔断原因
        self.monitor_logs = [] # 监控日志，全程留痕

    # 辅助方法：记录监控日志
    def _emit(self, msg: str):
        log_msg = f"[RUNTIME-MONITOR] {msg}"
        self.monitor_logs.append(log_msg)
        logger.info(log_msg)

    # ========== 核心：实时异常检测+熔断逻辑 ==========
    def _check_and_fuse(self):
        """
        每执行一步都调用这个方法，检查是否触发熔断规则
        一旦触发，直接抛出异常，终止代码执行
        """
        metrics = self.behavior_metrics

        # 1. 检查循环次数是否超限
        if metrics["loop_count"] > self.policy.max_loop_count:
            self.fuse_triggered = True
            self.fuse_reason = f"循环次数超限：最大允许{self.policy.max_loop_count}次，当前{metrics['loop_count']}次，疑似死循环"
        
        # 2. 检查敏感操作次数是否超限
        elif metrics["sensitive_operation_count"] > self.policy.max_sensitive_operation_count:
            self.fuse_triggered = True
            self.fuse_reason = f"敏感操作次数超限：最大允许{self.policy.max_sensitive_operation_count}次，当前{metrics['sensitive_operation_count']}次"
        
        # 3. 检查异常次数是否超限
        elif metrics["exception_count"] > self.policy.max_exception_count:
            self.fuse_triggered = True
            self.fuse_reason = f"异常抛出次数超限：最大允许{self.policy.max_exception_count}次，当前{metrics['exception_count']}次，疑似异常爆破"
        
        # 4. 检查函数执行行数是否超限
        elif metrics["current_function_exec_lines"] > self.policy.max_exec_lines_per_function:
            self.fuse_triggered = True
            self.fuse_reason = f"单函数执行行数超限：最大允许{self.policy.max_exec_lines_per_function}行，当前{metrics['current_function_exec_lines']}行"
        
        # 5. 检查函数调用频率（1秒内的调用次数）
        now = time.time()
        # 只保留1秒内的调用记录
        metrics["function_call_history"] = [t for t in metrics["function_call_history"] if now - t < 1]
        if len(metrics["function_call_history"]) > self.policy.max_call_frequency:
            self.fuse_triggered = True
            self.fuse_reason = f"函数调用频率超限：1秒内最多允许{self.policy.max_call_frequency}次，当前{len(metrics['function_call_history'])}次"

        # 如果触发熔断，直接抛出异常，终止代码执行
        if self.fuse_triggered:
            self._emit(f"[!] 熔断触发：{self.fuse_reason}")
            raise PermissionError(f"ClawGuard 运行时熔断：{self.fuse_reason}")

    # ========== 核心：跟踪函数，和之前的demo逻辑一致，加了采集和检测 ==========
    def trace_handler(self, frame, event, arg):
        # 如果已经触发熔断，直接返回None，停止监控
        if self.fuse_triggered:
            return None

        try:
            # ========== 1. 按事件类型采集数据 ==========
            # 事件1：调用函数
            if event == "call":
                self.behavior_metrics["function_call_count"] += 1
                self.behavior_metrics["function_call_history"].append(time.time())
                # 记录当前进入的函数名
                func_name = frame.f_code.co_name
                self.behavior_metrics["current_function_name"] = func_name
                self.behavior_metrics["current_function_exec_lines"] = 0
                # 如果是敏感函数，记录敏感操作
                if func_name in self.policy.monitored_sensitive_funcs:
                    self.behavior_metrics["sensitive_operation_count"] += 1
                    self._emit(f"检测到敏感函数调用：{func_name}，累计次数：{self.behavior_metrics['sensitive_operation_count']}")

            # 事件2：执行一行代码
            elif event == "line":
                self.behavior_metrics["total_exec_lines"] += 1
                self.behavior_metrics["current_function_exec_lines"] += 1
                # 简单判断循环：行号比上一行小，大概率是循环回头了
                if frame.f_lineno < frame.f_lasti:
                    self.behavior_metrics["loop_count"] += 1

            # 事件3：函数返回
            elif event == "return":
                self._emit(f"函数执行完成：{frame.f_code.co_name}，执行行数：{self.behavior_metrics['current_function_exec_lines']}")

            # 事件4：抛出异常
            elif event == "exception":
                self.behavior_metrics["exception_count"] += 1
                self._emit(f"检测到异常抛出，累计次数：{self.behavior_metrics['exception_count']}")

            # ========== 2. 每一步都执行熔断检查 ==========
            self._check_and_fuse()

        except Exception as e:
            # 监控本身的异常不能影响代码执行，只记录日志
            self._emit(f"监控器异常：{str(e)}")
        
        # 必须返回自身，继续监控
        return self.trace_handler

    # ========== 启动监控 ==========
    def start(self):
        if self.is_running:
            return
        self._emit("启动运行时行为监控引擎...")
        self.is_running = True
        # 给Python解释器注册我们的跟踪函数
        sys.settrace(self.trace_handler)
        self._emit("监控引擎启动成功，全程实时行为采集已开启")

    # ========== 停止监控 ==========
    def stop(self):
        self._emit("停止运行时行为监控引擎...")
        self.is_running = False
        # 注销跟踪函数，关闭监控
        sys.settrace(None)
        self._emit(f"监控引擎已停止，累计执行行数：{self.behavior_metrics['total_exec_lines']}，函数调用次数：{self.behavior_metrics['function_call_count']}")

    # ========== 生成监控报告 ==========
    def get_report(self) -> Dict:
        return {
            "fuse_triggered": self.fuse_triggered,
            "fuse_reason": self.fuse_reason,
            "behavior_metrics": self.behavior_metrics,
            "monitor_logs": self.monitor_logs
        }



# =========================================================================================
# 
# ========== 完整的ClawGuard安全检测入口 ==========
# 
# =========================================================================================



def full_security_check(code: str, policy: SecurityPolicy) -> Dict:
    """
    全流程安全检测：静态审计 → 动态沙箱检测
    :param code: 要检测的插件代码
    :param policy: 安全策略
    :return: 完整的检测报告
    """
    logger.info("="*40 + "开始全流程安全检测" + "="*40)
    full_report = {
        "static_audit": None,
        "sandbox_check": None,
        "final_status": "pending",
        "final_message": ""
    }

    # 第一步：静态AST审计
    logger.info("第一步：执行静态代码审计")
    static_result = audit_code(code, policy)
    full_report["static_audit"] = static_result

    # 静态审计不通过，直接终止
    if static_result["status"] != "passed":
        full_report["final_status"] = "blocked"
        full_report["final_message"] = f"静态审计拦截：{static_result['message']}"
        logger.error(f"全流程检测终止：{full_report['final_message']}")
        return full_report

    # 第二步：静态通过，进沙箱做动态检测
    logger.info("第二步：静态审计通过，执行沙箱动态检测")
    sandbox = SandboxRuntime(code, policy)
    success, error, sandbox_result = sandbox.run()
    full_report["sandbox_check"] = sandbox_result

    # 沙箱检测不通过
    if not success:
        full_report["final_status"] = "blocked"
        full_report["final_message"] = f"沙箱动态检测拦截：{error}"
        logger.error(f"全流程检测终止：{full_report['final_message']}")
        return full_report

    # 两层都通过，检测完成
    full_report["final_status"] = "passed"
    full_report["final_message"] = "全流程安全检测通过，代码未发现风险"
    logger.info(f"全流程检测完成：{full_report['final_message']}")
    return full_report
    
# =======================================
# =======================================
# ========== 安全检测核心服务层 ==========
# =======================================
# =======================================
import uuid
import time

class SecurityCheckService:
    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        logger.info("初始化ClawGuard安全检测服务...")

    # 核心：执行全流程安全检测
    def execute_full_check(self, code: str, agent_id: str = "default-agent", operator: str = "anonymous") -> Dict:
        """
        执行全流程安全检测，返回标准化结果
        :param code: 要检测的插件代码
        :param agent_id: 插件/Agent ID
        :param operator: 操作人
        :return: 标准化检测结果
        """
        # 生成唯一任务ID
        task_id = str(uuid.uuid4()).replace("-", "")
        logger.info(f"开始执行安全检测，任务ID：{task_id}，Agent ID：{agent_id}，操作人：{operator}")
        start_time = time.time()

        try:
            # 调用之前写的全流程检测函数
            full_result = full_security_check(code, self.policy)
            # 计算耗时
            cost_time = round(time.time() - start_time, 3)
            logger.info(f"检测完成，任务ID：{task_id}，结果：{full_result['final_status']}，耗时：{cost_time}秒")

            # 封装标准化返回结果
            result = {
                "task_id": task_id,
                "agent_id": agent_id,
                "operator": operator,
                "final_status": full_result["final_status"],
                "final_message": full_result["final_message"],
                "cost_time": cost_time,
                "static_audit_result": full_result["static_audit"],
                "sandbox_check_result": full_result["sandbox_check"],
                "code_content": code,
                "create_time": datetime.now().isoformat()
            }
            return result

        except Exception as e:
            cost_time = round(time.time() - start_time, 3)
            error_msg = f"检测服务异常：{str(e)}"
            logger.error(error_msg, exc_info=True)
            return {
                "task_id": task_id,
                "agent_id": agent_id,
                "operator": operator,
                "final_status": "error",
                "final_message": error_msg,
                "cost_time": cost_time,
                "static_audit_result": None,
                "sandbox_check_result": None,
                "code_content": code,
                "create_time": datetime.now().isoformat()
            }

# 全局初始化安全检测服务，用我们的全局策略
security_service = SecurityCheckService(policy)



# =========================================
# =========================================
# ========== API接口请求/响应模型 ==========
# =========================================
# =========================================

# 1. 代码检测请求模型
class CodeCheckRequest(BaseModel):
    code: str = Field(..., description="要检测的AI插件代码", min_length=1, max_length=100000)
    agent_id: Optional[str] = Field("default-agent", description="插件/Agent ID")

# 2. 审计日志分页查询请求模型
class AuditLogQueryRequest(BaseModel):
    page_num: Optional[int] = Field(1, description="页码", ge=1)
    page_size: Optional[int] = Field(20, description="每页条数", ge=1, le=100)
    status: Optional[str] = Field(None, description="筛选状态：passed/blocked/error")

# 3. 通用响应模型
class CommonResponse(BaseModel):
    code: int = Field(200, description="状态码：200成功/400参数错误/500服务错误")
    message: str = Field("操作成功", description="提示信息")
    data: Optional[Dict | List] = Field(None, description="返回数据")








# 
# 
# 5.写测试代码，验证我们的审计器能正确识别恶意代码和正常代码
# 
# 


# ====================================================#
# ====================================================#
# ========== 创建FastAPI应用，严格遵循品牌规范 =========#
# ====================================================#
# ====================================================#

app = FastAPI(
    title="ClawGuard Protocol API",
    description="企业级AI Agent插件全生命周期安全防护平台 - 官方API文档",
    version="5.0.0",
    docs_url="/docs",  # 自动生成的Swagger API文档地址
    redoc_url="/redoc"
)

# ========== 配置跨域支持，前端调用不会报错 ==========
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 生产环境可以改成你的前端域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== 全局异常处理，统一返回格式 ==========
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"全局异常捕获：{str(exc)}", exc_info=True)
    return CommonResponse(
        code=500,
        message=f"服务内部错误：{str(exc)}",
        data=None
    )

# ========== API路由接口 ==========
# 1. 健康检查接口（无需鉴权）
@app.get("/api/health", response_model=CommonResponse, summary="健康检查")
async def health_check():
    return CommonResponse(
        code=200,
        message="ClawGuard 服务运行正常",
        data={
            "status": "UP",
            "timestamp": datetime.now().isoformat(),
            "version": "5.0.0"
        }
    )

# 2. 管理员登录接口（获取JWT令牌）
@app.post("/api/auth/login", summary="管理员登录")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db = Depends(get_db)):
    # 查询用户
    user = db.query(DBUser).filter(DBUser.username == form_data.username).first()
    # 校验用户名密码
    if not user or not verify_password(form_data.password, user.hashed_password) or user.is_active == 0:
        return CommonResponse(
            code=400,
            message="用户名或密码错误，或账号已禁用",
            data=None
        )
    # 生成JWT令牌
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role
    }

# 3. 核心：全流程安全检测接口（需要鉴权）
@app.post("/api/security/check", response_model=CommonResponse, summary="执行代码安全检测")
async def code_security_check(
    request: CodeCheckRequest,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    # 调用安全检测服务
    check_result = security_service.execute_full_check(
        code=request.code,
        agent_id=request.agent_id,
        operator=current_user.username
    )
    # 把检测结果写入审计日志数据库
    audit_manager.save_audit_log(
        db=db,
        task_id=check_result["task_id"],
        agent_id=check_result["agent_id"],
        final_status=check_result["final_status"],
        final_message=check_result["final_message"],
        code_content=check_result["code_content"],
        static_result=check_result["static_audit_result"],
        sandbox_result=check_result["sandbox_check_result"],
        runtime_result=check_result["sandbox_check_result"]["runtime_monitor_report"] if check_result["sandbox_check_result"] else None,
        operator=check_result["operator"],
        cost_time=check_result["cost_time"]
    )
    # 返回结果
    return CommonResponse(
        code=200,
        message=check_result["final_message"],
        data=check_result
    )

# 4. 分页查询审计日志接口（需要鉴权）
@app.post("/api/audit/logs", response_model=CommonResponse, summary="分页查询审计日志")
async def get_audit_logs(
    request: AuditLogQueryRequest,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    logs_result = audit_manager.get_audit_logs(
        db=db,
        page_num=request.page_num,
        page_size=request.page_size,
        status=request.status
    )
    # 格式化返回数据，把数据库对象转成字典
    format_list = []
    for log in logs_result["list"]:
        format_list.append({
            "id": log.id,
            "task_id": log.task_id,
            "agent_id": log.agent_id,
            "final_status": log.final_status,
            "final_message": log.final_message,
            "operator": log.operator,
            "cost_time": log.cost_time,
            "create_time": log.create_time.isoformat()
        })
    return CommonResponse(
        code=200,
        message="查询成功",
        data={
            "total": logs_result["total"],
            "page_num": logs_result["page_num"],
            "page_size": logs_result["page_size"],
            "list": format_list
        }
    )

# 5. 获取当前安全策略配置接口（需要鉴权）
@app.get("/api/policy", response_model=CommonResponse, summary="获取安全策略配置")
async def get_security_policy(current_user = Depends(get_current_user)):
    # 把策略类转成字典返回
    policy_dict = {k:v for k,v in SecurityPolicy.__dict__.items() if not k.startswith("_")}
    return CommonResponse(
        code=200,
        message="获取成功",
        data=policy_dict
    )

# ========== 服务启动入口 ==========
if __name__ == "__main__":
    # 1. 创建数据库表（第一次运行自动创建，后续不会重复创建）
    Base.metadata.create_all(bind=engine)
    # 2. 初始化管理员账号
    init_admin_user()
    # 3. 打印品牌启动信息
    print("="*80)
    print("🔥 CLAWGURAD PROTOCOL - AI AGENT SECURITY SHIELD")
    print("✅ 服务启动成功，企业级API服务已就绪")
    print("📖 API文档地址：http://127.0.0.1:8000/docs")
    print("🔑 默认管理员账号：admin / 密码：clawguard123")
    print("="*80)
    # 4. 启动服务
    uvicorn.run(app, host="0.0.0.0", port=8000)