import os
import sys
import time
import signal
import subprocess
import platform
from pathlib import Path

class ServiceManager:
    def __init__(self, service_name, script_path, mode):
        """
        初始化服务管理器
        :param service_name: 服务名称
        :param script_path: Python 脚本路径
        """
        self.service_name = service_name
        self.system = platform.system()
        self.mode = mode
        if self.mode!='script' and self.system == 'Windows':
            script_path = script_path+'.exe'
        self.script_path = Path(script_path).resolve()
        self.pid_file = Path(f"/tmp/{service_name}.pid" if platform.system() != "Windows" 
                            else f"C:\\Windows\\Temp\\{service_name}.pid")

    def start(self):
        """启动服务"""
        running = False
        pid = -1
        command = ''
        if self.status():
            print(f"服务 {self.service_name} 已经在运行")
            return

        if self.system == "Windows":
            process = None
            if self.mode == 'script':
                # Windows 使用 pythonw.exe 后台运行
                #command = f'start /B pythonw "{self.script_path}"'
                command = f'pythonw "{self.script_path}"'
                command_list = ['pythonw.exe', '{self.script_path}']
                process = subprocess.Popen(command, shell=False, creationflags=subprocess.DETACHED_PROCESS|subprocess.CREATE_NO_WINDOW,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL)
            else:
                # Windows 使用 pythonw.exe 后台运行
                command = f'{self.script_path}'
                command_list = [self.script_path]
                process = subprocess.Popen(command_list, shell=False, creationflags=subprocess.DETACHED_PROCESS|subprocess.CREATE_NO_WINDOW|subprocess.SW_HIDE,
     stdin=subprocess.DEVNULL,
     stdout=subprocess.DEVNULL,
     stderr=subprocess.DEVNULL)
            if process is not None and process.pid:
                with open(self.pid_file, 'w') as f:
                    f.write(f'{process.pid}')
                running = True
                pid = process.pid

        else:
            # Linux 使用 nohup 后台运行
            pid = -1
            if self.mode == 'script':
                command = f'nohup python3 "{self.script_path}" > /dev/null 2>&1 & echo $!'
                pid = subprocess.check_output(command, shell=True).decode().strip()
            else:
                command = f'nohup "{self.script_path}" > /dev/null 2>&1 & echo $!'
                pid = subprocess.check_output(command, shell=True).decode().strip()
            if pid != -1:
                with open(self.pid_file, 'w') as f:
                    f.write(pid)
                    running = True
        if running:
            print(f"服务 {self.service_name} 已启动, pid: {pid}, command: {command}")
        else:
            print(f"服务 {self.service_name} 启动失败")

    def stop(self):
        """停止服务"""
        pid = self._get_pid()
        if not pid:
            print(f"服务 {self.service_name} 未运行")
            return

        if self.system == "Windows":
            # Windows 使用 taskkill 终止进程
            subprocess.call(f"taskkill /PID {pid} /F /T", shell=True)
        else:
            # Linux 使用 kill 终止进程
            os.kill(int(pid), signal.SIGTERM)

        self.pid_file.unlink(missing_ok=True)
        print(f"服务 {self.service_name} 已停止")

    def restart(self):
        """重启服务"""
        self.stop()
        time.sleep(1)  # 等待进程完全停止
        self.start()

    def status(self):
        """检查服务状态"""
        pid = self._get_pid()
        if not pid:
            print(f"服务 {self.service_name} 未运行")
            return False

        if self.system == "Windows":
            # Windows 检查进程是否存在
            try:
                result = subprocess.check_output(f"tasklist /FI \"PID eq {pid}\"", shell=True).decode(encoding='GBK')
                if result.startswith("信息: 没有运行的任务匹配指定标准"):
                    print(f"服务 {self.service_name} 未运行")
                    return False
                print(f"服务 {self.service_name} 正在运行 (PID: {pid}), 结果:{result}")
                return True
            except subprocess.CalledProcessError:
                print(f"服务 {self.service_name} 未运行")
                return False
        else:
            # Linux 检查进程是否存在
            try:
                os.kill(int(pid), 0)  # 发送信号 0 检查进程
                print(f"服务 {self.service_name} 正在运行 (PID: {pid})")
                return True
            except OSError:
                print(f"服务 {self.service_name} 未运行")
                return False

    def _get_pid(self):
        """获取服务的 PID"""
        if not self.pid_file.exists():
            return None
        with open(self.pid_file, 'r') as f:
            pid = f.read().strip()
        return pid if pid else None


if __name__ == "__main__":
    # 示例：管理一个名为 "oss_sync" 的服务
    script_path = ''
    usage = ''
    mode = 'script'
    if getattr(sys, 'frozen', False):
        # 打包后的程序
        base_path = sys.executable
        mode = 'executable'
        script_path = os.path.join(os.path.dirname(base_path), 'oss_sync')
        usage = 'oss_sync_service'
    else:
        # 未打包的脚本
        base_path = os.path.abspath(__file__)
        script_path = os.path.join(os.path.dirname(base_path), 'oss_sync.py')
        usage = 'python oss_sync_service.py'
    if len(sys.argv) > 2 and sys.argv[1].lower() == 'trigger':
       #单次执行
       sys.exit(0)

    service = ServiceManager(
        service_name="oss_sync",
        script_path=script_path,  # 替换为实际脚本路径
        mode=mode
    )

    # 解析命令行参数
    if len(sys.argv) != 2:
        print(f"用法: {usage} [start|stop|restart|status]")
        sys.exit(1)

    action = sys.argv[1].lower()
    if action == "start":
        service.start()
    elif action == "stop":
        service.stop()
    elif action == "restart":
        service.restart()
    elif action == "status":
        service.status()
    else:
        print("无效的操作，请使用 trigger/start/stop/restart/status")