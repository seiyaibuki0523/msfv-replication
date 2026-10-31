from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.console import Group
from collections import deque
import threading
import time

class SplitScreenTUI:
    """Singleton TUI Manager for AutoSecAgent"""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(SplitScreenTUI, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized: return
        self._initialized = True
        
        # UI State
        self.target_info = "Waiting for target initialization..."
        self.recon_data = "No reconnaissance data yet."
        self.logs_buffer = deque(maxlen=100) # Keep last 100 log lines
        self.tool_logs_buffer = deque(maxlen=50) # System and Tool errors

        # Setup Layout
        self.layout = Layout()
        
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main")
        )
        
        self.layout["main"].split_row(
            Layout(name="left_panel", ratio=1),
            Layout(name="right_panel", ratio=2)
        )
        
        self.layout["left_panel"].split_column(
            Layout(name="target_info", ratio=2),
            Layout(name="recon_data", ratio=3),
            Layout(name="tool_logs", ratio=3)
        )
        
        self._running = True
        self.start_time = time.time()
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()
        
        self.update_renderables()

    def update_renderables(self):
        """Re-render all panels with current state."""
        # Left Panel (Target, Recon, Tool Logs)
        self.layout["target_info"].update(Panel(Text(self.target_info), title="Target & Scope", border_style="yellow"))
        self.layout["recon_data"].update(Panel(Text(self.recon_data), title="Reconnaissance & Knowledge", border_style="blue"))
        
        tool_log_text = Text.from_markup("\n".join(self.tool_logs_buffer))
        self.layout["tool_logs"].update(Panel(tool_log_text, title="System & Tool Errors", border_style="red"))
        
        # Right Panel (Logs)
        log_text = Text.from_markup("\n".join(self.logs_buffer))
        self.layout["right_panel"].update(Panel(log_text, title="Execution & AI Thought Logs", border_style="green"))

    def _heartbeat_loop(self):
        spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        frame_idx = 0
        while self._running:
            time.sleep(0.125)
            elapsed = int(time.time() - self.start_time)
            m, s = divmod(elapsed, 60)
            h, m = divmod(m, 60)
            time_str = f"{h:02d}:{m:02d}:{s:02d}"
            
            spinner = spinner_frames[frame_idx % len(spinner_frames)]
            frame_idx += 1
            
            header_text = f"[bold cyan]AutoSecAgent - Automated Security Scanner[/bold cyan] | Uptime: [yellow]{time_str}[/yellow] [bold magenta]{spinner}[/bold magenta]"
            self.layout["header"].update(Panel(header_text, style="cyan"))
            
    def stop(self):
        self._running = False


    def set_target_info(self, info: str):
        self.target_info = str(info)
        self.update_renderables()

    def set_recon_data(self, data: str):
        safe_data = str(data)
        lines = safe_data.split('\n')
        if len(lines) > 50: safe_data = "[Truncated...]\n" + "\n".join(lines[-50:])
        self.recon_data = safe_data
        self.update_renderables()

    def log(self, message: str, color="white"):
        """Add a message to the right-side execution log panel."""
        from rich.markup import escape
        safe_msg = escape(str(message))
        self.logs_buffer.append(f"[{color}]{safe_msg}[/{color}]")
        self.update_renderables()

    def error(self, message: str):
        self.log(message, color="red")

    def success(self, message: str):
        self.log(message, color="green")
        
    def info(self, message: str):
        self.log(message, color="cyan")

    def warning(self, message: str):
        self.log(message, color="yellow")
        
    def raw_log(self, text: str):
        """Direct log injection without color formatting for raw text."""
        from rich.markup import escape
        safe_msg = escape(str(text))
        for line in safe_msg.split('\n'):
            self.logs_buffer.append(line)
        self.update_renderables()

    def tool_log(self, message: str, color="white"):
        """Add a message to the bottom-left tool error/log panel."""
        from rich.markup import escape
        safe_msg = escape(str(message))
        self.tool_logs_buffer.append(f"[{color}]{safe_msg}[/{color}]")
        self.update_renderables()

    def tool_error(self, message: str):
        self.tool_log(message, color="red")

    def tool_info(self, message: str):
        self.tool_log(message, color="cyan")

# Global instance
tui = SplitScreenTUI()
