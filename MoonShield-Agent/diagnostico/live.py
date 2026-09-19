
import uuid
import time
import subprocess
import threading
import logging
import re
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

_sessions: Dict[str, "LiveSession"] = {}
MAX_SESSIONS = 4
MAX_TTL_SEC = 1800

_registry_lock = threading.Lock()
_housekeeping_thread = None

class LiveSession:
    def __init__(self, tool: str, target: str, options: dict):
        self.session_id = str(uuid.uuid4())
        self.tool = tool
        self.target = target
        self.options = options
        
        self.started_at = time.time()
        self.updated_at = self.started_at
        self.status = "running"
        self.process: Optional[subprocess.Popen] = None
        self.thread: Optional[threading.Thread] = None
        
        self.stdout_buf = []
        self.stderr_buf = []
        self.structured = {}
        self.stop_requested = False
        
        if self.tool == "ping":
            self.structured = {
                "sent": 0, "received": 0, "loss_percent": 0.0,
                "last_ms": 0.0, "avg_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0,
                "sum_ms": 0.0
            }
        elif self.tool == "mtr":
            self.structured = {"hops": []}
            
    def touch(self):
        self.updated_at = time.time()
        
    def start(self, cmd_args):
        try:
            self.process = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
        except Exception as e:
            self.status = "error"
            self.stderr_buf.append(str(e))
            return
            
        self.thread = threading.Thread(target=self._read_stdout, daemon=True)
        self.thread.start()
        
    def stop(self):
        self.stop_requested = True
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                for _ in range(5):
                    if self.process.poll() is not None:
                        break
                    time.sleep(0.1)
                if self.process.poll() is None:
                    self.process.kill()
                self.process.wait(timeout=2.0)
            except Exception as e:
                logger.error(f"Erro ao matar processo live: {e}")
        self.status = "stopped"

        
    def _read_stdout(self):
        if not self.process or not self.process.stdout:
            return
            
        for line in self.process.stdout:
            if self.stop_requested:
                break
            line = line.strip()
            if not line:
                continue
                
            self.stdout_buf.append(line)
            if len(self.stdout_buf) > 500:
                self.stdout_buf.pop(0)
                
            try:
                if self.tool == "ping":
                    self._parse_ping(line)
                elif self.tool == "mtr":
                    self._parse_mtr(line)
            except Exception as e:
                logger.warning(f"Erro parser live {self.tool}: {e}")
                
        if self.process.stderr:
            err = self.process.stderr.read()
            if err:
                self.stderr_buf.append(err.strip())
                if len(self.stderr_buf) > 100:
                    self.stderr_buf.pop(0)
                
        if not self.stop_requested:
            self.status = "stopped"
            
    def _parse_ping(self, line):
        if "bytes from" in line and "time=" in line:
            self.structured["received"] += 1
            seq_m = re.search(r"icmp_seq=(\d+)", line)
            if seq_m:
                seq = int(seq_m.group(1))
                if seq > self.structured["sent"]:
                    self.structured["sent"] = seq
            else:
                self.structured["sent"] = max(self.structured["sent"], self.structured["received"])
                
            time_m = re.search(r"time=([\d.]+)", line)
            if time_m:
                ms = float(time_m.group(1))
                self.structured["last_ms"] = ms
                self.structured["sum_ms"] += ms
                if self.structured["received"] == 1:
                    self.structured["min_ms"] = ms
                    self.structured["max_ms"] = ms
                else:
                    self.structured["min_ms"] = min(self.structured["min_ms"], ms)
                    self.structured["max_ms"] = max(self.structured["max_ms"], ms)
                self.structured["avg_ms"] = round(self.structured["sum_ms"] / self.structured["received"], 2)
        elif "timeout" in line.lower() or "unreachable" in line.lower():
            seq_m = re.search(r"icmp_seq[ =](\d+)", line)
            if seq_m:
                seq = int(seq_m.group(1))
                if seq > self.structured["sent"]:
                    self.structured["sent"] = seq
            else:
                self.structured["sent"] += 1
                
        if self.structured["sent"] > 0:
            loss = (1.0 - (self.structured["received"] / self.structured["sent"])) * 100
            self.structured["loss_percent"] = round(loss, 1)

    def _parse_mtr(self, line):
        parts = line.split()
        if len(parts) < 3: return
        kind = parts[0]
        pos = int(parts[1])
        
        while len(self.structured["hops"]) <= pos:
            self.structured["hops"].append({
                "hop": len(self.structured["hops"]) + 1,
                "host": "???",
                "loss_percent": 0.0,
                "sent": 0,
                "received": 0,
                "last_ms": 0.0,
                "avg_ms": 0.0,
                "best_ms": 0.0,
                "worst_ms": 0.0,
                "stdev_ms": 0.0,
                "_sum_ms": 0.0,
                "_squares": 0.0
            })
            
        hop = self.structured["hops"][pos]
        
        if kind == "h":
            hop["host"] = parts[2]
        elif kind == "d":
            hop["host"] = parts[2]
        elif kind == "x":
            hop["sent"] += 1
        elif kind == "p":
            ms = int(parts[2]) / 1000.0
            hop["received"] += 1
            hop["last_ms"] = round(ms, 2)
            hop["_sum_ms"] += ms
            hop["_squares"] += ms * ms
            
            if hop["received"] == 1:
                hop["best_ms"] = ms
                hop["worst_ms"] = ms
            else:
                hop["best_ms"] = min(hop["best_ms"], ms)
                hop["worst_ms"] = max(hop["worst_ms"], ms)
                
            hop["avg_ms"] = round(hop["_sum_ms"] / hop["received"], 2)
            variance = (hop["_squares"] / hop["received"]) - (hop["avg_ms"] * hop["avg_ms"])
            if variance > 0:
                hop["stdev_ms"] = round(variance ** 0.5, 2)
            else:
                hop["stdev_ms"] = 0.0
                
        if hop["sent"] > 0:
            loss = (1.0 - (hop["received"] / hop["sent"])) * 100
            hop["loss_percent"] = round(loss, 1)


def _housekeeper():
    while True:
        time.sleep(30)
        cleanup_sessions()

def cleanup_sessions():
    now = time.time()
    with _registry_lock:
        for sid, sess in list(_sessions.items()):
            if now - sess.updated_at > MAX_TTL_SEC:
                sess.stop()
                del _sessions[sid]

def _ensure_housekeeper():
    global _housekeeping_thread
    with _registry_lock:
        if _housekeeping_thread is None or not _housekeeping_thread.is_alive():
            _housekeeping_thread = threading.Thread(target=_housekeeper, daemon=True)
            _housekeeping_thread.start()

def start_live_session(tool: str, target: str, options: dict) -> dict:
    _ensure_housekeeper()
    cleanup_sessions()
    with _registry_lock:
        if len(_sessions) >= MAX_SESSIONS:
            return {"ok": False, "status": "err", "error_code": "max_sessions", "summary": "Máximo de sessões ao vivo atingido."}
            
        from diagnostico.executor import _get_bin, validar_alvo_rede
        try:
            valid_target = validar_alvo_rede(target)
        except Exception as e:
            return {"ok": False, "status": "err", "error_code": "invalid_target", "summary": str(e)}
            
        sess = LiveSession(tool, valid_target, options)
        
        if tool == "ping":
            bin_path = _get_bin("ping")
            args = [bin_path, valid_target]
        elif tool == "mtr":
            bin_path = _get_bin("mtr")
            args = [bin_path, "--raw", valid_target]
        else:
            return {"ok": False, "status": "err", "error_code": "invalid_tool", "summary": f"Ferramenta {tool} não suportada em live."}
            
        sess.start(args)
        _sessions[sess.session_id] = sess
        
        return {
            "ok": True,
            "session_id": sess.session_id,
            "tool": tool,
            "target": target,
            "status": sess.status
        }

def status_live_session(session_id: str) -> dict:
    cleanup_sessions()
    with _registry_lock:
        sess = _sessions.get(session_id)
        if not sess:
            return {"ok": False, "status": "err", "error_code": "not_found", "summary": "Sessão não encontrada ou expirada."}
            
        sess.touch()
        elapsed = int((time.time() - sess.started_at) * 1000)
        
        # Copiar state de forma segura para não dar erro se mudar durante serialização
        structured = dict(sess.structured)
        if sess.tool == "mtr":
            structured["hops"] = [dict(h) for h in sess.structured.get("hops", [])]
            
        return {
            "ok": True,
            "session_id": sess.session_id,
            "tool": sess.tool,
            "target": sess.target,
            "status": sess.status,
            "elapsed_ms": elapsed,
            "structured": structured,
            "stdout": "\n".join(sess.stdout_buf),
            "stderr": "\n".join(sess.stderr_buf)
        }

def stop_live_session(session_id: str) -> dict:
    with _registry_lock:
        sess = _sessions.get(session_id)
        if not sess:
            return {"ok": False, "status": "err", "error_code": "not_found", "summary": "Sessão não encontrada."}
            
        sess.stop()
        elapsed = int((time.time() - sess.started_at) * 1000)
        
        structured = dict(sess.structured)
        if sess.tool == "mtr":
            structured["hops"] = [dict(h) for h in sess.structured.get("hops", [])]
        
        res = {
            "ok": True,
            "session_id": sess.session_id,
            "tool": sess.tool,
            "target": sess.target,
            "status": sess.status,
            "elapsed_ms": elapsed,
            "structured": structured,
            "stdout": "\n".join(sess.stdout_buf),
            "stderr": "\n".join(sess.stderr_buf)
        }
        del _sessions[session_id]
        return res
