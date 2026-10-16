# -*- coding: utf-8 -*-
"""会话对象与本地持久化

登录成功后保存 userid/sessionid/signvalid/cookies;
后续请求 (XCS/wt) 依赖该会话。
"""
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class ThsSession:
    userid: str = ""
    sessionid: str = ""
    signvalid: str = ""
    account: str = ""
    cookies: dict = field(default_factory=dict)
    zjzh: str = ""
    userkey: str = ""

    def is_valid(self) -> bool:
        return bool(self.userid and self.sessionid)

    def save(self, path: str | Path):
        Path(path).write_text(
            json.dumps(asdict(self), ensure_ascii=False, indent=2),
            encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "ThsSession":
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))
